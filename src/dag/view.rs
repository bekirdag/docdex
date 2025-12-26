use anyhow::Result;
use serde::Serialize;
use serde_json::Value;
use std::path::{Path, PathBuf};
use tracing::info;

use crate::dag::{load_session_dag, DagLoadResult};

const DEFAULT_MAX_NODES: usize = 200;
const HARD_MAX_NODES: usize = 5000;

#[derive(Serialize, Clone)]
pub struct DagExportCompatible {
    pub min: u32,
    pub max: u32,
}

#[derive(Serialize, Clone)]
pub struct DagExportSchema {
    pub name: &'static str,
    pub version: u32,
    pub compatible: DagExportCompatible,
}

#[derive(Serialize, Clone)]
pub struct DagExportNode {
    pub id: String,
    #[serde(rename = "type")]
    pub node_type: String,
    #[serde(rename = "createdAt")]
    pub created_at: i64,
    pub payload: Value,
}

#[derive(Serialize, Clone)]
pub struct DagExportEdge {
    pub source: String,
    pub target: String,
}

#[derive(Serialize, Clone)]
pub struct DagExportAppliedLimits {
    #[serde(rename = "maxNodes")]
    pub max_nodes: usize,
}

#[derive(Serialize, Clone)]
pub struct DagExportPayload {
    pub schema: DagExportSchema,
    #[serde(rename = "repoId")]
    pub repo_id: String,
    #[serde(rename = "sessionId")]
    pub session_id: String,
    pub nodes: Vec<DagExportNode>,
    pub edges: Vec<DagExportEdge>,
    pub truncated: bool,
    #[serde(rename = "appliedLimits")]
    pub applied_limits: DagExportAppliedLimits,
}

/// Render the DAG trace for the given session as plain text.
pub fn render_session_as_text(
    repo_root: &Path,
    session_id: &str,
    state_dir: Option<PathBuf>,
    max_nodes: Option<usize>,
) -> Result<String> {
    let trace = load_trace(repo_root, session_id, state_dir, "text")?;
    let payload = build_export_payload(&trace, max_nodes);
    Ok(format_export_text(&payload))
}

/// Render the DAG trace for the given session as Graphviz DOT.
pub fn render_session_as_dot(
    repo_root: &Path,
    session_id: &str,
    state_dir: Option<PathBuf>,
    max_nodes: Option<usize>,
) -> Result<String> {
    let trace = load_trace(repo_root, session_id, state_dir, "dot")?;
    let payload = build_export_payload(&trace, max_nodes);
    Ok(format_export_dot(&payload))
}

pub fn export_session(
    repo_root: &Path,
    session_id: &str,
    state_dir: Option<PathBuf>,
    max_nodes: Option<usize>,
) -> Result<DagExportPayload> {
    let trace = load_trace(repo_root, session_id, state_dir, "json")?;
    Ok(build_export_payload(&trace, max_nodes))
}

fn load_trace(
    repo_root: &Path,
    session_id: &str,
    state_dir: Option<PathBuf>,
    format: &str,
) -> Result<DagLoadResult> {
    info!(
        target: "docdexd",
        repo_root = %repo_root.display(),
        session_id = %session_id,
        format = %format,
        "dag render requested"
    );
    let trace = load_session_dag(repo_root, session_id, state_dir)?;
    info!(
        target: "docdexd",
        repo_root = %repo_root.display(),
        session_id = %session_id,
        format = %format,
        status = ?trace.status,
        nodes = trace.nodes.len(),
        "dag render completed"
    );
    Ok(trace)
}

fn build_export_payload(trace: &DagLoadResult, max_nodes: Option<usize>) -> DagExportPayload {
    let max_nodes = clamp_max_nodes(max_nodes);
    let mut nodes: Vec<DagExportNode> = trace
        .nodes
        .iter()
        .map(|node| DagExportNode {
            id: node.id.clone(),
            node_type: node.node_type.clone(),
            created_at: node.created_at.unwrap_or(0),
            payload: node.payload.clone(),
        })
        .collect();
    nodes.sort_by(|a, b| {
        a.created_at
            .cmp(&b.created_at)
            .then_with(|| a.id.cmp(&b.id))
    });
    let truncated = nodes.len() > max_nodes;
    if truncated {
        nodes.truncate(max_nodes);
    }
    let edges = build_edges(&nodes);
    DagExportPayload {
        schema: DagExportSchema {
            name: "docdex.dag_export",
            version: 1,
            compatible: DagExportCompatible { min: 1, max: 1 },
        },
        repo_id: trace.repo_fingerprint.clone(),
        session_id: trace.session_id.clone(),
        nodes,
        edges,
        truncated,
        applied_limits: DagExportAppliedLimits { max_nodes },
    }
}

fn build_edges(nodes: &[DagExportNode]) -> Vec<DagExportEdge> {
    if nodes.len() < 2 {
        return Vec::new();
    }
    nodes
        .windows(2)
        .map(|pair| DagExportEdge {
            source: pair[0].id.clone(),
            target: pair[1].id.clone(),
        })
        .collect()
}

fn clamp_max_nodes(max_nodes: Option<usize>) -> usize {
    let mut value = max_nodes.unwrap_or(DEFAULT_MAX_NODES);
    if value > HARD_MAX_NODES {
        value = HARD_MAX_NODES;
    }
    value
}

fn format_export_text(payload: &DagExportPayload) -> String {
    let mut lines = Vec::new();
    lines.push(format!("session_id: {}", payload.session_id));
    lines.push(format!("nodes: {}", payload.nodes.len()));
    for node in &payload.nodes {
        lines.push(format!(
            "{}\t{}\t{}",
            node.id, node.node_type, node.created_at
        ));
    }
    lines.push("edges:".to_string());
    for edge in &payload.edges {
        lines.push(format!("{} -> {}", edge.source, edge.target));
    }
    lines.push(format!("truncated: {}", payload.truncated));
    lines.join("\n")
}

fn format_export_dot(payload: &DagExportPayload) -> String {
    let mut lines = Vec::new();
    lines.push("digraph dag {".to_string());
    for node in &payload.nodes {
        lines.push(format!(
            "  \"{}\" [label=\"{}\"];",
            escape_dot_label(&node.id),
            escape_dot_label(&node.node_type)
        ));
    }
    for edge in &payload.edges {
        lines.push(format!(
            "  \"{}\" -> \"{}\";",
            escape_dot_label(&edge.source),
            escape_dot_label(&edge.target)
        ));
    }
    lines.push("}".to_string());
    lines.join("\n")
}

fn escape_dot_label(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => {}
            '\t' => out.push_str("\\t"),
            _ => out.push(ch),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dag::{DagLoadResult, DagNode, DagStatus};
    use serde_json::json;

    #[test]
    fn format_trace_reports_missing_message() -> Result<()> {
        let result = DagLoadResult {
            repo_root: "repo".to_string(),
            repo_fingerprint: "fp".to_string(),
            session_id: "session".to_string(),
            status: DagStatus::Missing,
            nodes: vec![],
            source: None,
            message: Some("none".to_string()),
            warnings: vec![],
        };
        let payload = build_export_payload(&result, None);
        let text = format_export_text(&payload);
        assert!(text.contains("session_id: session"));
        assert!(text.contains("nodes: 0"));
        Ok(())
    }

    #[test]
    fn render_session_with_nodes() -> Result<()> {
        let record = DagLoadResult {
            repo_root: "repo".to_string(),
            repo_fingerprint: "fp".to_string(),
            session_id: "session".to_string(),
            status: DagStatus::Found,
            nodes: vec![DagNode {
                id: "n1".to_string(),
                node_type: "UserRequest".to_string(),
                payload: json!({"text": "hello"}),
                created_at: Some(1),
            }],
            source: None,
            message: None,
            warnings: vec![],
        };
        let payload = build_export_payload(&record, None);
        let text = format_export_text(&payload);
        assert!(text.contains("UserRequest"));
        Ok(())
    }

    #[test]
    fn render_session_dot_includes_edges() -> Result<()> {
        let record = DagLoadResult {
            repo_root: "repo".to_string(),
            repo_fingerprint: "fp".to_string(),
            session_id: "session".to_string(),
            status: DagStatus::Found,
            nodes: vec![
                DagNode {
                    id: "n1".to_string(),
                    node_type: "UserRequest".to_string(),
                    payload: json!({"text": "hello"}),
                    created_at: Some(1),
                },
                DagNode {
                    id: "n2".to_string(),
                    node_type: "Decision".to_string(),
                    payload: json!({"result": "ok"}),
                    created_at: Some(2),
                },
            ],
            source: None,
            message: None,
            warnings: vec![],
        };
        let payload = build_export_payload(&record, None);
        let dot = format_export_dot(&payload);
        assert!(dot.contains("digraph dag"));
        assert!(dot.contains("n1"));
        assert!(dot.contains("\"n1\" -> \"n2\""));
        Ok(())
    }
}
