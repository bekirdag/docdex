use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

use crate::symbols::{SchemaCompatibleRange, SchemaInfo};

pub const DEFAULT_MAX_NODES: usize = 200;
pub const HARD_MAX_NODES: usize = 5000;

fn default_dag_schema() -> SchemaInfo {
    SchemaInfo {
        name: "docdex.dag_export".to_string(),
        version: 1,
        compatible: SchemaCompatibleRange { min: 1, max: 1 },
    }
}

#[derive(Debug, Clone, Deserialize)]
struct DagNodeRecord {
    id: String,
    #[serde(rename = "session_id", alias = "sessionId")]
    session_id: String,
    #[serde(rename = "type", alias = "kind")]
    kind: String,
    #[serde(default)]
    payload: Value,
    #[serde(rename = "created_at", alias = "createdAt")]
    created_at: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DagExportNode {
    pub id: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub created_at: i64,
    #[serde(default)]
    pub payload: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct DagExportEdge {
    pub source: String,
    pub target: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DagExportLimits {
    pub max_nodes: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DagExportResponseV1 {
    #[serde(default = "default_dag_schema")]
    pub schema: SchemaInfo,
    #[serde(default)]
    pub repo_id: String,
    #[serde(default)]
    pub session_id: String,
    #[serde(default)]
    pub nodes: Vec<DagExportNode>,
    #[serde(default)]
    pub edges: Vec<DagExportEdge>,
    pub truncated: bool,
    pub applied_limits: DagExportLimits,
}

#[derive(Debug, Clone, Copy)]
pub struct DagExportOptions {
    pub max_nodes: usize,
}

impl DagExportOptions {
    pub fn from_optional(max_nodes: Option<usize>) -> Self {
        let max_nodes = max_nodes.unwrap_or(DEFAULT_MAX_NODES).min(HARD_MAX_NODES);
        Self { max_nodes }
    }
}

pub struct DagExport {
    pub nodes: Vec<DagExportNode>,
    pub edges: Vec<DagExportEdge>,
    pub truncated: bool,
    pub applied_limits: DagExportLimits,
}

pub struct DagStore {
    path: PathBuf,
}

impl DagStore {
    pub fn new(state_dir: &Path) -> Self {
        Self {
            path: state_dir.join("dag.jsonl"),
        }
    }

    pub fn export_session(&self, session_id: &str, options: DagExportOptions) -> Result<DagExport> {
        let records = self.read_session(session_id)?;
        let mut nodes: Vec<DagExportNode> = records
            .into_iter()
            .map(|record| DagExportNode {
                id: record.id,
                kind: record.kind,
                created_at: record.created_at,
                payload: record.payload,
            })
            .collect();

        nodes.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.id.cmp(&b.id))
        });

        let total = nodes.len();
        let max_nodes = options.max_nodes.min(HARD_MAX_NODES);
        let truncated = total > max_nodes;
        if total > max_nodes {
            nodes.truncate(max_nodes);
        }

        let edges = nodes
            .windows(2)
            .map(|pair| DagExportEdge {
                source: pair[0].id.clone(),
                target: pair[1].id.clone(),
            })
            .collect();

        Ok(DagExport {
            nodes,
            edges,
            truncated,
            applied_limits: DagExportLimits { max_nodes },
        })
    }

    fn read_session(&self, session_id: &str) -> Result<Vec<DagNodeRecord>> {
        let file = match OpenOptions::new().read(true).open(&self.path) {
            Ok(file) => file,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => return Err(err).with_context(|| format!("open {}", self.path.display())),
        };
        let reader = BufReader::new(file);
        let mut records = Vec::new();

        for line in reader.lines() {
            let line = match line {
                Ok(line) => line,
                Err(_) => continue,
            };
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let parsed: DagNodeRecord = match serde_json::from_str(trimmed) {
                Ok(value) => value,
                Err(_) => continue,
            };
            if parsed.session_id == session_id {
                records.push(parsed);
            }
        }

        Ok(records)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DagExportFormat {
    Json,
    Text,
    Dot,
}

impl DagExportFormat {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "json" => Some(Self::Json),
            "text" => Some(Self::Text),
            "dot" => Some(Self::Dot),
            _ => None,
        }
    }
}

pub fn build_export_response(
    repo_id: &str,
    session_id: &str,
    export: DagExport,
) -> DagExportResponseV1 {
    DagExportResponseV1 {
        schema: default_dag_schema(),
        repo_id: repo_id.to_string(),
        session_id: session_id.to_string(),
        nodes: export.nodes,
        edges: export.edges,
        truncated: export.truncated,
        applied_limits: export.applied_limits,
    }
}

pub fn render_text(response: &DagExportResponseV1) -> String {
    let mut out = String::new();
    out.push_str(&format!("session_id: {}\n", response.session_id));
    out.push_str(&format!("nodes: {}\n", response.nodes.len()));
    for node in &response.nodes {
        out.push_str(&format!(
            "{}\t{}\t{}\n",
            node.id, node.kind, node.created_at
        ));
    }
    out.push_str("edges:\n");
    for edge in &response.edges {
        out.push_str(&format!("{} -> {}\n", edge.source, edge.target));
    }
    out.push_str(&format!("truncated: {}\n", response.truncated));
    out
}

fn escape_dot_string(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            _ => escaped.push(ch),
        }
    }
    escaped
}

fn dot_id(input: &str) -> String {
    format!("\"{}\"", escape_dot_string(input))
}

pub fn render_dot(response: &DagExportResponseV1) -> String {
    let mut out = String::new();
    out.push_str("digraph dag {\n");
    for node in &response.nodes {
        out.push_str(&format!(
            "  {} [label=\"{}\"];\n",
            dot_id(&node.id),
            escape_dot_string(&node.kind)
        ));
    }
    for edge in &response.edges {
        out.push_str(&format!(
            "  {} -> {};\n",
            dot_id(&edge.source),
            dot_id(&edge.target)
        ));
    }
    out.push_str("}\n");
    out
}
