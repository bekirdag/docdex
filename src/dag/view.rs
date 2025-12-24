use anyhow::Result;
use std::path::{Path, PathBuf};

use crate::dag::{load_session_dag, DagLoadResult, NO_TRACE_MESSAGE};

/// Render the DAG trace for the given session as plain text.
pub fn render_session_as_text(
    repo_root: &Path,
    session_id: &str,
    state_dir: Option<PathBuf>,
) -> Result<String> {
    let trace = load_session_dag(repo_root, session_id, state_dir)?;
    format_trace(&trace)
}

fn format_trace(trace: &DagLoadResult) -> Result<String> {
    if trace.nodes.is_empty() {
        let message = trace
            .message
            .clone()
            .unwrap_or_else(|| NO_TRACE_MESSAGE.to_string());
        return Ok(message);
    }
    let mut lines = Vec::with_capacity(trace.nodes.len());
    for node in &trace.nodes {
        let payload = if node.payload.is_null() {
            "payload=null".to_string()
        } else {
            node.payload.to_string()
        };
        lines.push(format!("[{}] {}", node.node_type, payload.trim()));
    }
    Ok(lines.join("\n"))
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
        assert_eq!(format_trace(&result)?, "none");
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
                id: 1,
                node_type: "UserRequest".to_string(),
                payload: json!({"text": "hello"}),
                created_at: Some(1),
            }],
            source: None,
            message: None,
            warnings: vec![],
        };
        let text = format_trace(&record)?;
        assert!(text.contains("UserRequest"));
        Ok(())
    }
}
