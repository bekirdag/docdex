use serde_json::Value;
use std::collections::{BTreeMap, HashSet};

const DEFAULT_MAX_NODES: usize = 1000;
const DEFAULT_MAX_EDGES: usize = 2000;
const DEFAULT_MAX_PAYLOAD_BYTES: usize = 1024;
const DEFAULT_MAX_OUTPUT_BYTES: usize = 256 * 1024;
const OUTPUT_TRUNCATION_MARKER: &str = "\n... output truncated\n";
const PAYLOAD_TRUNCATION_SUFFIX: &str = "...";
const ERR_DAG_EXPORT_INVALID: &str = "dag_export_invalid";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DagNodeType {
    UserRequest,
    Thought,
    ToolCall,
    Observation,
    Decision,
}

impl std::fmt::Display for DagNodeType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let label = match self {
            DagNodeType::UserRequest => "UserRequest",
            DagNodeType::Thought => "Thought",
            DagNodeType::ToolCall => "ToolCall",
            DagNodeType::Observation => "Observation",
            DagNodeType::Decision => "Decision",
        };
        write!(f, "{label}")
    }
}

#[derive(Debug, Clone)]
pub struct DagNode {
    pub id: String,
    pub node_type: DagNodeType,
    pub created_at: i64,
    pub payload: Value,
}

#[derive(Debug, Clone)]
pub struct DagEdge {
    pub from: String,
    pub to: String,
    pub kind: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SessionDag {
    pub session_id: String,
    pub nodes: Vec<DagNode>,
    pub edges: Vec<DagEdge>,
}

#[derive(Debug, Clone)]
pub struct DagExportLimits {
    pub max_nodes: usize,
    pub max_edges: usize,
    pub max_payload_bytes: usize,
    pub max_output_bytes: usize,
}

impl Default for DagExportLimits {
    fn default() -> Self {
        Self {
            max_nodes: DEFAULT_MAX_NODES,
            max_edges: DEFAULT_MAX_EDGES,
            max_payload_bytes: DEFAULT_MAX_PAYLOAD_BYTES,
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DagTextExport {
    pub text: String,
    pub truncated: bool,
    pub truncated_nodes: usize,
    pub truncated_edges: usize,
    pub truncated_payloads: usize,
    pub truncated_output: bool,
    pub total_nodes: usize,
    pub total_edges: usize,
    pub applied_limits: DagExportLimits,
}

#[derive(Debug, thiserror::Error)]
#[error("{message}")]
pub struct DagExportError {
    pub code: &'static str,
    pub message: String,
}

impl DagExportError {
    fn invalid(message: impl Into<String>) -> Self {
        Self {
            code: ERR_DAG_EXPORT_INVALID,
            message: message.into(),
        }
    }
}

pub fn export_session_dag_text(
    dag: &SessionDag,
    limits: &DagExportLimits,
) -> Result<DagTextExport, DagExportError> {
    validate_dag(dag)?;

    let mut nodes: Vec<&DagNode> = dag.nodes.iter().collect();
    nodes.sort_by(|left, right| {
        (
            left.created_at,
            left.id.as_str(),
            left.node_type,
        )
            .cmp(&(right.created_at, right.id.as_str(), right.node_type))
    });

    let mut edges: Vec<&DagEdge> = dag.edges.iter().collect();
    edges.sort_by(|left, right| {
        (
            left.from.as_str(),
            left.to.as_str(),
            left.kind.as_deref(),
        )
            .cmp(&(right.from.as_str(), right.to.as_str(), right.kind.as_deref()))
    });

    let total_nodes = nodes.len();
    let total_edges = edges.len();
    let max_nodes = limits.max_nodes.min(total_nodes);
    let max_edges = limits.max_edges.min(total_edges);
    let truncated_nodes = total_nodes.saturating_sub(max_nodes);
    let truncated_edges = total_edges.saturating_sub(max_edges);
    let mut truncated_payloads = 0;

    let mut lines = Vec::new();
    lines.push(format!("session: {}", dag.session_id));
    lines.push(format!("nodes: {}/{}", max_nodes, total_nodes));
    for node in nodes.iter().take(max_nodes) {
        let payload = canonical_json(&node.payload);
        let (payload, payload_truncated) = truncate_payload(&payload, limits.max_payload_bytes);
        if payload_truncated {
            truncated_payloads += 1;
        }
        lines.push(format!(
            "- {} {} payload={}",
            node.id, node.node_type, payload
        ));
    }
    lines.push(format!("edges: {}/{}", max_edges, total_edges));
    for edge in edges.iter().take(max_edges) {
        let kind = edge.kind.as_deref().unwrap_or("-");
        lines.push(format!("- {} -> {} kind={}", edge.from, edge.to, kind));
    }

    let mut truncated_output = false;
    let mut summary_line = format!(
        "truncated: nodes={} edges={} payloads={} output=false",
        truncated_nodes, truncated_edges, truncated_payloads
    );
    lines.push(summary_line.clone());
    let mut text = join_lines(&lines);

    if text.len() > limits.max_output_bytes {
        truncated_output = true;
        lines.pop();
        summary_line = format!(
            "truncated: nodes={} edges={} payloads={} output=true",
            truncated_nodes, truncated_edges, truncated_payloads
        );
        lines.push(summary_line);
        text = join_lines(&lines);
        if text.len() > limits.max_output_bytes {
            text = truncate_output(&text, limits.max_output_bytes);
        }
    }

    let truncated = truncated_nodes > 0
        || truncated_edges > 0
        || truncated_payloads > 0
        || truncated_output;

    Ok(DagTextExport {
        text,
        truncated,
        truncated_nodes,
        truncated_edges,
        truncated_payloads,
        truncated_output,
        total_nodes,
        total_edges,
        applied_limits: limits.clone(),
    })
}

fn validate_dag(dag: &SessionDag) -> Result<(), DagExportError> {
    let mut ids = HashSet::new();
    for node in &dag.nodes {
        if !ids.insert(node.id.as_str()) {
            return Err(DagExportError::invalid(format!(
                "duplicate node id: {}",
                node.id
            )));
        }
    }
    for edge in &dag.edges {
        if !ids.contains(edge.from.as_str()) {
            return Err(DagExportError::invalid(format!(
                "edge references unknown node: {}",
                edge.from
            )));
        }
        if !ids.contains(edge.to.as_str()) {
            return Err(DagExportError::invalid(format!(
                "edge references unknown node: {}",
                edge.to
            )));
        }
    }
    Ok(())
}

fn canonical_json(value: &Value) -> String {
    let normalized = canonicalize_value(value);
    serde_json::to_string(&normalized).unwrap_or_else(|_| "null".to_string())
}

fn canonicalize_value(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut sorted: BTreeMap<String, Value> = BTreeMap::new();
            for (key, value) in map {
                sorted.insert(key.clone(), canonicalize_value(value));
            }
            let mut ordered = serde_json::Map::new();
            for (key, value) in sorted {
                ordered.insert(key, value);
            }
            Value::Object(ordered)
        }
        Value::Array(list) => Value::Array(list.iter().map(canonicalize_value).collect()),
        other => other.clone(),
    }
}

fn truncate_bytes_with_suffix(input: &str, max_bytes: usize, suffix: &str) -> (String, bool) {
    if input.len() <= max_bytes {
        return (input.to_string(), false);
    }
    if max_bytes == 0 {
        return (String::new(), true);
    }
    if max_bytes <= suffix.len() {
        return (suffix[..max_bytes].to_string(), true);
    }

    let mut end = max_bytes.saturating_sub(suffix.len());
    while end > 0 && !input.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = input[..end].to_string();
    out.push_str(suffix);
    (out, true)
}

fn truncate_payload(payload: &str, max_bytes: usize) -> (String, bool) {
    if max_bytes >= 2 && payload.starts_with('"') && payload.ends_with('"') && payload.len() >= 2 {
        let inner = &payload[1..payload.len() - 1];
        let max_inner = max_bytes.saturating_sub(2);
        let (truncated_inner, was_truncated) =
            truncate_bytes_with_suffix(inner, max_inner, PAYLOAD_TRUNCATION_SUFFIX);
        if was_truncated {
            return (format!("\"{}\"", truncated_inner), true);
        }
        return (payload.to_string(), false);
    }
    truncate_bytes_with_suffix(payload, max_bytes, PAYLOAD_TRUNCATION_SUFFIX)
}

fn join_lines(lines: &[String]) -> String {
    let mut out = String::new();
    for (idx, line) in lines.iter().enumerate() {
        if idx > 0 {
            out.push('\n');
        }
        out.push_str(line);
    }
    out.push('\n');
    out
}

fn truncate_output(output: &str, max_bytes: usize) -> String {
    if output.len() <= max_bytes {
        return output.to_string();
    }
    if max_bytes == 0 {
        return String::new();
    }
    if max_bytes <= OUTPUT_TRUNCATION_MARKER.len() {
        return OUTPUT_TRUNCATION_MARKER[..max_bytes].to_string();
    }

    let mut end = max_bytes.saturating_sub(OUTPUT_TRUNCATION_MARKER.len());
    while end > 0 && !output.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = output[..end].to_string();
    out.push_str(OUTPUT_TRUNCATION_MARKER);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn text_export_is_deterministic_and_ordered() {
        let dag = SessionDag {
            session_id: "session-1".to_string(),
            nodes: vec![
                DagNode {
                    id: "n2".to_string(),
                    node_type: DagNodeType::Thought,
                    created_at: 2,
                    payload: json!({"msg": "hello"}),
                },
                DagNode {
                    id: "n1".to_string(),
                    node_type: DagNodeType::UserRequest,
                    created_at: 1,
                    payload: json!({"b": 2, "a": 1}),
                },
                DagNode {
                    id: "n3".to_string(),
                    node_type: DagNodeType::ToolCall,
                    created_at: 3,
                    payload: json!([1, 2, 3]),
                },
            ],
            edges: vec![
                DagEdge {
                    from: "n2".to_string(),
                    to: "n3".to_string(),
                    kind: None,
                },
                DagEdge {
                    from: "n1".to_string(),
                    to: "n2".to_string(),
                    kind: Some("next".to_string()),
                },
            ],
        };

        let limits = DagExportLimits {
            max_nodes: 10,
            max_edges: 10,
            max_payload_bytes: 64,
            max_output_bytes: 4096,
        };

        let export_a = export_session_dag_text(&dag, &limits).unwrap();
        let export_b = export_session_dag_text(&dag, &limits).unwrap();
        assert_eq!(export_a.text, export_b.text);

        let expected = "\
session: session-1
nodes: 3/3
- n1 UserRequest payload={\"a\":1,\"b\":2}
- n2 Thought payload={\"msg\":\"hello\"}
- n3 ToolCall payload=[1,2,3]
edges: 2/2
- n1 -> n2 kind=next
- n2 -> n3 kind=-
truncated: nodes=0 edges=0 payloads=0 output=false
";
        assert_eq!(export_a.text, expected);
        assert!(!export_a.truncated);
    }

    #[test]
    fn text_export_truncates_nodes_edges_and_payloads() {
        let dag = SessionDag {
            session_id: "session-2".to_string(),
            nodes: vec![
                DagNode {
                    id: "n1".to_string(),
                    node_type: DagNodeType::UserRequest,
                    created_at: 1,
                    payload: json!("0123456789"),
                },
                DagNode {
                    id: "n2".to_string(),
                    node_type: DagNodeType::Thought,
                    created_at: 2,
                    payload: json!("ok"),
                },
            ],
            edges: vec![DagEdge {
                from: "n1".to_string(),
                to: "n2".to_string(),
                kind: Some("next".to_string()),
            }],
        };

        let limits = DagExportLimits {
            max_nodes: 1,
            max_edges: 0,
            max_payload_bytes: 5,
            max_output_bytes: 4096,
        };

        let export = export_session_dag_text(&dag, &limits).unwrap();
        assert!(export.truncated);
        assert_eq!(export.truncated_nodes, 1);
        assert_eq!(export.truncated_edges, 1);
        assert_eq!(export.truncated_payloads, 1);
        assert!(!export.truncated_output);
        assert!(export.text.contains("payload=\"...\""));
    }
}
