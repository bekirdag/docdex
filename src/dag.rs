#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};

const ERR_DAG_EXPORT_INVALID: &str = "dag_export_invalid";
const ERR_DAG_EXPORT_TOO_LARGE: &str = "dag_export_too_large";

const DEFAULT_MAX_NODES: usize = 10_000;
const DEFAULT_MAX_EDGES: usize = 20_000;
const DEFAULT_MAX_BYTES: usize = 1_000_000;
const DEFAULT_MAX_LABEL_BYTES: usize = 4_096;

#[derive(Debug, Clone)]
pub struct Dag {
    pub session_id: String,
    pub nodes: Vec<DagNode>,
    pub edges: Vec<DagEdge>,
}

impl Dag {
    pub fn new(
        session_id: impl Into<String>,
        nodes: Vec<DagNode>,
        edges: Vec<DagEdge>,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            nodes,
            edges,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DagNode {
    pub id: String,
    pub label: Option<String>,
    pub kind: Option<String>,
}

impl DagNode {
    pub fn new(id: impl Into<String>, label: Option<String>, kind: Option<String>) -> Self {
        Self {
            id: id.into(),
            label,
            kind,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DagEdge {
    pub from: String,
    pub to: String,
    pub label: Option<String>,
    pub kind: Option<String>,
}

impl DagEdge {
    pub fn new(
        from: impl Into<String>,
        to: impl Into<String>,
        label: Option<String>,
        kind: Option<String>,
    ) -> Self {
        Self {
            from: from.into(),
            to: to.into(),
            label,
            kind,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DagExportLimits {
    pub max_nodes: usize,
    pub max_edges: usize,
    pub max_bytes: usize,
    pub max_label_bytes: usize,
}

impl Default for DagExportLimits {
    fn default() -> Self {
        Self {
            max_nodes: DEFAULT_MAX_NODES,
            max_edges: DEFAULT_MAX_EDGES,
            max_bytes: DEFAULT_MAX_BYTES,
            max_label_bytes: DEFAULT_MAX_LABEL_BYTES,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DagExportOptions {
    pub graph_name: Option<String>,
    pub limits: DagExportLimits,
}

impl Default for DagExportOptions {
    fn default() -> Self {
        Self {
            graph_name: None,
            limits: DagExportLimits::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DagExportError {
    EmptyNodeId,
    EmptyEdgeEndpoint { field: &'static str },
    TooManyNodes { limit: usize, actual: usize },
    TooManyEdges { limit: usize, actual: usize },
    LabelTooLarge { limit: usize, actual: usize },
    OutputTooLarge { limit: usize, actual: usize },
}

impl DagExportError {
    pub fn code(&self) -> &'static str {
        match self {
            DagExportError::EmptyNodeId | DagExportError::EmptyEdgeEndpoint { .. } => {
                ERR_DAG_EXPORT_INVALID
            }
            DagExportError::TooManyNodes { .. }
            | DagExportError::TooManyEdges { .. }
            | DagExportError::LabelTooLarge { .. }
            | DagExportError::OutputTooLarge { .. } => ERR_DAG_EXPORT_TOO_LARGE,
        }
    }
}

impl std::fmt::Display for DagExportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DagExportError::EmptyNodeId => write!(f, "node id must not be empty"),
            DagExportError::EmptyEdgeEndpoint { field } => {
                write!(f, "edge endpoint {field} must not be empty")
            }
            DagExportError::TooManyNodes { limit, actual } => {
                write!(f, "node count {actual} exceeds limit {limit}")
            }
            DagExportError::TooManyEdges { limit, actual } => {
                write!(f, "edge count {actual} exceeds limit {limit}")
            }
            DagExportError::LabelTooLarge { limit, actual } => {
                write!(f, "label size {actual} exceeds limit {limit}")
            }
            DagExportError::OutputTooLarge { limit, actual } => {
                write!(f, "export size {actual} exceeds limit {limit}")
            }
        }
    }
}

impl std::error::Error for DagExportError {}

#[derive(Debug, Clone)]
struct NodeInfo {
    label: Option<String>,
    kind: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct EdgeKey {
    from: String,
    to: String,
    label: Option<String>,
}

pub fn export_dag_dot(dag: &Dag, options: &DagExportOptions) -> Result<String, DagExportError> {
    let limits = &options.limits;
    let mut nodes: BTreeMap<String, NodeInfo> = BTreeMap::new();

    for node in &dag.nodes {
        let id = normalize_id(&node.id)?;
        let entry = nodes.entry(id).or_insert(NodeInfo {
            label: None,
            kind: None,
        });
        prefer_value(&mut entry.label, node.label.as_deref());
        prefer_value(&mut entry.kind, node.kind.as_deref());
    }

    let mut edges: BTreeSet<EdgeKey> = BTreeSet::new();
    for edge in &dag.edges {
        let from = normalize_id(&edge.from)?;
        let to = normalize_id(&edge.to)?;
        nodes.entry(from.clone()).or_insert(NodeInfo {
            label: None,
            kind: None,
        });
        nodes.entry(to.clone()).or_insert(NodeInfo {
            label: None,
            kind: None,
        });
        let label = preferred_label(edge.label.as_deref(), edge.kind.as_deref());
        edges.insert(EdgeKey { from, to, label });
    }

    if nodes.len() > limits.max_nodes {
        return Err(DagExportError::TooManyNodes {
            limit: limits.max_nodes,
            actual: nodes.len(),
        });
    }
    if edges.len() > limits.max_edges {
        return Err(DagExportError::TooManyEdges {
            limit: limits.max_edges,
            actual: edges.len(),
        });
    }

    let graph_name = normalized_graph_name(dag, options);
    let mut out = String::new();
    push_line(
        &mut out,
        &format!("digraph {} {{", dot_quote(&graph_name)),
        limits,
    )?;

    for (id, info) in nodes {
        let label = info.label.or(info.kind);
        let line = if let Some(label) = label {
            let label_len = label.len();
            if label_len > limits.max_label_bytes {
                return Err(DagExportError::LabelTooLarge {
                    limit: limits.max_label_bytes,
                    actual: label_len,
                });
            }
            format!(
                "  {} [label={}];",
                dot_quote(&id),
                dot_quote(&label)
            )
        } else {
            format!("  {};", dot_quote(&id))
        };
        push_line(&mut out, &line, limits)?;
    }

    for edge in edges {
        let line = if let Some(label) = edge.label {
            let label_len = label.len();
            if label_len > limits.max_label_bytes {
                return Err(DagExportError::LabelTooLarge {
                    limit: limits.max_label_bytes,
                    actual: label_len,
                });
            }
            format!(
                "  {} -> {} [label={}];",
                dot_quote(&edge.from),
                dot_quote(&edge.to),
                dot_quote(&label)
            )
        } else {
            format!("  {} -> {};", dot_quote(&edge.from), dot_quote(&edge.to))
        };
        push_line(&mut out, &line, limits)?;
    }

    push_line(&mut out, "}", limits)?;
    Ok(out)
}

fn normalized_graph_name(dag: &Dag, options: &DagExportOptions) -> String {
    let explicit = options
        .graph_name
        .as_deref()
        .and_then(|value| normalize_text(value).map(str::to_string));
    if let Some(name) = explicit {
        return name;
    }
    if let Some(name) = normalize_text(&dag.session_id) {
        return name.to_string();
    }
    "session_dag".to_string()
}

fn normalize_id(value: &str) -> Result<String, DagExportError> {
    let Some(trimmed) = normalize_text(value) else {
        return Err(DagExportError::EmptyNodeId);
    };
    Ok(trimmed.to_string())
}

fn normalize_text(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

fn prefer_value(existing: &mut Option<String>, candidate: Option<&str>) {
    let Some(candidate) = candidate.and_then(normalize_text) else {
        return;
    };
    match existing {
        None => *existing = Some(candidate.to_string()),
        Some(current) => {
            if is_preferred(candidate, current.as_str()) {
                *current = candidate.to_string();
            }
        }
    }
}

fn is_preferred(candidate: &str, current: &str) -> bool {
    if candidate.len() != current.len() {
        return candidate.len() < current.len();
    }
    candidate < current
}

fn preferred_label(label: Option<&str>, kind: Option<&str>) -> Option<String> {
    if let Some(label) = label.and_then(normalize_text) {
        return Some(label.to_string());
    }
    kind.and_then(normalize_text).map(str::to_string)
}

fn dot_quote(value: &str) -> String {
    format!("\"{}\"", escape_dot(value))
}

fn escape_dot(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            ch if ch.is_control() => {
                escaped.push_str(&format!("\\x{:02X}", ch as u32));
            }
            _ => escaped.push(ch),
        }
    }
    escaped
}

fn push_line(
    out: &mut String,
    line: &str,
    limits: &DagExportLimits,
) -> Result<(), DagExportError> {
    out.push_str(line);
    out.push('\n');
    let size = out.len();
    if size > limits.max_bytes {
        return Err(DagExportError::OutputTooLarge {
            limit: limits.max_bytes,
            actual: size,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dot_export_is_deterministic() {
        let dag_a = Dag::new(
            "session-1",
            vec![
                DagNode::new("b", Some("label-b".to_string()), Some("kind-b".to_string())),
                DagNode::new("a", Some("label-a".to_string()), None),
            ],
            vec![DagEdge::new("b", "a", None, Some("edge-kind".to_string()))],
        );

        let dag_b = Dag::new(
            "session-1",
            vec![
                DagNode::new("a", Some("label-a".to_string()), None),
                DagNode::new("b", Some("label-b".to_string()), Some("kind-b".to_string())),
            ],
            vec![DagEdge::new("b", "a", None, Some("edge-kind".to_string()))],
        );

        let options = DagExportOptions::default();
        let a = export_dag_dot(&dag_a, &options).expect("export dag a");
        let b = export_dag_dot(&dag_b, &options).expect("export dag b");
        assert_eq!(a, b);
    }

    #[test]
    fn dot_export_escapes_labels() {
        let dag = Dag::new(
            "session-2",
            vec![
                DagNode::new(
                    "node\"1",
                    Some("line1\nline2\\\"".to_string()),
                    None,
                ),
                DagNode::new("node2", None, None),
            ],
            vec![DagEdge::new(
                "node\"1",
                "node2",
                Some("edge\"label".to_string()),
                None,
            )],
        );

        let output = export_dag_dot(&dag, &DagExportOptions::default()).expect("export dag");
        assert!(output.contains("\\\""));
        assert!(output.contains("\\n"));
        assert!(output.contains("\\\\"));
    }

    #[test]
    fn dot_export_enforces_limits() {
        let dag = Dag::new(
            "session-3",
            vec![
                DagNode::new("a", None, None),
                DagNode::new("b", None, None),
            ],
            Vec::new(),
        );
        let options = DagExportOptions {
            graph_name: None,
            limits: DagExportLimits {
                max_nodes: 1,
                ..DagExportLimits::default()
            },
        };
        let err = export_dag_dot(&dag, &options).expect_err("limit enforcement");
        assert!(matches!(err, DagExportError::TooManyNodes { .. }));
    }
}
