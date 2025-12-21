use crate::error::{AppError, ERR_INTERNAL_ERROR, ERR_INVALID_ARGUMENT, ERR_SESSION_NOT_FOUND};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use thiserror::Error;

const DAG_JSONL_NAME: &str = "dag.jsonl";
const DAG_JSON_NAME: &str = "dag.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DagNodeType {
    #[serde(alias = "UserRequest", alias = "userRequest")]
    UserRequest,
    #[serde(alias = "Thought")]
    Thought,
    #[serde(alias = "ToolCall", alias = "toolCall")]
    ToolCall,
    #[serde(alias = "Observation")]
    Observation,
    #[serde(alias = "Decision")]
    Decision,
}

impl DagNodeType {
    pub fn as_str(&self) -> &'static str {
        match self {
            DagNodeType::UserRequest => "user_request",
            DagNodeType::Thought => "thought",
            DagNodeType::ToolCall => "tool_call",
            DagNodeType::Observation => "observation",
            DagNodeType::Decision => "decision",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DagNodeRecord {
    pub id: String,
    #[serde(rename = "session_id", alias = "sessionId")]
    pub session_id: String,
    #[serde(rename = "type", alias = "nodeType")]
    pub node_type: DagNodeType,
    #[serde(rename = "created_at", alias = "createdAt")]
    pub created_at: i64,
    #[serde(default)]
    pub payload: Value,
}

#[derive(Debug, Clone)]
pub struct DagSession {
    pub session_id: String,
    pub nodes: Vec<DagNodeRecord>,
}

#[derive(Debug, Clone)]
pub struct DagEdge {
    pub from: String,
    pub to: String,
}

impl DagSession {
    pub fn edges(&self) -> Vec<DagEdge> {
        let mut edges = Vec::new();
        for pair in self.nodes.windows(2) {
            if let [from, to] = pair {
                edges.push(DagEdge {
                    from: from.id.clone(),
                    to: to.id.clone(),
                });
            }
        }
        edges
    }
}

#[derive(Debug, Clone, Copy)]
pub enum DagExportFormat {
    Text,
    Dot,
}

impl DagExportFormat {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_lowercase().as_str() {
            "text" => Some(DagExportFormat::Text),
            "dot" => Some(DagExportFormat::Dot),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct DagStore {
    jsonl_path: PathBuf,
    json_path: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum DagStoreFile {
    Nodes(Vec<DagNodeRecord>),
    Container { nodes: Vec<DagNodeRecord> },
}

impl DagStore {
    pub fn new(state_dir: &Path) -> Self {
        Self {
            jsonl_path: state_dir.join(DAG_JSONL_NAME),
            json_path: state_dir.join(DAG_JSON_NAME),
        }
    }

    pub fn load_session(&self, session_id: &str) -> Result<DagSession, DagError> {
        let session_id = session_id.trim();
        if session_id.is_empty() {
            return Err(DagError::InvalidArgument(
                "session id must not be empty".to_string(),
            ));
        }

        let jsonl_file = match OpenOptions::new().read(true).open(&self.jsonl_path) {
            Ok(file) => Some(file),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
            Err(err) => return Err(DagError::StoreIo(err)),
        };

        if let Some(file) = jsonl_file {
            let nodes = read_nodes_from_jsonl(file, session_id);
            if nodes.is_empty() {
                return Err(DagError::SessionNotFound(session_id.to_string()));
            }
            return Ok(DagSession {
                session_id: session_id.to_string(),
                nodes,
            });
        }

        let raw = match std::fs::read_to_string(&self.json_path) {
            Ok(data) => data,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Err(DagError::SessionNotFound(session_id.to_string()));
            }
            Err(err) => return Err(DagError::StoreIo(err)),
        };
        let parsed: DagStoreFile =
            serde_json::from_str(&raw).map_err(DagError::StoreParse)?;
        let nodes = match parsed {
            DagStoreFile::Nodes(nodes) => nodes,
            DagStoreFile::Container { nodes } => nodes,
        };
        let filtered: Vec<DagNodeRecord> = nodes
            .into_iter()
            .filter(|node| node.session_id == session_id)
            .collect();
        if filtered.is_empty() {
            return Err(DagError::SessionNotFound(session_id.to_string()));
        }
        Ok(DagSession {
            session_id: session_id.to_string(),
            nodes: filtered,
        })
    }
}

#[derive(Debug, Error)]
pub enum DagError {
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("session not found: {0}")]
    SessionNotFound(String),
    #[error("dag store read failed: {0}")]
    StoreIo(#[from] std::io::Error),
    #[error("dag store parse failed: {0}")]
    StoreParse(#[from] serde_json::Error),
}

pub fn map_dag_error(err: DagError) -> AppError {
    match err {
        DagError::InvalidArgument(message) => AppError::new(ERR_INVALID_ARGUMENT, message),
        DagError::SessionNotFound(session_id) => AppError::new(
            ERR_SESSION_NOT_FOUND,
            "session not found",
        )
        .with_details(json!({ "sessionId": session_id })),
        DagError::StoreIo(err) => AppError::new(ERR_INTERNAL_ERROR, "dag export failed")
            .with_details(json!({ "error": err.to_string() })),
        DagError::StoreParse(err) => AppError::new(ERR_INTERNAL_ERROR, "dag export failed")
            .with_details(json!({ "error": err.to_string() })),
    }
}

pub fn export_session(session: &DagSession, format: DagExportFormat) -> String {
    match format {
        DagExportFormat::Text => export_text(session),
        DagExportFormat::Dot => export_dot(session),
    }
}

fn export_text(session: &DagSession) -> String {
    let mut output = String::new();
    let edges = session.edges();
    output.push_str(&format!("session {}\n", session.session_id));
    output.push_str(&format!("nodes {}\n", session.nodes.len()));
    for node in &session.nodes {
        output.push_str(&format!(
            "node {} {} {}\n",
            node.id,
            node.node_type.as_str(),
            node.created_at
        ));
    }
    output.push_str(&format!("edges {}\n", edges.len()));
    for edge in edges {
        output.push_str(&format!("edge {} -> {}\n", edge.from, edge.to));
    }
    output
}

fn export_dot(session: &DagSession) -> String {
    let mut output = String::new();
    let edges = session.edges();
    output.push_str(&format!(
        "digraph \"session:{}\" {{\n",
        dot_escape(&session.session_id)
    ));
    output.push_str("  node [shape=box];\n");
    for node in &session.nodes {
        let label = format!("{} ({})", node.node_type.as_str(), node.created_at);
        output.push_str(&format!(
            "  \"{}\" [label=\"{}\"];\n",
            dot_escape(&node.id),
            dot_escape(&label)
        ));
    }
    for edge in edges {
        output.push_str(&format!(
            "  \"{}\" -> \"{}\";\n",
            dot_escape(&edge.from),
            dot_escape(&edge.to)
        ));
    }
    output.push_str("}\n");
    output
}

fn dot_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn read_nodes_from_jsonl(file: std::fs::File, session_id: &str) -> Vec<DagNodeRecord> {
    let reader = BufReader::new(file);
    let mut nodes = Vec::new();
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
            Ok(record) => record,
            Err(_) => continue,
        };
        if parsed.session_id == session_id {
            nodes.push(parsed);
        }
    }
    nodes
}
