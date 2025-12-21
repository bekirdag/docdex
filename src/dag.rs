<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
use anyhow::{Context, Result};
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::{Path, PathBuf};

pub fn dag_db_path_from_index_state_dir(index_state_dir: &Path) -> PathBuf {
    index_state_dir
        .parent()
        .unwrap_or(index_state_dir)
        .join("dag.db")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DagNode {
    pub id: String,
    pub session_id: String,
    #[serde(rename = "type")]
    pub kind: String,
=======
use crate::error::{AppError, ERR_INVALID_ARGUMENT, ERR_MISSING_DEPENDENCY};
use anyhow::{Context, Result};
use rusqlite::{params, Connection};
use serde_json::Value;
use std::fmt::Write;
use std::path::{Path, PathBuf};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct DagNode {
    pub id: String,
    pub node_type: String,
>>>>>>> mcoda/task/bck-05-us-07-t25
    pub payload: Value,
    pub created_at: i64,
}

<<<<<<< HEAD
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DagEdge {
    pub source: String,
    pub target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DagSession {
    pub repo_id: String,
=======
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
>>>>>>> mcoda/task/bck-05-us-07-t24
    pub session_id: String,
    pub nodes: Vec<DagNode>,
    pub edges: Vec<DagEdge>,
}

<<<<<<< HEAD
pub struct DagStore {
    repo_id: String,
=======
#[derive(Debug, Clone)]
pub struct DagSession {
    pub session_id: String,
    pub nodes: Vec<DagNode>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DagFormat {
    Text,
    Dot,
}

impl DagFormat {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "text" => Some(Self::Text),
            "dot" => Some(Self::Dot),
            _ => None,
        }
    }

    pub fn content_type(self) -> &'static str {
        match self {
            Self::Text => "text/plain; charset=utf-8",
            Self::Dot => "text/vnd.graphviz; charset=utf-8",
        }
    }
}

#[derive(Clone)]
pub struct DagStore {
>>>>>>> mcoda/task/bck-05-us-07-t25
    path: PathBuf,
}

impl DagStore {
<<<<<<< HEAD
    pub fn new(repo_root: &Path, index_state_dir: &Path) -> Result<Self> {
        Ok(Self {
            repo_id: crate::symbols::repo_id_for_root(repo_root)?,
            path: dag_db_path_from_index_state_dir(index_state_dir),
        })
    }

    pub fn repo_id(&self) -> &str {
        &self.repo_id
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load_session(&self, session_id: &str) -> Result<Option<DagSession>> {
        if session_id.trim().is_empty() {
            return Ok(None);
        }
        if !self.path.exists() {
            return Ok(None);
        }
        let conn = Connection::open_with_flags(&self.path, OpenFlags::SQLITE_OPEN_READ_ONLY)
            .with_context(|| format!("open dag db {}", self.path.display()))?;
        if !table_exists(&conn, "nodes")? {
            anyhow::bail!("dag.db missing nodes table");
        }
        let mut stmt = conn.prepare(
            "SELECT id, session_id, \"type\", payload, created_at \
             FROM nodes WHERE session_id = ?1 ORDER BY created_at ASC, id ASC",
        )?;
        let rows = stmt.query_map([session_id], |row| {
            let payload_raw: Option<String> = row.get(3)?;
            let payload = payload_raw
                .as_deref()
                .and_then(|raw| serde_json::from_str(raw).ok())
                .unwrap_or_else(|| payload_raw.map(Value::String).unwrap_or(Value::Null));
            Ok(DagNode {
                id: row.get(0)?,
                session_id: row.get(1)?,
                kind: row.get(2)?,
                payload,
                created_at: row.get(4)?,
            })
        })?;
        let mut nodes = Vec::new();
        for row in rows {
            nodes.push(row?);
        }
        if nodes.is_empty() {
            return Ok(None);
        }
        // Edges are implied by session ordering when no explicit edge table is present.
        let mut edges = Vec::new();
        for window in nodes.windows(2) {
            edges.push(DagEdge {
                source: window[0].id.clone(),
                target: window[1].id.clone(),
                kind: None,
            });
        }
        Ok(Some(DagSession {
            repo_id: self.repo_id.clone(),
            session_id: session_id.to_string(),
            nodes,
            edges,
        }))
    }
}

fn table_exists(conn: &Connection, table: &str) -> Result<bool> {
    let exists: Option<i64> = conn
        .query_row(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name = ?1",
            [table],
            |row| row.get(0),
        )
        .optional()?;
    Ok(exists.is_some())
=======
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
=======
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
>>>>>>> mcoda/task/bck-05-us-07-t23
    }
}

#[derive(Debug, Clone)]
pub struct DagNode {
    pub id: String,
<<<<<<< HEAD
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
=======
    pub node_type: DagNodeType,
    pub created_at: i64,
    pub payload: Value,
>>>>>>> mcoda/task/bck-05-us-07-t23
=======
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
=======
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
>>>>>>> mcoda/task/bck-05-us-07-t27
    pub created_at: i64,
    #[serde(default)]
    pub payload: Value,
}

<<<<<<< HEAD
#[derive(Debug, Clone)]
pub struct DagSession {
    pub session_id: String,
    pub nodes: Vec<DagNodeRecord>,
>>>>>>> mcoda/task/bck-05-us-07-t26
}

#[derive(Debug, Clone)]
pub struct DagEdge {
    pub from: String,
    pub to: String,
<<<<<<< HEAD
<<<<<<< HEAD
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
=======
    pub kind: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SessionDag {
    pub session_id: String,
    pub nodes: Vec<DagNode>,
    pub edges: Vec<DagEdge>,
>>>>>>> mcoda/task/bck-05-us-07-t23
}

#[derive(Debug, Clone)]
pub struct DagExportLimits {
    pub max_nodes: usize,
    pub max_edges: usize,
<<<<<<< HEAD
    pub max_bytes: usize,
    pub max_label_bytes: usize,
=======
    pub max_payload_bytes: usize,
    pub max_output_bytes: usize,
>>>>>>> mcoda/task/bck-05-us-07-t23
}

impl Default for DagExportLimits {
    fn default() -> Self {
        Self {
            max_nodes: DEFAULT_MAX_NODES,
            max_edges: DEFAULT_MAX_EDGES,
<<<<<<< HEAD
            max_bytes: DEFAULT_MAX_BYTES,
            max_label_bytes: DEFAULT_MAX_LABEL_BYTES,
=======
            max_payload_bytes: DEFAULT_MAX_PAYLOAD_BYTES,
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
>>>>>>> mcoda/task/bck-05-us-07-t23
        }
    }
}

#[derive(Debug, Clone)]
<<<<<<< HEAD
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
=======
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
>>>>>>> mcoda/task/bck-05-us-07-t23
        }
    }
}

<<<<<<< HEAD
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
=======
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
=======
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
>>>>>>> mcoda/task/bck-05-us-07-t27
    Text,
    Dot,
}

impl DagExportFormat {
<<<<<<< HEAD
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_lowercase().as_str() {
            "text" => Some(DagExportFormat::Text),
            "dot" => Some(DagExportFormat::Dot),
            _ => None,
>>>>>>> mcoda/task/bck-05-us-07-t26
=======
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "json" => Some(Self::Json),
            "text" => Some(Self::Text),
            "dot" => Some(Self::Dot),
            _ => None,
>>>>>>> mcoda/task/bck-05-us-07-t27
        }
    }
}

<<<<<<< HEAD
<<<<<<< HEAD
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
=======
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
>>>>>>> mcoda/task/bck-05-us-07-t27
        match ch {
            '\\' => escaped.push_str("\\\\"),
            '"' => escaped.push_str("\\\""),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
<<<<<<< HEAD
            ch if ch.is_control() => {
                escaped.push_str(&format!("\\x{:02X}", ch as u32));
            }
=======
>>>>>>> mcoda/task/bck-05-us-07-t27
            _ => escaped.push(ch),
        }
    }
    escaped
}

<<<<<<< HEAD
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
>>>>>>> mcoda/task/bck-05-us-07-t24
=======
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
>>>>>>> mcoda/task/bck-05-us-07-t23
}

#[cfg(test)]
mod tests {
    use super::*;
<<<<<<< HEAD
<<<<<<< HEAD
    use tempfile::TempDir;

    fn setup_repo_with_dag() -> Result<(TempDir, PathBuf)> {
        let repo = TempDir::new()?;
        let state_dir = repo.path().join(".docdex").join("index");
        let dag_path = dag_db_path_from_index_state_dir(&state_dir);
        std::fs::create_dir_all(dag_path.parent().unwrap())?;
        let conn = Connection::open(&dag_path)?;
        conn.execute_batch(
            "CREATE TABLE nodes (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                type TEXT NOT NULL,
                payload TEXT,
                created_at INTEGER NOT NULL
            );",
        )?;
        conn.execute(
            "INSERT INTO nodes (id, session_id, type, payload, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params!["n1", "s1", "UserRequest", "{\"text\":\"hi\"}", 100_i64],
        )?;
        conn.execute(
            "INSERT INTO nodes (id, session_id, type, payload, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params!["n2", "s1", "Observation", "{\"text\":\"ok\"}", 101_i64],
        )?;
        Ok((repo, state_dir))
    }

    #[test]
    fn load_session_reads_nodes_and_derives_edges() -> Result<()> {
        let (repo, state_dir) = setup_repo_with_dag()?;
        let store = DagStore::new(repo.path(), &state_dir)?;
        let session = store.load_session("s1")?.expect("session");
        assert_eq!(session.session_id, "s1");
        assert_eq!(session.nodes.len(), 2);
        assert_eq!(session.edges.len(), 1);
        assert_eq!(session.edges[0].source, "n1");
        assert_eq!(session.edges[0].target, "n2");
        assert!(!session.repo_id.is_empty());
        Ok(())
    }
}
=======
    pub fn new(state_dir: &Path) -> Self {
        Self {
            path: state_dir.join("dag.db"),
        }
    }

    pub fn read_session(&self, session_id: &Uuid) -> Result<DagSession> {
        if !self.path.exists() {
            return Err(AppError::new(
                ERR_MISSING_DEPENDENCY,
                "dag store not initialized",
            )
            .into());
        }
        let conn =
            Connection::open(&self.path).with_context(|| format!("open {}", self.path.display()))?;
        if !has_nodes_table(&conn)? {
            return Err(AppError::new(
                ERR_MISSING_DEPENDENCY,
                "dag store not initialized",
            )
            .into());
        }
        let mut stmt = conn
            .prepare(
                "SELECT id, type, payload, created_at \
                 FROM nodes WHERE session_id = ?1 \
                 ORDER BY created_at ASC, id ASC",
            )
            .context("prepare dag query")?;
        let rows = stmt
            .query_map(params![session_id.to_string()], |row| {
                let id: String = row.get(0)?;
                let node_type: String = row.get(1)?;
                let payload_raw: Option<String> = row.get(2)?;
                let created_at: Option<i64> = row.get(3)?;
                let payload = match payload_raw {
                    Some(raw) => serde_json::from_str(&raw).unwrap_or(Value::String(raw)),
                    None => Value::Null,
                };
                Ok(DagNode {
                    id,
                    node_type,
                    payload,
                    created_at: created_at.unwrap_or_default(),
                })
            })
            .context("query dag nodes")?;
        let mut nodes = Vec::new();
        for node in rows {
            nodes.push(node.context("read dag node")?);
        }
        if nodes.is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "session not found").into());
        }
        nodes.sort_by(|a, b| (a.created_at, &a.id).cmp(&(b.created_at, &b.id)));
        Ok(DagSession {
            session_id: session_id.to_string(),
            nodes,
=======
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
>>>>>>> mcoda/task/bck-05-us-07-t26
        })
    }
}

<<<<<<< HEAD
fn has_nodes_table(conn: &Connection) -> Result<bool> {
    let mut stmt = conn
        .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='nodes'")
        .context("check dag table")?;
    let mut rows = stmt.query([]).context("query dag table")?;
    Ok(rows.next()?.is_some())
}

pub fn export_text(session: &DagSession) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "session_id: {}", session.session_id);
    let _ = writeln!(out, "nodes: {}", session.nodes.len());
    let _ = writeln!(out, "edges: {}", session.nodes.len().saturating_sub(1));
    out.push_str("nodes:\n");
    for node in &session.nodes {
        let _ = writeln!(out, "- id: {}", node.id);
        let _ = writeln!(out, "  type: {}", node.node_type);
        let _ = writeln!(out, "  created_at: {}", node.created_at);
        if !node.payload.is_null() {
            if let Ok(payload) = serde_json::to_string(&node.payload) {
                let _ = writeln!(out, "  payload: {}", payload);
            }
        }
    }
    out.push_str("edges:\n");
    for window in session.nodes.windows(2) {
        let _ = writeln!(out, "- {} -> {}", window[0].id, window[1].id);
    }
    out
}

pub fn export_dot(session: &DagSession) -> String {
    let mut out = String::new();
    out.push_str("digraph session_dag {\n");
    out.push_str("  rankdir=LR;\n");
    out.push_str("  node [shape=box];\n");
    for node in &session.nodes {
        let label = format!("{}\n{}", node.node_type, short_id(&node.id));
        let _ = writeln!(
            out,
            "  \"{}\" [label=\"{}\"];",
            escape_dot(&node.id),
            escape_dot(&label)
        );
    }
    for window in session.nodes.windows(2) {
        let _ = writeln!(
            out,
            "  \"{}\" -> \"{}\";",
            escape_dot(&window[0].id),
            escape_dot(&window[1].id)
        );
=======
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
>>>>>>> mcoda/task/bck-05-us-07-t27
    }
    out.push_str("}\n");
    out
}
<<<<<<< HEAD

fn short_id(value: &str) -> &str {
    let trimmed = value.trim();
    if trimmed.len() <= 8 {
        trimmed
    } else {
        &trimmed[..8]
    }
}

fn escape_dot(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}
>>>>>>> mcoda/task/bck-05-us-07-t25
=======

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
>>>>>>> mcoda/task/bck-05-us-07-t24
=======
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
>>>>>>> mcoda/task/bck-05-us-07-t23
=======
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
>>>>>>> mcoda/task/bck-05-us-07-t26
=======
>>>>>>> mcoda/task/bck-05-us-07-t27
