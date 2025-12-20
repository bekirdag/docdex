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
    pub payload: Value,
    pub created_at: i64,
}

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
    path: PathBuf,
}

impl DagStore {
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
        })
    }
}

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
    }
    out.push_str("}\n");
    out
}

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
