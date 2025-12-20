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
    pub session_id: String,
    pub nodes: Vec<DagNode>,
    pub edges: Vec<DagEdge>,
}

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
}

#[cfg(test)]
mod tests {
    use super::*;
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
>>>>>>> mcoda/task/bck-05-us-07-t25
