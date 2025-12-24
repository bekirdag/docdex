use anyhow::{Context, Result};
use rusqlite::{params, Connection, OpenFlags};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::dag::repo as dag_repo;

/// Append a node to the repo-scoped DAG. Creates the database if needed.
pub fn log_node(
    repo_state_dir: &Path,
    session_id: &str,
    node_type: &str,
    payload: &Value,
) -> Result<()> {
    let db_path = dag_repo::dag_db_path(repo_state_dir);
    let conn = Connection::open_with_flags(
        &db_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_CREATE,
    )
    .with_context(|| format!("open {}", db_path.display()))?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS nodes (
            session_id TEXT,
            type TEXT,
            payload TEXT,
            created_at INTEGER
        )",
        [],
    )
    .context("prepare dag schema")?;
    conn.execute(
        "INSERT INTO nodes (session_id, type, payload, created_at) VALUES (?1, ?2, ?3, ?4)",
        params![
            session_id,
            node_type,
            serde_json::to_string(payload).unwrap_or_default(),
            current_timestamp_ms(),
        ],
    )
    .context("insert dag node")?;
    Ok(())
}

fn current_timestamp_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_millis() as i64)
        .unwrap_or_else(|_| 0)
}

/// Loads the JSON trace for a session if present.
pub fn load_json_trace(repo_state_dir: &Path, session_id: &str) -> Result<Option<Value>> {
    let trace_path = repo_state_dir
        .join("dag")
        .join(format!("{session_id}.json"));
    if !trace_path.exists() {
        return Ok(None);
    }
    let raw = std::fs::read_to_string(&trace_path)
        .with_context(|| format!("read {}", trace_path.display()))?;
    let parsed: Value =
        serde_json::from_str(&raw).with_context(|| format!("parse {}", trace_path.display()))?;
    Ok(Some(parsed))
}

pub fn repo_state_dir_for_root(state_root: &Path, state_key: &str) -> PathBuf {
    state_root.join("repos").join(state_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use tempfile::TempDir;

    #[test]
    fn log_node_creates_db() -> Result<()> {
        let temp = TempDir::new()?;
        let repo_dir = temp.path().join("repo");
        std::fs::create_dir_all(&repo_dir)?;
        let output = log_node(
            &repo_dir,
            "session-1",
            "UserRequest",
            &json!({"text": "hi"}),
        )?;
        assert_eq!(output, ());
        let conn = Connection::open(repo_dir.join("dag.db"))?;
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM nodes WHERE session_id = ?1",
            params!["session-1"],
            |row| row.get(0),
        )?;
        assert_eq!(count, 1);
        Ok(())
    }
}
