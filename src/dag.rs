use anyhow::{anyhow, Context, Result};
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

pub const NO_TRACE_MESSAGE: &str = "No reasoning trace recorded";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DagStatus {
    Found,
    Missing,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DagDataSource {
    Sqlite,
    JsonFile,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DagNode {
    pub id: i64,
    #[serde(rename = "type")]
    pub node_type: String,
    pub payload: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DagLoadResult {
    pub repo_root: String,
    pub repo_fingerprint: String,
    pub session_id: String,
    pub status: DagStatus,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub nodes: Vec<DagNode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<DagDataSource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

pub fn load_session_dag(
    repo_root: &Path,
    session_id: &str,
    global_state_dir: Option<PathBuf>,
) -> Result<DagLoadResult> {
    let repo_root = repo_root
        .canonicalize()
        .context("resolve repo root for DAG lookup")?;
    let repo_fingerprint = fingerprint_repo(&repo_root)?;
    let state_root = resolve_state_root(global_state_dir)?;
    let repo_dir = state_root.join("repos").join(&repo_fingerprint);
    let mut warnings = Vec::new();

    if !state_root.exists() {
        warnings.push(format!(
            "Offline cache directory not found at {}. DAG traces are unavailable while offline.",
            state_root.display()
        ));
        return Ok(DagLoadResult {
            repo_root: repo_root.display().to_string(),
            repo_fingerprint,
            session_id: session_id.to_string(),
            status: DagStatus::Missing,
            nodes: vec![],
            source: None,
            message: Some(NO_TRACE_MESSAGE.to_string()),
            warnings,
        });
    }

    let sqlite_path = repo_dir.join("dag.db");
    let json_path = repo_dir.join("dag").join(format!("{session_id}.json"));

    if !repo_dir.exists() {
        warnings.push(format!(
            "No cached DAG directory for repo fingerprint {} (searched {}).",
            repo_fingerprint,
            repo_dir.display()
        ));
    }

    if sqlite_path.exists() {
        match load_from_sqlite(&sqlite_path, session_id) {
            Ok(Some(nodes)) => {
                return Ok(DagLoadResult {
                    repo_root: repo_root.display().to_string(),
                    repo_fingerprint,
                    session_id: session_id.to_string(),
                    status: DagStatus::Found,
                    nodes,
                    source: Some(DagDataSource::Sqlite),
                    message: None,
                    warnings,
                })
            }
            Ok(None) => {
                warnings.push(format!(
                    "Found SQLite DAG at {} but no rows for session {}.",
                    sqlite_path.display(),
                    session_id
                ));
            }
            Err(err) => {
                let message = format_error(&sqlite_path, &err);
                warnings.push(message.clone());
                return Ok(DagLoadResult {
                    repo_root: repo_root.display().to_string(),
                    repo_fingerprint,
                    session_id: session_id.to_string(),
                    status: DagStatus::Error,
                    nodes: vec![],
                    source: Some(DagDataSource::Sqlite),
                    message: Some(message),
                    warnings,
                });
            }
        }
    }

    if json_path.exists() {
        match load_from_json(&json_path) {
            Ok(nodes) if !nodes.is_empty() => {
                return Ok(DagLoadResult {
                    repo_root: repo_root.display().to_string(),
                    repo_fingerprint,
                    session_id: session_id.to_string(),
                    status: DagStatus::Found,
                    nodes,
                    source: Some(DagDataSource::JsonFile),
                    message: None,
                    warnings,
                })
            }
            Ok(_) => {
                warnings.push(format!(
                    "Found JSON trace at {} but it contained no nodes.",
                    json_path.display()
                ));
            }
            Err(err) => {
                let message = format_error(&json_path, &err);
                warnings.push(message.clone());
                return Ok(DagLoadResult {
                    repo_root: repo_root.display().to_string(),
                    repo_fingerprint,
                    session_id: session_id.to_string(),
                    status: DagStatus::Error,
                    nodes: vec![],
                    source: Some(DagDataSource::JsonFile),
                    message: Some(message),
                    warnings,
                });
            }
        }
    }

    if warnings.is_empty() {
        warnings.push(format!(
            "No cached DAG found for session {} (looked for {} and {}).",
            session_id,
            sqlite_path.display(),
            json_path.display()
        ));
    }

    Ok(DagLoadResult {
        repo_root: repo_root.display().to_string(),
        repo_fingerprint,
        session_id: session_id.to_string(),
        status: DagStatus::Missing,
        nodes: vec![],
        source: None,
        message: Some(NO_TRACE_MESSAGE.to_string()),
        warnings,
    })
}

fn resolve_state_root(global_state_dir: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(dir) = global_state_dir {
        return Ok(dir);
    }
    if let Ok(env_override) = std::env::var("DOCDEX_GLOBAL_STATE_DIR") {
        return Ok(PathBuf::from(env_override));
    }
    let home = std::env::var("HOME").context("HOME not set for DAG lookup")?;
    Ok(Path::new(&home).join(".docdex").join("state"))
}

fn fingerprint_repo(repo_root: &Path) -> Result<String> {
    let canonical = repo_root
        .canonicalize()
        .unwrap_or_else(|_| repo_root.to_path_buf());
    let mut hasher = Sha256::new();
    hasher.update(canonical.to_string_lossy().as_bytes());
    Ok(hex::encode(hasher.finalize()))
}

fn load_from_sqlite(path: &Path, session_id: &str) -> Result<Option<Vec<DagNode>>> {
    let conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_ONLY)
        .with_context(|| format!("open {}", path.display()))?;
    let mut stmt = conn
        .prepare(
            "SELECT rowid, type, payload, created_at FROM nodes WHERE session_id = ?1 ORDER BY rowid ASC",
        )
        .context("prepare dag query")?;
    let mapped = stmt
        .query_map([session_id], |row| {
            let payload_raw: Option<String> = row.get(2)?;
            let payload = match payload_raw {
                Some(raw) if !raw.is_empty() => {
                    serde_json::from_str(&raw).unwrap_or(Value::String(raw))
                }
                Some(_) | None => Value::Null,
            };
            Ok(DagNode {
                id: row.get(0)?,
                node_type: row.get(1)?,
                payload,
                created_at: row.get(3)?,
            })
        })
        .context("map dag rows")?;
    let mut nodes = Vec::new();
    for row in mapped {
        nodes.push(row?);
    }
    if nodes.is_empty() {
        return Ok(None);
    }
    Ok(Some(nodes))
}

fn load_from_json(path: &Path) -> Result<Vec<DagNode>> {
    let data = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    let value: Value =
        serde_json::from_str(&data).with_context(|| format!("parse {}", path.display()))?;
    let nodes = if let Some(array) = value.as_array() {
        array.clone()
    } else {
        value
            .get("nodes")
            .and_then(|v| v.as_array().cloned())
            .ok_or_else(|| anyhow!("JSON DAG is missing nodes array"))?
    };
    let mut result = Vec::new();
    for (idx, node) in nodes.into_iter().enumerate() {
        let node_type = node
            .get("type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let payload = node.get("payload").cloned().unwrap_or(Value::Null);
        let created_at = node.get("created_at").and_then(|v| v.as_i64());
        let id = node
            .get("id")
            .and_then(|v| v.as_i64())
            .unwrap_or(idx as i64);
        result.push(DagNode {
            id,
            node_type: node_type.to_string(),
            payload,
            created_at,
        });
    }
    Ok(result)
}

fn format_error(path: &Path, err: impl std::fmt::Display) -> String {
    format!("Failed to load DAG from {}: {err}", path.display())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlite_trace_loaded() -> Result<()> {
        let temp = tempfile::TempDir::new()?;
        let repo = temp.path().join("repo_sqlite");
        fs::create_dir_all(&repo)?;
        let state_root = temp.path().join("state");
        let repo_fp = fingerprint_repo(&repo)?;
        let repo_state = state_root.join("repos").join(repo_fp);
        fs::create_dir_all(&repo_state)?;

        let db_path = repo_state.join("dag.db");
        let conn = Connection::open(&db_path)?;
        conn.execute(
            "CREATE TABLE nodes (session_id TEXT, type TEXT, payload TEXT, created_at INTEGER)",
            [],
        )?;
        let session_id = "session-1";
        conn.execute(
            "INSERT INTO nodes (session_id, type, payload, created_at) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![session_id, "UserRequest", r#"{"text":"hello"}"#, 111i64],
        )?;
        conn.execute(
            "INSERT INTO nodes (session_id, type, payload, created_at) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![session_id, "Decision", r#"{"outcome":"ok"}"#, 222i64],
        )?;

        let result = load_session_dag(&repo, session_id, Some(state_root.clone()))?;
        assert_eq!(result.status, DagStatus::Found);
        assert_eq!(result.source, Some(DagDataSource::Sqlite));
        assert_eq!(result.nodes.len(), 2);
        assert_eq!(result.nodes[0].node_type, "UserRequest");
        assert_eq!(result.nodes[1].node_type, "Decision");
        Ok(())
    }

    #[test]
    fn json_trace_loaded_without_cross_repo_leak() -> Result<()> {
        let temp = tempfile::TempDir::new()?;
        let repo_a = temp.path().join("repo_a");
        let repo_b = temp.path().join("repo_b");
        fs::create_dir_all(&repo_a)?;
        fs::create_dir_all(&repo_b)?;
        let state_root = temp.path().join("state");

        let fp_a = fingerprint_repo(&repo_a)?;
        let dag_dir = state_root.join("repos").join(fp_a).join("dag");
        fs::create_dir_all(&dag_dir)?;
        fs::write(
            dag_dir.join("session-1.json"),
            r#"{ "nodes": [ { "id": 7, "type": "Thought", "payload": {"note": "draft"} } ] }"#,
        )?;

        let found = load_session_dag(&repo_a, "session-1", Some(state_root.clone()))?;
        assert_eq!(found.status, DagStatus::Found);
        assert_eq!(found.source, Some(DagDataSource::JsonFile));
        assert_eq!(found.nodes.len(), 1);
        assert_eq!(found.nodes[0].id, 7);

        let missing = load_session_dag(&repo_b, "session-1", Some(state_root))?;
        assert_eq!(missing.status, DagStatus::Missing);
        assert_eq!(missing.message.as_deref(), Some(NO_TRACE_MESSAGE));
        Ok(())
    }

    #[test]
    fn missing_trace_reports_canonical_message() -> Result<()> {
        let temp = tempfile::TempDir::new()?;
        let repo = temp.path().join("repo_missing");
        fs::create_dir_all(&repo)?;
        let result = load_session_dag(&repo, "unknown", Some(temp.path().join("state")))?;
        assert_eq!(result.status, DagStatus::Missing);
        assert_eq!(result.message.as_deref(), Some(NO_TRACE_MESSAGE));
        Ok(())
    }

    #[test]
    fn invalid_json_sets_error_status() -> Result<()> {
        let temp = tempfile::TempDir::new()?;
        let repo = temp.path().join("repo_invalid");
        fs::create_dir_all(&repo)?;
        let state_root = temp.path().join("state");
        let fp = fingerprint_repo(&repo)?;
        let dag_dir = state_root.join("repos").join(fp).join("dag");
        fs::create_dir_all(&dag_dir)?;
        fs::write(dag_dir.join("broken.json"), "not-json")?;

        let result = load_session_dag(&repo, "broken", Some(state_root))?;
        assert_eq!(result.status, DagStatus::Error);
        assert!(result
            .message
            .unwrap_or_default()
            .contains("Failed to load DAG"));
        Ok(())
    }

    #[test]
    fn offline_state_dir_reports_offline_missing() -> Result<()> {
        let temp = tempfile::TempDir::new()?;
        let repo = temp.path().join("repo_offline");
        fs::create_dir_all(&repo)?;
        let state_root = temp.path().join("offline_state");
        let result = load_session_dag(&repo, "offline", Some(state_root.clone()))?;
        assert_eq!(result.status, DagStatus::Missing);
        assert_eq!(result.message.as_deref(), Some(NO_TRACE_MESSAGE));
        assert!(result.warnings.iter().any(|w| w.contains("Offline cache")));
        Ok(())
    }

    #[test]
    fn empty_json_trace_reports_warning() -> Result<()> {
        let temp = tempfile::TempDir::new()?;
        let repo = temp.path().join("repo_empty");
        fs::create_dir_all(&repo)?;
        let state_root = temp.path().join("state");
        let fp = fingerprint_repo(&repo)?;
        let dag_dir = state_root.join("repos").join(fp).join("dag");
        fs::create_dir_all(&dag_dir)?;
        fs::write(dag_dir.join("empty.json"), r#"{ "nodes": [] }"#)?;
        let result = load_session_dag(&repo, "empty", Some(state_root))?;
        assert_eq!(result.status, DagStatus::Missing);
        assert_eq!(result.message.as_deref(), Some(NO_TRACE_MESSAGE));
        assert!(result
            .warnings
            .iter()
            .any(|w| w.contains("contained no nodes") || w.contains("No cached DAG")));
        Ok(())
    }
}
