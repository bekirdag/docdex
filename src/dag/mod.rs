pub mod logging;
pub mod repo;
pub mod view;

use crate::dag::repo as dag_repo;
use anyhow::{Context, Result};
use rusqlite::{Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader};
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
    Jsonl,
    Json,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DagNode {
    pub id: String,
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
    let state_paths =
        crate::state_layout::resolve_state_paths_for_inspect(&repo_root, global_state_dir)?;
    let repo_fingerprint = state_paths.fingerprint().to_string();
    let state_root = state_paths.layout().base_dir();
    let repo_dir = state_paths.repo_root().to_path_buf();
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

    let sqlite_path = state_paths.dag_path().to_path_buf();
    if !repo_dir.exists() {
        warnings.push(format!(
            "No cached DAG directory for repo fingerprint {} (searched {}).",
            repo_fingerprint,
            repo_dir.display()
        ));
    }

    if sqlite_path.exists() {
        match load_from_sqlite(&repo_dir, &sqlite_path, session_id) {
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

    let jsonl_paths = [
        repo_dir.join("dag.jsonl"),
        state_paths.index_dir().join("dag.jsonl"),
    ];
    for jsonl_path in jsonl_paths {
        if !jsonl_path.exists() {
            continue;
        }
        match load_from_jsonl(&jsonl_path, session_id) {
            Ok(Some(nodes)) => {
                return Ok(DagLoadResult {
                    repo_root: repo_root.display().to_string(),
                    repo_fingerprint,
                    session_id: session_id.to_string(),
                    status: DagStatus::Found,
                    nodes,
                    source: Some(DagDataSource::Jsonl),
                    message: None,
                    warnings,
                })
            }
            Ok(None) => {
                warnings.push(format!(
                    "Found JSONL DAG at {} but no rows for session {}.",
                    jsonl_path.display(),
                    session_id
                ));
            }
            Err(err) => {
                warnings.push(format!(
                    "Failed to read JSONL DAG at {}: {err}",
                    jsonl_path.display()
                ));
            }
        }
    }

    match load_from_json_trace(&repo_dir, session_id) {
        Ok(Some(nodes)) => {
            return Ok(DagLoadResult {
                repo_root: repo_root.display().to_string(),
                repo_fingerprint,
                session_id: session_id.to_string(),
                status: DagStatus::Found,
                nodes,
                source: Some(DagDataSource::Json),
                message: None,
                warnings,
            })
        }
        Ok(None) => {}
        Err(err) => {
            warnings.push(format!("Failed to read JSON DAG trace: {err}"));
        }
    }

    if warnings.is_empty() {
        warnings.push(format!(
            "No cached DAG found for session {} (looked for {}).",
            session_id,
            sqlite_path.display()
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

pub fn resolve_state_root(global_state_dir: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(dir) = global_state_dir {
        return Ok(dir);
    }
    if let Ok(env_override) = std::env::var("DOCDEX_GLOBAL_STATE_DIR") {
        return Ok(PathBuf::from(env_override));
    }
    let home = std::env::var("HOME").context("HOME not set for DAG lookup")?;
    Ok(Path::new(&home).join(".docdex").join("state"))
}

fn load_from_sqlite(
    repo_state_root: &Path,
    path: &Path,
    session_id: &str,
) -> Result<Option<Vec<DagNode>>> {
    let lock_path = dag_repo::dag_lock_path(repo_state_root);
    let lock_dir = dag_repo::locks_dir_from_repo_state_root(repo_state_root);
    crate::state_layout::ensure_state_dir_secure(&lock_dir)?;
    let _lock = DagReadLock::acquire(&lock_path)?;
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
                id: row.get::<_, i64>(0)?.to_string(),
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

fn load_from_jsonl(path: &Path, session_id: &str) -> Result<Option<Vec<DagNode>>> {
    let file = fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let reader = BufReader::new(file);
    let mut nodes = Vec::new();
    for (idx, line) in reader.lines().enumerate() {
        let line = line.with_context(|| format!("read {}", path.display()))?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let value: Value = match serde_json::from_str(trimmed) {
            Ok(value) => value,
            Err(_) => continue,
        };
        if let Some(node) = parse_node_value(&value, Some(session_id), idx) {
            nodes.push(node);
        }
    }
    if nodes.is_empty() {
        Ok(None)
    } else {
        Ok(Some(nodes))
    }
}

fn load_from_json_trace(repo_state_root: &Path, session_id: &str) -> Result<Option<Vec<DagNode>>> {
    let Some(value) = crate::dag::logging::load_json_trace(repo_state_root, session_id)? else {
        return Ok(None);
    };
    let nodes = parse_nodes_from_value(&value, None);
    if nodes.is_empty() {
        Ok(None)
    } else {
        Ok(Some(nodes))
    }
}

fn parse_nodes_from_value(value: &Value, session_id: Option<&str>) -> Vec<DagNode> {
    let nodes_value = if let Some(array) = value.as_array() {
        Some(array)
    } else if let Some(nodes) = value.get("nodes").and_then(|nodes| nodes.as_array()) {
        Some(nodes)
    } else {
        None
    };
    let Some(nodes_value) = nodes_value else {
        return Vec::new();
    };
    nodes_value
        .iter()
        .enumerate()
        .filter_map(|(idx, value)| parse_node_value(value, session_id, idx))
        .collect()
}

fn parse_node_value(
    value: &Value,
    session_id: Option<&str>,
    fallback_idx: usize,
) -> Option<DagNode> {
    let obj = value.as_object()?;
    if let Some(filter) = session_id {
        let session_value = obj.get("session_id").or_else(|| obj.get("sessionId"));
        let Some(session_value) = session_value.and_then(value_as_string) else {
            return None;
        };
        if session_value != filter {
            return None;
        }
    }

    let id_value = obj.get("id").or_else(|| obj.get("node_id"));
    let id = id_value
        .and_then(value_as_string)
        .unwrap_or_else(|| format!("n{}", fallback_idx + 1));
    let node_type = obj
        .get("type")
        .or_else(|| obj.get("node_type"))
        .and_then(value_as_string)
        .unwrap_or_else(|| "Unknown".to_string());
    let payload = obj.get("payload").cloned().unwrap_or(Value::Null);
    let created_at = obj
        .get("created_at")
        .or_else(|| obj.get("createdAt"))
        .and_then(value_as_i64);

    Some(DagNode {
        id,
        node_type,
        payload,
        created_at,
    })
}

fn value_as_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        _ => None,
    }
}

fn value_as_i64(value: &Value) -> Option<i64> {
    if let Some(raw) = value.as_i64() {
        return Some(raw);
    }
    value
        .as_str()
        .and_then(|raw| raw.trim().parse::<i64>().ok())
}

struct DagReadLock {
    file: std::fs::File,
}

impl DagReadLock {
    fn acquire(path: &Path) -> Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(path)
            .with_context(|| format!("open lock file {}", path.display()))?;
        file.lock_shared()
            .with_context(|| format!("lock {}", path.display()))?;
        Ok(Self { file })
    }
}

impl Drop for DagReadLock {
    fn drop(&mut self) {
        let _ = self.file.unlock();
    }
}

fn format_error(path: &Path, err: impl std::fmt::Display) -> String {
    format!("Failed to load DAG from {}: {err}", path.display())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn sqlite_trace_loaded() -> Result<()> {
        let temp = tempfile::TempDir::new()?;
        let repo = temp.path().join("repo_sqlite");
        fs::create_dir_all(&repo)?;
        let state_root = temp.path().join("state");
        let repo_fp = crate::repo_manager::repo_fingerprint_sha256(&repo)?;
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
}
