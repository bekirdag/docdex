use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SetupStatus {
    Complete,
    Deferred,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupStatusRecord {
    pub status: SetupStatus,
    pub timestamp_ms: u128,
    pub message: String,
    #[serde(default)]
    pub models_installed: Vec<String>,
    pub default_model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub fn write_status(summary: &crate::setup::SetupSummary) -> Result<()> {
    let status = match summary.status.as_str() {
        "complete" | "installed" => SetupStatus::Complete,
        "deferred" | "skipped" => SetupStatus::Deferred,
        _ => SetupStatus::Failed,
    };
    let timestamp_ms = if summary.timestamp_ms > 0 {
        summary.timestamp_ms
    } else {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    };
    let record = SetupStatusRecord {
        status,
        timestamp_ms,
        message: summary.message.clone(),
        models_installed: summary.models_installed.clone(),
        default_model: summary.default_model.clone(),
        error: summary.error.clone(),
    };
    write_record(&status_path()?, &record)
}

pub fn write_failed(message: &str) -> Result<()> {
    let record = serde_json::json!({
        "status": "failed",
        "timestamp_ms": SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
        "message": message,
    });
    write_raw(&failed_path()?, &record.to_string())
}

pub fn clear_failed() -> Result<()> {
    let path = failed_path()?;
    if path.exists() {
        fs::remove_file(&path).with_context(|| format!("remove {}", path.display()))?;
    }
    Ok(())
}

#[allow(dead_code)]
pub fn write_pending() -> Result<()> {
    let record = serde_json::json!({
        "status": "pending",
        "timestamp_ms": SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    });
    write_raw(&pending_path()?, &record.to_string())
}

pub fn clear_pending() -> Result<()> {
    let path = pending_path()?;
    if path.exists() {
        fs::remove_file(&path).with_context(|| format!("remove {}", path.display()))?;
    }
    Ok(())
}

fn status_path() -> Result<PathBuf> {
    Ok(state_root()?.join("setup_status.json"))
}

fn pending_path() -> Result<PathBuf> {
    Ok(state_root()?.join("setup_pending.json"))
}

fn failed_path() -> Result<PathBuf> {
    Ok(state_root()?.join("setup_failed.json"))
}

fn state_root() -> Result<PathBuf> {
    if let Ok(value) = std::env::var("DOCDEX_STATE_DIR") {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return Ok(PathBuf::from(trimmed));
        }
    }
    let base = crate::state_paths::default_state_base_dir()?;
    Ok(base)
}

fn write_record(path: &Path, record: &SetupStatusRecord) -> Result<()> {
    let payload = serde_json::to_string_pretty(record).context("serialize setup status")?;
    write_raw(path, &payload)
}

fn write_raw(path: &Path, payload: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create setup dir {}", parent.display()))?;
    }
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, payload).with_context(|| format!("write {}", tmp.display()))?;
    fs::rename(&tmp, path).with_context(|| format!("rename {}", path.display()))?;
    Ok(())
}
