use crate::memory::{ensure_repo_state_dir, repo_state_root_from_state_dir};
use crate::metrics::{DelegationMetrics, DelegationTelemetrySnapshot, Metrics};
use crate::state_paths::StatePaths;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::warn;
use uuid::Uuid;

const DELEGATION_TELEMETRY_VERSION: u32 = 1;
const GLOBAL_TELEMETRY_DIR: &str = "telemetry";
const GLOBAL_TELEMETRY_FILE: &str = "delegation.json";
const REPO_TELEMETRY_FILE: &str = "delegation_telemetry.json";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PersistedDelegationTelemetry {
    version: u32,
    snapshot: DelegationTelemetrySnapshot,
}

impl PersistedDelegationTelemetry {
    fn new(snapshot: DelegationTelemetrySnapshot) -> Self {
        Self {
            version: DELEGATION_TELEMETRY_VERSION,
            snapshot,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RepoDelegationTelemetrySnapshot {
    pub state_key: String,
    pub project: String,
    pub snapshot: DelegationTelemetrySnapshot,
}

#[derive(Debug, Clone, Deserialize, Default)]
struct RepoRegistryFile {
    #[serde(default)]
    repos: HashMap<String, RepoRegistryEntry>,
}

#[derive(Debug, Clone, Deserialize)]
struct RepoRegistryEntry {
    state_key: String,
    canonical_path: String,
}

pub fn restore_global_metrics_if_empty(
    metrics: &Metrics,
    global_state_dir: Option<&Path>,
) -> Result<bool> {
    if !metrics.delegation_snapshot().is_zero() {
        return Ok(false);
    }
    let Some(path) = restore_global_snapshot_path(global_state_dir) else {
        return Ok(false);
    };
    let Some(snapshot) = load_snapshot(&path)? else {
        return Ok(false);
    };
    metrics.apply_delegation_snapshot(snapshot);
    Ok(true)
}

pub fn restore_repo_metrics_if_empty(
    metrics: &DelegationMetrics,
    state_dir: &Path,
) -> Result<bool> {
    if !metrics.snapshot().is_zero() {
        return Ok(false);
    }
    let repo_state_root = repo_state_root_from_state_dir(state_dir);
    let path = repo_snapshot_path(&repo_state_root);
    let Some(snapshot) = load_snapshot(&path)? else {
        return Ok(false);
    };
    metrics.apply_snapshot(snapshot);
    Ok(true)
}

pub fn persist_metrics(
    global_state_dir: Option<&Path>,
    global_metrics: &Metrics,
    repo_state_root: Option<&Path>,
    repo_metrics: Option<&DelegationMetrics>,
) {
    if let Some(path) = persist_global_snapshot_path(global_state_dir) {
        if let Err(err) = write_snapshot(&path, global_metrics.delegation_snapshot()) {
            warn!(
                target: "docdexd",
                path = %path.display(),
                error = ?err,
                "failed to persist delegation telemetry"
            );
        }
    }
    if let (Some(repo_state_root), Some(repo_metrics)) = (repo_state_root, repo_metrics) {
        let path = repo_snapshot_path(repo_state_root);
        if let Err(err) = write_snapshot(&path, repo_metrics.snapshot()) {
            warn!(
                target: "docdexd",
                path = %path.display(),
                error = ?err,
                "failed to persist repo delegation telemetry"
            );
        }
    }
}

pub fn repo_snapshot_path(repo_state_root: &Path) -> PathBuf {
    repo_state_root.join(REPO_TELEMETRY_FILE)
}

pub fn load_repo_snapshots(
    global_state_dir: &Path,
) -> Result<Vec<RepoDelegationTelemetrySnapshot>> {
    let layout = StatePaths::new(global_state_dir.to_path_buf());
    let repos_dir = layout.repos_dir();
    if !repos_dir.exists() {
        return Ok(Vec::new());
    }

    let registry_paths = load_registry_state_key_paths(&layout.repo_registry_path())?;
    let mut snapshots = Vec::new();
    for entry in fs::read_dir(&repos_dir)
        .with_context(|| format!("read repo telemetry dir {}", repos_dir.display()))?
    {
        let entry = entry.with_context(|| format!("iterate {}", repos_dir.display()))?;
        let file_type = entry
            .file_type()
            .with_context(|| format!("read type {}", entry.path().display()))?;
        if !file_type.is_dir() {
            continue;
        }
        let state_key = entry.file_name().to_string_lossy().to_string();
        let Some(snapshot) = load_snapshot(&repo_snapshot_path(&entry.path()))? else {
            continue;
        };
        let project = registry_paths
            .get(&state_key)
            .cloned()
            .unwrap_or_else(|| state_key.clone());
        snapshots.push(RepoDelegationTelemetrySnapshot {
            state_key,
            project,
            snapshot,
        });
    }
    snapshots.sort_by(|a, b| {
        a.project
            .cmp(&b.project)
            .then_with(|| a.state_key.cmp(&b.state_key))
    });
    Ok(snapshots)
}

pub fn load_global_snapshot(global_state_dir: &Path) -> Result<Option<DelegationTelemetrySnapshot>> {
    load_snapshot(&global_state_dir.join(GLOBAL_TELEMETRY_DIR).join(GLOBAL_TELEMETRY_FILE))
}

fn persist_global_snapshot_path(global_state_dir: Option<&Path>) -> Option<PathBuf> {
    global_state_dir.map(|root| root.join(GLOBAL_TELEMETRY_DIR).join(GLOBAL_TELEMETRY_FILE))
}

fn restore_global_snapshot_path(global_state_dir: Option<&Path>) -> Option<PathBuf> {
    persist_global_snapshot_path(global_state_dir)
}

pub fn effective_global_state_dir(
    configured_global_state_dir: Option<&Path>,
    state_dir: &Path,
) -> Option<PathBuf> {
    crate::repo_manager::split_scoped_state_dir(state_dir)
        .map(|(base_dir, _, _)| base_dir)
        .or_else(|| configured_global_state_dir.map(Path::to_path_buf))
}

fn load_snapshot(path: &Path) -> Result<Option<DelegationTelemetrySnapshot>> {
    if !path.exists() {
        return Ok(None);
    }
    let payload = fs::read_to_string(path)
        .with_context(|| format!("read delegation telemetry {}", path.display()))?;
    let parsed: PersistedDelegationTelemetry = serde_json::from_str(&payload)
        .with_context(|| format!("parse delegation telemetry {}", path.display()))?;
    Ok(Some(parsed.snapshot))
}

fn load_registry_state_key_paths(path: &Path) -> Result<HashMap<String, String>> {
    if !path.exists() {
        return Ok(HashMap::new());
    }
    let payload = fs::read_to_string(path)
        .with_context(|| format!("read repo registry {}", path.display()))?;
    let parsed: RepoRegistryFile = serde_json::from_str(&payload)
        .with_context(|| format!("parse repo registry {}", path.display()))?;
    Ok(parsed
        .repos
        .into_values()
        .map(|entry| (entry.state_key, entry.canonical_path))
        .collect())
}

fn write_snapshot(path: &Path, snapshot: DelegationTelemetrySnapshot) -> Result<()> {
    ensure_parent_dir(path)?;
    let payload = PersistedDelegationTelemetry::new(snapshot);
    let bytes = serde_json::to_vec_pretty(&payload).context("serialize delegation telemetry")?;
    let tmp = path.with_extension(format!("tmp.{}", Uuid::new_v4()));
    fs::write(&tmp, bytes).with_context(|| format!("write {}", tmp.display()))?;
    if path.exists() {
        let _ = fs::remove_file(path);
    }
    fs::rename(&tmp, path).with_context(|| format!("rename {}", path.display()))?;
    Ok(())
}

fn ensure_parent_dir(path: &Path) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    if path.file_name().and_then(|name| name.to_str()) == Some(REPO_TELEMETRY_FILE) {
        ensure_repo_state_dir(parent)?;
        return Ok(());
    }
    crate::state_layout::ensure_state_dir_secure(parent)
        .with_context(|| format!("create delegation telemetry dir {}", parent.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_layout::resolve_state_paths;
    use serde_json::json;
    use tempfile::TempDir;

    #[test]
    fn global_metrics_round_trip() -> Result<()> {
        let temp = TempDir::new()?;
        let metrics = Metrics::default();
        metrics.inc_delegate_request();
        metrics.inc_delegate_offloaded();
        metrics.inc_delegate_failed();
        metrics.record_delegate_token_estimate(24);
        metrics.record_delegate_local_tokens(18);
        metrics.record_delegate_primary_tokens(3);
        metrics.record_delegate_token_savings(18);
        metrics.record_delegate_local_cost_micros(42);
        metrics.record_delegate_primary_cost_micros(7);
        metrics.record_delegate_cost_savings_micros(91);

        persist_metrics(Some(temp.path()), &metrics, None, None);

        let restored = Metrics::default();
        assert!(restore_global_metrics_if_empty(
            &restored,
            Some(temp.path())
        )?);
        assert_eq!(
            restored.delegation_snapshot(),
            metrics.delegation_snapshot()
        );
        Ok(())
    }

    #[test]
    fn repo_metrics_round_trip() -> Result<()> {
        let temp = TempDir::new()?;
        let repo_state_root = temp.path().join("repos").join("demo");
        let metrics = DelegationMetrics::default();
        metrics.inc_delegate_request();
        metrics.inc_delegate_offloaded();
        metrics.inc_delegate_failed();
        metrics.record_delegate_token_estimate(11);
        metrics.record_delegate_local_tokens(9);
        metrics.record_delegate_primary_tokens(2);
        metrics.record_delegate_token_savings(9);
        metrics.record_delegate_local_cost_micros(15);
        metrics.record_delegate_primary_cost_micros(4);
        metrics.record_delegate_cost_savings_micros(22);

        persist_metrics(
            None,
            &Metrics::default(),
            Some(&repo_state_root),
            Some(&metrics),
        );

        let restored = DelegationMetrics::default();
        assert!(restore_repo_metrics_if_empty(
            &restored,
            &repo_state_root.join("index"),
        )?);
        assert_eq!(restored.snapshot(), metrics.snapshot());
        Ok(())
    }

    #[test]
    fn restore_does_not_override_live_metrics() -> Result<()> {
        let temp = TempDir::new()?;
        let persisted = Metrics::default();
        persisted.inc_delegate_request();
        persist_metrics(Some(temp.path()), &persisted, None, None);

        let live = Metrics::default();
        live.inc_delegate_request();
        live.inc_delegate_request();
        assert!(!restore_global_metrics_if_empty(&live, Some(temp.path()))?);
        assert_eq!(live.delegation_snapshot().delegate_requests_total, 2);
        Ok(())
    }

    #[test]
    fn effective_global_state_dir_prefers_repo_state_base() -> Result<()> {
        let repo = TempDir::new()?;
        fs::create_dir_all(repo.path().join(".git"))?;
        let shared_state = TempDir::new()?;
        let state_paths =
            resolve_state_paths(repo.path(), Some(shared_state.path().to_path_buf()))?;
        let configured = PathBuf::from("/tmp/should-not-win");

        let resolved =
            effective_global_state_dir(Some(configured.as_path()), state_paths.index_dir())
                .context("resolved global state dir")?;

        assert_eq!(resolved, shared_state.path());
        Ok(())
    }

    #[test]
    fn load_repo_snapshots_uses_registry_paths() -> Result<()> {
        let temp = TempDir::new()?;
        let state_root = temp.path();
        let repos_dir = state_root.join("repos");
        fs::create_dir_all(&repos_dir)?;
        let repo_state_root = repos_dir.join("demo-state");
        fs::create_dir_all(&repo_state_root)?;
        write_snapshot(
            &repo_snapshot_path(&repo_state_root),
            DelegationTelemetrySnapshot {
                delegate_requests_total: 2,
                delegate_offloaded_total: 1,
                delegate_failed_total: 1,
                delegate_token_savings_total: 12,
                delegate_cost_savings_micros_total: 34,
                ..DelegationTelemetrySnapshot::default()
            },
        )?;
        fs::write(
            repos_dir.join("repo_registry.json"),
            serde_json::to_vec_pretty(&json!({
                "version": 1,
                "repos": {
                    "demo-fingerprint": {
                        "state_key": "demo-state",
                        "canonical_path": "/tmp/demo",
                        "prior_paths": [],
                        "last_seen_at_epoch_ms": 0
                    }
                }
            }))?,
        )?;

        let snapshots = load_repo_snapshots(state_root)?;

        assert_eq!(snapshots.len(), 1);
        assert_eq!(snapshots[0].state_key, "demo-state");
        assert_eq!(snapshots[0].project, "/tmp/demo");
        assert_eq!(snapshots[0].snapshot.delegate_requests_total, 2);
        Ok(())
    }
}
