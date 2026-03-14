use crate::delegation_telemetry;
use crate::index::{IndexConfig, Indexer};
use crate::libs;
use crate::memory::MemoryStore;
use crate::metrics::{DelegationMetrics, DelegationTelemetrySnapshot};
use crate::ollama::OllamaEmbedder;
use crate::repo_manager;
use crate::search::MemoryState;
use crate::watcher;
use anyhow::Result;
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{info, warn};

#[derive(Clone)]
pub struct RepoRuntime {
    pub repo_id: String,
    pub legacy_repo_id: String,
    pub repo_root: PathBuf,
    pub indexer: Arc<Indexer>,
    pub libs_indexer: Option<Arc<libs::LibsIndexer>>,
    pub memory: Option<MemoryState>,
    pub delegation_metrics: Arc<DelegationMetrics>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RepoMountStatus {
    Ready,
    Indexing,
}

impl RepoMountStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            RepoMountStatus::Ready => "ready",
            RepoMountStatus::Indexing => "indexing",
        }
    }
}

pub struct RepoMount {
    pub repo: Arc<RepoRuntime>,
    pub status: RepoMountStatus,
}

struct RepoEntry {
    runtime: Arc<RepoRuntime>,
    watcher: Option<watcher::WatcherHandle>,
    last_access: Instant,
}

pub struct RepoManager {
    repos: RwLock<HashMap<String, Arc<Mutex<RepoEntry>>>>,
    legacy_repos: RwLock<HashMap<String, Arc<Mutex<RepoEntry>>>>,
    delegation_metrics: RwLock<HashMap<String, Arc<DelegationMetrics>>>,
    memory_embedder: Option<OllamaEmbedder>,
    shared_state_dir: Option<PathBuf>,
    pinned_repo_id: RwLock<Option<String>>,
    idle_timeout: Duration,
    hibernate_timeout: Duration,
    cleanup_interval: Duration,
}

impl RepoManager {
    pub fn new(memory_embedder: Option<OllamaEmbedder>, shared_state_dir: Option<PathBuf>) -> Self {
        fn duration_from_env(var: &str, default: Duration) -> Duration {
            let Ok(value) = std::env::var(var) else {
                return default;
            };
            let Ok(seconds) = value.trim().parse::<u64>() else {
                return default;
            };
            if seconds == 0 {
                return default;
            }
            Duration::from_secs(seconds)
        }

        let idle_timeout =
            duration_from_env("DOCDEX_REPO_IDLE_SECONDS", Duration::from_secs(2 * 60 * 60));
        let mut hibernate_timeout = duration_from_env(
            "DOCDEX_REPO_HIBERNATE_SECONDS",
            Duration::from_secs(24 * 60 * 60),
        );
        if hibernate_timeout < idle_timeout {
            hibernate_timeout = idle_timeout + Duration::from_secs(60);
        }
        let cleanup_interval = duration_from_env(
            "DOCDEX_REPO_CLEANUP_INTERVAL_SECONDS",
            Duration::from_secs(600),
        );
        Self {
            repos: RwLock::new(HashMap::new()),
            legacy_repos: RwLock::new(HashMap::new()),
            delegation_metrics: RwLock::new(HashMap::new()),
            memory_embedder,
            shared_state_dir,
            pinned_repo_id: RwLock::new(None),
            idle_timeout,
            hibernate_timeout,
            cleanup_interval,
        }
    }

    #[cfg(test)]
    pub(crate) fn new_with_timeouts(
        memory_embedder: Option<OllamaEmbedder>,
        shared_state_dir: Option<PathBuf>,
        idle_timeout: Duration,
        hibernate_timeout: Duration,
        cleanup_interval: Duration,
    ) -> Self {
        Self {
            repos: RwLock::new(HashMap::new()),
            legacy_repos: RwLock::new(HashMap::new()),
            delegation_metrics: RwLock::new(HashMap::new()),
            memory_embedder,
            shared_state_dir,
            pinned_repo_id: RwLock::new(None),
            idle_timeout,
            hibernate_timeout,
            cleanup_interval,
        }
    }

    pub fn pin_repo(&self, repo_id: String) {
        *self.pinned_repo_id.write() = Some(repo_id);
    }

    pub fn insert_repo(&self, repo: Arc<RepoRuntime>, watcher: Option<watcher::WatcherHandle>) {
        let entry = Arc::new(Mutex::new(RepoEntry {
            runtime: repo.clone(),
            watcher,
            last_access: Instant::now(),
        }));
        self.repos
            .write()
            .insert(repo.repo_id.clone(), entry.clone());
        self.legacy_repos
            .write()
            .insert(repo.legacy_repo_id.clone(), entry);
        self.delegation_metrics
            .write()
            .entry(repo.repo_id.clone())
            .or_insert_with(|| repo.delegation_metrics.clone());
    }

    pub fn delegation_metrics_for_repo_id(&self, repo_id: &str) -> Arc<DelegationMetrics> {
        if let Some(metrics) = self.delegation_metrics.read().get(repo_id).cloned() {
            return metrics;
        }
        let mut guard = self.delegation_metrics.write();
        guard
            .entry(repo_id.to_string())
            .or_insert_with(|| Arc::new(DelegationMetrics::default()))
            .clone()
    }

    pub fn delegation_metrics_snapshot(&self) -> DelegationTelemetrySnapshot {
        let mut snapshot = DelegationTelemetrySnapshot::default();
        for metrics in self.delegation_metrics.read().values() {
            snapshot.merge(DelegationTelemetrySnapshot::from_delegation_metrics(
                metrics.as_ref(),
            ));
        }
        snapshot
    }

    pub fn delegation_project_snapshots(
        &self,
    ) -> Vec<delegation_telemetry::RepoDelegationTelemetrySnapshot> {
        let mut snapshots = Vec::new();
        for entry in self.repos.read().values() {
            let runtime = entry.lock().runtime.clone();
            snapshots.push(delegation_telemetry::RepoDelegationTelemetrySnapshot {
                state_key: runtime.repo_id.clone(),
                project: repo_manager::normalize_path(&runtime.repo_root),
                snapshot: runtime.delegation_metrics.snapshot(),
            });
        }
        snapshots.sort_by(|a, b| {
            a.project
                .cmp(&b.project)
                .then_with(|| a.state_key.cmp(&b.state_key))
        });
        snapshots
    }

    fn get_entry(&self, repo_id: &str) -> Option<Arc<Mutex<RepoEntry>>> {
        if let Some(entry) = self.repos.read().get(repo_id) {
            return Some(entry.clone());
        }
        self.legacy_repos.read().get(repo_id).cloned()
    }

    fn touch_entry(&self, entry: &Arc<Mutex<RepoEntry>>) {
        let mut entry = entry.lock();
        entry.last_access = Instant::now();
        if entry.watcher.is_none() {
            match watcher::spawn(entry.runtime.indexer.clone()) {
                Ok(handle) => {
                    entry.watcher = Some(handle);
                }
                Err(err) => {
                    warn!(
                        target: "docdexd",
                        error = ?err,
                        repo = %entry.runtime.repo_root.display(),
                        "failed to restart file watcher"
                    );
                }
            }
        }
    }

    pub fn get_by_id(&self, repo_id: &str) -> Option<Arc<RepoRuntime>> {
        let entry = self.get_entry(repo_id)?;
        self.touch_entry(&entry);
        let runtime = entry.lock().runtime.clone();
        Some(runtime)
    }

    pub fn repo_count(&self) -> usize {
        self.repos.read().len()
    }

    pub fn start_housekeeping(self: &Arc<Self>) {
        let manager = Arc::clone(self);
        let interval = manager.cleanup_interval;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                manager.sweep_idle(Instant::now());
            }
        });
    }

    pub(crate) fn sweep_idle(&self, now: Instant) {
        let mut idle_entries: Vec<Arc<Mutex<RepoEntry>>> = Vec::new();
        let mut hibernate_ids: Vec<String> = Vec::new();
        let pinned_repo_id = self.pinned_repo_id.read().clone();
        {
            let repos = self.repos.read();
            for (repo_id, entry) in repos.iter() {
                let last_access = entry.lock().last_access;
                let idle_for = now.duration_since(last_access);
                if idle_for >= self.hibernate_timeout {
                    let is_pinned = pinned_repo_id
                        .as_ref()
                        .map(|pinned| pinned == repo_id)
                        .unwrap_or(false);
                    if !is_pinned {
                        hibernate_ids.push(repo_id.clone());
                    } else {
                        idle_entries.push(entry.clone());
                    }
                } else if idle_for >= self.idle_timeout {
                    idle_entries.push(entry.clone());
                }
            }
        }

        for entry in idle_entries {
            let mut entry = entry.lock();
            if let Some(mut watcher) = entry.watcher.take() {
                watcher.stop();
            }
        }

        if !hibernate_ids.is_empty() {
            let mut repos = self.repos.write();
            let mut legacy = self.legacy_repos.write();
            for repo_id in hibernate_ids {
                if let Some(entry) = repos.remove(&repo_id) {
                    let mut entry = entry.lock();
                    if let Some(mut watcher) = entry.watcher.take() {
                        watcher.stop();
                    }
                    let legacy_id = entry.runtime.legacy_repo_id.clone();
                    legacy.remove(&legacy_id);
                }
            }
        }
    }

    pub fn mount_repo(&self, repo_root: &Path) -> Result<RepoMount> {
        let repo_root = repo_root
            .canonicalize()
            .unwrap_or_else(|_| repo_root.to_path_buf());
        let repo_id = repo_manager::repo_fingerprint_sha256(&repo_root)?;
        if let Some(existing) = self.get_entry(&repo_id) {
            self.touch_entry(&existing);
            return Ok(RepoMount {
                repo: existing.lock().runtime.clone(),
                status: RepoMountStatus::Ready,
            });
        }
        let legacy_repo_id = repo_manager::fingerprint::legacy_repo_id_for_root(&repo_root);
        if let Some(existing) = self.get_entry(&legacy_repo_id) {
            self.touch_entry(&existing);
            return Ok(RepoMount {
                repo: existing.lock().runtime.clone(),
                status: RepoMountStatus::Ready,
            });
        }

        let config = match self.shared_state_dir.clone() {
            Some(base) => {
                IndexConfig::with_overrides(&repo_root, Some(base), Vec::new(), Vec::new(), true)?
            }
            None => IndexConfig::for_repo(&repo_root)?,
        };
        let (indexer, read_only) = match Indexer::with_config(repo_root.clone(), config.clone()) {
            Ok(indexer) => (Arc::new(indexer), false),
            Err(err) if is_lock_busy_error(&err) => {
                warn!(
                    target: "docdexd",
                    repo = %repo_root.display(),
                    error = %err,
                    "index writer busy; opening read-only"
                );
                let readonly = Indexer::with_config_read_only(repo_root.clone(), config)?;
                (Arc::new(readonly), true)
            }
            Err(err) => return Err(err),
        };
        let libs_indexer = {
            let libs_dir = libs::libs_state_dir_from_index_state_dir(indexer.state_dir());
            libs::LibsIndexer::open_read_only(libs_dir)
                .ok()
                .flatten()
                .map(Arc::new)
        };
        let memory = self.memory_embedder.clone().map(|embedder| MemoryState {
            store: MemoryStore::new(indexer.state_dir()),
            embedder,
            repo_id: repo_id.clone(),
        });
        let delegation_metrics = self.delegation_metrics_for_repo_id(&repo_id);
        if let Err(err) = delegation_telemetry::restore_repo_metrics_if_empty(
            delegation_metrics.as_ref(),
            indexer.state_dir(),
        ) {
            warn!(
                target: "docdexd",
                error = ?err,
                repo = %repo_root.display(),
                "failed to restore repo delegation telemetry"
            );
        }
        let repo = Arc::new(RepoRuntime {
            repo_id: repo_id.clone(),
            legacy_repo_id,
            repo_root: repo_root.clone(),
            indexer: indexer.clone(),
            libs_indexer,
            memory,
            delegation_metrics,
        });
        let watcher = if read_only {
            None
        } else {
            match watcher::spawn(indexer.clone()) {
                Ok(handle) => Some(handle),
                Err(err) => {
                    warn!(
                        target: "docdexd",
                        error = ?err,
                        repo = %repo_root.display(),
                        "failed to start file watcher"
                    );
                    None
                }
            }
        };
        self.insert_repo(repo.clone(), watcher);
        let index_ready = indexer.index_ready();
        let status = if index_ready {
            RepoMountStatus::Ready
        } else {
            RepoMountStatus::Indexing
        };
        if status == RepoMountStatus::Indexing && !read_only {
            let repo_id_clone = repo.repo_id.clone();
            let indexer = indexer.clone();
            tokio::spawn(async move {
                match crate::index::ensure_indexed(indexer).await {
                    Ok(true) => info!(repo_id = %repo_id_clone, "background reindex complete"),
                    Ok(false) => info!(repo_id = %repo_id_clone, "index already ready"),
                    Err(err) => {
                        warn!(repo_id = %repo_id_clone, error = ?err, "background reindex failed")
                    }
                };
            });
        }
        Ok(RepoMount { repo, status })
    }
}

fn is_lock_busy_error(err: &anyhow::Error) -> bool {
    let message = err.to_string();
    message.contains("LockBusy")
        || message.contains("Failed to acquire")
        || message.contains("failed to acquire")
        || message.contains("index writer")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delegation_telemetry;
    use crate::metrics::Metrics;
    use crate::state_layout::resolve_state_paths;
    use tempfile::TempDir;

    #[tokio::test]
    async fn repo_manager_stops_watcher_after_idle() {
        let repo = TempDir::new().expect("repo dir");
        std::fs::write(repo.path().join("README.md"), "# test\n").expect("write file");
        let state_dir = TempDir::new().expect("state dir");
        let manager = RepoManager::new_with_timeouts(
            None,
            Some(state_dir.path().to_path_buf()),
            Duration::from_secs(1),
            Duration::from_secs(10),
            Duration::from_secs(1),
        );
        let mount = manager.mount_repo(repo.path()).expect("mount repo");
        let entry = manager
            .repos
            .read()
            .get(&mount.repo.repo_id)
            .expect("entry")
            .clone();
        assert!(entry.lock().watcher.is_some());
        let now = Instant::now();
        entry.lock().last_access = now - Duration::from_secs(2);
        manager.sweep_idle(now);
        assert!(entry.lock().watcher.is_none());
    }

    #[tokio::test]
    async fn repo_manager_hibernates_idle_repo() {
        let repo = TempDir::new().expect("repo dir");
        std::fs::write(repo.path().join("README.md"), "# test\n").expect("write file");
        let state_dir = TempDir::new().expect("state dir");
        let manager = RepoManager::new_with_timeouts(
            None,
            Some(state_dir.path().to_path_buf()),
            Duration::from_secs(1),
            Duration::from_secs(3),
            Duration::from_secs(1),
        );
        let mount = manager.mount_repo(repo.path()).expect("mount repo");
        let entry = manager
            .repos
            .read()
            .get(&mount.repo.repo_id)
            .expect("entry")
            .clone();
        let now = Instant::now();
        entry.lock().last_access = now - Duration::from_secs(4);
        manager.sweep_idle(now);
        assert!(manager.repos.read().is_empty());
    }

    #[tokio::test]
    async fn repo_manager_updates_last_access_on_get() {
        let repo = TempDir::new().expect("repo dir");
        std::fs::write(repo.path().join("README.md"), "# test\n").expect("write file");
        let state_dir = TempDir::new().expect("state dir");
        let manager = RepoManager::new_with_timeouts(
            None,
            Some(state_dir.path().to_path_buf()),
            Duration::from_secs(60),
            Duration::from_secs(120),
            Duration::from_secs(60),
        );
        let mount = manager.mount_repo(repo.path()).expect("mount repo");
        let entry = manager
            .repos
            .read()
            .get(&mount.repo.repo_id)
            .expect("entry")
            .clone();
        let stale = Instant::now() - Duration::from_secs(120);
        entry.lock().last_access = stale;
        let _ = manager.get_by_id(&mount.repo.repo_id);
        let updated = entry.lock().last_access;
        assert!(updated > stale);
    }

    #[tokio::test]
    async fn repo_manager_restores_persisted_repo_delegation_metrics() {
        let repo = TempDir::new().expect("repo dir");
        std::fs::write(repo.path().join("README.md"), "# test\n").expect("write file");
        let state_dir = TempDir::new().expect("state dir");
        let state_paths = resolve_state_paths(repo.path(), Some(state_dir.path().to_path_buf()))
            .expect("resolve state paths");

        let persisted = DelegationMetrics::default();
        persisted.inc_delegate_request();
        persisted.inc_delegate_offloaded();
        persisted.record_delegate_local_tokens(9);
        persisted.record_delegate_token_savings(9);
        delegation_telemetry::persist_metrics(
            Some(state_dir.path()),
            &Metrics::default(),
            Some(state_paths.repo_root()),
            Some(&persisted),
        );

        let manager = RepoManager::new_with_timeouts(
            None,
            Some(state_dir.path().to_path_buf()),
            Duration::from_secs(60),
            Duration::from_secs(120),
            Duration::from_secs(60),
        );
        let mount = manager.mount_repo(repo.path()).expect("mount repo");
        let snapshot = mount.repo.delegation_metrics.snapshot();
        assert_eq!(snapshot.delegate_requests_total, 1);
        assert_eq!(snapshot.delegate_offloaded_total, 1);
        assert_eq!(snapshot.delegate_local_tokens_total, 9);
        assert_eq!(snapshot.delegate_token_savings_total, 9);
    }
}
