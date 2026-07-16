use crate::mcp_proxy::McpProxy;
use anyhow::{anyhow, Result};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Mutex, RwLock};

const MCP_ROUTER_SESSION_IDLE_SECS: u64 = 3600;
const MCP_ROUTER_CLEANUP_INTERVAL_SECS: u64 = 600;
const MCP_CHILD_SPAWN_ATTEMPTS: usize = 4;
const MCP_ROUTER_MAX_SESSIONS_DEFAULT: usize = 256;

pub async fn spawn_proxy_for_serve(
    repo: crate::config::RepoArgs,
    max_results: usize,
    rate_limit_per_min: u32,
    rate_limit_burst: u32,
    memory_enabled: bool,
    embedding_base_url: String,
    embedding_model: String,
    embedding_timeout_ms: u64,
    docdex_http_base_url: Option<String>,
    global_state_dir: Option<PathBuf>,
    personal_preferences_config: Option<crate::config::MemoryPersonalPreferencesConfig>,
    auth_token: Option<String>,
    repo_manager: Option<Arc<crate::daemon::multi_repo::RepoManager>>,
    default_delegation_metrics: Arc<crate::metrics::DelegationMetrics>,
) -> Result<Arc<McpProxyRouter>> {
    let config = McpProxyConfig {
        repo,
        max_results,
        rate_limit_per_min,
        rate_limit_burst,
        memory_enabled,
        embedding_base_url,
        embedding_model,
        embedding_timeout_ms,
        docdex_http_base_url,
        global_state_dir,
        personal_preferences_config,
        auth_token,
        repo_manager,
        default_delegation_metrics,
    };
    Ok(McpProxyRouter::new(config))
}

pub struct McpProxyRouter {
    config: McpProxyConfig,
    children: RwLock<HashMap<PathBuf, Arc<McpProxy>>>,
    child_spawn_lock: Mutex<()>,
    sessions: RwLock<HashMap<String, RouterSession>>,
    max_sessions: AtomicUsize,
}

#[derive(Clone)]
pub(crate) struct McpProxyConfig {
    repo: crate::config::RepoArgs,
    max_results: usize,
    rate_limit_per_min: u32,
    rate_limit_burst: u32,
    memory_enabled: bool,
    embedding_base_url: String,
    embedding_model: String,
    embedding_timeout_ms: u64,
    docdex_http_base_url: Option<String>,
    global_state_dir: Option<PathBuf>,
    personal_preferences_config: Option<crate::config::MemoryPersonalPreferencesConfig>,
    auth_token: Option<String>,
    repo_manager: Option<Arc<crate::daemon::multi_repo::RepoManager>>,
    default_delegation_metrics: Arc<crate::metrics::DelegationMetrics>,
}

struct RouterSession {
    sender: Option<mpsc::Sender<Value>>,
    last_active: Instant,
    binding: Option<SessionBinding>,
    pending_initialize: Option<Value>,
    bind_lock: Arc<Mutex<()>>,
    next_binding_generation: u64,
}

#[derive(Clone)]
struct SessionBinding {
    repo_root: PathBuf,
    child: Arc<McpProxy>,
    child_session_id: String,
    generation: u64,
}

impl McpProxyRouter {
    pub(crate) fn new(config: McpProxyConfig) -> Arc<Self> {
        Self::new_with_max_sessions(config, mcp_router_max_sessions())
    }

    fn new_with_max_sessions(config: McpProxyConfig, max_sessions: usize) -> Arc<Self> {
        let router = Arc::new(Self {
            config,
            children: RwLock::new(HashMap::new()),
            child_spawn_lock: Mutex::new(()),
            sessions: RwLock::new(HashMap::new()),
            max_sessions: AtomicUsize::new(max_sessions.max(1)),
        });
        McpProxyRouter::spawn_cleanup(&router);
        router
    }

    pub async fn create_session(&self) -> Result<(String, mpsc::Receiver<Value>)> {
        let session_id = format!("mcp-{}", uuid::Uuid::new_v4());
        let (tx, rx) = mpsc::channel(64);
        let mut sessions = self.sessions.write().await;
        if sessions.len() >= self.max_sessions.load(Ordering::Relaxed) {
            return Err(anyhow!("mcp session capacity reached"));
        }
        sessions.insert(
            session_id.clone(),
            RouterSession {
                sender: Some(tx),
                last_active: Instant::now(),
                binding: None,
                pending_initialize: None,
                bind_lock: Arc::new(Mutex::new(())),
                next_binding_generation: 0,
            },
        );
        Ok((session_id, rx))
    }

    pub async fn create_direct_session(&self) -> Result<String> {
        let session_id = format!("mcp-{}", uuid::Uuid::new_v4());
        let mut sessions = self.sessions.write().await;
        if sessions.len() >= self.max_sessions.load(Ordering::Relaxed) {
            return Err(anyhow!("mcp session capacity reached"));
        }
        sessions.insert(
            session_id.clone(),
            RouterSession {
                sender: None,
                last_active: Instant::now(),
                binding: None,
                pending_initialize: None,
                bind_lock: Arc::new(Mutex::new(())),
                next_binding_generation: 0,
            },
        );
        Ok(session_id)
    }

    pub async fn bind_session(self: &Arc<Self>, session_id: &str, repo_root: &Path) -> Result<()> {
        let repo_root = normalize_repo_root(repo_root);
        let bind_lock = {
            let mut sessions = self.sessions.write().await;
            let entry = sessions
                .get_mut(session_id)
                .ok_or_else(|| anyhow!("unknown mcp session"))?;
            entry.last_active = Instant::now();
            entry.bind_lock.clone()
        };
        let _bind_guard = bind_lock.lock().await;
        let existing_binding = {
            let mut sessions = self.sessions.write().await;
            let entry = sessions
                .get_mut(session_id)
                .ok_or_else(|| anyhow!("unknown mcp session"))?;
            entry.last_active = Instant::now();
            entry.binding.clone()
        };
        if let Some(binding) = existing_binding {
            if binding.repo_root != repo_root {
                return Err(anyhow!(
                    "mcp session is already bound to a different repository; create a new session"
                ));
            }
            if binding.repo_root == repo_root && binding.child.is_alive().await {
                return Ok(());
            }
        }
        let child = self.ensure_child(&repo_root).await?;
        let (child_session_id, rx) = child.create_session().await;
        let committed = {
            let mut sessions = self.sessions.write().await;
            if let Some(entry) = sessions.get_mut(session_id) {
                entry.next_binding_generation =
                    entry.next_binding_generation.checked_add(1).unwrap_or(1);
                let binding = SessionBinding {
                    repo_root: repo_root.clone(),
                    child: child.clone(),
                    child_session_id: child_session_id.clone(),
                    generation: entry.next_binding_generation,
                };
                let previous = entry.binding.replace(binding.clone());
                entry.last_active = Instant::now();
                Some((entry.sender.clone(), binding, previous))
            } else {
                None
            }
        };
        let Some((sender, binding, previous_binding)) = committed else {
            child.remove_session(&child_session_id).await;
            return Err(anyhow!("unknown mcp session"));
        };
        if let Some(sender) = sender {
            let router = Arc::clone(self);
            let session_id = session_id.to_string();
            let forwarded_child_session_id = binding.child_session_id.clone();
            let generation = binding.generation;
            tokio::spawn(async move {
                let mut rx = rx;
                while let Some(payload) = rx.recv().await {
                    router
                        .forward_to_session(
                            &session_id,
                            &sender,
                            generation,
                            &forwarded_child_session_id,
                            payload,
                        )
                        .await;
                }
            });
        }
        if let Some(previous) = previous_binding {
            previous
                .child
                .remove_session(&previous.child_session_id)
                .await;
            self.evict_child(&previous.repo_root, false).await;
        }
        Ok(())
    }

    pub async fn set_pending_initialize(&self, session_id: &str, payload: Value) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        let entry = sessions
            .get_mut(session_id)
            .ok_or_else(|| anyhow!("unknown mcp session"))?;
        entry.last_active = Instant::now();
        entry.pending_initialize = Some(payload);
        Ok(())
    }

    pub async fn take_pending_initialize(&self, session_id: &str) -> Option<Value> {
        let mut sessions = self.sessions.write().await;
        let entry = sessions.get_mut(session_id)?;
        entry.last_active = Instant::now();
        entry.pending_initialize.take()
    }

    pub async fn session_exists(&self, session_id: &str) -> bool {
        self.sessions.read().await.contains_key(session_id)
    }

    pub(crate) fn bootstrap_repo_root(&self) -> PathBuf {
        self.config.repo.repo_root()
    }

    pub async fn enqueue_for_session(
        self: &Arc<Self>,
        session_id: &str,
        payload: Value,
    ) -> Result<Value> {
        let binding = {
            let mut sessions = self.sessions.write().await;
            let entry = sessions
                .get_mut(session_id)
                .ok_or_else(|| anyhow!("unknown mcp session"))?;
            entry.last_active = Instant::now();
            entry.binding.clone()
        }
        .ok_or_else(|| anyhow!("mcp session not initialized"))?;
        let repo_root = binding.repo_root.clone();
        if !binding.child.is_alive().await {
            self.invalidate_child_sessions(&binding.child).await;
            self.evict_child(&repo_root, true).await;
            return Err(anyhow!(
                "mcp session backend is unavailable; create and initialize a new session"
            ));
        }
        let attempt = binding
            .child
            .enqueue_for_session(&binding.child_session_id, payload)
            .await;
        match attempt {
            Ok(resp) => Ok(resp),
            Err(err) if is_child_liveness_error(&err) => {
                self.invalidate_child_sessions(&binding.child).await;
                self.evict_child(&repo_root, true).await;
                Err(anyhow!(
                    "mcp session backend became unavailable; create and initialize a new session: {err}"
                ))
            }
            Err(err) => Err(err),
        }
    }

    pub async fn call(
        &self,
        repo_root: Option<&Path>,
        session_id: Option<&str>,
        payload: Value,
    ) -> Result<Value> {
        let repo_root = match repo_root {
            Some(root) => normalize_repo_root(root),
            None => {
                return Err(anyhow!(
                    "missing repo binding for mcp request (call initialize with rootUri or include project_root)"
                ));
            }
        };
        let child = self.ensure_child(&repo_root).await?;
        let attempt =
            Self::call_child(child, session_id.map(str::to_string), payload.clone()).await;
        match attempt {
            Ok(resp) => Ok(resp),
            Err(err) if is_child_liveness_error(&err) => {
                self.evict_child(&repo_root, true).await;
                let child = self.ensure_child(&repo_root).await?;
                Self::call_child(child, session_id.map(str::to_string), payload).await
            }
            Err(err) => Err(err),
        }
    }

    pub async fn call_for_session(&self, session_id: &str, payload: Value) -> Result<Value> {
        let binding = {
            let mut sessions = self.sessions.write().await;
            let entry = sessions
                .get_mut(session_id)
                .ok_or_else(|| anyhow!("unknown or expired mcp session"))?;
            entry.last_active = Instant::now();
            entry.binding.clone()
        }
        .ok_or_else(|| anyhow!("mcp session not initialized"))?;
        if !binding.child.is_alive().await {
            self.invalidate_child_sessions(&binding.child).await;
            self.evict_child(&binding.repo_root, true).await;
            return Err(anyhow!(
                "mcp session backend is unavailable; create and initialize a new session"
            ));
        }
        match Self::call_child(
            binding.child.clone(),
            Some(binding.child_session_id),
            payload,
        )
        .await
        {
            Err(err) if is_child_liveness_error(&err) => {
                self.invalidate_child_sessions(&binding.child).await;
                self.evict_child(&binding.repo_root, true).await;
                Err(anyhow!(
                    "mcp session backend became unavailable; create and initialize a new session: {err}"
                ))
            }
            result => result,
        }
    }

    pub async fn touch_bound_session(&self, session_id: &str) -> Result<()> {
        let binding = {
            let mut sessions = self.sessions.write().await;
            let entry = sessions
                .get_mut(session_id)
                .ok_or_else(|| anyhow!("unknown or expired mcp session"))?;
            entry.last_active = Instant::now();
            entry.binding.clone()
        }
        .ok_or_else(|| anyhow!("mcp session not initialized"))?;
        if !binding.child.is_alive().await {
            self.invalidate_child_sessions(&binding.child).await;
            self.evict_child(&binding.repo_root, true).await;
            return Err(anyhow!(
                "mcp session backend is unavailable; create and initialize a new session"
            ));
        }
        binding.child.touch_session(&binding.child_session_id).await
    }

    async fn call_child(
        child: Arc<McpProxy>,
        session_id: Option<String>,
        payload: Value,
    ) -> Result<Value> {
        Box::pin(child.call(session_id.as_deref(), payload)).await
    }

    pub async fn remove_session(&self, session_id: &str) -> bool {
        let bind_lock = self
            .sessions
            .read()
            .await
            .get(session_id)
            .map(|entry| entry.bind_lock.clone());
        let Some(bind_lock) = bind_lock else {
            return false;
        };
        let _bind_guard = bind_lock.lock().await;
        let removed = self.sessions.write().await.remove(session_id);
        let binding = removed.as_ref().and_then(|entry| entry.binding.clone());
        if let Some(binding) = binding {
            binding
                .child
                .remove_session(&binding.child_session_id)
                .await;
        }
        removed.is_some()
    }

    async fn remove_session_if_idle(&self, session_id: &str, cutoff: Instant) -> bool {
        let bind_lock = self
            .sessions
            .read()
            .await
            .get(session_id)
            .map(|entry| entry.bind_lock.clone());
        let Some(bind_lock) = bind_lock else {
            return false;
        };
        let _bind_guard = bind_lock.lock().await;
        let removed = {
            let mut sessions = self.sessions.write().await;
            let still_idle = sessions
                .get(session_id)
                .is_some_and(|entry| entry.last_active <= cutoff);
            if still_idle {
                sessions.remove(session_id)
            } else {
                None
            }
        };
        let binding = removed.as_ref().and_then(|entry| entry.binding.clone());
        if let Some(binding) = binding {
            binding
                .child
                .remove_session(&binding.child_session_id)
                .await;
        }
        removed.is_some()
    }

    #[cfg(test)]
    pub(crate) async fn session_state_for_tests(
        &self,
        session_id: &str,
    ) -> Option<(bool, Option<String>, Option<String>)> {
        let binding = self
            .sessions
            .read()
            .await
            .get(session_id)
            .and_then(|entry| entry.binding.clone())?;
        binding
            .child
            .session_state_for_tests(&binding.child_session_id)
            .await
    }

    #[cfg(test)]
    pub(crate) async fn session_count_for_tests(&self) -> usize {
        self.sessions.read().await.len()
    }

    #[cfg(test)]
    pub(crate) fn set_max_sessions_for_tests(&self, max_sessions: usize) {
        self.max_sessions
            .store(max_sessions.max(1), Ordering::Relaxed);
    }

    pub async fn session_repo_root(&self, session_id: &str) -> Option<PathBuf> {
        self.sessions
            .read()
            .await
            .get(session_id)
            .and_then(|entry| {
                entry
                    .binding
                    .as_ref()
                    .map(|binding| binding.repo_root.clone())
            })
    }

    async fn ensure_child(&self, repo_root: &Path) -> Result<Arc<McpProxy>> {
        let repo_root = normalize_repo_root(repo_root);
        if let Some(existing) = self.children.read().await.get(&repo_root).cloned() {
            if existing.is_alive().await {
                return Ok(existing);
            }
        }

        // Child construction opens the repo index and several state stores. Keep
        // first-use construction single-flight so concurrent sessions cannot
        // create competing writers and then leak the losing proxy.
        let _spawn_guard = self.child_spawn_lock.lock().await;
        if let Some(existing) = self.children.read().await.get(&repo_root).cloned() {
            if !existing.is_alive().await {
                self.evict_child(&repo_root, true).await;
            } else {
                return Ok(existing);
            }
        }
        let mut repo = self.config.repo.clone();
        repo.repo = repo_root.clone();
        let options = McpSpawnOptions {
            repo,
            max_results: self.config.max_results,
            rate_limit_per_min: self.config.rate_limit_per_min,
            rate_limit_burst: self.config.rate_limit_burst,
            memory_enabled: self.config.memory_enabled,
            embedding_base_url: Some(self.config.embedding_base_url.clone()),
            embedding_model: Some(self.config.embedding_model.clone()),
            embedding_timeout_ms: Some(self.config.embedding_timeout_ms),
            docdex_http_base_url: self.config.docdex_http_base_url.clone(),
            global_state_dir: self.config.global_state_dir.clone(),
            personal_preferences_config: self.config.personal_preferences_config.clone(),
            auth_token: self.config.auth_token.clone(),
            delegation_metrics: self.delegation_metrics_for_repo(&repo_root),
        };
        let child = spawn_mcp_proxy_with_retry(options).await?;
        let mut children = self.children.write().await;
        if let Some(existing) = children.get(&repo_root) {
            return Ok(existing.clone());
        }
        children.insert(repo_root, child.clone());
        Ok(child)
    }

    fn delegation_metrics_for_repo(
        &self,
        repo_root: &Path,
    ) -> Arc<crate::metrics::DelegationMetrics> {
        let Some(manager) = self.config.repo_manager.as_ref() else {
            return self.config.default_delegation_metrics.clone();
        };
        let repo_id =
            crate::repo_manager::repo_fingerprint_sha256(repo_root).unwrap_or_else(|_| {
                crate::repo_manager::fingerprint::legacy_repo_id_for_root(repo_root)
            });
        manager.delegation_metrics_for_repo_id(&repo_id)
    }

    async fn evict_child(&self, repo_root: &Path, force: bool) {
        let repo_root = normalize_repo_root(repo_root);
        if !force && self.repo_root_in_use(&repo_root).await {
            return;
        }
        if let Some(child) = self.children.write().await.remove(&repo_root) {
            child.shutdown().await;
        }
    }

    async fn invalidate_child_sessions(&self, child: &Arc<McpProxy>) {
        let session_ids: Vec<String> = self
            .sessions
            .read()
            .await
            .iter()
            .filter(|(_, entry)| {
                entry
                    .binding
                    .as_ref()
                    .is_some_and(|binding| Arc::ptr_eq(&binding.child, child))
            })
            .map(|(session_id, _)| session_id.clone())
            .collect();
        for session_id in session_ids {
            self.remove_session(&session_id).await;
        }
    }

    async fn forward_to_session(
        &self,
        session_id: &str,
        sender: &mpsc::Sender<Value>,
        binding_generation: u64,
        child_session_id: &str,
        payload: Value,
    ) {
        let should_evict = {
            let mut sessions = self.sessions.write().await;
            let Some(entry) = sessions.get_mut(session_id) else {
                return;
            };
            let is_current_binding = entry.binding.as_ref().is_some_and(|binding| {
                binding.generation == binding_generation
                    && binding.child_session_id == child_session_id
            });
            if !is_current_binding {
                return;
            }
            match sender.try_send(payload) {
                Ok(()) => {
                    entry.last_active = Instant::now();
                    false
                }
                Err(_) => true,
            }
        };
        if should_evict {
            self.remove_session(session_id).await;
        }
    }

    fn spawn_cleanup(router: &Arc<Self>) {
        let router = Arc::downgrade(router);
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(MCP_ROUTER_CLEANUP_INTERVAL_SECS));
            loop {
                interval.tick().await;
                let Some(router) = router.upgrade() else {
                    break;
                };
                router.cleanup_sessions().await;
            }
        });
    }

    async fn cleanup_sessions(&self) {
        let now = Instant::now();
        let cutoff = now
            .checked_sub(Duration::from_secs(MCP_ROUTER_SESSION_IDLE_SECS))
            .unwrap_or(now);
        let expired_session_ids: Vec<String> = self
            .sessions
            .read()
            .await
            .iter()
            .filter(|(_, entry)| {
                now.duration_since(entry.last_active)
                    >= Duration::from_secs(MCP_ROUTER_SESSION_IDLE_SECS)
            })
            .map(|(session_id, _)| session_id.clone())
            .collect();
        for session_id in expired_session_ids {
            self.remove_session_if_idle(&session_id, cutoff).await;
        }
        let sessions = self.sessions.read().await;
        let active_roots: HashSet<PathBuf> = sessions
            .values()
            .filter_map(|entry| {
                entry
                    .binding
                    .as_ref()
                    .map(|binding| binding.repo_root.clone())
            })
            .collect();
        drop(sessions);
        self.evict_inactive_children(&active_roots).await;
    }

    async fn repo_root_in_use(&self, repo_root: &Path) -> bool {
        let sessions = self.sessions.read().await;
        sessions.values().any(|entry| {
            entry
                .binding
                .as_ref()
                .map(|binding| binding.repo_root == repo_root)
                .unwrap_or(false)
        })
    }

    async fn evict_inactive_children(&self, active_roots: &HashSet<PathBuf>) {
        let mut to_shutdown = Vec::new();
        {
            let mut children = self.children.write().await;
            children.retain(|repo_root, child| {
                if active_roots.contains(repo_root) {
                    true
                } else {
                    to_shutdown.push(child.clone());
                    false
                }
            });
        }
        for child in to_shutdown {
            child.shutdown().await;
        }
    }
}

fn normalize_repo_root(repo_root: &Path) -> PathBuf {
    repo_root
        .canonicalize()
        .unwrap_or_else(|_| repo_root.to_path_buf())
}

fn mcp_router_max_sessions() -> usize {
    std::env::var("DOCDEX_MCP_MAX_SESSIONS")
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|value| (1..=100_000).contains(value))
        .unwrap_or(MCP_ROUTER_MAX_SESSIONS_DEFAULT)
}

fn is_child_liveness_error(err: &anyhow::Error) -> bool {
    for cause in err.chain() {
        if let Some(io) = cause.downcast_ref::<std::io::Error>() {
            if matches!(
                io.kind(),
                std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
            ) {
                return true;
            }
        }
    }
    let msg = err.to_string().to_lowercase();
    msg.contains("broken pipe")
        || msg.contains("connection reset")
        || msg.contains("mcp proxy shutdown")
        || msg.contains("write mcp request")
        || msg.contains("flush mcp request")
}

fn is_retryable_mcp_spawn_error(err: &anyhow::Error) -> bool {
    let msg = err.to_string().to_lowercase();
    is_child_liveness_error(err)
        || msg.contains("database is locked")
        || msg.contains("database table is locked")
        || msg.contains("sql busy")
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::anyhow;
    use std::fs;
    use tempfile::TempDir;

    fn test_router(
        max_sessions: usize,
    ) -> Result<(Arc<McpProxyRouter>, TempDir), Box<dyn std::error::Error>> {
        let temp = TempDir::new()?;
        let repo_root = temp.path().join("repo");
        let state_dir = temp.path().join("state");
        let global_state_dir = temp.path().join("global");
        let personal_preferences_root = temp.path().join("personal-preferences");
        fs::create_dir_all(&repo_root)?;
        fs::create_dir_all(&state_dir)?;
        fs::create_dir_all(&global_state_dir)?;
        fs::write(repo_root.join("README.md"), "# MCP router test\n")?;
        let config = McpProxyConfig {
            repo: crate::config::RepoArgs {
                repo: repo_root,
                state_dir: Some(state_dir),
                exclude_prefix: Vec::new(),
                exclude_dir: Vec::new(),
                enable_symbol_extraction: true,
            },
            max_results: 8,
            rate_limit_per_min: 0,
            rate_limit_burst: 0,
            memory_enabled: false,
            embedding_base_url: String::new(),
            embedding_model: String::new(),
            embedding_timeout_ms: 5_000,
            docdex_http_base_url: None,
            global_state_dir: Some(global_state_dir),
            personal_preferences_config: Some(crate::config::MemoryPersonalPreferencesConfig {
                storage_root: personal_preferences_root.to_string_lossy().into_owned(),
                ..crate::config::MemoryPersonalPreferencesConfig::default()
            }),
            auth_token: None,
            repo_manager: None,
            default_delegation_metrics: Arc::new(crate::metrics::DelegationMetrics::default()),
        };
        Ok((
            McpProxyRouter::new_with_max_sessions(config, max_sessions),
            temp,
        ))
    }

    #[test]
    fn retryable_mcp_error_detects_transient_sqlite_locking() {
        assert!(is_retryable_mcp_spawn_error(&anyhow!("database is locked")));
        assert!(is_retryable_mcp_spawn_error(&anyhow!(
            "database table is locked"
        )));
        assert!(!is_child_liveness_error(&anyhow!("database is locked")));
    }

    #[tokio::test]
    async fn router_session_capacity_is_bounded_and_reclaimable(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (router, _temp) = test_router(1)?;
        let first = router.create_direct_session().await?;
        let err = router
            .create_direct_session()
            .await
            .expect_err("second session must exceed capacity");
        assert!(err.to_string().contains("capacity"));
        assert!(router.remove_session(&first).await);
        let replacement = router.create_direct_session().await?;
        assert_ne!(replacement, first);
        Ok(())
    }

    #[tokio::test]
    async fn idle_cleanup_rechecks_activity_after_snapshot(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (router, _temp) = test_router(2)?;
        let session_id = router.create_direct_session().await?;
        let cutoff = Instant::now();
        let bind_lock = {
            let mut sessions = router.sessions.write().await;
            let entry = sessions.get_mut(&session_id).expect("router session");
            entry.last_active = cutoff
                .checked_sub(Duration::from_secs(MCP_ROUTER_SESSION_IDLE_SECS + 1))
                .expect("stale timestamp");
            entry.bind_lock.clone()
        };
        let guard = bind_lock.lock().await;
        let cleanup_router = router.clone();
        let cleanup_session_id = session_id.clone();
        let cleanup = tokio::spawn(async move {
            cleanup_router
                .remove_session_if_idle(&cleanup_session_id, cutoff)
                .await
        });
        tokio::task::yield_now().await;
        router
            .sessions
            .write()
            .await
            .get_mut(&session_id)
            .expect("router session")
            .last_active = Instant::now();
        drop(guard);

        assert!(!cleanup.await?);
        assert_eq!(router.session_count_for_tests().await, 1);
        Ok(())
    }

    #[tokio::test]
    async fn dead_child_invalidates_every_bound_outer_session(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (router, _temp) = test_router(4)?;
        let first = router.create_direct_session().await?;
        let second = router.create_direct_session().await?;
        let repo_root = router.config.repo.repo_root();
        router.bind_session(&first, &repo_root).await?;
        router.bind_session(&second, &repo_root).await?;
        let child = router
            .sessions
            .read()
            .await
            .get(&first)
            .and_then(|entry| entry.binding.as_ref())
            .map(|binding| binding.child.clone())
            .expect("shared child");
        child.shutdown().await;

        let err = router
            .call_for_session(
                &first,
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/list",
                    "params": {}
                }),
            )
            .await
            .expect_err("dead child must invalidate sessions");
        assert!(err.to_string().contains("new session"));
        assert_eq!(router.session_count_for_tests().await, 0);
        assert!(router.session_repo_root(&second).await.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn full_outer_response_channel_evicts_session_without_waiting(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (router, _temp) = test_router(2)?;
        let (session_id, _rx) = router.create_session().await?;
        let repo_root = router.config.repo.repo_root();
        router.bind_session(&session_id, &repo_root).await?;
        let (sender, binding) = {
            let sessions = router.sessions.read().await;
            let entry = sessions.get(&session_id).expect("router session");
            (
                entry.sender.clone().expect("SSE sender"),
                entry.binding.clone().expect("child binding"),
            )
        };
        for sequence in 0..64 {
            sender.try_send(serde_json::json!({ "sequence": sequence }))?;
        }
        assert_eq!(sender.capacity(), 0, "test must saturate response channel");

        tokio::time::timeout(
            Duration::from_secs(1),
            router.forward_to_session(
                &session_id,
                &sender,
                binding.generation,
                &binding.child_session_id,
                serde_json::json!({ "overflow": true }),
            ),
        )
        .await?;

        assert_eq!(router.session_count_for_tests().await, 0);
        assert!(binding
            .child
            .touch_session(&binding.child_session_id)
            .await
            .is_err());
        Ok(())
    }
}

#[derive(Clone)]
struct McpSpawnOptions {
    repo: crate::config::RepoArgs,
    max_results: usize,
    rate_limit_per_min: u32,
    rate_limit_burst: u32,
    memory_enabled: bool,
    embedding_base_url: Option<String>,
    embedding_model: Option<String>,
    embedding_timeout_ms: Option<u64>,
    docdex_http_base_url: Option<String>,
    global_state_dir: Option<PathBuf>,
    personal_preferences_config: Option<crate::config::MemoryPersonalPreferencesConfig>,
    auth_token: Option<String>,
    delegation_metrics: Arc<crate::metrics::DelegationMetrics>,
}

async fn spawn_mcp_proxy(options: McpSpawnOptions) -> Result<Arc<McpProxy>> {
    let service = build_mcp_service(&options)?;
    Ok(McpProxy::new(service))
}

async fn spawn_mcp_proxy_with_retry(options: McpSpawnOptions) -> Result<Arc<McpProxy>> {
    let mut last_err = None;
    for attempt in 1..=MCP_CHILD_SPAWN_ATTEMPTS {
        match spawn_mcp_proxy(options.clone()).await {
            Ok(proxy) => return Ok(proxy),
            Err(err)
                if is_retryable_mcp_spawn_error(&err) && attempt < MCP_CHILD_SPAWN_ATTEMPTS =>
            {
                last_err = Some(err);
                tokio::time::sleep(Duration::from_millis(75 * attempt as u64)).await;
            }
            Err(err) => return Err(err),
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("mcp proxy spawn failed")))
}

fn build_mcp_service(options: &McpSpawnOptions) -> Result<crate::mcp_server::McpService> {
    let repo_root = options.repo.repo_root();
    let repo_encryption = crate::config::AppConfig::load_default()
        .ok()
        .map(|config| config.repo_encryption)
        .unwrap_or_default();
    let index_config = crate::index::IndexConfig::with_overrides(
        &repo_root,
        options.repo.state_dir_override(),
        options.repo.exclude_dir_overrides(),
        options.repo.exclude_prefix_overrides(),
        options.repo.symbols_enabled(),
    )?
    .with_repo_encryption(repo_encryption);
    crate::mcp_server::McpService::new(
        repo_root,
        index_config,
        options.max_results,
        options.rate_limit_per_min,
        options.rate_limit_burst,
        crate::mcp_server::McpRuntimeOptions {
            memory_enabled: options.memory_enabled,
            embedding_base_url: options.embedding_base_url.clone(),
            embedding_model: options.embedding_model.clone(),
            embedding_timeout_ms: options.embedding_timeout_ms,
            docdex_http_base_url: options.docdex_http_base_url.clone(),
            global_state_dir: options.global_state_dir.clone(),
            personal_preferences_config: options.personal_preferences_config.clone(),
        },
        options.auth_token.clone(),
        options.delegation_metrics.clone(),
    )
}
