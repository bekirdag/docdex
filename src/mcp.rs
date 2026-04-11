use crate::mcp_proxy::McpProxy;
use anyhow::{anyhow, Result};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};
use uuid::Uuid;

const MCP_ROUTER_SESSION_IDLE_SECS: u64 = 3600;
const MCP_ROUTER_CLEANUP_INTERVAL_SECS: u64 = 600;

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
        auth_token,
        repo_manager,
        default_delegation_metrics,
    };
    Ok(McpProxyRouter::new(config))
}

pub struct McpProxyRouter {
    config: McpProxyConfig,
    children: RwLock<HashMap<PathBuf, Arc<McpProxy>>>,
    sessions: RwLock<HashMap<String, RouterSession>>,
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
    auth_token: Option<String>,
    repo_manager: Option<Arc<crate::daemon::multi_repo::RepoManager>>,
    default_delegation_metrics: Arc<crate::metrics::DelegationMetrics>,
}

struct RouterSession {
    sender: mpsc::Sender<Value>,
    last_active: Instant,
    binding: Option<SessionBinding>,
    internal_inits: HashSet<String>,
}

#[derive(Clone)]
struct SessionBinding {
    repo_root: PathBuf,
    child: Arc<McpProxy>,
    child_session_id: String,
}

impl McpProxyRouter {
    pub(crate) fn new(config: McpProxyConfig) -> Arc<Self> {
        let router = Arc::new(Self {
            config,
            children: RwLock::new(HashMap::new()),
            sessions: RwLock::new(HashMap::new()),
        });
        McpProxyRouter::spawn_cleanup(router.clone());
        router
    }

    pub async fn create_session(&self) -> (String, mpsc::Receiver<Value>) {
        let session_id = format!("mcp-{}", uuid::Uuid::new_v4());
        let (tx, rx) = mpsc::channel(64);
        self.sessions.write().await.insert(
            session_id.clone(),
            RouterSession {
                sender: tx,
                last_active: Instant::now(),
                binding: None,
                internal_inits: HashSet::new(),
            },
        );
        (session_id, rx)
    }

    pub async fn bind_session(self: &Arc<Self>, session_id: &str, repo_root: &Path) -> Result<()> {
        let repo_root = normalize_repo_root(repo_root);
        let existing_binding = {
            let mut sessions = self.sessions.write().await;
            let entry = sessions
                .get_mut(session_id)
                .ok_or_else(|| anyhow!("unknown mcp session"))?;
            entry.last_active = Instant::now();
            entry.binding.clone()
        };
        if let Some(binding) = existing_binding {
            if binding.repo_root == repo_root && binding.child.is_alive().await {
                return Ok(());
            }
            self.evict_child(&binding.repo_root, false).await;
        }
        let child = self.ensure_child(&repo_root).await?;
        let (child_session_id, rx) = child.create_session().await;
        let sender = {
            let mut sessions = self.sessions.write().await;
            let entry = sessions
                .get_mut(session_id)
                .ok_or_else(|| anyhow!("unknown mcp session"))?;
            entry.last_active = Instant::now();
            entry.binding = Some(SessionBinding {
                repo_root: repo_root.clone(),
                child: child.clone(),
                child_session_id: child_session_id.clone(),
            });
            entry.sender.clone()
        };
        let router = Arc::clone(self);
        let session_id = session_id.to_string();
        tokio::spawn(async move {
            let mut rx = rx;
            while let Some(payload) = rx.recv().await {
                router
                    .forward_to_session(&session_id, &sender, payload)
                    .await;
            }
        });
        Ok(())
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
        let attempt = binding
            .child
            .enqueue_for_session(&binding.child_session_id, payload.clone())
            .await;
        match attempt {
            Ok(resp) => Ok(resp),
            Err(err) if is_retryable_mcp_error(&err) => {
                self.evict_child(&repo_root, true).await;
                self.bind_session(session_id, &repo_root).await?;
                let rebound = {
                    let mut sessions = self.sessions.write().await;
                    let entry = sessions
                        .get_mut(session_id)
                        .ok_or_else(|| anyhow!("unknown mcp session"))?;
                    entry.last_active = Instant::now();
                    entry.binding.clone()
                }
                .ok_or_else(|| anyhow!("mcp session not initialized"))?;
                rebound
                    .child
                    .enqueue_for_session(&rebound.child_session_id, payload)
                    .await
            }
            Err(err) => Err(err),
        }
    }

    pub async fn enqueue_internal_initialize(
        self: &Arc<Self>,
        session_id: &str,
        repo_root: &Path,
    ) -> Result<()> {
        let init_id = format!("docdex-init-{}", Uuid::new_v4());
        {
            let mut sessions = self.sessions.write().await;
            let entry = sessions
                .get_mut(session_id)
                .ok_or_else(|| anyhow!("unknown mcp session"))?;
            entry.last_active = Instant::now();
            entry.internal_inits.insert(init_id.clone());
        }
        let payload = json!({
            "jsonrpc": "2.0",
            "id": init_id,
            "method": "initialize",
            "params": { "workspace_root": repo_root.to_string_lossy().to_string() }
        });
        if let Err(err) = self.enqueue_for_session(session_id, payload).await {
            let mut sessions = self.sessions.write().await;
            if let Some(entry) = sessions.get_mut(session_id) {
                entry.internal_inits.remove(&init_id);
            }
            return Err(err);
        }
        Ok(())
    }

    pub async fn call(&self, repo_root: Option<&Path>, payload: Value) -> Result<Value> {
        let repo_root = match repo_root {
            Some(root) => normalize_repo_root(root),
            None => {
                return Err(anyhow!(
                    "missing repo binding for mcp request (call initialize with rootUri or include project_root)"
                ));
            }
        };
        let child = self.ensure_child(&repo_root).await?;
        let attempt = child.call(payload.clone()).await;
        match attempt {
            Ok(resp) => Ok(resp),
            Err(err) if is_retryable_mcp_error(&err) => {
                self.evict_child(&repo_root, true).await;
                let child = self.ensure_child(&repo_root).await?;
                child.call(payload).await
            }
            Err(err) => Err(err),
        }
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
            auth_token: self.config.auth_token.clone(),
            delegation_metrics: self.delegation_metrics_for_repo(&repo_root),
        };
        let child = spawn_mcp_proxy(options).await?;
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

    async fn forward_to_session(
        &self,
        session_id: &str,
        sender: &mpsc::Sender<Value>,
        payload: Value,
    ) {
        let mut suppress = false;
        {
            let mut sessions = self.sessions.write().await;
            if let Some(entry) = sessions.get_mut(session_id) {
                entry.last_active = Instant::now();
                if let Some(id) = payload.get("id").and_then(|value| value.as_str()) {
                    if entry.internal_inits.remove(id) {
                        suppress = true;
                    }
                }
            }
        }
        if suppress {
            return;
        }
        let _ = sender.send(payload).await;
    }

    fn spawn_cleanup(router: Arc<Self>) {
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(MCP_ROUTER_CLEANUP_INTERVAL_SECS));
            loop {
                interval.tick().await;
                router.cleanup_sessions().await;
            }
        });
    }

    async fn cleanup_sessions(&self) {
        let mut sessions = self.sessions.write().await;
        let now = Instant::now();
        sessions.retain(|_, entry| {
            now.duration_since(entry.last_active)
                < Duration::from_secs(MCP_ROUTER_SESSION_IDLE_SECS)
        });
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

fn is_retryable_mcp_error(err: &anyhow::Error) -> bool {
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
        || msg.contains("database is locked")
        || msg.contains("database table is locked")
        || msg.contains("sql busy")
        || msg.contains("write mcp request")
        || msg.contains("flush mcp request")
        || msg.contains("mcp proxy failed")
}

#[cfg(test)]
mod tests {
    use super::is_retryable_mcp_error;
    use anyhow::anyhow;

    #[test]
    fn retryable_mcp_error_detects_transient_sqlite_locking() {
        assert!(is_retryable_mcp_error(&anyhow!("database is locked")));
        assert!(is_retryable_mcp_error(&anyhow!("database table is locked")));
    }
}

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
    auth_token: Option<String>,
    delegation_metrics: Arc<crate::metrics::DelegationMetrics>,
}

async fn spawn_mcp_proxy(options: McpSpawnOptions) -> Result<Arc<McpProxy>> {
    apply_mcp_env(&options);
    let service = build_mcp_service(&options)?;
    Ok(McpProxy::new(service))
}

fn build_mcp_service(options: &McpSpawnOptions) -> Result<crate::mcp_server::McpService> {
    let repo_root = options.repo.repo_root();
    let index_config = crate::index::IndexConfig::with_overrides(
        &repo_root,
        options.repo.state_dir_override(),
        options.repo.exclude_dir_overrides(),
        options.repo.exclude_prefix_overrides(),
        options.repo.symbols_enabled(),
    )?;
    crate::mcp_server::McpService::new(
        repo_root,
        index_config,
        options.max_results,
        options.rate_limit_per_min,
        options.rate_limit_burst,
        options.auth_token.clone(),
        options.delegation_metrics.clone(),
    )
}

fn apply_mcp_env(options: &McpSpawnOptions) {
    std::env::set_var(
        "DOCDEX_ENABLE_MEMORY",
        if options.memory_enabled { "1" } else { "0" },
    );
    if let Some(base_url) = options.embedding_base_url.as_ref() {
        if !base_url.trim().is_empty() {
            std::env::set_var("DOCDEX_EMBEDDING_BASE_URL", base_url);
        }
    }
    if let Some(model) = options.embedding_model.as_ref() {
        if !model.trim().is_empty() {
            std::env::set_var("DOCDEX_EMBEDDING_MODEL", model);
        }
    }
    if let Some(timeout_ms) = options.embedding_timeout_ms {
        std::env::set_var("DOCDEX_EMBEDDING_TIMEOUT_MS", timeout_ms.to_string());
    }
    if let Some(base_url) = options.docdex_http_base_url.as_ref() {
        if !base_url.trim().is_empty() {
            std::env::set_var("DOCDEX_HTTP_BASE_URL", base_url);
        }
    }
    if std::env::var("DOCDEX_WEB_ENABLED").is_err() {
        std::env::set_var("DOCDEX_WEB_ENABLED", "1");
    }
}
