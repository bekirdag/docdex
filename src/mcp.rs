use crate::mcp_proxy::McpProxy;
use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, RwLock};
use which::which;
use uuid::Uuid;

const MCP_SERVER_BIN_ENV: &str = "DOCDEX_MCP_SERVER_BIN";
const MCP_SERVER_BIN_NAME: &str = "docdex-mcp-server";
const MCP_ROUTER_SESSION_IDLE_SECS: u64 = 3600;
const MCP_ROUTER_CLEANUP_INTERVAL_SECS: u64 = 600;

pub async fn serve(
    repo: crate::config::RepoArgs,
    log: String,
    max_results: usize,
    rate_limit_per_min: u32,
    rate_limit_burst: u32,
    auth_token: Option<String>,
) -> Result<()> {
    let _ = (log, max_results, rate_limit_per_min, rate_limit_burst);
    let base_url = crate::cli::http_client::resolve_base_url_with_lock()
        .context("resolve MCP daemon base URL")?;
    let repo_root = repo.repo_root();
    crate::mcp_proxy::McpHttpProxy::run(repo_root, base_url, auth_token).await
}

pub async fn spawn_for_serve(
    repo: crate::config::RepoArgs,
    log_level: String,
    max_results: usize,
    rate_limit_per_min: u32,
    rate_limit_burst: u32,
    memory_enabled: bool,
    embedding_base_url: String,
    embedding_model: String,
    embedding_timeout_ms: u64,
    docdex_http_base_url: Option<String>,
    auth_token: Option<String>,
) -> Result<Child> {
    let options = McpSpawnOptions {
        repo,
        log_level,
        max_results,
        rate_limit_per_min,
        rate_limit_burst,
        memory_enabled,
        embedding_base_url: Some(embedding_base_url),
        embedding_model: Some(embedding_model),
        embedding_timeout_ms: Some(embedding_timeout_ms),
        docdex_http_base_url,
        auth_token,
        detach_stdio: true,
        capture_stdio: false,
    };
    spawn_mcp(options).await
}

pub async fn spawn_proxy_for_serve(
    repo: crate::config::RepoArgs,
    log_level: String,
    max_results: usize,
    rate_limit_per_min: u32,
    rate_limit_burst: u32,
    memory_enabled: bool,
    embedding_base_url: String,
    embedding_model: String,
    embedding_timeout_ms: u64,
    docdex_http_base_url: Option<String>,
    auth_token: Option<String>,
) -> Result<Arc<McpProxyRouter>> {
    let _ = resolve_mcp_server_binary()?;
    let config = McpProxyConfig {
        repo,
        log_level,
        max_results,
        rate_limit_per_min,
        rate_limit_burst,
        memory_enabled,
        embedding_base_url,
        embedding_model,
        embedding_timeout_ms,
        docdex_http_base_url,
        auth_token,
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
    log_level: String,
    max_results: usize,
    rate_limit_per_min: u32,
    rate_limit_burst: u32,
    memory_enabled: bool,
    embedding_base_url: String,
    embedding_model: String,
    embedding_timeout_ms: u64,
    docdex_http_base_url: Option<String>,
    auth_token: Option<String>,
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
            self.evict_child(&binding.repo_root).await;
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
                self.evict_child(&repo_root).await;
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
                self.evict_child(&repo_root).await;
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
                self.evict_child(&repo_root).await;
            } else {
                return Ok(existing);
            }
        }
        let mut repo = self.config.repo.clone();
        repo.repo = repo_root.clone();
        let options = McpSpawnOptions {
            repo,
            log_level: self.config.log_level.clone(),
            max_results: self.config.max_results,
            rate_limit_per_min: self.config.rate_limit_per_min,
            rate_limit_burst: self.config.rate_limit_burst,
            memory_enabled: self.config.memory_enabled,
            embedding_base_url: Some(self.config.embedding_base_url.clone()),
            embedding_model: Some(self.config.embedding_model.clone()),
            embedding_timeout_ms: Some(self.config.embedding_timeout_ms),
            docdex_http_base_url: self.config.docdex_http_base_url.clone(),
            auth_token: self.config.auth_token.clone(),
            detach_stdio: false,
            capture_stdio: true,
        };
        let child = spawn_mcp_proxy(options).await?;
        let mut children = self.children.write().await;
        if let Some(existing) = children.get(&repo_root) {
            return Ok(existing.clone());
        }
        children.insert(repo_root, child.clone());
        Ok(child)
    }

    async fn evict_child(&self, repo_root: &Path) {
        let repo_root = normalize_repo_root(repo_root);
        self.children.write().await.remove(&repo_root);
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
        || msg.contains("write mcp request")
        || msg.contains("flush mcp request")
        || msg.contains("mcp proxy failed")
}

struct McpSpawnOptions {
    repo: crate::config::RepoArgs,
    log_level: String,
    max_results: usize,
    rate_limit_per_min: u32,
    rate_limit_burst: u32,
    memory_enabled: bool,
    embedding_base_url: Option<String>,
    embedding_model: Option<String>,
    embedding_timeout_ms: Option<u64>,
    docdex_http_base_url: Option<String>,
    auth_token: Option<String>,
    detach_stdio: bool,
    capture_stdio: bool,
}

async fn spawn_mcp(options: McpSpawnOptions) -> Result<Child> {
    let mut cmd = build_mcp_command(&options)?;
    if options.capture_stdio {
        cmd.stdin(Stdio::piped());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::inherit());
    } else if options.detach_stdio {
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::null());
        cmd.stderr(Stdio::null());
    } else {
        cmd.stdin(Stdio::inherit());
        cmd.stdout(Stdio::inherit());
        cmd.stderr(Stdio::inherit());
    }
    cmd.kill_on_drop(true);
    cmd.spawn()
        .with_context(|| format!("launch {MCP_SERVER_BIN_NAME}"))
}

async fn spawn_mcp_proxy(options: McpSpawnOptions) -> Result<Arc<McpProxy>> {
    let mut cmd = build_mcp_command(&options)?;
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::inherit());
    cmd.kill_on_drop(true);
    let mut child = cmd
        .spawn()
        .with_context(|| format!("launch {MCP_SERVER_BIN_NAME}"))?;
    let stdin = child.stdin.take().context("capture mcp stdin")?;
    let stdout = child.stdout.take().context("capture mcp stdout")?;
    Ok(McpProxy::new(child, stdin, stdout))
}

fn build_mcp_command(options: &McpSpawnOptions) -> Result<Command> {
    let bin = resolve_mcp_server_binary()?;
    let mut cmd = Command::new(&bin);
    cmd.arg("--repo").arg(&options.repo.repo);
    if let Some(state_dir) = options.repo.state_dir.clone() {
        cmd.arg("--state-dir").arg(state_dir);
    }
    for dir in &options.repo.exclude_dir {
        cmd.arg("--exclude-dir").arg(dir);
    }
    for prefix in &options.repo.exclude_prefix {
        cmd.arg("--exclude-prefix").arg(prefix);
    }
    if options.repo.enable_symbol_extraction {
        cmd.arg("--enable-symbol-extraction").arg("true");
    }
    cmd.arg("--log").arg(&options.log_level);
    cmd.arg("--max-results")
        .arg(options.max_results.to_string());
    cmd.arg("--rate-limit-per-min")
        .arg(options.rate_limit_per_min.to_string());
    cmd.arg("--rate-limit-burst")
        .arg(options.rate_limit_burst.to_string());
    cmd.env(
        "DOCDEX_ENABLE_MEMORY",
        if options.memory_enabled { "1" } else { "0" },
    );
    if let Some(base_url) = options.embedding_base_url.as_ref() {
        cmd.env("DOCDEX_EMBEDDING_BASE_URL", base_url);
    }
    if let Some(model) = options.embedding_model.as_ref() {
        cmd.env("DOCDEX_EMBEDDING_MODEL", model);
    }
    if let Some(timeout_ms) = options.embedding_timeout_ms {
        cmd.env("DOCDEX_EMBEDDING_TIMEOUT_MS", timeout_ms.to_string());
    }
    if let Some(base_url) = options.docdex_http_base_url.as_ref() {
        if !base_url.trim().is_empty() {
            cmd.env("DOCDEX_HTTP_BASE_URL", base_url);
        }
    }
    if let Some(token) = options.auth_token.as_ref() {
        if !token.trim().is_empty() {
            cmd.arg("--auth-token").arg(token.trim());
        }
    }
    if std::env::var("DOCDEX_WEB_ENABLED").is_err() {
        cmd.env("DOCDEX_WEB_ENABLED", "1");
    }
    Ok(cmd)
}

pub(crate) fn resolve_mcp_server_binary() -> Result<PathBuf> {
    if let Ok(path) = std::env::var(MCP_SERVER_BIN_ENV) {
        if !path.trim().is_empty() {
            let candidate = PathBuf::from(path);
            if candidate.is_file() {
                return Ok(candidate);
            }
            #[cfg(windows)]
            {
                let exe = candidate.with_extension("exe");
                if exe.is_file() {
                    return Ok(exe);
                }
            }
            return Err(anyhow!(
                "{MCP_SERVER_BIN_ENV} points to missing MCP server binary; set it to the docdex-mcp-server path"
            ));
        }
    }

    if let Ok(current) = std::env::current_exe() {
        if let Some(dir) = current.parent() {
            if let Some(candidate) = sibling_binary(dir, MCP_SERVER_BIN_NAME) {
                return Ok(candidate);
            }
        }
    }

    if let Ok(found) = which(MCP_SERVER_BIN_NAME) {
        return Ok(found);
    }

    Err(anyhow!(
        "docdex-mcp-server not found; build it with `cargo build -p docdex-mcp-server` or set {MCP_SERVER_BIN_ENV} to the binary path"
    ))
}

fn sibling_binary(dir: &Path, name: &str) -> Option<PathBuf> {
    let candidate = dir.join(name);
    if candidate.is_file() {
        return Some(candidate);
    }
    #[cfg(windows)]
    {
        let candidate = dir.join(format!("{name}.exe"));
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}
