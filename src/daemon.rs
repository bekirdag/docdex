pub mod fd_limits;
pub mod lock;
pub mod multi_repo;

use crate::audit::AuditLogger;
use crate::config::RepoArgs;
use crate::delegation_telemetry;
use crate::error::StartupError;
use crate::index::{IndexConfig, Indexer};
use crate::ipc::mcp_ipc;
use crate::libs;
use crate::mcp;
use crate::memory::repo_state_root_from_state_dir;
use crate::memory::MemoryStore;
use crate::metrics;
use crate::ollama::OllamaEmbedder;
use crate::profiles::{ProfileEmbedder, ProfileManager};
use crate::repo_manager;
use crate::search::{self, AppState, SecurityConfig};
use crate::util;
use crate::watcher;
use anyhow::{anyhow, Context, Result};
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    service::TowerToHyperService,
};
use rustls_pemfile;
use std::env;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;
use std::{io, sync::Arc};
use tokio::net::TcpListener;
#[cfg(unix)]
use tokio::net::UnixListener;
use tokio_rustls::{
    rustls::{self, pki_types::CertificateDer, pki_types::PrivateKeyDer},
    TlsAcceptor,
};
use tower::Service;
use tracing::{debug, error, info, warn};

#[cfg(unix)]
use std::fs;

#[derive(Clone, Copy, Debug)]
pub enum McpEnableSource {
    Cli,
    Env,
    Config,
}

impl McpEnableSource {
    fn as_str(self) -> &'static str {
        match self {
            McpEnableSource::Cli => "cli",
            McpEnableSource::Env => "env",
            McpEnableSource::Config => "config",
        }
    }
}

#[derive(Clone, Debug)]
pub struct TlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

impl TlsConfig {
    pub fn from_options(
        cert: Option<PathBuf>,
        key: Option<PathBuf>,
        certbot_domain: Option<String>,
        certbot_live_dir: Option<PathBuf>,
    ) -> Result<Option<Self>> {
        if certbot_domain.is_some() || certbot_live_dir.is_some() {
            if cert.is_some() || key.is_some() {
                return Err(anyhow!(
                    "--certbot-domain/--certbot-live-dir cannot be combined with --tls-cert/--tls-key"
                ));
            }
            let live_dir = match (certbot_live_dir, certbot_domain) {
                (Some(dir), None) => dir,
                (None, Some(domain)) => PathBuf::from("/etc/letsencrypt/live").join(domain),
                (Some(dir), Some(domain)) => dir.join(domain),
                (None, None) => unreachable!("handled by outer check"),
            };
            let cert_path = live_dir.join("fullchain.pem");
            let key_path = live_dir.join("privkey.pem");
            if !cert_path.exists() {
                return Err(anyhow!(
                    "certbot certificate not found at {}",
                    cert_path.display()
                ));
            }
            if !key_path.exists() {
                return Err(anyhow!(
                    "certbot private key not found at {}",
                    key_path.display()
                ));
            }
            return Ok(Some(Self {
                cert_path,
                key_path,
            }));
        }

        match (cert, key) {
            (Some(cert_path), Some(key_path)) => Ok(Some(Self {
                cert_path,
                key_path,
            })),
            (None, None) => Ok(None),
            _ => Err(anyhow!(
                "both --tls-cert and --tls-key must be provided together"
            )),
        }
    }

    fn to_rustls(&self) -> Result<rustls::ServerConfig> {
        let certs = load_certs(&self.cert_path)?;
        let key = load_private_key(&self.key_path)?;
        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .with_context(|| {
                format!(
                    "build TLS config from cert={} key={}",
                    self.cert_path.display(),
                    self.key_path.display()
                )
            })?;
        Ok(config)
    }
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let mut reader = io::BufReader::new(
        std::fs::File::open(path)
            .with_context(|| format!("open TLS certificate {}", path.display()))?,
    );
    let mut certs = Vec::new();
    for cert in rustls_pemfile::certs(&mut reader) {
        certs
            .push(cert.map_err(|err| anyhow!("read certificates from {}: {err}", path.display()))?);
    }
    if certs.is_empty() {
        return Err(anyhow!("no certificates found in {}", path.display()));
    }
    Ok(certs)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let mut reader = io::BufReader::new(
        std::fs::File::open(path)
            .with_context(|| format!("open TLS private key {}", path.display()))?,
    );
    match rustls_pemfile::private_key(&mut reader)
        .map_err(|err| anyhow!("read private key from {}: {err}", path.display()))?
    {
        Some(key) => Ok(key),
        None => Err(anyhow!("no private key found in {}", path.display())),
    }
}

pub fn enter_chroot(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        let target = dir
            .canonicalize()
            .with_context(|| format!("resolve chroot dir {}", dir.display()))?;
        if !target.exists() {
            return Err(anyhow!("chroot target {} does not exist", target.display()));
        }
        nix::unistd::chroot(&target)
            .with_context(|| format!("chroot into {}", target.display()))?;
        env::set_current_dir("/").context("chdir to / after chroot")?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Err(anyhow!("chroot is only supported on Unix platforms"))
    }
}

pub fn apply_privilege_drop(
    run_as_uid: Option<u32>,
    run_as_gid: Option<u32>,
    unshare_net: bool,
) -> Result<()> {
    #[cfg(all(unix, target_os = "linux"))]
    {
        use nix::sched::{unshare, CloneFlags};
        use nix::unistd::{setgid, setuid, Gid, Uid};

        if unshare_net {
            unshare(CloneFlags::CLONE_NEWNET).context("unshare network namespace")?;
        }
        if let Some(gid) = run_as_gid {
            let gid = Gid::from_raw(gid);
            setgid(gid).context("drop to target gid")?;
        }
        if let Some(uid) = run_as_uid {
            let uid = Uid::from_raw(uid);
            setuid(uid).context("drop to target uid")?;
        }
        return Ok(());
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        use nix::unistd::{setgid, setuid, Gid, Uid};
        if unshare_net {
            warn!(
                target: "docdexd",
                "network namespace unshare is only supported on Linux; ignoring --unshare-net"
            );
        }
        if let Some(gid) = run_as_gid {
            let gid = Gid::from_raw(gid);
            setgid(gid).context("drop to target gid")?;
        }
        if let Some(uid) = run_as_uid {
            let uid = Uid::from_raw(uid);
            setuid(uid).context("drop to target uid")?;
        }
        return Ok(());
    }
    #[cfg(not(unix))]
    {
        if run_as_uid.is_some() || run_as_gid.is_some() || unshare_net {
            return Err(anyhow!(
                "privilege dropping is only supported on Unix platforms"
            ));
        }
        Ok(())
    }
}

fn env_agent_override() -> Option<String> {
    env::var("DOCDEX_LLM_AGENT")
        .ok()
        .and_then(|value| {
            let trimmed = value.trim().to_string();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        })
        .or_else(|| {
            env::var("DOCDEX_AGENT").ok().and_then(|value| {
                let trimmed = value.trim().to_string();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed)
                }
            })
        })
}

fn mcp_http_base_url(host: &str, port: u16) -> String {
    let host = match host {
        "0.0.0.0" | "::" => "127.0.0.1",
        _ => host,
    };
    let host = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    format!("http://{host}:{port}")
}

pub async fn serve(
    repo: PathBuf,
    host: String,
    port: u16,
    log_level: String,
    config: IndexConfig,
    security: SecurityConfig,
    tls: Option<TlsConfig>,
    allow_insecure: bool,
    require_tls: bool,
    access_log: bool,
    audit: Option<AuditLogger>,
    run_as_uid: Option<u32>,
    run_as_gid: Option<u32>,
    unshare_net: bool,
    enable_memory: bool,
    enable_mcp: bool,
    mcp_enable_source: McpEnableSource,
    mcp_repo_args: RepoArgs,
    mcp_max_results: usize,
    mcp_rate_limit_per_min: u32,
    mcp_rate_limit_burst: u32,
    llm_provider: String,
    ollama_base_url: String,
    embedding_model: String,
    profile_embedding_model: String,
    profile_embedding_dim: usize,
    max_answer_tokens: u32,
    llm_base_url: String,
    llm_default_model: String,
    llm_config: crate::config::LlmConfig,
    embedding_timeout_ms: u64,
    hook_socket_path: Option<PathBuf>,
    mcp_ipc_config: crate::ipc::mcp_ipc::McpIpcConfig,
    feature_flags: crate::config::FeatureFlagsConfig,
    default_agent_id: Option<String>,
    global_state_dir: Option<PathBuf>,
    daemon_mode: bool,
    require_repo_id: bool,
) -> Result<()> {
    #[cfg(unix)]
    {
        if nix::unistd::Uid::effective().is_root() && run_as_uid.is_none() && run_as_gid.is_none() {
            return Err(StartupError::new(
                "startup_refuse_root",
                "refusing to run as root without --run-as-uid/--run-as-gid; provide explicit drop targets",
            )
            .with_hint("Provide `--run-as-uid <uid>` and/or `--run-as-gid <gid>` to drop privileges after startup preparation.")
            .into());
        }
    }
    if let Some(low_limit_warning) = fd_limits::startup_low_nofile_warning() {
        warn!(target: "docdexd", "{low_limit_warning}");
    }
    let repo_display = repo.display().to_string();
    let provider = llm_provider.trim();
    let agent_override = env_agent_override().or_else(|| {
        let trimmed = llm_config.agent_id.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    });
    let mcp_http_base_url = mcp_http_base_url(&host, port);
    if daemon_mode && enable_mcp {
        let enable_web = std::env::var("DOCDEX_WEB_ENABLED")
            .ok()
            .map(|value| value.trim().is_empty())
            .unwrap_or(true);
        if enable_web {
            std::env::set_var("DOCDEX_WEB_ENABLED", "1");
        }
    }
    if !provider.eq_ignore_ascii_case("ollama") {
        if provider.is_empty() {
            warn!("llm provider is empty; LLM features will be disabled");
        } else if let Some(agent) = agent_override.as_deref() {
            warn!("llm provider `{provider}` allowed via main llm agent `{agent}`");
        } else {
            warn!("llm provider `{provider}` is not supported; LLM features will be disabled");
        }
    }

    let _daemon_lock = {
        let lock_path = lock::default_lock_path().ok();
        let outcome = lock::acquire_or_reuse(port).map_err(|err| {
            let mut error = StartupError::new(
                "startup_daemon_locked",
                format!("docdexd lock unavailable: {err}"),
            );
            if let Some(ref path) = lock_path {
                if let Ok(Some(metadata)) = lock::read_metadata(path) {
                    error = error.with_hint(format!(
                        "Existing daemon pid={} port={} (lock: {}). Stop it or remove the lock file.",
                        metadata.pid,
                        metadata.port,
                        path.display()
                    ));
                } else {
                    error = error.with_hint(format!(
                        "Check lock file at {} or stop the running daemon.",
                        path.display()
                    ));
                }
            }
            error
        })?;
        match outcome {
            lock::DaemonLockOutcome::Acquired(lock) => Some(lock),
            lock::DaemonLockOutcome::AlreadyRunning(metadata) => {
                if let Some(path) = lock_path {
                    println!(
                        "docdexd already running (pid={} port={}, lock={})",
                        metadata.pid,
                        metadata.port,
                        path.display()
                    );
                } else {
                    println!(
                        "docdexd already running (pid={} port={})",
                        metadata.pid, metadata.port
                    );
                }
                if metadata.port != 0 {
                    println!(
                        "Use the existing daemon at http://127.0.0.1:{} (set DOCDEX_HTTP_BASE_URL or configure your MCP client to use /v1/mcp/sse).",
                        metadata.port
                    );
                }
                return Ok(());
            }
        }
    };

    let tls_config = match tls {
        Some(tls) => Some(Arc::new(tls.to_rustls().map_err(|err| {
            StartupError::new(
                "startup_config_invalid",
                format!("invalid TLS configuration: {err}"),
            )
            .with_hint("Check certificate/key paths and PEM contents (or disable TLS options).")
        })?)),
        None => None,
    };
    let ip = if host.eq_ignore_ascii_case("localhost") {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    } else {
        host.parse::<IpAddr>().map_err(|_| {
            StartupError::new(
                "startup_config_invalid",
                format!("invalid --host value `{host}`: expected an IP address"),
            )
            .with_hint("Use `127.0.0.1` (default) or a specific interface IP like `0.0.0.0`.")
        })?
    };
    let is_loopback = ip.is_loopback();
    if require_tls && !is_loopback && tls_config.is_none() && !allow_insecure {
        return Err(StartupError::new(
            "startup_tls_required",
            "refusing to bind on non-loopback without TLS; provide --tls-cert/--tls-key or --insecure to allow plain HTTP",
        )
        .with_hint("Provide `--tls-cert/--tls-key`, use `--certbot-domain/--certbot-live-dir`, or (unsafe) pass `--insecure` behind a trusted proxy.")
        .into());
    }

    apply_privilege_drop(run_as_uid, run_as_gid, unshare_net).map_err(|err| {
        StartupError::new(
            "startup_state_invalid",
            format!("failed to apply privilege drop settings: {err}"),
        )
        .with_hint("On non-Unix platforms, remove --run-as-uid/--run-as-gid/--unshare-net.")
    })?;

    let indexer = Arc::new(Indexer::with_config(repo, config).map_err(|err| {
        if err.downcast_ref::<crate::error::AppError>().is_some() {
            return err;
        }
        StartupError::new(
            "startup_state_invalid",
            format!("failed to initialize state directory/index: {err}"),
        )
        .with_hint("Verify repo/state-dir paths and permissions; consider `--state-dir <path>`.")
        .into()
    })?);
    let libs_indexer = {
        let libs_dir = libs::libs_state_dir_from_index_state_dir(indexer.state_dir());
        libs::LibsIndexer::open_read_only(libs_dir)
            .ok()
            .flatten()
            .map(Arc::new)
    };
    let memory_embedder = if enable_memory {
        let model = embedding_model.trim();
        let base_url = ollama_base_url.trim();
        if model.is_empty() || base_url.is_empty() {
            warn!("embedding base URL/model not configured; memory endpoints are disabled");
            None
        } else {
            let timeout = Duration::from_millis(embedding_timeout_ms);
            match OllamaEmbedder::new(base_url.to_string(), model.to_string(), timeout) {
                Ok(embedder) => Some(embedder),
                Err(err) => {
                    warn!(
                        error = ?err,
                        "embedding configuration invalid; memory endpoints are disabled"
                    );
                    None
                }
            }
        }
    } else {
        None
    };
    let profile_state_dir = match global_state_dir.clone() {
        Some(state_dir) => Some(state_dir),
        None => match crate::state_paths::default_state_base_dir() {
            Ok(state_dir) => {
                warn!(
                    state_dir = %state_dir.display(),
                    "global_state_dir missing; falling back to default state dir for profile memory"
                );
                Some(state_dir)
            }
            Err(err) => {
                warn!(
                    error = ?err,
                    "global_state_dir missing and default state dir unavailable; profile memory disabled"
                );
                None
            }
        },
    };
    let profile_state = {
        let mut manager: Option<ProfileManager> = None;
        if let Some(state_dir) = profile_state_dir.as_ref() {
            match ProfileManager::new(state_dir, profile_embedding_dim) {
                Ok(value) => manager = Some(value),
                Err(err) => {
                    warn!(
                        error = ?err,
                        state_dir = %state_dir.display(),
                        "profile manager initialization failed; retrying with default state dir"
                    );
                }
            }
        }
        if manager.is_none() {
            if let Ok(fallback_dir) = crate::state_paths::default_state_base_dir() {
                if Some(&fallback_dir) != profile_state_dir.as_ref() {
                    match ProfileManager::new(&fallback_dir, profile_embedding_dim) {
                        Ok(value) => manager = Some(value),
                        Err(err) => {
                            warn!(
                                error = ?err,
                                fallback_dir = %fallback_dir.display(),
                                "profile manager fallback initialization failed"
                            );
                        }
                    }
                }
            }
        }
        if manager.is_none() {
            let temp_dir = std::env::temp_dir().join("docdex").join("state");
            match ProfileManager::new(&temp_dir, profile_embedding_dim) {
                Ok(value) => {
                    warn!(
                        temp_dir = %temp_dir.display(),
                        "profile manager initialized in temp dir"
                    );
                    manager = Some(value);
                }
                Err(err) => {
                    warn!(
                        error = ?err,
                        temp_dir = %temp_dir.display(),
                        "profile manager temp initialization failed"
                    );
                }
            }
        }
        manager.map(|manager| {
            let timeout = Duration::from_millis(embedding_timeout_ms);
            let embedder = ProfileEmbedder::new(
                ollama_base_url.clone(),
                profile_embedding_model.clone(),
                timeout,
                profile_embedding_dim,
            )
            .ok();
            search::ProfileState { manager, embedder }
        })
    };
    let mcp_auth_token = security.auth_token.clone();
    let metrics = Arc::new(metrics::Metrics::default());
    if let Err(err) = delegation_telemetry::restore_global_metrics_if_empty(
        metrics.as_ref(),
        global_state_dir.as_deref(),
    ) {
        warn!(target: "docdexd", error = ?err, "failed to restore delegation telemetry");
    }
    metrics::set_global(metrics.clone());
    let repo_id = repo_manager::repo_fingerprint_sha256(indexer.repo_root()).map_err(|err| {
        StartupError::new(
            "startup_state_invalid",
            format!("failed to resolve repo identity: {err}"),
        )
        .with_hint("Verify the repo path is accessible and writable.")
    })?;
    let legacy_repo_id = repo_manager::fingerprint::legacy_repo_id_for_root(indexer.repo_root());
    let memory = memory_embedder.clone().map(|embedder| search::MemoryState {
        store: MemoryStore::new(indexer.state_dir()),
        embedder,
        repo_id: repo_id.clone(),
    });
    let shared_state_dir =
        repo_manager::split_scoped_state_dir(indexer.state_dir()).map(|(base_dir, _, _)| base_dir);
    let (repo_manager, delegation_metrics) = if daemon_mode {
        let manager = Arc::new(crate::daemon::multi_repo::RepoManager::new(
            memory_embedder.clone(),
            shared_state_dir,
        ));
        let delegation_metrics = manager.delegation_metrics_for_repo_id(&repo_id);
        if let Err(err) = delegation_telemetry::restore_repo_metrics_if_empty(
            delegation_metrics.as_ref(),
            indexer.state_dir(),
        ) {
            warn!(
                target: "docdexd",
                error = ?err,
                repo = %repo_display,
                "failed to restore repo delegation telemetry"
            );
        }
        let default_repo = Arc::new(crate::daemon::multi_repo::RepoRuntime {
            repo_id: repo_id.clone(),
            legacy_repo_id: legacy_repo_id.clone(),
            repo_root: indexer.repo_root().to_path_buf(),
            indexer: indexer.clone(),
            libs_indexer: libs_indexer.clone(),
            memory: memory.clone(),
            delegation_metrics: delegation_metrics.clone(),
        });
        manager.pin_repo(repo_id.clone());
        let watcher = match watcher::spawn(indexer.clone()) {
            Ok(handle) => Some(handle),
            Err(err) => {
                warn!(
                    error = ?err,
                    "failed to start file watcher"
                );
                None
            }
        };
        manager.insert_repo(default_repo, watcher);
        manager.start_housekeeping();
        (Some(manager), delegation_metrics)
    } else {
        let delegation_metrics = Arc::new(metrics::DelegationMetrics::default());
        if let Err(err) = delegation_telemetry::restore_repo_metrics_if_empty(
            delegation_metrics.as_ref(),
            indexer.state_dir(),
        ) {
            warn!(
                target: "docdexd",
                error = ?err,
                repo = %repo_state_root_from_state_dir(indexer.state_dir()).display(),
                "failed to restore repo delegation telemetry"
            );
        }
        (None, delegation_metrics)
    };

    let mut mcp_router = None;
    if enable_mcp {
        let result = mcp::spawn_proxy_for_serve(
            mcp_repo_args,
            mcp_max_results,
            mcp_rate_limit_per_min,
            mcp_rate_limit_burst,
            enable_memory,
            ollama_base_url.clone(),
            embedding_model.clone(),
            embedding_timeout_ms,
            Some(mcp_http_base_url.clone()),
            mcp_auth_token.clone(),
            repo_manager.clone(),
            delegation_metrics.clone(),
        )
        .await;
        match result {
            Ok(router) => {
                info!(
                    target: "docdexd",
                    source = %mcp_enable_source.as_str(),
                    "mcp proxy started"
                );
                mcp_router = Some(router);
            }
            Err(err) => {
                debug!(
                    target: "docdexd",
                    source = %mcp_enable_source.as_str(),
                    error = ?err,
                    "mcp proxy failed to start"
                );
                return Err(StartupError::new(
                    "startup_mcp_failed",
                    format!("mcp proxy failed to start: {err}"),
                )
                .with_hint("Verify the repo/state dir is writable or disable MCP auto-start.")
                .with_remediation(vec![
                    "Verify the repo can be indexed and the state dir is writable.".to_string(),
                    "Or disable MCP auto-start: `docdexd serve --disable-mcp` (or set DOCDEX_ENABLE_MCP=0).".to_string(),
                ])
                .into());
            }
        }
    } else {
        info!(
            target: "docdexd",
            source = %mcp_enable_source.as_str(),
            "mcp auto-start disabled"
        );
    }

    let state = AppState {
        repo_id,
        legacy_repo_id,
        indexer: indexer.clone(),
        libs_indexer,
        security,
        access_log,
        audit,
        metrics: metrics.clone(),
        delegation_metrics,
        memory,
        profile_state,
        features: feature_flags.clone(),
        default_agent_id,
        max_answer_tokens,
        llm_config,
        llm_base_url,
        llm_default_model,
        global_state_dir,
        repos: repo_manager,
        multi_repo: daemon_mode,
        require_repo_id,
        mcp_router,
    };
    if !daemon_mode {
        let _watcher = watcher::spawn(indexer.clone()).map_err(|err| {
            StartupError::new(
                "startup_state_invalid",
                format!("failed to start file watcher: {err}"),
            )
            .with_hint("Verify the repo path is accessible and not on an unsupported filesystem.")
        })?;
    }

    let addr = SocketAddr::new(ip, port);

    let listener = TcpListener::bind(&addr).await.map_err(|err| {
        StartupError::new("startup_bind_failed", format!("failed to bind {addr}: {err}")).with_hint(
            "If the port is in use, choose another with `--port`; if permission is denied, use an unprivileged port (>=1024).",
        )
    })?;

    // Logging is intentionally initialised only after startup validation + bind succeed so
    // startup failures emit a single structured error without interleaved log lines.
    util::init_logging(&log_level)?;

    {
        let refresh_state_dir = state.global_state_dir.clone();
        let refresh_llm_config = state.llm_config.clone();
        tokio::spawn(async move {
            if let Err(err) = crate::llm::local_library::refresh_local_library_if_stale(
                refresh_state_dir.as_deref(),
                &refresh_llm_config,
                false,
            )
            .await
            {
                warn!(
                    target: "docdexd",
                    error = ?err,
                    "local model library refresh failed on startup"
                );
            }
        });
    }

    if !is_loopback {
        warn!(
            target: "docdexd",
            host = %host,
            port,
            tls = %tls_config.as_ref().map(|_| "enabled").unwrap_or("disabled"),
            insecure = allow_insecure,
            require_tls,
            "binding on non-loopback interface; ensure network access is restricted"
        );
        if !require_tls && tls_config.is_none() {
            warn!(
                target: "docdexd",
                host = %host,
                port,
                "TLS enforcement disabled on non-loopback bind; run behind a trusted proxy"
            );
        }
    }
    let router = search::router(state);
    let mcp_ipc_router = router.clone();
    #[cfg(unix)]
    let unix_make_service = router.clone().into_make_service();
    let make_service = router.into_make_service_with_connect_info::<SocketAddr>();
    info!(
        target: "docdexd",
        repo = %repo_display,
        host = %host,
        port,
        "listening on {addr}"
    );
    if enable_mcp {
        if let Err(err) = mcp_ipc::spawn_mcp_ipc_listener(mcp_ipc_router, &mcp_ipc_config).await {
            if mcp_ipc_config.requires_bind_success() {
                return Err(StartupError::new(
                    "startup_mcp_ipc_failed",
                    format!("failed to start mcp ipc listener: {err}"),
                )
                .with_hint("Disable with --mcp-ipc off or DOCDEX_MCP_IPC=0.")
                .into());
            }
            warn!(
                target: "docdexd",
                error = ?err,
                "mcp ipc listener failed; continuing without ipc"
            );
        }
    }
    #[cfg(unix)]
    if let Some(socket_path) = hook_socket_path.clone() {
        if let Some(parent) = socket_path.parent() {
            fs::create_dir_all(parent).map_err(|err| {
                StartupError::new(
                    "startup_hook_socket_failed",
                    format!(
                        "failed to create hook socket directory {}: {err}",
                        parent.display()
                    ),
                )
            })?;
        }
        if socket_path.exists() {
            fs::remove_file(&socket_path).map_err(|err| {
                StartupError::new(
                    "startup_hook_socket_failed",
                    format!(
                        "failed to remove hook socket {}: {err}",
                        socket_path.display()
                    ),
                )
            })?;
        }
        let unix_listener = UnixListener::bind(&socket_path).map_err(|err| {
            StartupError::new(
                "startup_hook_socket_failed",
                format!(
                    "failed to bind hook socket {}: {err}",
                    socket_path.display()
                ),
            )
        })?;
        let unix_service = unix_make_service.clone();
        info!(
            target: "docdexd",
            socket = %socket_path.display(),
            "hook unix socket listening"
        );
        tokio::spawn(async move {
            loop {
                match unix_listener.accept().await {
                    Ok((stream, _)) => {
                        let mut make = unix_service.clone();
                        tokio::spawn(async move {
                            match make.call(()).await {
                                Ok(service) => {
                                    let io = TokioIo::new(stream);
                                    let hyper_service = TowerToHyperService::new(service);
                                    if let Err(err) = hyper_util::server::conn::auto::Builder::new(
                                        TokioExecutor::new(),
                                    )
                                    .serve_connection(io, hyper_service)
                                    .await
                                    {
                                        warn!(
                                            target: "docdexd",
                                            error = ?err,
                                            "hook unix socket connection failed"
                                        );
                                    }
                                }
                                Err(err) => {
                                    warn!(
                                        target: "docdexd",
                                        error = ?err,
                                        "hook unix socket service build failed"
                                    );
                                }
                            }
                        });
                    }
                    Err(err) => {
                        warn!(
                            target: "docdexd",
                            error = ?err,
                            "hook unix socket accept failed"
                        );
                        break;
                    }
                }
            }
        });
    }
    #[cfg(not(unix))]
    if hook_socket_path.is_some() {
        warn!(
            target: "docdexd",
            "hook_socket_path is configured but unix sockets are not supported on this platform"
        );
    }
    if let Some(tls_config) = tls_config.clone() {
        let tls_acceptor = TlsAcceptor::from(tls_config);
        loop {
            let (stream, remote_addr) = listener.accept().await?;
            let acceptor = tls_acceptor.clone();
            let svc = make_service.clone();
            tokio::spawn(async move {
                match acceptor.accept(stream).await {
                    Ok(tls_stream) => {
                        let io = TokioIo::new(tls_stream);
                        let mut make = svc;
                        match make.call(remote_addr).await {
                            Ok(service) => {
                                let hyper_service = TowerToHyperService::new(service);
                                if let Err(err) = hyper_util::server::conn::auto::Builder::new(
                                    TokioExecutor::new(),
                                )
                                .serve_connection(io, hyper_service)
                                .await
                                {
                                    warn!(target: "docdexd", error = ?err, client = %remote_addr, "tls connection failed");
                                }
                            }
                            Err(err) => {
                                warn!(target: "docdexd", error = ?err, client = %remote_addr, "failed to build service");
                            }
                        }
                    }
                    Err(err) => {
                        warn!(target: "docdexd", error = ?err, client = %remote_addr, "tls accept failed");
                    }
                }
            });
        }
    }
    let result = axum::serve(listener, make_service).await;
    match result {
        Ok(()) => {
            info!(
                target: "docdexd",
                repo = %repo_display,
                host = %host,
                port,
                "docdex daemon shut down gracefully"
            );
            Ok(())
        }
        Err(err) => {
            error!(
                target: "docdexd",
                repo = %repo_display,
                host = %host,
                port,
                error = ?err,
                "docdex daemon terminated with error"
            );
            Err(err.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;

    const RSA_PKCS1_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBANUee5GgCjqHEzWL
tMMq4ER76GyKDNMfY7F0VqkorzNpFBrG9muvKfZD/TvknitNkpbSnSJKQNYl97zS
OrvOMkak26EkWoWjjCrhwxm4oV1WrXt699r279A2tFQ2HyrbGcLoHI/iMVKmGU4J
zpYxKgQp5p4SbZiWLwRQVQqf3iBXAgMBAAECgYBfdmQLexCZ3t9v4MB7m70RcB9Q
XxYXi7vwRRh8dUjlUnA6/lxrJ+837ISGS4W+B+VdwcG5FmGsix1JazH75gUGZmNh
hI3ejlYaDlCaCQAqTLNL0y9a3N6O/2rb6dR6QuOMo3+yDb52DCC1kXGqmPEgzcAn
FvLyoq/Q9BIgy9oP4QJBAPQ5m3I/WA5zIRQdrKAgk/lQ1RI1WTmH9psb3uV7d1Tl
lDueYDToW+Ma1+bUqVkWns7BFGtT+Ik/k4XllhkhuAsCQQDfZPHHUeGJnaghM1vH
u1MtLP8XxUeN9By9GeB3h5XhQ+sUnPk/ipQ7YhHvtMnVouuyadRgy3mzaAgBfMXI
0AxlAkEAu3lNPlIpwk3WYp602OapMIVASo3xRBx+zWqDnB0+6UiilXFp4LNNdfQx
L9ynct/OYGAO0KTQ8GqBUBOBOSGNKQJBAKIzqD3iHRGP0IDyyoQ2ZolZr4qx6meO
xMMlI8+GOfRLHUhlRbC2TTTk20MiEJ624c40e0kg1KfING/oCa/qJ+UCQCiS+Isg
cUYCAn9PPJZDQP9LU4l6qeuEAoATKyuWprc/TceQyn6gmk1ObjxchTsMq+/z1FQk
HPNvqmQsrqx0Rc0=
-----END PRIVATE KEY-----"#;

    #[test]
    fn from_options_requires_both_manual_paths() {
        let err =
            TlsConfig::from_options(Some(PathBuf::from("cert.pem")), None, None, None).unwrap_err();
        assert!(err
            .to_string()
            .contains("both --tls-cert and --tls-key must be provided together"));
    }

    #[test]
    fn certbot_live_dir_paths_are_used() {
        let temp = TempDir::new().unwrap();
        let live = temp.path().join("live");
        fs::create_dir_all(&live).unwrap();
        let cert_path = live.join("fullchain.pem");
        let key_path = live.join("privkey.pem");
        fs::write(&cert_path, "dummy cert").unwrap();
        fs::write(&key_path, RSA_PKCS1_KEY).unwrap();

        let tls = TlsConfig::from_options(None, None, None, Some(live.clone()))
            .expect("certbot live dir should configure tls")
            .expect("tls should be present");
        assert_eq!(tls.cert_path, cert_path);
        assert_eq!(tls.key_path, key_path);
    }

    #[test]
    fn pkcs1_keys_are_supported() {
        let temp = TempDir::new().unwrap();
        let key_path = temp.path().join("rsa.pem");
        fs::write(&key_path, RSA_PKCS1_KEY).unwrap();
        load_private_key(&key_path).expect("pkcs1 key should parse");
    }
}
