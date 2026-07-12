pub mod fd_limits;
pub mod lock;
pub mod multi_repo;

use crate::audit::AuditLogger;
use crate::config::RepoArgs;
use crate::delegation_telemetry;
use crate::embeddings::{
    self, EmbeddingTargetHints, DEFAULT_PROFILE_EMBEDDING_MODEL, DEFAULT_REPO_EMBEDDING_MODEL,
};
use crate::error::StartupError;
use crate::index::{IndexConfig, Indexer};
use crate::ipc::mcp_ipc;
use crate::libs;
use crate::llm::local_library::load_local_library;
use crate::mcp;
use crate::memory::repo_state_root_from_state_dir;
use crate::memory::MemoryStore;
use crate::metrics;
use crate::ollama::OllamaEmbedder;
use crate::personal_preferences::PersonalPreferencesStore;
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
    embedding_base_url_explicit: bool,
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
    auth_config: crate::auth::AuthConfig,
    repo_encryption_config: crate::repo_encryption::RepoEncryptionConfig,
    conversation_config: crate::config::MemoryConversationConfig,
    personal_preferences_config: crate::config::MemoryPersonalPreferencesConfig,
    user_memory_sync_config: crate::config::MemoryUserSyncConfig,
    user_memory_sync_identity: crate::user_memory_sync::UserMemorySyncIdentity,
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
            lock::DaemonLockOutcome::Starting(metadata) => {
                if let Some(path) = lock_path {
                    println!(
                        "docdexd is starting (pid={} port={}, lock={})",
                        metadata.pid,
                        metadata.port,
                        path.display()
                    );
                } else {
                    println!(
                        "docdexd is starting (pid={} port={})",
                        metadata.pid, metadata.port
                    );
                }
                if metadata.port != 0 {
                    println!(
                        "Wait for http://127.0.0.1:{}/healthz to return ok before using MCP at http://127.0.0.1:{}/v1/mcp.",
                        metadata.port, metadata.port
                    );
                } else {
                    println!("A docdexd process was detected, but its HTTP port is not ready yet.");
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

    let config = config.with_repo_encryption(repo_encryption_config.clone());
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
    let telemetry_global_state_dir = delegation_telemetry::effective_global_state_dir(
        global_state_dir.as_deref(),
        indexer.state_dir(),
    );
    let local_model_library = load_local_library(telemetry_global_state_dir.as_deref()).ok();
    let libs_indexer = {
        let libs_dir = libs::libs_state_dir_from_index_state_dir(indexer.state_dir());
        libs::LibsIndexer::open_read_only(libs_dir)
            .ok()
            .flatten()
            .map(Arc::new)
    };
    let memory_embedder = if enable_memory {
        let timeout = Duration::from_millis(embedding_timeout_ms);
        let model_explicit = embeddings::env_present("DOCDEX_EMBEDDING_MODEL")
            || embedding_model.trim() != DEFAULT_REPO_EMBEDDING_MODEL;
        let hints = EmbeddingTargetHints::repo()
            .explicit_provider(embeddings::env_non_empty("DOCDEX_EMBEDDING_PROVIDER"))
            .explicit_base_url(
                embeddings::env_non_empty("DOCDEX_EMBEDDING_BASE_URL")
                    .or_else(|| embedding_base_url_explicit.then_some(ollama_base_url.clone())),
                embeddings::env_present("DOCDEX_EMBEDDING_BASE_URL") || embedding_base_url_explicit,
            )
            .explicit_model(Some(embedding_model.clone()), model_explicit)
            .legacy_ollama_base_url(
                embeddings::env_non_empty("DOCDEX_OLLAMA_BASE_URL")
                    .or_else(|| Some(ollama_base_url.clone())),
            );
        match embeddings::resolve_embedding_target(&llm_config, local_model_library.as_ref(), hints)
            .and_then(|target| OllamaEmbedder::with_target(target, timeout))
        {
            Ok(embedder) => Some(embedder),
            Err(err) => {
                warn!(
                    error = ?err,
                    "embedding configuration invalid; memory endpoints are disabled"
                );
                None
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
            let profile_model_explicit = embeddings::env_present("DOCDEX_PROFILE_EMBEDDING_MODEL")
                || profile_embedding_model.trim() != DEFAULT_PROFILE_EMBEDDING_MODEL;
            let profile_hints = EmbeddingTargetHints::profile()
                .explicit_provider(
                    embeddings::env_non_empty("DOCDEX_PROFILE_EMBEDDING_PROVIDER")
                        .or_else(|| embeddings::env_non_empty("DOCDEX_EMBEDDING_PROVIDER")),
                )
                .explicit_base_url(
                    embeddings::env_non_empty("DOCDEX_PROFILE_EMBEDDING_BASE_URL")
                        .or_else(|| embeddings::env_non_empty("DOCDEX_EMBEDDING_BASE_URL"))
                        .or_else(|| embedding_base_url_explicit.then_some(ollama_base_url.clone())),
                    embeddings::env_present("DOCDEX_PROFILE_EMBEDDING_BASE_URL")
                        || embeddings::env_present("DOCDEX_EMBEDDING_BASE_URL")
                        || embedding_base_url_explicit,
                )
                .explicit_model(
                    Some(profile_embedding_model.clone()),
                    profile_model_explicit,
                )
                .legacy_ollama_base_url(
                    embeddings::env_non_empty("DOCDEX_OLLAMA_BASE_URL")
                        .or_else(|| Some(ollama_base_url.clone())),
                );
            let embedder = embeddings::resolve_embedding_target(
                &llm_config,
                local_model_library.as_ref(),
                profile_hints,
            )
            .and_then(|target| ProfileEmbedder::with_target(target, timeout, profile_embedding_dim))
            .ok();
            search::ProfileState { manager, embedder }
        })
    };
    let personal_preferences = if personal_preferences_config.enabled {
        match personal_preferences_config.resolved_storage_root(global_state_dir.as_deref()) {
            Ok(storage_root) => match PersonalPreferencesStore::new(&storage_root) {
                Ok(store) => Some(search::PersonalPreferencesState {
                    store,
                    config: personal_preferences_config.clone(),
                }),
                Err(err) => {
                    warn!(
                        error = ?err,
                        storage_root = %storage_root.display(),
                        "personal preferences store initialization failed; feature disabled"
                    );
                    None
                }
            },
            Err(err) => {
                warn!(
                    error = ?err,
                    "personal preferences storage root resolution failed; feature disabled"
                );
                None
            }
        }
    } else {
        None
    };
    let mcp_auth_token = security.auth_token.clone();
    let metrics = Arc::new(metrics::Metrics::default());
    if let Err(err) = delegation_telemetry::restore_global_metrics_if_empty(
        metrics.as_ref(),
        telemetry_global_state_dir.as_deref(),
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
    let conversations = if conversation_config.enabled {
        Some(search::ConversationState {
            store: crate::conversations::ConversationStore::new(indexer.state_dir()),
            knowledge: crate::knowledge::KnowledgeStore::new(indexer.state_dir()),
            config: conversation_config.clone(),
            max_wakeup_tokens: conversation_config.max_wakeup_tokens,
            max_episodic_summaries: conversation_config.max_episodic_summaries,
            max_knowledge_facts: conversation_config.max_knowledge_facts,
            max_transcript_snippets: conversation_config.max_transcript_snippets,
        })
    } else {
        None
    };
    let shared_state_dir =
        repo_manager::split_scoped_state_dir(indexer.state_dir()).map(|(base_dir, _, _)| base_dir);
    let auth_state_dir = global_state_dir
        .clone()
        .or_else(|| shared_state_dir.clone())
        .unwrap_or_else(|| indexer.state_dir().to_path_buf());
    let auth = crate::auth::AuthRuntime::new(auth_config, &auth_state_dir).map_err(|err| {
        StartupError::new(
            "startup_state_invalid",
            format!("failed to initialize auth state: {err}"),
        )
        .with_hint("Verify global/state directory permissions for auth policy storage.")
    })?;
    let (repo_manager, delegation_metrics) = if daemon_mode {
        let manager = Arc::new(crate::daemon::multi_repo::RepoManager::new(
            memory_embedder.clone(),
            shared_state_dir,
            conversation_config.enabled,
            conversation_config.clone(),
            repo_encryption_config.clone(),
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
            read_only: false,
            libs_indexer: libs_indexer.clone(),
            memory: memory.clone(),
            conversations: conversations.clone(),
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
    start_mswarm_telemetry_housekeeping(telemetry_global_state_dir.clone());

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
            global_state_dir.clone(),
            Some(personal_preferences_config.clone()),
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
        conversations,
        personal_preferences: personal_preferences.clone(),
        profile_state,
        user_memory_sync: user_memory_sync_config,
        user_memory_sync_identity,
        features: feature_flags.clone(),
        auth,
        repo_encryption: repo_encryption_config,
        default_agent_id,
        max_answer_tokens,
        llm_config,
        llm_base_url,
        llm_default_model,
        global_state_dir: global_state_dir.clone(),
        repos: repo_manager,
        multi_repo: daemon_mode,
        require_repo_id,
        mcp_router,
    };
    if let Some(personal_preferences) = state.personal_preferences.clone() {
        if personal_preferences.config.process_in_background {
            let global_state_dir_for_task = global_state_dir.clone();
            let llm_config_for_task = state.llm_config.clone();
            let profile_state_for_task = state.profile_state.clone();
            let default_agent_id_for_task = state.default_agent_id.clone();
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(Duration::from_secs(
                    personal_preferences.config.digest_interval_seconds.max(1),
                ));
                loop {
                    ticker.tick().await;
                    match personal_preferences
                        .store
                        .scan_supported_client_transcripts(&personal_preferences.config, None)
                    {
                        Ok(scan_summary) => {
                            if scan_summary.captures_created > 0 || scan_summary.parse_errors > 0 {
                                info!(
                                    target: "docdexd",
                                    scanned_files = scan_summary.scanned_files,
                                    sessions_detected = scan_summary.sessions_detected,
                                    captures_created = scan_summary.captures_created,
                                    skipped_existing = scan_summary.skipped_existing,
                                    parse_errors = scan_summary.parse_errors,
                                    "personal preferences transcript scan completed"
                                );
                            }
                        }
                        Err(err) => {
                            warn!(
                                target: "docdexd",
                                error = ?err,
                                "personal preferences transcript scan failed"
                            );
                        }
                    }
                    match crate::personal_preferences::process_pending_with_local_agents(
                        &personal_preferences.store,
                        global_state_dir_for_task.as_deref(),
                        &llm_config_for_task,
                        &personal_preferences.config,
                        None,
                    )
                    .await
                    {
                        Ok(mut summary) => {
                            if let Some(profile_state) = profile_state_for_task.as_ref() {
                                match crate::personal_preferences::project_safe_preferences_to_profile(
                                    &personal_preferences.store,
                                    &profile_state.manager,
                                    profile_state.embedder.as_ref(),
                                    &personal_preferences.config,
                                    default_agent_id_for_task.as_deref(),
                                )
                                .await
                                {
                                    Ok(projected) => {
                                        summary.projected_profile_preferences = projected;
                                    }
                                    Err(err) => {
                                        warn!(
                                            target: "docdexd",
                                            error = ?err,
                                            "personal preferences profile projection failed"
                                        );
                                    }
                                }
                            }
                            if summary.records_written > 0 || summary.completed_captures > 0 {
                                match personal_preferences.store.sync_generated_skills(
                                    crate::personal_preferences::PersonalPreferenceGeneratedSkillsSyncOptions {
                                        min_confidence: None,
                                        min_support_count: None,
                                        include_sensitive: Some(false),
                                        install: Some(true),
                                        terminals: Vec::new(),
                                    },
                                ) {
                                    Ok(sync_summary) => {
                                        if sync_summary.rendered > 0
                                            || sync_summary.installed > 0
                                            || sync_summary.validation_failures > 0
                                        {
                                            info!(
                                                target: "docdexd",
                                                rendered = sync_summary.rendered,
                                                installed = sync_summary.installed,
                                                auto_installed = sync_summary.auto_installed,
                                                review_required = sync_summary.review_required,
                                                validation_failures = sync_summary.validation_failures,
                                                "personal preferences generated-skill sync completed"
                                            );
                                        }
                                    }
                                    Err(err) => {
                                        warn!(
                                            target: "docdexd",
                                            error = ?err,
                                            "personal preferences generated-skill sync failed"
                                        );
                                    }
                                }
                            }
                            match personal_preferences.store.prune_retention(
                                personal_preferences.config.raw_retention_days,
                                personal_preferences.config.derived_retention_days,
                                true,
                            ) {
                                Ok(prune_summary) => {
                                    if prune_summary.raw_redacted > 0
                                        || prune_summary.derived_deleted > 0
                                    {
                                        info!(
                                            target: "docdexd",
                                            raw_redacted = prune_summary.raw_redacted,
                                            derived_deleted = prune_summary.derived_deleted,
                                            "personal preferences retention prune applied"
                                        );
                                    }
                                }
                                Err(err) => {
                                    warn!(
                                        target: "docdexd",
                                        error = ?err,
                                        "personal preferences retention prune failed"
                                    );
                                }
                            }
                            if summary.processed_captures > 0 {
                                info!(
                                    target: "docdexd",
                                    processed_captures = summary.processed_captures,
                                    completed_captures = summary.completed_captures,
                                    deferred_captures = summary.deferred_captures,
                                    failed_captures = summary.failed_captures,
                                    records_written = summary.records_written,
                                    projected_profile_preferences = summary.projected_profile_preferences,
                                    "personal preferences background digest processed captures"
                                );
                            }
                        }
                        Err(err) => {
                            warn!(
                                target: "docdexd",
                                error = ?err,
                                "personal preferences background digest failed"
                            );
                        }
                    }
                }
            });
        }
    }
    if let Some(conversations) = state.conversations.clone() {
        state.metrics.set_conversation_archive_size_bytes(
            crate::conversations::archive_size_bytes_total(
                crate::conversations::combined_archive_size_bytes(
                    &conversations.store,
                    &conversations.knowledge,
                ),
                global_state_dir.as_deref(),
            ),
        );
        if !daemon_mode {
            let repo_for_task = repo_display.clone();
            let global_state_dir_for_task = global_state_dir.clone();
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(Duration::from_secs(
                    conversations.config.sweeper_interval_seconds.max(1),
                ));
                let retention_policy = crate::conversations::ConversationRetentionPolicy {
                    manual_retention_days: conversations.config.manual_retention_days,
                    auto_capture_retention_days: conversations.config.auto_capture_retention_days,
                    diary_retention_days: conversations.config.diary_retention_days,
                    hook_event_retention_days: conversations.config.hook_event_retention_days,
                    working_memory_retention_days: conversations
                        .config
                        .working_memory_retention_days,
                    episodic_rollup_retention_days: conversations
                        .config
                        .episodic_rollup_retention_days,
                };
                loop {
                    ticker.tick().await;
                    let before_size = crate::conversations::combined_archive_size_bytes(
                        &conversations.store,
                        &conversations.knowledge,
                    );
                    match crate::conversations::prune_with_knowledge(
                        &conversations.store,
                        &conversations.knowledge,
                        &retention_policy,
                        true,
                        true,
                    ) {
                        Ok(result) => {
                            let after_size = crate::conversations::combined_archive_size_bytes(
                                &conversations.store,
                                &conversations.knowledge,
                            );
                            if result.has_deletions() {
                                crate::metrics::global().record_conversation_compaction(
                                    result.deleted_sessions_total(),
                                    result.deleted_diary_entries,
                                    result.deleted_hook_events,
                                    result.deleted_knowledge_facts,
                                    before_size.saturating_sub(after_size),
                                );
                                info!(
                                    target: "docdexd",
                                    repo = %repo_for_task,
                                    deleted_manual_sessions = result.deleted_manual_sessions,
                                    deleted_auto_sessions = result.deleted_auto_sessions,
                                    deleted_diary_entries = result.deleted_diary_entries,
                                    deleted_hook_events = result.deleted_hook_events,
                                    deleted_knowledge_facts = result.deleted_knowledge_facts,
                                    reclaimed_bytes = before_size.saturating_sub(after_size),
                                    "conversation archive sweep pruned retained state"
                                );
                            }
                        }
                        Err(err) => {
                            warn!(
                                target: "docdexd",
                                repo = %repo_for_task,
                                error = ?err,
                                "conversation archive sweep failed"
                            );
                        }
                    }
                    if let Some(base_state_dir) = global_state_dir_for_task.as_deref() {
                        match crate::conversations::sweep_conversation_namespaces(
                            base_state_dir,
                            &retention_policy,
                            true,
                            true,
                        ) {
                            Ok(result) => {
                                if result.prune_result.has_deletions() {
                                    crate::metrics::global().record_conversation_compaction(
                                        result.prune_result.deleted_sessions_total(),
                                        result.prune_result.deleted_diary_entries,
                                        result.prune_result.deleted_hook_events,
                                        result.prune_result.deleted_knowledge_facts,
                                        result.bytes_before.saturating_sub(result.bytes_after),
                                    );
                                    info!(
                                        target: "docdexd",
                                        repo = %repo_for_task,
                                        namespace_count = result.namespace_count,
                                        pruned_namespace_count = result.pruned_namespace_count,
                                        deleted_manual_sessions = result.prune_result.deleted_manual_sessions,
                                        deleted_auto_sessions = result.prune_result.deleted_auto_sessions,
                                        deleted_diary_entries = result.prune_result.deleted_diary_entries,
                                        deleted_hook_events = result.prune_result.deleted_hook_events,
                                        deleted_working_memory_records = result.prune_result.deleted_working_memory_records,
                                        deleted_rollups = result.prune_result.deleted_rollups,
                                        created_rollups = result.prune_result.created_rollups,
                                        deleted_knowledge_facts = result.prune_result.deleted_knowledge_facts,
                                        reclaimed_bytes = result.bytes_before.saturating_sub(result.bytes_after),
                                        "conversation namespace sweep pruned retained state"
                                    );
                                }
                            }
                            Err(err) => {
                                warn!(
                                    target: "docdexd",
                                    repo = %repo_for_task,
                                    error = ?err,
                                    "conversation namespace sweep failed"
                                );
                            }
                        }
                    }
                    let repo_total = crate::conversations::combined_archive_size_bytes(
                        &conversations.store,
                        &conversations.knowledge,
                    );
                    crate::metrics::global().set_conversation_archive_size_bytes(
                        crate::conversations::archive_size_bytes_total(
                            repo_total,
                            global_state_dir_for_task.as_deref(),
                        ),
                    );
                }
            });
        }
    }
    let mut watcher_handle = if !daemon_mode {
        Some(watcher::spawn(indexer.clone()).map_err(|err| {
            StartupError::new(
                "startup_state_invalid",
                format!("failed to start file watcher: {err}"),
            )
            .with_hint("Verify the repo path is accessible and not on an unsupported filesystem.")
        })?)
    } else {
        None
    };

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
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = shutdown_tx.send(true);
    });

    let result = if let Some(tls_config) = tls_config.clone() {
        let tls_acceptor = TlsAcceptor::from(tls_config);
        let mut shutdown = Box::pin(wait_for_shutdown(shutdown_rx));
        let mut connections = tokio::task::JoinSet::new();
        let accept_result = loop {
            let accepted = tokio::select! {
                _ = &mut shutdown => break Ok(()),
                accepted = listener.accept() => accepted,
            };
            let (stream, remote_addr) = match accepted {
                Ok(connection) => connection,
                Err(err) => break Err(err),
            };
            let acceptor = tls_acceptor.clone();
            let svc = make_service.clone();
            connections.spawn(async move {
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
        };
        connections.abort_all();
        while connections.join_next().await.is_some() {}
        accept_result
    } else {
        let shutdown_observer = shutdown_rx.clone();
        let server = axum::serve(listener, make_service)
            .with_graceful_shutdown(wait_for_shutdown(shutdown_rx));
        let server = std::future::IntoFuture::into_future(server);
        tokio::pin!(server);
        tokio::select! {
            result = &mut server => result,
            _ = wait_for_shutdown(shutdown_observer.clone()) => {
                match tokio::time::timeout(Duration::from_secs(5), &mut server).await {
                    Ok(result) => result,
                    Err(_) => {
                        warn!(
                            target: "docdexd",
                            "HTTP connection drain exceeded five seconds; forcing shutdown"
                        );
                        Ok(())
                    }
                }
            }
        }
    };

    if let Some(watcher) = watcher_handle.as_mut() {
        watcher.stop();
    }
    if let Err(err) = crate::web::chrome::shutdown_global().await {
        warn!(
            target: "docdexd",
            error = ?err,
            "failed to shut down the global Chromium instance"
        );
    }
    #[cfg(unix)]
    if let Some(socket_path) = hook_socket_path.as_ref() {
        if let Err(err) = fs::remove_file(socket_path) {
            if err.kind() != std::io::ErrorKind::NotFound {
                warn!(
                    target: "docdexd",
                    socket = %socket_path.display(),
                    error = ?err,
                    "failed to remove hook unix socket during shutdown"
                );
            }
        }
    }
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

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};

        if let Ok(mut terminate) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = terminate.recv() => {}
            }
        } else {
            let _ = tokio::signal::ctrl_c().await;
        }
    }

    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

async fn wait_for_shutdown(mut shutdown: tokio::sync::watch::Receiver<bool>) {
    while !*shutdown.borrow() {
        if shutdown.changed().await.is_err() {
            break;
        }
    }
}

fn start_mswarm_telemetry_housekeeping(global_state_dir: Option<PathBuf>) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(60 * 60));
        loop {
            ticker.tick().await;
            match crate::mswarm_telemetry::run_housekeeping_cycle_async(global_state_dir.clone())
                .await
            {
                Ok(summary) => {
                    if summary.exported_ratings > 0
                        || summary.created_packages > 0
                        || summary.uploaded_packages > 0
                        || summary.failed_packages > 0
                        || summary.pruned_paths > 0
                    {
                        info!(
                            target: "docdexd",
                            exported_ratings = summary.exported_ratings,
                            created_packages = summary.created_packages,
                            uploaded_packages = summary.uploaded_packages,
                            failed_packages = summary.failed_packages,
                            pruned_paths = summary.pruned_paths,
                            "completed mswarm telemetry housekeeping cycle"
                        );
                    }
                }
                Err(err) => {
                    warn!(
                        target: "docdexd",
                        error = ?err,
                        "mswarm telemetry housekeeping cycle failed"
                    );
                }
            }
        }
    });
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
