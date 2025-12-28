use crate::audit;
use crate::config::{self, RepoArgs};
use crate::daemon;
use crate::error::StartupError;
use crate::hardware;
use crate::index;
use crate::search;
use crate::web;
use anyhow::Result;
use std::path::PathBuf;
use std::net::SocketAddr;
use tracing::info;

#[allow(clippy::too_many_arguments)]
pub async fn run(
    repo: RepoArgs,
    host: Option<String>,
    port: Option<u16>,
    expose: bool,
    log: String,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
    certbot_domain: Option<String>,
    certbot_live_dir: Option<PathBuf>,
    insecure: bool,
    require_tls: bool,
    auth_token: Option<String>,
    max_limit: usize,
    max_query_bytes: usize,
    max_request_bytes: usize,
    rate_limit_per_min: u32,
    rate_limit_burst: u32,
    strip_snippet_html: bool,
    secure_mode: bool,
    disable_snippet_text: bool,
    enable_memory: bool,
    enable_mcp: bool,
    disable_mcp: bool,
    embedding_base_url: Option<String>,
    ollama_base_url: String,
    embedding_model: String,
    embedding_timeout_ms: u64,
    access_log: bool,
    audit_log_path: Option<PathBuf>,
    audit_max_bytes: u64,
    audit_max_files: u32,
    audit_disable: bool,
    run_as_uid: Option<u32>,
    run_as_gid: Option<u32>,
    chroot_dir: Option<PathBuf>,
    unshare_net: bool,
    allow_ip: Vec<String>,
) -> Result<()> {
    let config = config::AppConfig::load_default().map_err(|err| {
        StartupError::new("startup_config_invalid", format!("failed to load config: {err}"))
            .with_hint("Ensure ~/.docdex is writable and config.toml is valid.")
    })?;
    let (host, port) = resolve_bind_addr(host, port, &config)?;
    if let Some(ref dir) = chroot_dir {
        daemon::enter_chroot(dir).map_err(|err| {
            StartupError::new("startup_state_invalid", err.to_string())
                .with_hint("Verify the chroot path exists and is accessible (Unix only).")
        })?;
    }
    let repo_root = repo.repo_root();
    let mcp_repo_args = repo.clone();
    let index_config = index::IndexConfig::with_overrides(
        &repo_root,
        repo.state_dir_override(),
        repo.exclude_dir_overrides(),
        repo.exclude_prefix_overrides(),
        repo.symbols_enabled(),
    )
    .map_err(|err| {
        StartupError::new(
            "startup_state_invalid",
            format!("failed to resolve state directory/identity: {err}"),
        )
        .with_hint("Verify repo/state-dir paths and permissions; consider removing --state-dir or running `docdexd index` once to initialize metadata.")
    })?;
    let tls = daemon::TlsConfig::from_options(tls_cert, tls_key, certbot_domain, certbot_live_dir)
        .map_err(|err| {
            StartupError::new("startup_config_invalid", err.to_string()).with_hint(
                "Fix TLS flags (provide both --tls-cert/--tls-key or use --certbot-* options).",
            )
        })?;
    let audit_logger = if audit_disable {
        None
    } else {
        let path = audit_log_path
            .clone()
            .unwrap_or_else(|| index_config.state_dir().join("audit.log"));
        Some(
            audit::AuditLogger::new(path, audit_max_bytes, audit_max_files as usize).map_err(
                |err| {
                StartupError::new("startup_state_invalid", err.to_string())
                    .with_hint("Verify the state dir is writable or set --audit-disable.")
            })?,
        )
    };
    let ip = if host.eq_ignore_ascii_case("localhost") {
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
    } else {
        host.parse::<std::net::IpAddr>().map_err(|_| {
            StartupError::new(
                "startup_config_invalid",
                format!("invalid --host value `{host}`: expected an IP address"),
            )
            .with_hint("Use `127.0.0.1` (default) or a specific interface IP like `0.0.0.0`.")
        })?
    };
    let is_loopback = ip.is_loopback();
    if !is_loopback && !expose {
        return Err(StartupError::new(
            "startup_expose_required",
            "refusing to bind on non-loopback without --expose",
        )
        .with_hint("Pass --expose to allow remote binds; keep --host 127.0.0.1 for local-only use.")
        .with_remediation(vec![
            "docdexd serve --repo . --host 0.0.0.0 --port 3210 --expose --auth-token <token> --require-tls=false"
                .to_string(),
            "docdexd serve --repo . --host 127.0.0.1 --port 3210".to_string(),
        ])
        .into());
    }
    let security = search::SecurityConfig::from_options(
        auth_token,
        allow_ip.as_slice(),
        max_limit,
        max_query_bytes,
        max_request_bytes,
        rate_limit_per_min,
        rate_limit_burst,
        strip_snippet_html,
        secure_mode,
        disable_snippet_text,
        !expose,
        !is_loopback,
    )?;
    let embedding_base_url = embedding_base_url.unwrap_or(ollama_base_url);
    let enable_memory = if std::env::var_os("DOCDEX_ENABLE_MEMORY").is_some() {
        enable_memory
    } else {
        enable_memory || config.memory.enabled
    };
    let (enable_mcp, mcp_source) =
        resolve_mcp_enabled(enable_mcp, disable_mcp, config.server.enable_mcp);
    let mcp_max_results = resolve_mcp_max_results();
    let mcp_rate_limit_per_min = resolve_mcp_rate_limit("DOCDEX_MCP_RATE_LIMIT_PER_MIN");
    let mcp_rate_limit_burst = resolve_mcp_rate_limit("DOCDEX_MCP_RATE_LIMIT_BURST");
    let hardware_profile = hardware::detect_hardware();
    info!(
        "hardware profile: {}; recommended model: {}",
        hardware::format_hardware_summary(&hardware_profile),
        hardware::recommend_model(&hardware_profile)
    );
    let _ = web::scraper::init_global_from_env();
    daemon::serve(
        repo_root,
        host,
        port,
        log,
        index_config,
        security,
        tls,
        insecure,
        require_tls,
        access_log,
        audit_logger,
        run_as_uid,
        run_as_gid,
        unshare_net,
        enable_memory,
        enable_mcp,
        mcp_source,
        mcp_repo_args,
        mcp_max_results,
        mcp_rate_limit_per_min,
        mcp_rate_limit_burst,
        config.llm.provider.clone(),
        embedding_base_url,
        embedding_model,
        config.llm.max_answer_tokens,
        config.llm.base_url.clone(),
        config.llm.default_model.clone(),
        embedding_timeout_ms,
    )
    .await
}

fn resolve_bind_addr(
    host: Option<String>,
    port: Option<u16>,
    config: &config::AppConfig,
) -> Result<(String, u16)> {
    if host.is_some() && port.is_some() {
        return Ok((host.unwrap(), port.unwrap()));
    }
    let bind_addr = config.server.http_bind_addr.trim();
    let addr: SocketAddr = bind_addr.parse().map_err(|err| {
        StartupError::new(
            "startup_config_invalid",
            format!("invalid server.http_bind_addr `{bind_addr}`: {err}"),
        )
        .with_hint("Use <ip>:<port> (e.g., 127.0.0.1:3210) or override with --host/--port.")
    })?;
    let default_host = addr.ip().to_string();
    let default_port = addr.port();
    Ok((host.unwrap_or(default_host), port.unwrap_or(default_port)))
}

fn resolve_mcp_enabled(
    enable_mcp: bool,
    disable_mcp: bool,
    config_enabled: bool,
) -> (bool, daemon::McpEnableSource) {
    if enable_mcp {
        return (true, daemon::McpEnableSource::Cli);
    }
    if disable_mcp {
        return (false, daemon::McpEnableSource::Cli);
    }
    if let Some(enabled) = env_boolish("DOCDEX_ENABLE_MCP") {
        return (enabled, daemon::McpEnableSource::Env);
    }
    (config_enabled, daemon::McpEnableSource::Config)
}

fn resolve_mcp_max_results() -> usize {
    std::env::var("DOCDEX_MCP_MAX_RESULTS")
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(8)
        .max(1)
}

fn resolve_mcp_rate_limit(env_key: &str) -> u32 {
    std::env::var(env_key)
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok())
        .unwrap_or(0)
}

fn env_boolish(key: &str) -> Option<bool> {
    let raw = std::env::var(key).ok()?;
    let trimmed = raw.trim().to_ascii_lowercase();
    match trimmed.as_str() {
        "1" | "true" | "t" | "yes" | "y" | "on" => Some(true),
        "0" | "false" | "f" | "no" | "n" | "off" => Some(false),
        _ => None,
    }
}
