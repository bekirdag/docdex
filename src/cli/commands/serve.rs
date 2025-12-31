use crate::audit;
use crate::cli::commands::check::{build_report, CheckOptions};
use crate::cli::ServeArgs;
use crate::config;
use crate::daemon;
use crate::error::StartupError;
use crate::hardware;
use crate::index;
use crate::search;
use crate::web;
use anyhow::Result;
use std::net::SocketAddr;
use std::path::PathBuf;
use tracing::info;

pub(crate) async fn run(args: ServeArgs) -> Result<()> {
    run_with_mode(args, false).await
}

pub(crate) async fn run_daemon(args: ServeArgs) -> Result<()> {
    run_with_mode(args, true).await
}

async fn run_with_mode(args: ServeArgs, daemon_mode: bool) -> Result<()> {
    let ServeArgs {
        repo,
        host,
        port,
        expose,
        log,
        tls_cert,
        tls_key,
        certbot_domain,
        certbot_live_dir,
        insecure,
        require_tls,
        auth_token,
        preflight_check,
        max_limit,
        max_query_bytes,
        max_request_bytes,
        rate_limit_per_min,
        rate_limit_burst,
        strip_snippet_html,
        secure_mode,
        disable_snippet_text,
        enable_memory,
        agent_id,
        enable_mcp,
        disable_mcp,
        embedding_base_url,
        ollama_base_url,
        embedding_model,
        embedding_timeout_ms,
        access_log,
        audit_log_path,
        audit_max_bytes,
        audit_max_files,
        audit_disable,
        run_as_uid,
        run_as_gid,
        chroot_dir,
        unshare_net,
        allow_ip,
    } = args;
    let config = config::AppConfig::load_default().map_err(|err| {
        StartupError::new("startup_config_invalid", format!("failed to load config: {err}"))
            .with_hint("Ensure ~/.docdex is writable and config.toml is valid.")
    })?;
    let mut config = config;
    if let Some(agent_id) = agent_id {
        config.server.default_agent_id = agent_id;
    }
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
    let hook_socket_path = {
        let trimmed = config.server.hook_socket_path.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(PathBuf::from(trimmed))
        }
    };
    let default_agent_id = {
        let trimmed = config.server.default_agent_id.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    };
    let (enable_mcp, mcp_source) =
        resolve_mcp_enabled(enable_mcp, disable_mcp, config.server.enable_mcp);
    let mcp_max_results = resolve_mcp_max_results();
    let mcp_rate_limit_per_min = resolve_mcp_rate_limit("DOCDEX_MCP_RATE_LIMIT_PER_MIN");
    let mcp_rate_limit_burst = resolve_mcp_rate_limit("DOCDEX_MCP_RATE_LIMIT_BURST");
    let preflight_enabled = resolve_preflight_enabled(preflight_check);
    let hardware_profile = hardware::detect_hardware();
    info!(
        "hardware profile: {}; recommended model: {}",
        hardware::format_hardware_summary(&hardware_profile),
        hardware::recommend_model(&hardware_profile)
    );
    let _ = web::scraper::init_global_from_env();
    if preflight_enabled {
        let bind_addr_override = if host.eq_ignore_ascii_case("localhost") {
            Some(format!("127.0.0.1:{port}"))
        } else {
            Some(format!("{host}:{port}"))
        };
        let report = build_report(CheckOptions {
            bind_addr_override,
            mcp_enabled_override: Some(enable_mcp),
            mcp_spawn_check_override: Some(enable_mcp),
            mcp_spawn_timeout_ms: None,
        })
        .await?;
        if !report.success {
            return Err(StartupError::new(
                "startup_preflight_failed",
                "preflight checks failed",
            )
            .with_hint(
                "Run `docdexd check` for the full report or disable preflight with --preflight-check=false.",
            )
            .into());
        }
    }
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
        config.memory.profile.embedding_model.clone(),
        config.memory.profile.embedding_dim,
        config.llm.max_answer_tokens,
        config.llm.base_url.clone(),
        config.llm.default_model.clone(),
        embedding_timeout_ms,
        hook_socket_path,
        config.features.clone(),
        default_agent_id,
        config.core.global_state_dir.clone(),
        daemon_mode,
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

fn resolve_preflight_enabled(preflight_check: bool) -> bool {
    if preflight_check {
        return true;
    }
    if let Some(enabled) = env_boolish("DOCDEX_PREFLIGHT_CHECK") {
        return enabled;
    }
    false
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
