use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::process::{Child, Command};
use which::which;

const MCP_SERVER_BIN_ENV: &str = "DOCDEX_MCP_SERVER_BIN";
const MCP_SERVER_BIN_NAME: &str = "docdex-mcp-server";

pub async fn serve(
    repo: crate::config::RepoArgs,
    log: String,
    max_results: usize,
    rate_limit_per_min: u32,
    rate_limit_burst: u32,
    auth_token: Option<String>,
) -> Result<()> {
    let memory_settings = resolve_memory_settings()?;
    let options = McpSpawnOptions {
        repo,
        log_level: log,
        max_results,
        rate_limit_per_min,
        rate_limit_burst,
        memory_enabled: memory_settings.enabled,
        embedding_base_url: Some(memory_settings.base_url),
        embedding_model: Some(memory_settings.model),
        embedding_timeout_ms: Some(memory_settings.timeout_ms),
        auth_token,
        detach_stdio: false,
    };
    let mut child = spawn_mcp(options).await?;
    let status = child
        .wait()
        .await
        .with_context(|| format!("launch {MCP_SERVER_BIN_NAME}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(anyhow!(
            "{MCP_SERVER_BIN_NAME} exited with status {status}"
        ))
    }
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
        auth_token,
        detach_stdio: true,
    };
    spawn_mcp(options).await
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
    auth_token: Option<String>,
    detach_stdio: bool,
}

struct McpMemorySettings {
    enabled: bool,
    base_url: String,
    model: String,
    timeout_ms: u64,
}

async fn spawn_mcp(options: McpSpawnOptions) -> Result<Child> {
    let mut cmd = build_mcp_command(&options)?;
    if options.detach_stdio {
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::null());
        cmd.stderr(Stdio::inherit());
    } else {
        cmd.stdin(Stdio::inherit());
        cmd.stdout(Stdio::inherit());
        cmd.stderr(Stdio::inherit());
    }
    cmd.kill_on_drop(true);
    cmd.spawn()
        .with_context(|| format!("launch {MCP_SERVER_BIN_NAME}"))
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
    if let Some(token) = options.auth_token.as_ref() {
        if !token.trim().is_empty() {
            cmd.arg("--auth-token").arg(token.trim());
        }
    }
    Ok(cmd)
}

fn resolve_memory_settings() -> Result<McpMemorySettings> {
    let config = crate::config::AppConfig::load_default()
        .context("load config for MCP memory enablement")?;
    let enabled = env_boolish("DOCDEX_ENABLE_MEMORY").unwrap_or(config.memory.enabled);
    let base_url = std::env::var("DOCDEX_EMBEDDING_BASE_URL")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| {
            std::env::var("DOCDEX_OLLAMA_BASE_URL")
                .ok()
                .filter(|v| !v.trim().is_empty())
        })
        .unwrap_or_else(|| config.llm.base_url.clone());
    let model = std::env::var("DOCDEX_EMBEDDING_MODEL")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| config.llm.embedding_model.clone());
    let timeout_ms = std::env::var("DOCDEX_EMBEDDING_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(5000)
        .max(1);
    Ok(McpMemorySettings {
        enabled,
        base_url,
        model,
        timeout_ms,
    })
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

fn env_boolish(key: &str) -> Option<bool> {
    let raw = std::env::var(key).ok()?;
    let trimmed = raw.trim().to_ascii_lowercase();
    match trimmed.as_str() {
        "1" | "true" | "t" | "yes" | "y" | "on" => Some(true),
        "0" | "false" | "f" | "no" | "n" | "off" => Some(false),
        _ => None,
    }
}
