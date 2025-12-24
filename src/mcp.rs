use anyhow::{anyhow, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::process::Command;

const MCP_SERVER_BIN_ENV: &str = "DOCDEX_MCP_SERVER_BIN";
const MCP_SERVER_BIN_NAME: &str = "docdex-mcp-server";

pub async fn serve(
    repo: crate::config::RepoArgs,
    log: String,
    max_results: usize,
    rate_limit_per_min: u32,
    rate_limit_burst: u32,
) -> Result<()> {
    let bin = resolve_mcp_server_binary()?;
    let mut cmd = Command::new(&bin);
    cmd.arg("--repo").arg(repo.repo);
    if let Some(state_dir) = repo.state_dir {
        cmd.arg("--state-dir").arg(state_dir);
    }
    for dir in repo.exclude_dir {
        cmd.arg("--exclude-dir").arg(dir);
    }
    for prefix in repo.exclude_prefix {
        cmd.arg("--exclude-prefix").arg(prefix);
    }
    if repo.enable_symbol_extraction {
        cmd.arg("--enable-symbol-extraction").arg("true");
    }
    cmd.arg("--log").arg(log);
    cmd.arg("--max-results").arg(max_results.to_string());
    cmd.arg("--rate-limit-per-min")
        .arg(rate_limit_per_min.to_string());
    cmd.arg("--rate-limit-burst")
        .arg(rate_limit_burst.to_string());

    cmd.stdin(Stdio::inherit());
    cmd.stdout(Stdio::inherit());
    cmd.stderr(Stdio::inherit());

    let status = cmd
        .status()
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

fn resolve_mcp_server_binary() -> Result<PathBuf> {
    if let Ok(path) = std::env::var(MCP_SERVER_BIN_ENV) {
        if !path.trim().is_empty() {
            return Ok(PathBuf::from(path));
        }
    }

    if let Ok(current) = std::env::current_exe() {
        if let Some(dir) = current.parent() {
            if let Some(candidate) = sibling_binary(dir, MCP_SERVER_BIN_NAME) {
                return Ok(candidate);
            }
        }
    }

    Ok(PathBuf::from(MCP_SERVER_BIN_NAME))
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
