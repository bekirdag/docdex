use crate::config;
use crate::error::{
    repo_resolution_details, AppError, ERR_MISSING_DEPENDENCY, ERR_MISSING_REPO_PATH,
};
use anyhow::{Context, Result};
use serde_json::json;
use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const TUI_BIN_ENV: &str = "DOCDEX_TUI_BIN";
const TUI_BIN_NAME: &str = "docdex-tui";

pub fn run(repo: Option<PathBuf>) -> Result<()> {
    let bin = resolve_tui_binary()?;
    let config = config::AppConfig::load_default()?;
    let mut cmd = Command::new(&bin);
    if let Some(repo_root) = repo {
        let repo_root = repo_root
            .canonicalize()
            .unwrap_or_else(|_| repo_root.clone());
        if !repo_root.exists() {
            let details = repo_resolution_details(
                repo_root.to_string_lossy().replace('\\', "/"),
                None,
                None,
                vec![
                    "Verify the repo path exists on disk.".to_string(),
                    "Pass the correct path with --repo.".to_string(),
                ],
            );
            return Err(AppError::new(ERR_MISSING_REPO_PATH, "repo path not found")
                .with_details(details)
                .into());
        }
        cmd.arg("--repo").arg(repo_root);
    }

    if !config.features.tui_overlay {
        cmd.env("DOCDEX_TUI_OVERLAY", "0");
    }

    cmd.stdin(Stdio::inherit());
    cmd.stdout(Stdio::inherit());
    cmd.stderr(Stdio::inherit());

    let status = cmd
        .status()
        .with_context(|| format!("launch {TUI_BIN_NAME}"));
    let status = match status {
        Ok(status) => status,
        Err(err)
            if err
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
        {
            return Err(AppError::new(
                ERR_MISSING_DEPENDENCY,
                format!("{TUI_BIN_NAME} binary not found"),
            )
            .with_details(json!({
                "binary": bin.to_string_lossy(),
                "recoverySteps": [
                    format!("Install {TUI_BIN_NAME} alongside docdexd."),
                    format!("Set {TUI_BIN_ENV} to the full path of the TUI binary.")
                ]
            }))
            .into());
        }
        Err(err) => return Err(err.into()),
    };
    if status.success() {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "{TUI_BIN_NAME} exited with status {status}"
        ))
    }
}

fn resolve_tui_binary() -> Result<PathBuf> {
    if let Ok(path) = env::var(TUI_BIN_ENV) {
        if !path.trim().is_empty() {
            return Ok(PathBuf::from(path));
        }
    }

    if let Ok(current) = env::current_exe() {
        if let Some(dir) = current.parent() {
            if let Some(candidate) = sibling_binary(dir, TUI_BIN_NAME) {
                return Ok(candidate);
            }
        }
    }

    Ok(PathBuf::from(TUI_BIN_NAME))
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
