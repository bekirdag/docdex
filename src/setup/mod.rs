use anyhow::{Context, Result};
use serde::Serialize;
use std::io::{self, IsTerminal};
use std::path::PathBuf;

use crate::cli::SetupArgs;
use crate::setup::state::StepSnapshot;

mod config;
mod hardware;
mod model;
pub(crate) mod ollama;
mod state;
mod state_store;
#[cfg(test)]
mod test_support;
mod ui;

#[derive(Debug, Clone)]
pub struct SetupOptions {
    pub non_interactive: bool,
    pub json: bool,
    pub force: bool,
    pub ollama_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SetupSummary {
    pub status: String,
    pub message: String,
    pub models_installed: Vec<String>,
    pub default_model: Option<String>,
    pub timestamp_ms: u128,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub steps: Vec<StepSnapshot>,
}

pub(crate) fn run(args: SetupArgs) -> Result<()> {
    let options = SetupOptions {
        non_interactive: args.non_interactive,
        json: args.json,
        force: args.force,
        ollama_path: args.ollama_path,
    };
    let summary = run_with_options(&options)?;
    if options.json {
        let payload = serde_json::to_string(&summary).context("serialize setup summary")?;
        println!("{payload}");
    } else {
        println!("{}", summary.message);
    }
    Ok(())
}

fn run_with_options(options: &SetupOptions) -> Result<SetupSummary> {
    if env_bool("DOCDEX_SETUP_SKIP") {
        return Ok(SetupSummary {
            status: "skipped".to_string(),
            message: "Setup skipped by DOCDEX_SETUP_SKIP.".to_string(),
            models_installed: Vec::new(),
            default_model: None,
            timestamp_ms: now_ms(),
            error: None,
            steps: Vec::new(),
        });
    }

    if options.non_interactive {
        return Ok(SetupSummary {
            status: "skipped".to_string(),
            message: "Run `docdex setup` in a terminal to install Ollama and models.".to_string(),
            models_installed: Vec::new(),
            default_model: None,
            timestamp_ms: now_ms(),
            error: None,
            steps: Vec::new(),
        });
    }

    let force = options.force || env_bool("DOCDEX_SETUP_FORCE");
    if should_skip_due_to_status(force)? {
        if let Some(status) = state_store::read_status()? {
            match status.status {
                state_store::SetupStatus::Complete => {
                    return Ok(SetupSummary {
                        status: "complete".to_string(),
                        message: "Setup already completed.".to_string(),
                        models_installed: status.models_installed.clone(),
                        default_model: status.default_model.clone(),
                        timestamp_ms: status.timestamp_ms,
                        error: status.error.clone(),
                        steps: Vec::new(),
                    });
                }
                state_store::SetupStatus::Deferred => {
                    return Ok(SetupSummary {
                        status: "deferred".to_string(),
                        message: status.message.clone(),
                        models_installed: status.models_installed.clone(),
                        default_model: status.default_model.clone(),
                        timestamp_ms: status.timestamp_ms,
                        error: status.error.clone(),
                        steps: Vec::new(),
                    });
                }
                state_store::SetupStatus::Failed => {}
            }
        }
    }

    let interactive = io::stdin().is_terminal() && io::stdout().is_terminal();
    if !interactive {
        return Ok(SetupSummary {
            status: "skipped".to_string(),
            message: "No interactive terminal detected. Run `docdex setup` from a terminal."
                .to_string(),
            models_installed: Vec::new(),
            default_model: None,
            timestamp_ms: now_ms(),
            error: None,
            steps: Vec::new(),
        });
    }

    let context = state::SetupContext::new(options.ollama_path.clone())?;
    let summary = ui::run_wizard(context)?;
    if summary.status == "complete" {
        let _ = state_store::clear_pending();
        let _ = state_store::clear_failed();
    } else if summary.status == "failed" {
        let _ = state_store::write_failed(&summary.message);
    }
    state_store::write_status(&summary)?;
    Ok(summary)
}

fn env_bool(key: &str) -> bool {
    std::env::var(key)
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "y" | "on"
            )
        })
        .unwrap_or(false)
}

fn should_skip_due_to_status(force: bool) -> Result<bool> {
    if force {
        return Ok(false);
    }
    if let Some(status) = state_store::read_status()? {
        if matches!(
            status.status,
            state_store::SetupStatus::Complete | state_store::SetupStatus::Deferred
        ) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup::test_support::ENV_LOCK;
    use tempfile::TempDir;

    #[test]
    fn force_ignores_completed_status() -> Result<()> {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = TempDir::new()?;
        std::env::set_var("DOCDEX_STATE_DIR", dir.path());
        let summary = SetupSummary {
            status: "complete".to_string(),
            message: "ok".to_string(),
            models_installed: Vec::new(),
            default_model: None,
            timestamp_ms: now_ms(),
            error: None,
            steps: Vec::new(),
        };
        state_store::write_status(&summary)?;
        assert!(should_skip_due_to_status(false)?);
        assert!(!should_skip_due_to_status(true)?);
        std::env::remove_var("DOCDEX_STATE_DIR");
        Ok(())
    }

    #[test]
    fn deferred_status_skips_without_force() -> Result<()> {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = TempDir::new()?;
        std::env::set_var("DOCDEX_STATE_DIR", dir.path());
        let summary = SetupSummary {
            status: "deferred".to_string(),
            message: "later".to_string(),
            models_installed: Vec::new(),
            default_model: None,
            timestamp_ms: now_ms(),
            error: None,
            steps: Vec::new(),
        };
        state_store::write_status(&summary)?;
        assert!(should_skip_due_to_status(false)?);
        std::env::remove_var("DOCDEX_STATE_DIR");
        Ok(())
    }
}
