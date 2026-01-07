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

const AGENTS_INSTRUCTIONS: &str = include_str!("../../npm/assets/agents.md");

#[derive(Debug, Clone)]
pub struct SetupOptions {
    pub non_interactive: bool,
    pub json: bool,
    pub force: bool,
    pub auto: bool,
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
        auto: args.auto,
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
            message: "Run `docdex setup` in a terminal to install Ollama, Playwright, and models."
                .to_string(),
            models_installed: Vec::new(),
            default_model: None,
            timestamp_ms: now_ms(),
            error: None,
            steps: Vec::new(),
        });
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
    if let Err(err) = write_agent_instructions() {
        eprintln!("[docdex] failed to write agents instructions: {err}");
    }
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

fn now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

fn write_agent_instructions() -> Result<()> {
    let state_base = crate::state_paths::default_state_base_dir()?;
    let root = state_base
        .parent()
        .ok_or_else(|| anyhow::anyhow!("resolve docdex state root"))?;
    crate::state_layout::ensure_state_dir_secure(root)?;
    let target = root.join("agents.md");
    let existing = std::fs::read_to_string(&target).ok();
    if existing.as_deref() == Some(AGENTS_INSTRUCTIONS) {
        return Ok(());
    }
    std::fs::write(&target, AGENTS_INSTRUCTIONS).context("write agents instructions")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup::test_support::ENV_LOCK;
    use tempfile::TempDir;

    #[test]
    fn setup_status_roundtrip_for_summary() -> Result<()> {
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
        let status_path = dir.path().join("setup_status.json");
        let raw = std::fs::read_to_string(&status_path)?;
        let read: state_store::SetupStatusRecord = serde_json::from_str(&raw)?;
        assert_eq!(read.status, state_store::SetupStatus::Complete);
        std::env::remove_var("DOCDEX_STATE_DIR");
        Ok(())
    }
}
