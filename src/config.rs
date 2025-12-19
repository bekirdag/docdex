use std::path::PathBuf;

use clap::{ArgAction, Args};

#[derive(Debug, Args)]
pub struct RepoArgs {
    #[arg(long, default_value = ".", help = "Repository/workspace root to index")]
    pub repo: PathBuf,
    #[arg(
        long,
        env = "DOCDEX_STATE_DIR",
        help = "Override Docdex state root (default: ~/.docdex/state). State is always scoped under <state-root>/repos/<fingerprint>/index to prevent cross-repo mixing. Relative paths are resolved under the repo root."
    )]
    pub state_dir: Option<PathBuf>,
    #[arg(
        long,
        env = "DOCDEX_EXCLUDE_PREFIXES",
        value_delimiter = ',',
        value_parser = non_empty_string,
        help = "Additional relative path prefixes to skip (comma-separated)"
    )]
    pub exclude_prefix: Vec<String>,
    #[arg(
        long,
        env = "DOCDEX_EXCLUDE_DIRS",
        value_delimiter = ',',
        value_parser = non_empty_string,
        help = "Additional directory names to skip anywhere under the repo (comma-separated)"
    )]
    pub exclude_dir: Vec<String>,
    #[arg(
        long,
        env = "DOCDEX_ENABLE_SYMBOL_EXTRACTION",
        value_parser = clap::builder::BoolishValueParser::new(),
        default_value_t = false,
        action = ArgAction::Set,
        help = "Enable best-effort symbol extraction into a per-repo symbols store (symbols.db)"
    )]
    pub enable_symbol_extraction: bool,
}

impl RepoArgs {
    pub fn repo_root(&self) -> PathBuf {
        self.repo
            .canonicalize()
            .unwrap_or_else(|_| self.repo.clone())
    }

    pub fn state_dir_override(&self) -> Option<PathBuf> {
        self.state_dir.clone()
    }

    pub fn exclude_dir_overrides(&self) -> Vec<String> {
        self.exclude_dir.clone()
    }

    pub fn exclude_prefix_overrides(&self) -> Vec<String> {
        self.exclude_prefix.clone()
    }

    pub fn symbols_enabled(&self) -> bool {
        self.enable_symbol_extraction
    }
}

pub fn non_empty_string(value: &str) -> Result<String, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("value cannot be empty".into());
    }
    Ok(trimmed.to_string())
}
