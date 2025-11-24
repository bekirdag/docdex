use std::path::PathBuf;

use clap::Args;

#[derive(Debug, Args)]
pub struct RepoArgs {
    #[arg(long, default_value = ".", help = "Repository/workspace root to index")]
    pub repo: PathBuf,
    #[arg(
        long,
        env = "DOCDEX_STATE_DIR",
        help = "Override index storage directory (default: <repo>/.docdex/index; falls back to legacy .gpt-creator/docdex/index if present)"
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
}

pub fn non_empty_string(value: &str) -> Result<String, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("value cannot be empty".into());
    }
    Ok(trimmed.to_string())
}
