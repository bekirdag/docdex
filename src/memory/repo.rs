use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

/// Ensure the repo-scoped state directory exists and is writable.
pub fn ensure_repo_state_dir(repo_state_root: &Path) -> Result<()> {
    fs::create_dir_all(repo_state_root)
        .with_context(|| format!("create repo state dir at {}", repo_state_root.display()))?;
    Ok(())
}

/// Repository-scoped memory storage path.
pub fn memory_path(repo_state_root: &Path) -> PathBuf {
    repo_state_root.join("memory.jsonl")
}
