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
pub fn memory_path(state_dir: &Path) -> PathBuf {
    if state_dir.file_name().and_then(|name| name.to_str()) == Some("index") {
        if let Some(parent) = state_dir.parent() {
            return parent.join("memory.db");
        }
    }
    state_dir.join("memory.db")
}
