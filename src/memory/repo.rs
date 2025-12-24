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
    repo_state_root_from_state_dir(state_dir).join("memory.db")
}

pub fn repo_state_root_from_state_dir(state_dir: &Path) -> PathBuf {
    if state_dir.file_name().and_then(|name| name.to_str()) == Some("index") {
        if let Some(parent) = state_dir.parent() {
            return parent.to_path_buf();
        }
    }
    state_dir.to_path_buf()
}

pub fn locks_dir_from_state_dir(state_dir: &Path) -> PathBuf {
    let repo_state_root = repo_state_root_from_state_dir(state_dir);
    if let Some(repos_dir) = repo_state_root.parent() {
        if repos_dir.file_name().and_then(|name| name.to_str()) == Some("repos") {
            if let Some(base_dir) = repos_dir.parent() {
                return base_dir.join("locks");
            }
        }
    }
    repo_state_root.join("locks")
}

pub fn memory_lock_path(state_dir: &Path) -> PathBuf {
    let repo_state_root = repo_state_root_from_state_dir(state_dir);
    let state_key = repo_state_root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("repo");
    locks_dir_from_state_dir(state_dir).join(format!("memory-{state_key}.lock"))
}
