use anyhow::Result;
use std::path::{Path, PathBuf};

/// Ensure the repo-scoped state directory exists and is writable.
pub fn ensure_repo_state_dir(repo_state_root: &Path) -> Result<()> {
    crate::state_layout::ensure_repo_state_root(repo_state_root)
}

/// Repository-scoped memory storage path.
pub fn memory_path(state_dir: &Path) -> PathBuf {
    repo_state_root_from_state_dir(state_dir).join("memory.db")
}

pub fn repo_state_root_from_state_dir(state_dir: &Path) -> PathBuf {
    crate::state_layout::repo_state_root_from_state_dir(state_dir)
}

pub fn locks_dir_from_state_dir(state_dir: &Path) -> PathBuf {
    crate::state_layout::locks_dir_from_state_dir(state_dir)
}

pub fn memory_lock_path(state_dir: &Path) -> PathBuf {
    let repo_state_root = repo_state_root_from_state_dir(state_dir);
    let state_key = repo_state_root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("repo");
    locks_dir_from_state_dir(state_dir).join(format!("memory-{state_key}.lock"))
}
