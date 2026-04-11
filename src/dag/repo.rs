use anyhow::Result;
use std::path::{Path, PathBuf};

/// Ensure the repo-scoped DAG directory exists.
pub fn ensure_repo_state_dir(repo_state_root: &Path) -> Result<()> {
    crate::state_layout::ensure_repo_state_root(repo_state_root)
}

/// Repository-scoped DAG database path.
pub fn dag_db_path(repo_state_root: &Path) -> PathBuf {
    repo_state_root.join("dag.db")
}

pub fn locks_dir_from_repo_state_root(repo_state_root: &Path) -> PathBuf {
    crate::state_layout::locks_dir_from_repo_state_root(repo_state_root)
}

pub fn dag_lock_path(repo_state_root: &Path) -> PathBuf {
    let state_key = repo_state_root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("repo");
    locks_dir_from_repo_state_root(repo_state_root).join(format!("dag-{state_key}.lock"))
}
