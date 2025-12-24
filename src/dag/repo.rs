use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

/// Ensure the repo-scoped DAG directory exists.
pub fn ensure_repo_state_dir(repo_state_root: &Path) -> Result<()> {
    fs::create_dir_all(repo_state_root)
        .with_context(|| format!("create DAG state dir at {}", repo_state_root.display()))?;
    Ok(())
}

/// Repository-scoped DAG database path.
pub fn dag_db_path(repo_state_root: &Path) -> PathBuf {
    repo_state_root.join("dag.db")
}

pub fn locks_dir_from_repo_state_root(repo_state_root: &Path) -> PathBuf {
    if let Some(repos_dir) = repo_state_root.parent() {
        if repos_dir.file_name().and_then(|name| name.to_str()) == Some("repos") {
            if let Some(base_dir) = repos_dir.parent() {
                return base_dir.join("locks");
            }
        }
    }
    repo_state_root.join("locks")
}

pub fn dag_lock_path(repo_state_root: &Path) -> PathBuf {
    let state_key = repo_state_root
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("repo");
    locks_dir_from_repo_state_root(repo_state_root).join(format!("dag-{state_key}.lock"))
}
