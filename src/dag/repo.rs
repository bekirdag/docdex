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
