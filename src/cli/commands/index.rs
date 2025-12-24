use crate::config::RepoArgs;
use crate::index;
use crate::util;
use anyhow::Result;
use std::path::PathBuf;
use tracing::info;

pub async fn run_index(repo: RepoArgs) -> Result<()> {
    let repo_root = repo.repo_root();
    let index_config = index::IndexConfig::with_overrides(
        &repo_root,
        repo.state_dir_override(),
        repo.exclude_dir_overrides(),
        repo.exclude_prefix_overrides(),
        repo.symbols_enabled(),
    )?;
    util::init_logging("info")?;
    info!("Rebuilding index for {}", repo_root.display());
    index::Indexer::with_config(repo_root, index_config)?
        .reindex_all()
        .await?;
    Ok(())
}

pub async fn run_ingest(repo: RepoArgs, file: PathBuf) -> Result<()> {
    let repo_root = repo.repo_root();
    let index_config = index::IndexConfig::with_overrides(
        &repo_root,
        repo.state_dir_override(),
        repo.exclude_dir_overrides(),
        repo.exclude_prefix_overrides(),
        repo.symbols_enabled(),
    )?;
    util::init_logging("warn")?;
    let _ = index::Indexer::with_config(repo_root, index_config)?
        .ingest_file(file)
        .await?;
    Ok(())
}
