use crate::config::{self, RepoArgs};
use crate::index;
use crate::indexer;
use crate::util;
use anyhow::Result;
use std::path::PathBuf;
use tracing::info;

pub async fn run_index(repo: RepoArgs, libs_sources: Option<PathBuf>) -> Result<()> {
    let _ = config::AppConfig::load_default()?;
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
    let options = match libs_sources.as_ref() {
        Some(path) => indexer::IndexingOptions::from_sources_path(path)?,
        None => indexer::IndexingOptions::none(),
    };
    let _ = indexer::reindex_repo(repo_root, index_config, options).await?;
    Ok(())
}

pub async fn run_ingest(repo: RepoArgs, file: PathBuf) -> Result<()> {
    let _ = config::AppConfig::load_default()?;
    let repo_root = repo.repo_root();
    let index_config = index::IndexConfig::with_overrides(
        &repo_root,
        repo.state_dir_override(),
        repo.exclude_dir_overrides(),
        repo.exclude_prefix_overrides(),
        repo.symbols_enabled(),
    )?;
    util::init_logging("warn")?;
    let _ = indexer::ingest_file(repo_root, index_config, file).await?;
    Ok(())
}
