use crate::config::RepoArgs;
use crate::index;
use crate::mcp;
use crate::util;
use crate::web;
use anyhow::Result;

pub async fn run(
    repo: RepoArgs,
    log: String,
    max_results: usize,
    rate_limit_per_min: u32,
    rate_limit_burst: u32,
) -> Result<()> {
    let max_results = std::env::var("DOCDEX_MCP_MAX_RESULTS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(max_results)
        .max(1);
    let repo_root = repo.repo_root();
    let index_config = index::IndexConfig::with_overrides(
        &repo_root,
        repo.state_dir_override(),
        repo.exclude_dir_overrides(),
        repo.exclude_prefix_overrides(),
        repo.symbols_enabled(),
    )?;
    util::init_logging(&log)?;
    let _ = web::scraper::init_global_from_env();
    mcp::serve(
        repo_root,
        index_config,
        max_results,
        rate_limit_per_min,
        rate_limit_burst,
    )
    .await?;
    Ok(())
}
