use crate::config::RepoArgs;
use crate::mcp;
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
    mcp::serve(
        repo,
        log,
        max_results,
        rate_limit_per_min,
        rate_limit_burst,
    )
    .await?;
    Ok(())
}
