use crate::config::RepoArgs;
use crate::index;
use crate::libs;
use crate::orchestrator::{run_waterfall, MemoryBudget, WaterfallRequest, WebGateConfig};
use crate::tier2::Tier2Config;
use crate::util;
use anyhow::Result;

pub async fn run(repo: RepoArgs, query: String, limit: usize, repo_only: bool) -> Result<()> {
    let repo_root = repo.repo_root();
    let index_config = index::IndexConfig::with_overrides(
        &repo_root,
        repo.state_dir_override(),
        repo.exclude_dir_overrides(),
        repo.exclude_prefix_overrides(),
        repo.symbols_enabled(),
    )?;
    util::init_logging("warn")?;
    let server = index::Indexer::with_config_read_only(repo_root, index_config)?;
    let libs_indexer = if repo_only {
        None
    } else {
        let libs_dir = libs::libs_state_dir_from_index_state_dir(server.state_dir());
        libs::LibsIndexer::open_read_only(libs_dir).ok().flatten()
    };
    let web_gate = WebGateConfig::from_env();
    let request = WaterfallRequest {
        request_id: "cli-query",
        query: &query,
        limit,
        force_web: false,
        indexer: &server,
        libs_indexer: libs_indexer.as_ref(),
        web_gate: &web_gate,
        tier2_config: Tier2Config::enabled(),
        tier2_limiter: None,
        memory: None,
        memory_budget: MemoryBudget::default(),
    };
    let waterfall = run_waterfall(request).await?;
    let tier2_status = waterfall.tier2.status;
    let memory_context = waterfall.memory_context;
    let mut response = waterfall.search_response;
    response.web_discovery = Some(tier2_status);
    response.memory_context = memory_context;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}
