use crate::config::RepoArgs;
use crate::error::{AppError, ERR_INVALID_ARGUMENT};
use crate::index;
use crate::libs;
use crate::cli::commands::query;
use crate::orchestrator::{run_waterfall, MemoryBudget, WaterfallPlan, WaterfallRequest, WebGateConfig};
use crate::tier2::Tier2Config;
use crate::util;
use crate::web;
use anyhow::Context;
use anyhow::Result;
use serde_json::json;
use url::Url;

pub async fn run_search(query: String, limit: usize) -> Result<()> {
    util::init_logging("warn")?;
    let config = web::WebConfig::from_env();
    let discovery = web::ddg::DdgDiscovery::new(config)?;
    let response = discovery.discover(&query, limit).await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

pub async fn run_fetch(url: String) -> Result<()> {
    util::init_logging("warn")?;
    let config = web::WebConfig::from_env();
    let url = Url::parse(url.trim()).map_err(|err| {
        AppError::new(ERR_INVALID_ARGUMENT, format!("invalid url: {err}"))
    })?;
    let layout = web::cache::cache_layout_from_config();
    if let Some(layout) = layout.as_ref() {
        if let Ok(Some(payload)) =
            web::cache::read_cache_entry_with_ttl(layout, url.as_str(), config.cache_ttl)
        {
            if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&payload) {
                println!("{}", serde_json::to_string_pretty(&value)?);
                return Ok(());
            }
        }
    }
    let client = reqwest::Client::builder()
        .user_agent(config.user_agent)
        .timeout(config.request_timeout)
        .build()
        .context("build web fetch client")?;
    web::fetch::enforce_domain_delay(&url, config.fetch_delay).await;
    let resp = client.get(url.clone()).send().await?;
    let status = resp.status();
    let body = resp.text().await?;
    let payload = json!({
        "url": url.as_str(),
        "status": status.as_u16(),
        "body": body,
    });
    if let Some(layout) = layout.as_ref() {
        if config.cache_ttl.as_secs() > 0 {
            if let Ok(serialized) = serde_json::to_vec(&payload) {
                let _ = web::cache::write_cache_entry(layout, url.as_str(), &serialized);
            }
        }
    }
    println!("{}", serde_json::to_string_pretty(&payload)?);
    Ok(())
}

pub async fn run_rag(
    repo: RepoArgs,
    query: String,
    limit: usize,
    repo_only: bool,
    stream: bool,
) -> Result<()> {
    let repo_root = repo.repo_root();
    if stream {
        return query::stream_via_http(&repo_root, &query, limit, true, !repo_only).await;
    }
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
    let plan = WaterfallPlan::new(web_gate, Tier2Config::enabled(), MemoryBudget::default());
    let request = WaterfallRequest {
        request_id: "cli-web-rag",
        query: &query,
        limit,
        force_web: true,
        indexer: &server,
        libs_indexer: libs_indexer.as_ref(),
        plan,
        tier2_limiter: None,
        memory: None,
    };
    let waterfall = run_waterfall(request).await?;
    if stream {
        query::stream_completion(&query, &waterfall.search_response.hits)?;
        return Ok(());
    }
    let tier2_status = waterfall.tier2.status;
    let memory_context = waterfall.memory_context;
    let mut response = waterfall.search_response;
    response.web_discovery = Some(tier2_status);
    response.memory_context = memory_context;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}
