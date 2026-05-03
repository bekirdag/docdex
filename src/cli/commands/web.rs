use crate::cli::commands::query;
use crate::cli::http_client::CliHttpClient;
use crate::config::RepoArgs;
use crate::dag::logging as dag_logging;
use crate::error::{
    AppError, ERR_INVALID_ARGUMENT, ERR_MISSING_DEPENDENCY, ERR_REPO_ENCRYPTION_UNSUPPORTED,
};
use crate::index;
use crate::libs;
use crate::memory::repo_state_root_from_state_dir;
use crate::orchestrator::{
    memory_budget_from_max_answer_tokens, run_waterfall, ProfileBudget, WaterfallPlan,
    WaterfallRequest, WebGateConfig,
};
use crate::tier2::Tier2Config;
use crate::util;
use crate::web;
use crate::web::readability::extract_readable_text;
use crate::web::scraper::ScraperEngine;
use crate::web::status::fetch_status;
use anyhow::Result;
use reqwest::Method;
use serde_json::json;
use serde_json::Value;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;
use uuid::Uuid;

pub async fn run_search(query: String, limit: usize) -> Result<()> {
    if !crate::cli::cli_local_mode() {
        match run_search_via_http(&query, limit).await {
            Ok(()) => return Ok(()),
            Err(err) => {
                if !should_fallback_to_local(&err) {
                    return Err(err);
                }
                eprintln!(
                    "docdexd web-search: http endpoint unavailable; falling back to local ({err})"
                );
            }
        }
    }
    util::init_logging("warn")?;
    let mut config = web::WebConfig::from_env();
    config.enabled = true;
    let discovery = web::ddg::DdgDiscovery::new(config)?;
    let response = discovery.discover(&query, limit).await?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

pub async fn run_fetch(url: String) -> Result<()> {
    if !crate::cli::cli_local_mode() {
        match run_fetch_via_http(&url).await {
            Ok(()) => return Ok(()),
            Err(err) => {
                if !should_fallback_to_local(&err) {
                    return Err(err);
                }
                eprintln!(
                    "docdexd web-fetch: http endpoint unavailable; falling back to local ({err})"
                );
            }
        }
    }
    util::init_logging("warn")?;
    let config = web::WebConfig::from_env();
    let url = Url::parse(url.trim())
        .map_err(|err| AppError::new(ERR_INVALID_ARGUMENT, format!("invalid url: {err}")))?;
    let layout = web::cache::cache_layout_from_config();
    if let Some(layout) = layout.as_ref() {
        if let Ok(Some(payload)) =
            web::cache::read_cache_entry_with_ttl(layout, url.as_str(), config.cache_ttl)
        {
            if let Ok(entry) = serde_json::from_slice::<WebFetchCacheEntry>(&payload) {
                println!("{}", serde_json::to_string_pretty(&entry)?);
                return Ok(());
            }
            if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&payload) {
                println!("{}", serde_json::to_string_pretty(&value)?);
                return Ok(());
            }
        }
    }
    let scraper = ScraperEngine::from_web_config(&config).map_err(|err| {
        let message = err.to_string();
        AppError::new(ERR_MISSING_DEPENDENCY, message)
    })?;
    web::fetch::enforce_domain_delay(&url, config.fetch_delay).await;
    let status_probe = fetch_status(&url, &config.user_agent, config.request_timeout).await;
    let fetch_result = scraper.fetch_dom(&url).await?;
    let status = fetch_result.status.or(status_probe);
    let body = extract_readable_text(&fetch_result.html, &url).unwrap_or_else(|| {
        let cleaned = ammonia::Builder::default()
            .tags(std::collections::HashSet::new())
            .clean(&fetch_result.html)
            .to_string();
        cleaned.split_whitespace().collect::<Vec<_>>().join(" ")
    });
    let entry = WebFetchCacheEntry {
        url: url.as_str().to_string(),
        status,
        fetched_at_epoch_ms: now_epoch_ms(),
        content: body,
        code_blocks: Vec::new(),
    };
    if let Some(layout) = layout.as_ref() {
        if config.cache_ttl.as_secs() > 0 {
            if let Ok(serialized) = serde_json::to_vec(&entry) {
                let _ = web::cache::write_cache_entry(layout, url.as_str(), &serialized);
            }
        }
    }
    println!("{}", serde_json::to_string_pretty(&entry)?);
    Ok(())
}

#[derive(serde::Serialize, serde::Deserialize)]
struct WebFetchCacheEntry {
    url: String,
    status: Option<u16>,
    fetched_at_epoch_ms: u128,
    content: String,
    #[serde(default)]
    code_blocks: Vec<String>,
}

fn now_epoch_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
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
        return query::stream_via_http(
            &repo_root,
            &query,
            None,
            None,
            None,
            limit,
            None,
            true,
            !repo_only,
            false,
            false,
            false,
            false,
            None,
            None,
            None,
            Vec::new(),
        )
        .await;
    }
    if !crate::cli::cli_local_mode() {
        let payload = query::search_via_http(
            &repo_root,
            &query,
            limit,
            !repo_only,
            true,
            false,
            false,
            false,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Vec::new(),
        )
        .await?;
        println!("{}", serde_json::to_string_pretty(&payload)?);
        return Ok(());
    }
    let config = crate::config::AppConfig::load_default().ok();
    let repo_encryption = config
        .as_ref()
        .map(|cfg| cfg.repo_encryption.clone())
        .unwrap_or_default();
    if repo_encryption.is_enabled() && !repo_encryption.web_discovery_enabled {
        return Err(AppError::new(
            ERR_REPO_ENCRYPTION_UNSUPPORTED,
            "web discovery is disabled by repository encryption policy",
        )
        .into());
    }
    let index_config = index::IndexConfig::with_overrides(
        &repo_root,
        repo.state_dir_override(),
        repo.exclude_dir_overrides(),
        repo.exclude_prefix_overrides(),
        repo.symbols_enabled(),
    )?
    .with_repo_encryption(repo_encryption.clone());
    util::init_logging("warn")?;
    let server = Arc::new(index::Indexer::with_config_read_only(
        repo_root,
        index_config,
    )?);
    let libs_indexer = if repo_only {
        None
    } else {
        let libs_dir = libs::libs_state_dir_from_index_state_dir(server.state_dir());
        libs::LibsIndexer::open_read_only(libs_dir)
            .ok()
            .flatten()
            .map(Arc::new)
    };
    let web_gate = WebGateConfig::from_env();
    let max_answer_tokens = config
        .as_ref()
        .map(|cfg| cfg.llm.max_answer_tokens)
        .unwrap_or(1024);
    let memory_state =
        query::resolve_memory_state(config.as_ref(), server.state_dir(), server.repo_root())?;
    let plan = WaterfallPlan::new(
        web_gate,
        Tier2Config::enabled(),
        memory_budget_from_max_answer_tokens(max_answer_tokens),
        ProfileBudget::default(),
    );
    let request_id = format!("cli-web-rag-{}", Uuid::new_v4());
    let repo_state_root = repo_state_root_from_state_dir(server.state_dir());
    let _ = dag_logging::log_node(
        &repo_state_root,
        &request_id,
        "UserRequest",
        &json!({
            "query": query.as_str(),
            "limit": limit,
            "force_web": true,
            "repo_only": repo_only,
        }),
    );
    let request = WaterfallRequest {
        request_id: &request_id,
        dag_session_id: None,
        global_state_dir: config
            .as_ref()
            .and_then(|cfg| cfg.core.global_state_dir.clone()),
        query: &query,
        limit,
        diff: None,
        web_limit: None,
        force_web: true,
        skip_local_search: false,
        disable_web_cache: false,
        llm_filter_local_results: false,
        llm_model: None,
        llm_agent: None,
        indexer: server.clone(),
        libs_indexer: libs_indexer.clone(),
        plan,
        tier2_limiter: None,
        memory: memory_state.as_ref(),
        profile_state: None,
        profile_agent_id: None,
        memory_route: None,
        ranking_surface: crate::search::RankingSurface::Search,
        async_web: false,
    };
    let waterfall = run_waterfall(request).await?;
    let _ = dag_logging::log_node(
        &repo_state_root,
        &request_id,
        "Decision",
        &json!({
            "hits": waterfall.search_response.hits.len(),
            "top_score": waterfall.search_response.top_score,
            "web_status": waterfall.tier2.status.status,
        }),
    );
    if stream {
        query::stream_completion(&query, &waterfall.search_response.hits)?;
        return Ok(());
    }
    let tier2_status = waterfall.tier2.status;
    let memory_context = waterfall.memory_context;
    let impact_context = waterfall.impact_context;
    let mut response = waterfall.search_response;
    response.web_discovery = Some(tier2_status);
    response.memory_context = memory_context;
    response.impact_context = impact_context;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

pub async fn run_cache_flush() -> Result<()> {
    if !crate::cli::cli_local_mode() {
        match run_cache_flush_via_http().await {
            Ok(()) => return Ok(()),
            Err(err) => {
                if !should_fallback_to_local(&err) {
                    return Err(err);
                }
                eprintln!(
                    "docdexd web-cache-flush: http endpoint unavailable; falling back to local ({err})"
                );
            }
        }
    }
    let Some(layout) = web::cache::cache_layout_from_config() else {
        println!("web cache is not configured");
        return Ok(());
    };
    let dir = web::cache::web_cache_dir(&layout);
    if dir.exists() {
        std::fs::remove_dir_all(&dir)?;
    }
    std::fs::create_dir_all(&dir)?;
    println!("web cache cleared: {}", dir.display());
    Ok(())
}

async fn run_search_via_http(query: &str, limit: usize) -> Result<()> {
    let client = CliHttpClient::new()?;
    let payload = serde_json::json!({
        "query": query,
        "limit": limit,
    });
    let resp = client
        .request(Method::POST, "/v1/web/search")
        .json(&payload)
        .send()
        .await?;
    emit_json_or_error(resp, "web search").await?;
    Ok(())
}

async fn run_fetch_via_http(url: &str) -> Result<()> {
    let client = CliHttpClient::new()?;
    let payload = serde_json::json!({ "url": url });
    let resp = client
        .request(Method::POST, "/v1/web/fetch")
        .json(&payload)
        .send()
        .await?;
    emit_json_or_error(resp, "web fetch").await?;
    Ok(())
}

async fn run_cache_flush_via_http() -> Result<()> {
    let client = CliHttpClient::new()?;
    let resp = client
        .request(Method::POST, "/v1/web/cache/flush")
        .send()
        .await?;
    emit_json_or_error(resp, "web cache flush").await?;
    Ok(())
}

async fn emit_json_or_error(resp: reqwest::Response, label: &str) -> Result<()> {
    let status = resp.status();
    let text = resp.text().await?;
    if !status.is_success() {
        anyhow::bail!("docdexd {} failed ({}): {}", label, status, text);
    }
    let value: Value = serde_json::from_str(&text)?;
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}

fn should_fallback_to_local(err: &anyhow::Error) -> bool {
    if let Some(reqwest_err) = err.downcast_ref::<reqwest::Error>() {
        return reqwest_err.is_connect() || reqwest_err.is_timeout();
    }
    let message = err.to_string().to_lowercase();
    message.contains("error sending request")
        || message.contains("connection refused")
        || message.contains("connection error")
}
