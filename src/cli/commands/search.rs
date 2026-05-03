use crate::cli::commands::query::resolve_memory_state;
use crate::cli::http_client::CliHttpClient;
use crate::config::{self, RepoArgs};
use crate::index;
use crate::libs;
use crate::orchestrator::web::web_context_from_status;
use crate::orchestrator::{
    memory_budget_from_max_answer_tokens, run_waterfall, ProfileBudget, WaterfallPlan,
    WaterfallRequest, WebGateConfig,
};
use crate::search::{
    normalize_score, ContextAssemblyMeta, PrunedHitMeta, SelectedSourceMeta, SnippetPolicy,
};
use crate::tier2::Tier2Config;
use crate::util;
use anyhow::Result;
use reqwest::Method;
use std::sync::Arc;
use uuid::Uuid;

pub(crate) async fn run(
    repo: RepoArgs,
    query: String,
    limit: usize,
    include_libs: bool,
    snippets: bool,
    max_tokens: Option<u64>,
    force_web: bool,
    skip_local_search: bool,
    no_cache: bool,
    max_web_results: Option<usize>,
    llm_filter_local_results: bool,
    async_web: bool,
) -> Result<()> {
    let query = query.trim().to_string();
    if query.is_empty() {
        anyhow::bail!("query must not be empty");
    }
    let limit = limit.max(1);
    if !crate::cli::cli_local_mode() {
        return run_via_http(
            repo,
            query,
            limit,
            include_libs,
            snippets,
            max_tokens,
            force_web,
            skip_local_search,
            no_cache,
            max_web_results,
            llm_filter_local_results,
            async_web,
        )
        .await;
    }
    run_local(
        repo,
        query,
        limit,
        include_libs,
        snippets,
        max_tokens,
        force_web,
        skip_local_search,
        no_cache,
        max_web_results,
        llm_filter_local_results,
        async_web,
    )
    .await
}

async fn run_local(
    repo: RepoArgs,
    query: String,
    limit: usize,
    include_libs: bool,
    snippets: bool,
    max_tokens: Option<u64>,
    force_web: bool,
    skip_local_search: bool,
    no_cache: bool,
    max_web_results: Option<usize>,
    llm_filter_local_results: bool,
    async_web: bool,
) -> Result<()> {
    let repo_root = repo.repo_root();
    let config = config::AppConfig::load_default().ok();
    let repo_encryption = config
        .as_ref()
        .map(|cfg| cfg.repo_encryption.clone())
        .unwrap_or_default();
    if repo_encryption.is_enabled()
        && !repo_encryption.web_discovery_enabled
        && (force_web || skip_local_search)
    {
        anyhow::bail!("web discovery is disabled by repository encryption policy");
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
    let indexer = Arc::new(index::Indexer::with_config_read_only(
        repo_root,
        index_config,
    )?);
    let libs_indexer = if include_libs {
        let libs_dir = libs::libs_state_dir_from_index_state_dir(indexer.state_dir());
        libs::LibsIndexer::open_read_only(libs_dir)
            .ok()
            .flatten()
            .map(Arc::new)
    } else {
        None
    };
    let max_answer_tokens = config
        .as_ref()
        .map(|cfg| cfg.llm.max_answer_tokens)
        .unwrap_or(1024);
    let memory_state =
        resolve_memory_state(config.as_ref(), indexer.state_dir(), indexer.repo_root())?;
    let plan = WaterfallPlan::new(
        WebGateConfig::from_env(),
        if repo_encryption.is_enabled() && !repo_encryption.web_discovery_enabled {
            Tier2Config::default()
        } else {
            Tier2Config::enabled()
        },
        memory_budget_from_max_answer_tokens(max_answer_tokens),
        ProfileBudget::default(),
    );
    let request_id = format!("cli-search-{}", Uuid::new_v4());
    let request = WaterfallRequest {
        request_id: &request_id,
        dag_session_id: None,
        global_state_dir: config
            .as_ref()
            .and_then(|cfg| cfg.core.global_state_dir.clone()),
        query: &query,
        limit,
        diff: None,
        web_limit: max_web_results,
        force_web,
        skip_local_search,
        disable_web_cache: no_cache,
        llm_filter_local_results,
        llm_model: None,
        llm_agent: None,
        indexer: indexer.clone(),
        libs_indexer,
        plan,
        tier2_limiter: None,
        memory: memory_state.as_ref(),
        profile_state: None,
        profile_agent_id: None,
        memory_route: None,
        ranking_surface: crate::search::RankingSurface::Search,
        async_web,
    };
    let waterfall = run_waterfall(request).await?;
    let response = finalize_search_response(
        indexer.as_ref(),
        waterfall.search_response,
        waterfall.tier2.status,
        waterfall.impact_context,
        waterfall.memory_context,
        limit,
        snippets,
        max_tokens,
    )?;
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

fn finalize_search_response(
    indexer: &index::Indexer,
    mut response: crate::search::SearchResponse,
    tier2_status: crate::orchestrator::web::WebDiscoveryStatus,
    impact_context: Option<crate::impact::ImpactContextAssembly>,
    memory_context: Option<crate::orchestrator::MemoryContextAssembly>,
    limit: usize,
    snippets: bool,
    max_tokens: Option<u64>,
) -> Result<crate::search::SearchResponse> {
    let mut hits = std::mem::take(&mut response.hits);
    let query_meta = response.meta.as_ref().and_then(|meta| meta.query.clone());
    let snippet_policy = if snippets {
        SnippetPolicy::Full
    } else {
        SnippetPolicy::SummaryOnly
    };

    let hits_before_pruning = hits.len();
    let mut pruned: Vec<PrunedHitMeta> = Vec::new();
    if let Some(budget) = max_tokens {
        hits.retain(|hit| {
            if hit.token_estimate <= budget {
                true
            } else {
                pruned.push(PrunedHitMeta {
                    doc_id: hit.doc_id.clone(),
                    rel_path: hit.rel_path.clone(),
                    score: hit.score,
                    token_estimate: hit.token_estimate,
                    reason: format!(
                        "token_estimate {}/{} exceeds max_tokens",
                        hit.token_estimate, budget
                    ),
                });
                false
            }
        });
    }

    if !matches!(snippet_policy, SnippetPolicy::Full) {
        for hit in hits.iter_mut() {
            hit.snippet.clear();
        }
    }

    let top_score = hits.first().map(|hit| hit.score);
    let token_estimate_sum_kept = hits.iter().map(|hit| hit.token_estimate).sum();
    let selected_sources = hits
        .iter()
        .map(|hit| SelectedSourceMeta {
            doc_id: hit.doc_id.clone(),
            rel_path: hit.rel_path.clone(),
            score: hit.score,
            token_estimate: hit.token_estimate,
            snippet_origin: hit.snippet_origin.clone(),
            snippet_truncated: hit.snippet_truncated,
        })
        .collect::<Vec<_>>();

    let context_assembly = ContextAssemblyMeta {
        requested_limit: Some(limit),
        effective_limit: limit,
        snippet_policy,
        max_tokens,
        token_budget_mode: "per_hit_token_estimate",
        hits_before_pruning,
        hits_after_pruning: hits.len(),
        token_estimate_sum_kept,
        pruned,
        selected_sources,
    };
    let meta = crate::search::build_search_meta(indexer, query_meta, Some(context_assembly)).ok();
    let top_score_normalized = top_score.map(normalize_score);
    let web_context = web_context_from_status(&tier2_status);
    response.hits = hits;
    response.top_score = top_score;
    response.top_score_camel = top_score;
    response.top_score_normalized = top_score_normalized;
    response.top_score_normalized_camel = top_score_normalized;
    response.web_context = web_context;
    response.web_discovery = Some(tier2_status);
    response.impact_context = impact_context;
    response.memory_context = memory_context;
    response.meta = meta;
    Ok(response)
}

async fn run_via_http(
    repo: RepoArgs,
    query: String,
    limit: usize,
    include_libs: bool,
    snippets: bool,
    max_tokens: Option<u64>,
    force_web: bool,
    skip_local_search: bool,
    no_cache: bool,
    max_web_results: Option<usize>,
    llm_filter_local_results: bool,
    async_web: bool,
) -> Result<()> {
    let repo_root = repo.repo_root();
    let client = CliHttpClient::new()?;
    client.ensure_repo(&repo_root).await?;
    let mut req = client.request(Method::GET, "/search");
    let mut params: Vec<(&str, String)> = vec![
        ("q", query),
        ("limit", limit.to_string()),
        ("include_libs", include_libs.to_string()),
        ("snippets", snippets.to_string()),
        ("async_web", async_web.to_string()),
    ];
    if let Some(max_tokens) = max_tokens {
        params.push(("max_tokens", max_tokens.to_string()));
    }
    if force_web {
        params.push(("force_web", "true".to_string()));
    }
    if skip_local_search {
        params.push(("skip_local_search", "true".to_string()));
    }
    if no_cache {
        params.push(("no_cache", "true".to_string()));
    }
    if let Some(max_web_results) = max_web_results {
        params.push(("max_web_results", max_web_results.to_string()));
    }
    if llm_filter_local_results {
        params.push(("llm_filter_local_results", "true".to_string()));
    }
    req = req.query(&params);
    req = client.with_repo(req, &repo_root)?;
    let resp = req.send().await?;
    let status = resp.status();
    let text = resp.text().await?;
    if !status.is_success() {
        anyhow::bail!("docdexd search failed ({}): {}", status, text);
    }
    let value: serde_json::Value = serde_json::from_str(&text)?;
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
}
