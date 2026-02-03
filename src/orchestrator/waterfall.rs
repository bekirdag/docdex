use anyhow::{anyhow, Context, Result};
use serde::Serialize;
use serde_json::json;
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use tokio::task;
use tracing::{info, warn};

use super::budget::{MemoryBudget, ProfileBudget};
use super::plan::WaterfallPlan;
use crate::dag::logging as dag_logging;
use crate::diff;
use crate::error::{
    AppError, ERR_EMBEDDING_FAILED, ERR_EMBEDDING_MODEL_NOT_FOUND, ERR_EMBEDDING_TIMEOUT,
};
use crate::impact::{
    assemble_impact_context, expand_impact_from_diff_files, ImpactContextAssembly,
    ImpactQueryControlsRaw,
};
use crate::index::{Hit, Indexer};
use crate::libs::LibsIndexer;
use crate::memory::filter_memory_candidates_by_repo;
use crate::memory::{
    prune_and_truncate_memory_context, repo_state_root_from_state_dir, MemoryContextItem,
    MemoryContextPruneTrace,
};
use crate::metrics;
use crate::orchestrator::web::{
    build_gate_meta, detect_query_intent, evaluate_gate_status, filter_local_hits_with_llm,
    local_match_ratio, run_web_research, QueryIntent, WebDiscoveryStatus, WebDiscoveryStatusCode,
    WebGateConfig, WebResearchResponse,
};
use crate::profiles::ops::{
    prune_and_truncate_profile_context, ProfileCandidate, ProfileContextItem,
    ProfileContextPruneTrace,
};
use crate::search::{MemoryState, ProfileState, RankingSurface, SearchResponse};
use crate::tier2::{self, Tier2Limiter, Tier2Unavailable};
use std::env;

/// Description of the waterfall request.
#[derive(Clone)]
pub struct WaterfallRequest<'a> {
    pub request_id: &'a str,
    pub dag_session_id: Option<&'a str>,
    pub query: &'a str,
    pub limit: usize,
    pub diff: Option<crate::diff::DiffRequest>,
    pub web_limit: Option<usize>,
    pub force_web: bool,
    pub skip_local_search: bool,
    pub disable_web_cache: bool,
    pub llm_filter_local_results: bool,
    pub llm_model: Option<&'a str>,
    pub llm_agent: Option<&'a str>,
    pub indexer: Arc<Indexer>,
    pub libs_indexer: Option<Arc<LibsIndexer>>,
    pub plan: WaterfallPlan,
    pub tier2_limiter: Option<&'a Tier2Limiter>,
    pub memory: Option<&'a MemoryState>,
    pub profile_state: Option<&'a ProfileState>,
    pub profile_agent_id: Option<&'a str>,
    pub ranking_surface: RankingSurface,
    pub async_web: bool,
}

/// Result of running the waterfall through all tiers.
pub struct WaterfallResult {
    pub search_response: SearchResponse,
    pub tier2: Tier2Outcome,
    pub impact_context: Option<ImpactContextAssembly>,
    pub memory_context: Option<MemoryContextAssembly>,
    pub profile_context: Option<ProfileContextAssembly>,
}

/// Tier-2 outcome: optional Tier-2 response plus discovery status and guardrail details.
pub struct Tier2Outcome {
    pub response: Option<WebResearchResponse>,
    pub status: WebDiscoveryStatus,
    pub tier2_unavailable: Option<Tier2Unavailable>,
}

/// Memory context assembly returned from Tier 3.
#[derive(Clone, Debug, Serialize)]
pub struct MemoryContextAssembly {
    pub items: Vec<MemoryContextItem>,
    pub prune_trace: MemoryContextPruneTrace,
}

/// Profile context assembly returned from Tier 0.
#[derive(Clone, Debug, Serialize)]
pub struct ProfileContextAssembly {
    pub items: Vec<ProfileContextItem>,
    pub prune_trace: ProfileContextPruneTrace,
}

/// Symbol context assembly returned alongside local search hits.
#[derive(Clone, Debug, Serialize)]
pub struct SymbolContextAssembly {
    pub items: Vec<SymbolContextItem>,
    pub prune_trace: SymbolContextPruneTrace,
}

#[derive(Clone, Debug, Serialize)]
pub struct SymbolContextItem {
    pub file: String,
    pub symbols: Vec<SymbolContextSymbol>,
    pub truncated: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct SymbolContextSymbol {
    pub name: String,
    pub kind: String,
    pub line_start: u32,
    pub line_end: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SymbolContextPruneTrace {
    pub candidate_files: usize,
    pub kept_files: usize,
    pub max_files: usize,
    pub max_symbols_per_file: usize,
    pub truncated_files: usize,
}

const DEFAULT_DIFF_MAX_EDGES: usize = 200;
const DEFAULT_DIFF_MAX_DEPTH: usize = 1;

/// Execute the waterfall (Tier 1 → Tier 2 → Tier 3) for a single query.
pub async fn run_waterfall(request: WaterfallRequest<'_>) -> Result<WaterfallResult> {
    let intent = detect_query_intent(request.query);
    let mut search_response = if request.skip_local_search {
        SearchResponse {
            hits: Vec::new(),
            top_score: None,
            top_score_camel: None,
            top_score_normalized: None,
            top_score_normalized_camel: None,
            web_context: None,
            web_discovery: None,
            impact_context: None,
            profile_context: None,
            memory_context: None,
            symbols_context: None,
            meta: None,
        }
    } else {
        crate::search::run_query(
            request.indexer.as_ref(),
            request.libs_indexer.as_deref(),
            request.query,
            request.limit,
            request.ranking_surface,
        )
        .await?
    };
    let repo_state_root = repo_state_root_from_state_dir(request.indexer.state_dir());
    let dag_session_id = request.dag_session_id.unwrap_or(request.request_id);
    let impact_context = collect_impact_context(
        request.indexer.repo_root(),
        request.indexer.state_dir(),
        request.diff.as_ref(),
        request.request_id,
    )?;

    let (top_score, top_score_normalized, local_match_ratio) = if request.skip_local_search {
        (None, None, None)
    } else {
        search_response.hits = filter_local_hits_with_llm(
            request.query,
            intent,
            search_response.hits,
            search_response.top_score_normalized,
            request.llm_filter_local_results,
            request.llm_model,
            request.llm_agent,
        )
        .await;
        if request.ranking_surface == RankingSurface::Chat {
            crate::search::apply_ranking_deltas(
                request.indexer.as_ref(),
                &mut search_response.hits,
                request.query,
                request.limit,
                request.ranking_surface,
            )?;
        }
        let mut top_score = search_response.hits.first().map(|hit| hit.score);
        let mut top_score_normalized = top_score.map(crate::search::normalize_score);
        let mut local_match_ratio = local_match_ratio(request.query, &search_response.hits);
        if matches!(intent, QueryIntent::Code) && local_match_ratio == Some(0.0) {
            search_response.hits.clear();
            top_score = None;
            top_score_normalized = None;
            local_match_ratio = Some(0.0);
        }
        search_response.top_score = top_score;
        search_response.top_score_camel = top_score;
        search_response.top_score_normalized = top_score_normalized;
        search_response.top_score_normalized_camel = top_score_normalized;
        (top_score, top_score_normalized, local_match_ratio)
    };

    if !request.skip_local_search {
        search_response.symbols_context =
            collect_symbol_context(request.indexer.as_ref(), &search_response.hits);
    }
    let effective_force_web = request.force_web || request.skip_local_search;
    let should_run_tier2 = request.plan.web_gate.should_attempt(
        top_score_normalized,
        local_match_ratio,
        effective_force_web,
        request.llm_filter_local_results,
    );
    queue_dag_log(
        &repo_state_root,
        dag_session_id,
        "Thought",
        json!({
            "intent": format!("{intent:?}"),
            "top_score": top_score,
            "top_score_normalized": top_score_normalized,
            "local_match_ratio": local_match_ratio,
            "force_web": effective_force_web,
            "should_run_tier2": should_run_tier2,
        }),
    );
    let metrics = metrics::global();
    if should_run_tier2 {
        metrics.inc_waterfall_tier2_attempt();
    } else {
        metrics.inc_waterfall_tier2_skipped();
    }

    let tier2 = if request.async_web
        && should_run_tier2
        && !effective_force_web
        && !request.skip_local_search
        && request.plan.web_gate.enabled
    {
        let request_id = request.request_id.to_string();
        let dag_session_id = request
            .dag_session_id
            .unwrap_or(request.request_id)
            .to_string();
        let query = request.query.to_string();
        let plan = request.plan.clone();
        let indexer = request.indexer.clone();
        let libs_indexer = request.libs_indexer.clone();
        let llm_model = request.llm_model.map(|value| value.to_string());
        let llm_agent = request.llm_agent.map(|value| value.to_string());
        let limit = request.limit;
        let web_limit = request.web_limit;
        let llm_filter_local_results = request.llm_filter_local_results;
        let disable_web_cache = request.disable_web_cache;
        let ranking_surface = request.ranking_surface;
        let force_web = effective_force_web;
        let top_score_copy = top_score;
        let top_score_normalized_copy = top_score_normalized;
        let local_match_ratio_copy = local_match_ratio;

        tokio::spawn(async move {
            let request_id_ref = request_id.as_str();
            let dag_session_id_ref = dag_session_id.as_str();
            let llm_model_ref = llm_model.as_deref();
            let llm_agent_ref = llm_agent.as_deref();
            let async_request = WaterfallRequest {
                request_id: request_id_ref,
                dag_session_id: Some(dag_session_id_ref),
                query: &query,
                limit,
                diff: None,
                web_limit,
                force_web,
                skip_local_search: false,
                disable_web_cache,
                llm_filter_local_results,
                llm_model: llm_model_ref,
                llm_agent: llm_agent_ref,
                indexer,
                libs_indexer,
                plan,
                tier2_limiter: None,
                memory: None,
                profile_state: None,
                profile_agent_id: None,
                ranking_surface,
                async_web: false,
            };
            let _ = run_tier2(
                &async_request,
                top_score_copy,
                top_score_normalized_copy,
                local_match_ratio_copy,
                force_web,
            )
            .await;
        });

        Tier2Outcome {
            response: None,
            status: WebDiscoveryStatus {
                status: WebDiscoveryStatusCode::Skipped,
                reason: Some("async_deferred".to_string()),
                message: Some("web discovery deferred; running in background".to_string()),
                unavailable: None,
                discovery: None,
                fetches: None,
                debug: None,
                gate: build_gate_meta(
                    &request.plan.web_gate,
                    top_score,
                    top_score_normalized,
                    local_match_ratio,
                    effective_force_web,
                ),
            },
            tier2_unavailable: None,
        }
    } else if should_run_tier2 {
        run_tier2(
            &request,
            top_score,
            top_score_normalized,
            local_match_ratio,
            effective_force_web,
        )
        .await?
    } else {
        Tier2Outcome {
            response: None,
            status: evaluate_gate_status(
                request.request_id,
                &request.plan.web_gate,
                top_score,
                top_score_normalized,
                local_match_ratio,
                effective_force_web,
                request.llm_filter_local_results,
            ),
            tier2_unavailable: None,
        }
    };

    let profile_context = if let (Some(profile_state), Some(agent_id)) =
        (request.profile_state, request.profile_agent_id)
    {
        queue_dag_log(
            &repo_state_root,
            dag_session_id,
            "ToolCall",
            json!({
                "tool": "profile_recall",
                "agent_id": agent_id,
                "recall_candidates": request.plan.profile_budget.recall_candidates,
                "max_items": request.plan.profile_budget.max_items,
                "budget_tokens": request.plan.profile_budget.token_budget,
            }),
        );
        let started = Instant::now();
        let context = collect_profile_context(
            profile_state,
            agent_id,
            request.query,
            &request.plan.profile_budget,
        )
        .await?;
        if let Some(ctx) = &context {
            let latency_ms = started.elapsed().as_millis();
            metrics::global().record_profile_recall(
                ctx.prune_trace.candidates,
                ctx.prune_trace.kept,
                ctx.prune_trace.dropped.len(),
                latency_ms,
            );
            info!(
                target: "docdexd",
                request_id = %request.request_id,
                repo_root = %request.indexer.repo_root().display(),
                agent_id = %agent_id,
                candidates = ctx.prune_trace.candidates,
                kept = ctx.prune_trace.kept,
                dropped = ctx.prune_trace.dropped.len(),
                latency_ms,
                "profile_recall waterfall"
            );
            let truncated = ctx.items.iter().filter(|item| item.truncated).count();
            let dropped_total = ctx.prune_trace.dropped.len();
            if dropped_total > 0 || truncated > 0 {
                if dropped_total > 0 {
                    metrics::global().inc_profile_budget_drop(dropped_total);
                }
                let mut dropped_max_items = 0usize;
                let mut dropped_budget = 0usize;
                for dropped in &ctx.prune_trace.dropped {
                    match dropped.reason {
                        "max_items" => dropped_max_items += 1,
                        "budget_exhausted" => dropped_budget += 1,
                        _ => {}
                    }
                }
                info!(
                    target: "docdexd",
                    request_id = %request.request_id,
                    repo_root = %request.indexer.repo_root().display(),
                    agent_id = %agent_id,
                    budget_tokens = ctx.prune_trace.budget_tokens,
                    max_items = ctx.prune_trace.max_items,
                    dropped_total,
                    dropped_max_items,
                    dropped_budget,
                    truncated,
                    "profile_context pruned to fit token budget"
                );
            }
            queue_dag_log(
                &repo_state_root,
                dag_session_id,
                "Observation",
                json!({
                    "tool": "profile_recall",
                    "agent_id": agent_id,
                    "candidates": ctx.prune_trace.candidates,
                    "kept": ctx.prune_trace.kept,
                    "dropped": ctx.prune_trace.dropped.len(),
                    "truncated": truncated,
                    "latency_ms": latency_ms,
                }),
            );
        }
        context
    } else {
        None
    };

    search_response.profile_context = profile_context.clone();

    let memory_context = if let Some(memory) = request.memory {
        queue_dag_log(
            &repo_state_root,
            dag_session_id,
            "ToolCall",
            json!({
                "tool": "memory_recall",
                "recall_candidates": request.plan.memory_budget.recall_candidates,
                "max_items": request.plan.memory_budget.max_items,
                "budget_tokens": request.plan.memory_budget.token_budget,
            }),
        );
        let started = Instant::now();
        let context =
            collect_memory_context(memory, request.query, &request.plan.memory_budget).await?;
        if let Some(ctx) = &context {
            info!(
                target: "docdexd",
                request_id = %request.request_id,
                repo_root = %request.indexer.repo_root().display(),
                candidates = ctx.prune_trace.candidates,
                kept = ctx.prune_trace.kept,
                dropped = ctx.prune_trace.dropped.len(),
                latency_ms = started.elapsed().as_millis(),
                "memory_recall waterfall"
            );
            let truncated = ctx.items.iter().filter(|item| item.truncated).count();
            let dropped_total = ctx.prune_trace.dropped.len();
            if dropped_total > 0 || truncated > 0 {
                let mut dropped_max_items = 0usize;
                let mut dropped_budget = 0usize;
                for dropped in &ctx.prune_trace.dropped {
                    match dropped.reason {
                        "max_items" => dropped_max_items += 1,
                        "budget_exhausted" => dropped_budget += 1,
                        _ => {}
                    }
                }
                info!(
                    target: "docdexd",
                    request_id = %request.request_id,
                    repo_root = %request.indexer.repo_root().display(),
                    budget_tokens = ctx.prune_trace.budget_tokens,
                    max_items = ctx.prune_trace.max_items,
                    dropped_total,
                    dropped_max_items,
                    dropped_budget,
                    truncated,
                    "memory_context pruned to fit token budget"
                );
            }
            queue_dag_log(
                &repo_state_root,
                dag_session_id,
                "Observation",
                json!({
                    "tool": "memory_recall",
                    "candidates": ctx.prune_trace.candidates,
                    "kept": ctx.prune_trace.kept,
                    "dropped": ctx.prune_trace.dropped.len(),
                    "truncated": truncated,
                    "latency_ms": started.elapsed().as_millis(),
                }),
            );
        }
        context
    } else {
        None
    };

    let web_context = crate::orchestrator::web::web_context_from_status(&tier2.status);
    search_response.web_context = web_context;

    if let Some(ctx) = &memory_context {
        metrics.record_waterfall_memory_context(
            ctx.prune_trace.candidates,
            ctx.prune_trace.kept,
            ctx.prune_trace.dropped.len(),
        );
    }

    Ok(WaterfallResult {
        search_response,
        tier2,
        impact_context,
        memory_context,
        profile_context,
    })
}

fn collect_impact_context(
    repo_root: &Path,
    state_dir: &Path,
    diff_request: Option<&diff::DiffRequest>,
    request_id: &str,
) -> Result<Option<ImpactContextAssembly>> {
    let Some(diff_request) = diff_request else {
        return Ok(None);
    };
    let diff_changes = diff::collect_git_diff(repo_root, diff_request)?;
    if diff_changes.is_empty() {
        return Ok(None);
    }
    let diff_file_count = diff_changes.len();
    let diff_ranges = diff_changes
        .iter()
        .map(|change| change.ranges.len())
        .sum::<usize>();
    let diff_lines = diff_changes
        .iter()
        .flat_map(|change| change.ranges.iter())
        .map(|range| range.end.saturating_sub(range.start).saturating_add(1) as usize)
        .sum::<usize>();
    let diff_files = diff_changes
        .iter()
        .map(|change| change.path.clone())
        .collect::<Vec<_>>();
    let controls = impact_controls_from_env();
    let expansion = expand_impact_from_diff_files(state_dir, &diff_files, &controls)?;
    let context = assemble_impact_context(&diff_files, expansion, &controls);
    info!(
        target: "docdexd",
        request_id = %request_id,
        repo_root = %repo_root.display(),
        diff_files = diff_file_count,
        diff_ranges,
        diff_lines,
        "diff context collected"
    );
    info!(
        target: "docdexd",
        request_id = %request_id,
        repo_root = %repo_root.display(),
        sources = context.prune_trace.normalized_sources,
        dropped_sources = context.prune_trace.dropped_sources,
        expanded_files = context.prune_trace.expanded_files,
        edges = context.prune_trace.edges,
        max_edges = context.prune_trace.max_edges,
        max_depth = context.prune_trace.max_depth,
        truncated = context.prune_trace.truncated,
        "impact context expanded from diff"
    );
    if context.prune_trace.truncated {
        info!(
            target: "docdexd",
            repo_root = %repo_root.display(),
            max_edges = context.prune_trace.max_edges,
            max_depth = context.prune_trace.max_depth,
            edges = context.prune_trace.edges,
            "impact graph expansion truncated"
        );
    }
    Ok(Some(context))
}

fn impact_controls_from_env() -> crate::impact::ImpactQueryControls {
    let max_edges = env::var("DOCDEX_DIFF_MAX_EDGES")
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(DEFAULT_DIFF_MAX_EDGES as i64);
    let max_depth = env::var("DOCDEX_DIFF_MAX_DEPTH")
        .ok()
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(DEFAULT_DIFF_MAX_DEPTH as i64);
    let raw = ImpactQueryControlsRaw {
        max_edges: Some(max_edges),
        max_depth: Some(max_depth),
        edge_types: None,
    };
    match raw.validate() {
        Ok(controls) => controls,
        Err(_) => crate::impact::ImpactQueryControls {
            max_edges: DEFAULT_DIFF_MAX_EDGES,
            max_depth: DEFAULT_DIFF_MAX_DEPTH,
            edge_types: None,
        },
    }
}

async fn run_tier2(
    request: &WaterfallRequest<'_>,
    top_score: Option<f32>,
    top_score_normalized: Option<f32>,
    local_match_ratio: Option<f32>,
    force_web: bool,
) -> Result<Tier2Outcome> {
    let repo_state_root = repo_state_root_from_state_dir(request.indexer.state_dir());
    let dag_session_id = request.dag_session_id.unwrap_or(request.request_id);
    queue_dag_log(
        &repo_state_root,
        dag_session_id,
        "ToolCall",
        json!({
            "tool": "web_research",
            "limit": request.limit,
            "web_limit": request.web_limit,
            "force_web": force_web,
            "skip_local_search": request.skip_local_search,
            "disable_web_cache": request.disable_web_cache,
        }),
    );
    let run_result = tier2::run_with_fallback(
        request.request_id,
        request.plan.tier2_config.clone(),
        request.tier2_limiter,
        || async {
            let response = run_web_research(
                request.request_id,
                request.indexer.as_ref(),
                request.libs_indexer.as_deref(),
                request.query,
                request.limit,
                request.web_limit,
                force_web,
                &request.plan.web_gate,
                request.llm_filter_local_results,
                request.skip_local_search,
                request.disable_web_cache,
                request.llm_model,
                request.llm_agent,
            )
            .await?;
            Ok::<_, anyhow::Error>(Some(response))
        },
        || async { Ok::<_, anyhow::Error>(None) },
    )
    .await?;

    let status = if let Some(response) = run_result.value.as_ref() {
        metrics::global().inc_waterfall_tier2_served();
        response.web_discovery.clone()
    } else if let Some(unavailable) = run_result.tier2_unavailable.as_ref() {
        metrics::global().inc_waterfall_tier2_unavailable();
        build_tier2_unavailable_status(
            &request.plan.web_gate,
            top_score,
            top_score_normalized,
            local_match_ratio,
            force_web,
            unavailable,
        )
    } else {
        evaluate_gate_status(
            request.request_id,
            &request.plan.web_gate,
            top_score,
            top_score_normalized,
            local_match_ratio,
            force_web,
            request.llm_filter_local_results,
        )
    };

    queue_dag_log(
        &repo_state_root,
        dag_session_id,
        "Observation",
        json!({
            "tool": "web_research",
            "status": status,
            "hits": run_result.value.as_ref().map(|value| value.hits.len()),
            "top_score": run_result.value.as_ref().and_then(|value| value.top_score),
        }),
    );

    Ok(Tier2Outcome {
        response: run_result.value,
        status,
        tier2_unavailable: run_result.tier2_unavailable,
    })
}

fn build_tier2_unavailable_status(
    gate: &WebGateConfig,
    top_score: Option<f32>,
    top_score_normalized: Option<f32>,
    local_match_ratio: Option<f32>,
    force_web: bool,
    unavailable: &Tier2Unavailable,
) -> WebDiscoveryStatus {
    WebDiscoveryStatus {
        status: WebDiscoveryStatusCode::Unavailable,
        reason: Some(format!("tier2_{:?}", unavailable.reason).to_lowercase()),
        message: Some(unavailable.message.clone()),
        unavailable: Some(unavailable.clone()),
        discovery: None,
        fetches: None,
        debug: None,
        gate: build_gate_meta(
            gate,
            top_score,
            top_score_normalized,
            local_match_ratio,
            force_web,
        ),
    }
}

fn queue_dag_log(
    repo_state_root: &Path,
    session_id: &str,
    node_type: &'static str,
    payload: serde_json::Value,
) {
    let repo_state_root = repo_state_root.to_path_buf();
    let session_id = session_id.to_string();
    tokio::spawn(async move {
        let session_id_log = session_id.clone();
        let result = tokio::task::spawn_blocking(move || {
            dag_logging::log_node(&repo_state_root, &session_id, node_type, &payload)
        })
        .await;
        match result {
            Ok(Ok(())) => {}
            Ok(Err(err)) => warn!(
                target: "docdexd",
                session_id = %session_id_log,
                error = ?err,
                "dag log failed"
            ),
            Err(err) => warn!(
                target: "docdexd",
                session_id = %session_id_log,
                error = ?err,
                "dag log task failed"
            ),
        }
    });
}

async fn collect_memory_context(
    memory: &MemoryState,
    query: &str,
    budget: &MemoryBudget,
) -> Result<Option<MemoryContextAssembly>> {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    let embedding = match memory.embedder.embed(trimmed).await {
        Ok(value) => value,
        Err(err) => {
            if embedding_unavailable(&err) {
                warn!(
                    target: "docdexd",
                    repo_id = %memory.repo_id,
                    error = ?err,
                    "memory embedder unavailable; skipping memory context"
                );
                return Ok(None);
            }
            return Err(err);
        }
    };
    let recall_limit = budget.recall_candidates.max(1);
    let store = memory.store.clone();
    let recall = task::spawn_blocking(move || store.recall_candidates(&embedding, recall_limit))
        .await
        .map_err(|err| anyhow!("memory recall aborted: {err}"))?
        .context("memory recall failed")?;

    let (recall, dropped) = filter_memory_candidates_by_repo(recall, &memory.repo_id);
    if dropped > 0 {
        metrics::global().inc_memory_repo_mismatch(dropped as u64);
        warn!(
            target: "docdexd",
            repo_id = %memory.repo_id,
            dropped,
            "memory context dropped items with mismatched repo id"
        );
    }
    let (items, prune_trace) =
        prune_and_truncate_memory_context(&recall, budget.max_items.max(1), budget.token_budget);

    Ok(Some(MemoryContextAssembly { items, prune_trace }))
}

fn embedding_unavailable(err: &anyhow::Error) -> bool {
    let Some(app) = err.downcast_ref::<AppError>() else {
        return false;
    };
    matches!(
        app.code,
        ERR_EMBEDDING_FAILED | ERR_EMBEDDING_TIMEOUT | ERR_EMBEDDING_MODEL_NOT_FOUND
    )
}

async fn collect_profile_context(
    profile_state: &ProfileState,
    agent_id: &str,
    query: &str,
    budget: &ProfileBudget,
) -> Result<Option<ProfileContextAssembly>> {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    let Some(embedder) = profile_state.embedder.as_ref() else {
        return Ok(None);
    };
    let embedding = embedder.embed(trimmed).await?;
    let recall_limit = budget.recall_candidates.max(1);
    let manager = profile_state.manager.clone();
    let agent_id = agent_id.to_string();
    let recall = task::spawn_blocking(move || {
        manager.search_preferences(&agent_id, &embedding, recall_limit)
    })
    .await
    .map_err(|err| anyhow!("profile recall aborted: {err}"))?
    .context("profile recall failed")?;

    let candidates: Vec<ProfileCandidate> = recall
        .into_iter()
        .map(|result| ProfileCandidate {
            id: result.preference.id,
            agent_id: result.preference.agent_id,
            content: result.preference.content,
            category: result.preference.category,
            score: result.score,
            last_updated: result.preference.last_updated,
        })
        .collect();
    let (items, prune_trace) = prune_and_truncate_profile_context(
        &candidates,
        budget.max_items.max(1),
        budget.token_budget,
    );

    Ok(Some(ProfileContextAssembly { items, prune_trace }))
}

fn collect_symbol_context(indexer: &Indexer, hits: &[Hit]) -> Option<SymbolContextAssembly> {
    const MAX_FILES: usize = 5;
    const MAX_SYMBOLS_PER_FILE: usize = 20;

    if !indexer.symbols_enabled() {
        return None;
    }
    if let Ok(true) = indexer.symbols_reindex_required() {
        warn!(
            target: "docdexd",
            "symbols reindex required; skipping symbol context"
        );
        return None;
    }

    let candidate_files = hits.iter().take(MAX_FILES).count();
    let mut items = Vec::new();
    let mut truncated_files = 0usize;

    for hit in hits.iter().take(MAX_FILES) {
        let symbols = match indexer.read_symbols(&hit.rel_path) {
            Ok(Some(payload)) => payload.symbols,
            Ok(None) => continue,
            Err(err) => {
                warn!(
                    target: "docdexd",
                    error = ?err,
                    rel_path = %hit.rel_path,
                    "symbols lookup failed"
                );
                continue;
            }
        };
        if symbols.is_empty() {
            continue;
        }
        let truncated = symbols.len() > MAX_SYMBOLS_PER_FILE;
        if truncated {
            truncated_files += 1;
        }
        let symbols = symbols
            .into_iter()
            .take(MAX_SYMBOLS_PER_FILE)
            .map(|symbol| SymbolContextSymbol {
                name: symbol.name,
                kind: symbol.kind,
                line_start: symbol.range.start_line,
                line_end: symbol.range.end_line,
                signature: symbol.signature,
            })
            .collect::<Vec<_>>();
        items.push(SymbolContextItem {
            file: hit.rel_path.clone(),
            symbols,
            truncated,
        });
    }

    if items.is_empty() {
        return None;
    }

    let kept_files = items.len();
    Some(SymbolContextAssembly {
        items,
        prune_trace: SymbolContextPruneTrace {
            candidate_files,
            kept_files,
            max_files: MAX_FILES,
            max_symbols_per_file: MAX_SYMBOLS_PER_FILE,
            truncated_files,
        },
    })
}
