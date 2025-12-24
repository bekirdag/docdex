use anyhow::{anyhow, Context, Result};
use serde::Serialize;
use tokio::task;

use crate::index::Indexer;
use crate::libs::LibsIndexer;
use crate::memory::{
    prune_and_truncate_memory_context, MemoryContextItem, MemoryContextPruneTrace,
};
use crate::orchestrator::web::{
    build_gate_meta, evaluate_gate_status, run_web_research, WebDiscoveryStatus,
    WebDiscoveryStatusCode, WebGateConfig, WebResearchResponse,
};
use crate::metrics;
use crate::search::{MemoryState, SearchResponse};
use crate::tier2::{self, Tier2Config, Tier2Limiter, Tier2Unavailable};

/// Budget configuration for assembling memory context during Tier 3.
#[derive(Clone, Debug)]
pub struct MemoryBudget {
    pub max_items: usize,
    pub token_budget: usize,
    pub recall_candidates: usize,
}

impl Default for MemoryBudget {
    fn default() -> Self {
        Self {
            max_items: 5,
            token_budget: 350,
            recall_candidates: 20,
        }
    }
}

/// Description of the waterfall request.
#[derive(Clone)]
pub struct WaterfallRequest<'a> {
    pub request_id: &'a str,
    pub query: &'a str,
    pub limit: usize,
    pub force_web: bool,
    pub indexer: &'a Indexer,
    pub libs_indexer: Option<&'a LibsIndexer>,
    pub web_gate: &'a WebGateConfig,
    pub tier2_config: Tier2Config,
    pub tier2_limiter: Option<&'a Tier2Limiter>,
    pub memory: Option<&'a MemoryState>,
    pub memory_budget: MemoryBudget,
}

/// Result of running the waterfall through all tiers.
pub struct WaterfallResult {
    pub search_response: SearchResponse,
    pub tier2: Tier2Outcome,
    pub memory_context: Option<MemoryContextAssembly>,
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

/// Execute the waterfall (Tier 1 → Tier 2 → Tier 3) for a single query.
pub async fn run_waterfall(request: WaterfallRequest<'_>) -> Result<WaterfallResult> {
    let search_response =
        crate::search::run_query(request.indexer, request.libs_indexer, request.query, request.limit)
            .await?;

    let should_run_tier2 =
        request
            .web_gate
            .should_attempt(search_response.top_score, request.force_web);
    let metrics = metrics::global();
    if should_run_tier2 {
        metrics.inc_waterfall_tier2_attempt();
    } else {
        metrics.inc_waterfall_tier2_skipped();
    }

    let tier2 = if should_run_tier2 {
        run_tier2(&request, search_response.top_score).await?
    } else {
        Tier2Outcome {
            response: None,
            status: evaluate_gate_status(
                request.request_id,
                request.web_gate,
                search_response.top_score,
                request.force_web,
            ),
            tier2_unavailable: None,
        }
    };

    let memory_context = if let Some(memory) = request.memory {
        collect_memory_context(memory, request.query, &request.memory_budget).await?
    } else {
        None
    };

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
        memory_context,
    })
}

async fn run_tier2(
    request: &WaterfallRequest<'_>,
    top_score: Option<f32>,
) -> Result<Tier2Outcome> {
    let run_result = tier2::run_with_fallback(
        request.request_id,
        request.tier2_config.clone(),
        request.tier2_limiter,
        || async {
            let response = run_web_research(
                request.request_id,
                request.indexer,
                request.libs_indexer,
                request.query,
                request.limit,
                request.force_web,
                request.web_gate,
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
            request.web_gate,
            top_score,
            request.force_web,
            unavailable,
        )
    } else {
        evaluate_gate_status(
            request.request_id,
            request.web_gate,
            top_score,
            request.force_web,
        )
    };

    Ok(Tier2Outcome {
        response: run_result.value,
        status,
        tier2_unavailable: run_result.tier2_unavailable,
    })
}

fn build_tier2_unavailable_status(
    gate: &WebGateConfig,
    top_score: Option<f32>,
    force_web: bool,
    unavailable: &Tier2Unavailable,
) -> WebDiscoveryStatus {
    WebDiscoveryStatus {
        status: WebDiscoveryStatusCode::Unavailable,
        reason: Some(format!("tier2_{:?}", unavailable.reason).to_lowercase()),
        message: Some(unavailable.message.clone()),
        unavailable: Some(unavailable.clone()),
        gate: build_gate_meta(gate, top_score, force_web),
    }
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

    let embedding = memory.embedder.embed(trimmed).await?;
    let recall_limit = budget.recall_candidates.max(1);
    let store = memory.store.clone();
    let recall = task::spawn_blocking(move || store.recall_candidates(&embedding, recall_limit))
        .await
        .map_err(|err| anyhow!("memory recall aborted: {err}"))?
        .context("memory recall failed")?;

    let (items, prune_trace) =
        prune_and_truncate_memory_context(&recall, budget.max_items.max(1), budget.token_budget);

    Ok(Some(MemoryContextAssembly { items, prune_trace }))
}
