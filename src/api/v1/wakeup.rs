use crate::conversations::{assemble_wakeup_bundle, render_wakeup_bundle, WakeupBundle};
use crate::error::{ERR_INTERNAL_ERROR, ERR_INVALID_ARGUMENT, ERR_MEMORY_DISABLED};
use crate::http_api::{json_error, repo_error_response, resolve_conversation_context};
use crate::search::{AppState, RepoIdQuery, RequestId};
use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use std::time::Instant;
use tracing::{info, warn};

#[derive(Deserialize)]
pub struct WakeupRequest {
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub query: Option<String>,
    #[serde(default)]
    pub max_tokens: Option<usize>,
    #[serde(default)]
    pub repo_id: Option<String>,
    #[serde(default, alias = "namespace")]
    pub conversation_namespace: Option<String>,
}

#[derive(Serialize)]
pub struct WakeupResponse {
    pub text: String,
    pub trace: WakeupApiTrace,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub working_memory: Option<crate::conversations::WorkingMemoryRecord>,
    pub episodic_summaries: Vec<crate::conversations::SessionSummaryRecord>,
    pub knowledge_facts: Vec<crate::knowledge::KnowledgeFactRecord>,
    pub knowledge_edges: Vec<crate::knowledge::KnowledgeGraphEdgeRecord>,
    pub knowledge_episodes: Vec<crate::knowledge::KnowledgeEpisodeRecord>,
    pub knowledge_entity_links: Vec<crate::knowledge::KnowledgeEntityLinkRecord>,
    pub transcript_snippets: Vec<crate::conversations::TranscriptSnippet>,
}

#[derive(Serialize)]
pub struct WakeupApiTrace {
    pub budget_tokens: usize,
    pub available_items: usize,
    pub selected_items: usize,
    pub truncated_items: usize,
    pub summary_candidates: usize,
    pub kg_candidates: usize,
    pub graph_edge_candidates: usize,
    pub graph_episode_candidates: usize,
    pub graph_link_candidates: usize,
    pub snippet_candidates: usize,
    pub startup_diary_candidates: usize,
    pub startup_diary_selected: usize,
    pub available_tokens: usize,
    pub selected_tokens: usize,
    pub saved_tokens: usize,
    pub working_memory_tokens: usize,
    pub summary_tokens: usize,
    pub knowledge_tokens: usize,
    pub snippet_tokens: usize,
}

pub(crate) async fn wakeup_handler(
    State(state): State<AppState>,
    axum::extract::Extension(request_id): axum::extract::Extension<RequestId>,
    headers: HeaderMap,
    Query(repo_id): Query<RepoIdQuery>,
    Json(req): Json<WakeupRequest>,
) -> impl IntoResponse {
    let scope = match resolve_conversation_context(
        &state,
        &headers,
        repo_id.repo_id.as_deref(),
        req.repo_id.as_deref(),
        repo_id.conversation_namespace.as_deref(),
        req.conversation_namespace.as_deref(),
        false,
    ) {
        Ok(scope) => scope,
        Err(err) => return repo_error_response(err),
    };
    let Some(conversations) = scope.conversations() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            "conversation memory is disabled; enable [memory.conversations].enabled",
        );
    };

    let max_tokens = req
        .max_tokens
        .unwrap_or(conversations.max_wakeup_tokens)
        .min(conversations.max_wakeup_tokens)
        .max(1);
    let query = req
        .query
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let agent_id = req
        .agent_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    if req.max_tokens == Some(0) {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "max_tokens must be greater than 0",
        );
    }

    let started = Instant::now();
    let scope_label = scope.scope_label();
    let store = conversations.store.clone();
    let knowledge = conversations.knowledge.clone();
    let summary_limit = conversations.max_episodic_summaries;
    let knowledge_limit = conversations.max_knowledge_facts;
    let snippet_limit = conversations.max_transcript_snippets;
    let bundle = match tokio::task::spawn_blocking(move || {
        assemble_wakeup_bundle(
            &store,
            &knowledge,
            &conversations.config,
            agent_id.as_deref(),
            query.as_deref(),
            summary_limit,
            knowledge_limit,
            snippet_limit,
        )
    })
    .await
    {
        Ok(Ok(bundle)) => bundle,
        Ok(Err(err)) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                request_id = %request_id.0,
                error = ?err,
                "wakeup assembly failed"
            );
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "wakeup assembly failed",
            );
        }
        Err(err) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                request_id = %request_id.0,
                error = ?err,
                "wakeup task join failed"
            );
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "wakeup assembly failed",
            );
        }
    };
    let (text, render_trace) = render_wakeup_bundle(&bundle, max_tokens);
    state.metrics.record_conversation_wakeup(
        render_trace.selected > 0,
        render_trace.saved_tokens,
        render_trace.working_memory_tokens,
        render_trace.summary_tokens,
        render_trace.knowledge_tokens,
        render_trace.snippet_tokens,
    );
    info!(
        target: "docdexd",
        request_id = %request_id.0,
        scope = %scope_label,
        latency_ms = started.elapsed().as_millis(),
        selected = render_trace.selected,
        "wakeup assembled"
    );
    Json(WakeupResponse {
        text,
        trace: WakeupApiTrace {
            budget_tokens: max_tokens,
            available_items: render_trace.available,
            selected_items: render_trace.selected,
            truncated_items: render_trace.truncated,
            summary_candidates: bundle.trace.summary_candidates,
            kg_candidates: bundle.trace.kg_candidates,
            graph_edge_candidates: bundle.trace.graph_edge_candidates,
            graph_episode_candidates: bundle.trace.graph_episode_candidates,
            graph_link_candidates: bundle.trace.graph_link_candidates,
            snippet_candidates: bundle.trace.snippet_candidates,
            startup_diary_candidates: bundle.trace.startup_diary_candidates,
            startup_diary_selected: bundle.trace.startup_diary_selected,
            available_tokens: render_trace.available_tokens,
            selected_tokens: render_trace.selected_tokens,
            saved_tokens: render_trace.saved_tokens,
            working_memory_tokens: render_trace.working_memory_tokens,
            summary_tokens: render_trace.summary_tokens,
            knowledge_tokens: render_trace.knowledge_tokens,
            snippet_tokens: render_trace.snippet_tokens,
        },
        working_memory: bundle.working_memory,
        episodic_summaries: bundle.episodic_summaries,
        knowledge_facts: bundle.knowledge_facts,
        knowledge_edges: bundle.knowledge_edges,
        knowledge_episodes: bundle.knowledge_episodes,
        knowledge_entity_links: bundle.knowledge_entity_links,
        transcript_snippets: bundle.transcript_snippets,
    })
    .into_response()
}

pub fn load_wakeup_bundle_for_chat(
    conversations: &crate::search::ConversationState,
    agent_id: Option<&str>,
    query: Option<&str>,
    max_tokens: usize,
) -> Result<
    (
        WakeupBundle,
        String,
        crate::conversations::WakeupRenderTrace,
    ),
    anyhow::Error,
> {
    let bundle = assemble_wakeup_bundle(
        &conversations.store,
        &conversations.knowledge,
        &conversations.config,
        agent_id,
        query,
        conversations.max_episodic_summaries,
        conversations.max_knowledge_facts,
        conversations.max_transcript_snippets,
    )?;
    let effective_budget = max_tokens.min(conversations.max_wakeup_tokens).max(1);
    let (rendered, trace) = render_wakeup_bundle(&bundle, effective_budget);
    crate::metrics::global().record_conversation_wakeup(
        trace.selected > 0,
        trace.saved_tokens,
        trace.working_memory_tokens,
        trace.summary_tokens,
        trace.knowledge_tokens,
        trace.snippet_tokens,
    );
    Ok((bundle, rendered, trace))
}
