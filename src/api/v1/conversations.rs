use crate::conversations::{
    build_conversation_profile_target, build_conversation_route_targets,
    combined_archive_size_bytes, import_conversation_with_routing_options,
    normalize_import_request, prune_with_knowledge, ConversationCaptureKind,
    ConversationExportRecord, ConversationImportEnvelope, ConversationImportOptions,
    ConversationMessage, ConversationPruneResult, ConversationRedactResult,
    ConversationRetentionPolicy, ConversationRole,
};
use crate::error::{
    ERR_CONVERSATION_NOT_FOUND, ERR_INTERNAL_ERROR, ERR_INVALID_ARGUMENT, ERR_MEMORY_DISABLED,
};
use crate::http_api::{
    json_error, json_error_with_details, repo_error_response, resolve_conversation_context,
};
use crate::search::{AppState, RepoIdQuery, RequestId};
use axum::{
    extract::{Path as AxumPath, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Instant;
use tracing::{info, warn};

const DEFAULT_CONVERSATION_LIST_LIMIT: usize = 20;
const MAX_CONVERSATION_LIST_LIMIT: usize = 100;

#[derive(Deserialize)]
pub struct ConversationImportRequest {
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub source_session_id: Option<String>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub transport: Option<String>,
    #[serde(default)]
    pub started_at_ms: Option<i64>,
    #[serde(default)]
    pub ended_at_ms: Option<i64>,
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default)]
    pub messages: Option<Vec<ConversationImportMessage>>,
    #[serde(default)]
    pub transcript_text: Option<String>,
    #[serde(default)]
    pub metadata: Option<Value>,
    #[serde(default)]
    pub repo_id: Option<String>,
    #[serde(default, alias = "namespace")]
    pub conversation_namespace: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ConversationImportMessage {
    pub role: String,
    pub content: String,
    #[serde(default)]
    pub author: Option<String>,
    #[serde(default)]
    pub created_at_ms: Option<i64>,
    #[serde(default)]
    pub metadata: Option<Value>,
}

#[derive(Serialize)]
pub struct ConversationImportResponse {
    pub session_id: String,
    pub deduplicated: bool,
    pub message_count: usize,
    pub capture_kind: crate::conversations::ConversationCaptureKind,
    pub raw_messages_stored: bool,
    pub summary: crate::conversations::SessionSummaryRecord,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub working_memory: Option<crate::conversations::WorkingMemoryRecord>,
    #[serde(default)]
    pub durable_memories: Vec<crate::conversations::ConversationDurableMemoryRouteRecord>,
    #[serde(default)]
    pub knowledge_facts: Vec<crate::knowledge::KnowledgeFactRecord>,
}

#[derive(Deserialize)]
pub struct ConversationListQuery {
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub offset: Option<usize>,
    #[serde(default)]
    pub repo_id: Option<String>,
    #[serde(default, alias = "namespace")]
    pub conversation_namespace: Option<String>,
}

#[derive(Deserialize)]
pub struct ConversationSearchQuery {
    #[serde(default, alias = "query")]
    pub q: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub offset: Option<usize>,
    #[serde(default)]
    pub repo_id: Option<String>,
    #[serde(default, alias = "namespace")]
    pub conversation_namespace: Option<String>,
}

#[derive(Serialize)]
pub struct ConversationReadResponse {
    pub session: crate::conversations::ConversationSessionRecord,
}

#[derive(Serialize)]
pub struct ConversationDeleteResponse {
    pub session_id: String,
    pub deleted: bool,
}

#[derive(Serialize)]
pub struct ConversationExportResponse {
    pub export: ConversationExportRecord,
}

#[derive(Serialize)]
pub struct ConversationRedactResponse {
    pub result: ConversationRedactResult,
}

#[derive(Debug, Deserialize)]
pub struct ConversationPruneRequest {
    #[serde(default)]
    pub manual_retention_days: Option<u32>,
    #[serde(default)]
    pub auto_capture_retention_days: Option<u32>,
    #[serde(default)]
    pub diary_retention_days: Option<u32>,
    #[serde(default)]
    pub hook_event_retention_days: Option<u32>,
    #[serde(default)]
    pub working_memory_retention_days: Option<u32>,
    #[serde(default)]
    pub episodic_rollup_retention_days: Option<u32>,
    #[serde(default)]
    pub apply: Option<bool>,
    #[serde(default)]
    pub repo_id: Option<String>,
    #[serde(default, alias = "namespace")]
    pub conversation_namespace: Option<String>,
}

#[derive(Serialize)]
pub struct ConversationPruneResponse {
    pub result: ConversationPruneResult,
}

pub(crate) async fn conversation_import_handler(
    State(state): State<AppState>,
    axum::extract::Extension(request_id): axum::extract::Extension<RequestId>,
    headers: HeaderMap,
    Query(repo_id): Query<RepoIdQuery>,
    Json(req): Json<ConversationImportRequest>,
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
    let payload = match normalize_import_request(ConversationImportEnvelope {
        source: req.source,
        source_session_id: req.source_session_id,
        title: req.title,
        agent_id: req.agent_id.or_else(|| state.default_agent_id.clone()),
        transport: req.transport,
        started_at_ms: req.started_at_ms,
        ended_at_ms: req.ended_at_ms,
        format: req.format,
        messages: map_import_messages(req.messages),
        transcript_text: req.transcript_text,
        metadata: req.metadata.unwrap_or_else(|| serde_json::json!({})),
    }) {
        Ok(payload) => payload,
        Err(message) => {
            return json_error(StatusCode::BAD_REQUEST, ERR_INVALID_ARGUMENT, &message);
        }
    };
    if !conversations.config.allows_source(&payload.source) {
        log_conversation_audit(
            &state,
            "conversation.import",
            "deny",
            &request_id.0,
            "/v1/conversations/import",
            "POST",
            StatusCode::FORBIDDEN,
            format!("scope={} source={}", scope.scope_id(), payload.source),
        );
        return json_error(
            StatusCode::FORBIDDEN,
            ERR_INVALID_ARGUMENT,
            "conversation source is blocked by memory.conversations source policy",
        );
    }
    let personal_preferences_capture = state
        .personal_preferences
        .as_ref()
        .filter(|personal_preferences| {
            crate::personal_preferences::should_capture_external_source(
                &personal_preferences.config,
                &payload.source,
                personal_preferences.config.capture_imported_conversations,
            )
        })
        .map(|personal_preferences| {
            (
                personal_preferences.clone(),
                build_personal_preferences_import_capture_request(
                    scope.scope_id(),
                    scope.scope_label(),
                    &payload,
                ),
            )
        });
    let route_targets = build_conversation_route_targets(
        scope.repo_memory_target(),
        state.profile_state.as_ref().map(|profile| {
            build_conversation_profile_target(
                profile.manager.clone(),
                profile.embedder.clone(),
                "conversation_import",
            )
        }),
        conversations.knowledge.clone(),
        conversations.config.graph.clone(),
        state.default_agent_id.clone(),
    );

    let started = Instant::now();
    let scope_label = scope.scope_label();
    let scope_id = scope.scope_id();
    let store = conversations.store.clone();
    let payload_source = payload.source.clone();
    let import_options = ConversationImportOptions {
        capture_kind: ConversationCaptureKind::Manual,
        store_raw_messages: conversations.config.archive_raw_transcripts,
    };
    match import_conversation_with_routing_options(store, payload, import_options, route_targets)
        .await
    {
        Ok(imported) => {
            if let Some((personal_preferences, capture_request)) = personal_preferences_capture {
                if let Err(err) = personal_preferences.store.capture_conversation(
                    capture_request,
                    personal_preferences.config.digest_enabled,
                    personal_preferences.config.archive_raw_conversations,
                ) {
                    warn!(
                        target: "docdexd",
                        request_id = %request_id.0,
                        error = ?err,
                        "personal preferences capture failed for imported conversation"
                    );
                }
            }
            update_conversation_archive_metric(&state, &conversations);
            info!(
                target: "docdexd",
                request_id = %request_id.0,
                scope = %scope_label,
                latency_ms = started.elapsed().as_millis(),
                session_id = %imported.session_id,
                deduplicated = imported.deduplicated,
                "conversation import succeeded"
            );
            log_conversation_audit(
                &state,
                "conversation.import",
                "ok",
                &request_id.0,
                "/v1/conversations/import",
                "POST",
                StatusCode::OK,
                format!(
                    "scope={} source={} session_id={} deduplicated={} raw_messages_stored={}",
                    scope_id,
                    payload_source,
                    imported.session_id,
                    imported.deduplicated,
                    imported.raw_messages_stored
                ),
            );
            Json(ConversationImportResponse {
                session_id: imported.session_id,
                deduplicated: imported.deduplicated,
                message_count: imported.message_count,
                capture_kind: imported.capture_kind,
                raw_messages_stored: imported.raw_messages_stored,
                summary: imported.summary,
                working_memory: imported.working_memory,
                durable_memories: imported.durable_memories,
                knowledge_facts: imported.knowledge_facts,
            })
            .into_response()
        }
        Err(err) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                request_id = %request_id.0,
                error = ?err,
                "conversation import failed"
            );
            log_conversation_audit(
                &state,
                "conversation.import",
                "error",
                &request_id.0,
                "/v1/conversations/import",
                "POST",
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("scope={} source={} error={}", scope_id, payload_source, err),
            );
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "conversation import failed",
            )
        }
    }
}

pub(crate) async fn conversation_list_handler(
    State(state): State<AppState>,
    axum::extract::Extension(request_id): axum::extract::Extension<RequestId>,
    headers: HeaderMap,
    Query(params): Query<ConversationListQuery>,
) -> impl IntoResponse {
    let scope = match resolve_conversation_context(
        &state,
        &headers,
        params.repo_id.as_deref(),
        None,
        params.conversation_namespace.as_deref(),
        None,
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
    if matches!(params.limit, Some(0)) {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "limit must be greater than 0",
        );
    }
    let limit = params
        .limit
        .unwrap_or(DEFAULT_CONVERSATION_LIST_LIMIT)
        .clamp(1, MAX_CONVERSATION_LIST_LIMIT);
    let offset = params.offset.unwrap_or(0);
    let agent_id = params
        .agent_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let started = Instant::now();
    let scope_label = scope.scope_label();
    let store = conversations.store.clone();
    match tokio::task::spawn_blocking(move || {
        store.list_sessions(agent_id.as_deref(), limit, offset)
    })
    .await
    {
        Ok(Ok(list)) => {
            info!(
                target: "docdexd",
                request_id = %request_id.0,
                scope = %scope_label,
                latency_ms = started.elapsed().as_millis(),
                returned = list.sessions.len(),
                total = list.total,
                "conversation list succeeded"
            );
            Json(list).into_response()
        }
        Ok(Err(err)) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                request_id = %request_id.0,
                error = ?err,
                "conversation list failed"
            );
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "conversation list failed",
            )
        }
        Err(err) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                request_id = %request_id.0,
                error = ?err,
                "conversation list task join failed"
            );
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "conversation list failed",
            )
        }
    }
}

pub(crate) async fn conversation_search_handler(
    State(state): State<AppState>,
    axum::extract::Extension(request_id): axum::extract::Extension<RequestId>,
    headers: HeaderMap,
    Query(params): Query<ConversationSearchQuery>,
) -> impl IntoResponse {
    let scope = match resolve_conversation_context(
        &state,
        &headers,
        params.repo_id.as_deref(),
        None,
        params.conversation_namespace.as_deref(),
        None,
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
    let query = match params
        .q
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(query) => query.to_string(),
        None => {
            return json_error(
                StatusCode::BAD_REQUEST,
                ERR_INVALID_ARGUMENT,
                "q must not be empty",
            );
        }
    };
    if matches!(params.limit, Some(0)) {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "limit must be greater than 0",
        );
    }
    let limit = params
        .limit
        .unwrap_or(DEFAULT_CONVERSATION_LIST_LIMIT)
        .clamp(1, MAX_CONVERSATION_LIST_LIMIT);
    let offset = params.offset.unwrap_or(0);
    let agent_id = params
        .agent_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let started = Instant::now();
    let scope_label = scope.scope_label();
    let store = conversations.store.clone();
    let query_for_task = query.clone();
    match tokio::task::spawn_blocking(move || {
        store.search_sessions(&query_for_task, agent_id.as_deref(), limit, offset)
    })
    .await
    {
        Ok(Ok(result)) => {
            info!(
                target: "docdexd",
                request_id = %request_id.0,
                scope = %scope_label,
                latency_ms = started.elapsed().as_millis(),
                returned = result.hits.len(),
                total = result.total,
                "conversation search succeeded"
            );
            Json(result).into_response()
        }
        Ok(Err(err)) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                request_id = %request_id.0,
                error = ?err,
                "conversation search failed"
            );
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "conversation search failed",
            )
        }
        Err(err) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                request_id = %request_id.0,
                error = ?err,
                "conversation search task join failed"
            );
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "conversation search failed",
            )
        }
    }
}

pub(crate) async fn conversation_read_handler(
    State(state): State<AppState>,
    axum::extract::Extension(request_id): axum::extract::Extension<RequestId>,
    headers: HeaderMap,
    Query(repo_id): Query<RepoIdQuery>,
    AxumPath(session_id): AxumPath<String>,
) -> impl IntoResponse {
    let scope = match resolve_conversation_context(
        &state,
        &headers,
        repo_id.repo_id.as_deref(),
        None,
        repo_id.conversation_namespace.as_deref(),
        None,
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
    let session_id = session_id.trim().to_string();
    if session_id.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "session_id must not be empty",
        );
    }
    let started = Instant::now();
    let scope_label = scope.scope_label();
    let store = conversations.store.clone();
    let session_id_for_task = session_id.clone();
    match tokio::task::spawn_blocking(move || store.read_session(&session_id_for_task)).await {
        Ok(Ok(Some(session))) => {
            info!(
                target: "docdexd",
                request_id = %request_id.0,
                scope = %scope_label,
                latency_ms = started.elapsed().as_millis(),
                session_id = %session_id,
                "conversation read succeeded"
            );
            Json(ConversationReadResponse { session }).into_response()
        }
        Ok(Ok(None)) => json_error_with_details(
            StatusCode::NOT_FOUND,
            ERR_CONVERSATION_NOT_FOUND,
            "conversation session not found",
            serde_json::json!({ "session_id": session_id }),
        ),
        Ok(Err(err)) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                request_id = %request_id.0,
                error = ?err,
                "conversation read failed"
            );
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "conversation read failed",
            )
        }
        Err(err) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                request_id = %request_id.0,
                error = ?err,
                "conversation read task join failed"
            );
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "conversation read failed",
            )
        }
    }
}

pub(crate) async fn conversation_export_handler(
    State(state): State<AppState>,
    axum::extract::Extension(request_id): axum::extract::Extension<RequestId>,
    headers: HeaderMap,
    Query(repo_id): Query<RepoIdQuery>,
    AxumPath(session_id): AxumPath<String>,
) -> impl IntoResponse {
    let scope = match resolve_conversation_context(
        &state,
        &headers,
        repo_id.repo_id.as_deref(),
        None,
        repo_id.conversation_namespace.as_deref(),
        None,
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
    let session_id = session_id.trim().to_string();
    if session_id.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "session_id must not be empty",
        );
    }
    let started = Instant::now();
    let scope_label = scope.scope_label();
    let store = conversations.store.clone();
    let knowledge = conversations.knowledge.clone();
    let session_id_for_task = session_id.clone();
    match tokio::task::spawn_blocking(
        move || -> anyhow::Result<Option<ConversationExportRecord>> {
            let Some(mut export) = store.export_session(&session_id_for_task)? else {
                return Ok(None);
            };
            export.knowledge_facts = knowledge.facts_for_session(&session_id_for_task)?;
            Ok(Some(export))
        },
    )
    .await
    {
        Ok(Ok(Some(export))) => {
            info!(
                target: "docdexd",
                request_id = %request_id.0,
                scope = %scope_label,
                latency_ms = started.elapsed().as_millis(),
                session_id = %session_id,
                "conversation export succeeded"
            );
            Json(ConversationExportResponse { export }).into_response()
        }
        Ok(Ok(None)) => json_error_with_details(
            StatusCode::NOT_FOUND,
            ERR_CONVERSATION_NOT_FOUND,
            "conversation session not found",
            serde_json::json!({ "session_id": session_id }),
        ),
        Ok(Err(err)) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                request_id = %request_id.0,
                error = ?err,
                "conversation export failed"
            );
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "conversation export failed",
            )
        }
        Err(err) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                request_id = %request_id.0,
                error = ?err,
                "conversation export task join failed"
            );
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "conversation export failed",
            )
        }
    }
}

pub(crate) async fn conversation_redact_handler(
    State(state): State<AppState>,
    axum::extract::Extension(request_id): axum::extract::Extension<RequestId>,
    headers: HeaderMap,
    Query(repo_id): Query<RepoIdQuery>,
    AxumPath(session_id): AxumPath<String>,
) -> impl IntoResponse {
    let scope = match resolve_conversation_context(
        &state,
        &headers,
        repo_id.repo_id.as_deref(),
        None,
        repo_id.conversation_namespace.as_deref(),
        None,
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
    let session_id = session_id.trim().to_string();
    if session_id.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "session_id must not be empty",
        );
    }
    let started = Instant::now();
    let scope_label = scope.scope_label();
    let scope_id = scope.scope_id();
    let store = conversations.store.clone();
    let knowledge = conversations.knowledge.clone();
    let session_id_for_task = session_id.clone();
    match tokio::task::spawn_blocking(
        move || -> anyhow::Result<Option<ConversationRedactResult>> {
            let result = store.redact_session(&session_id_for_task)?;
            if result.as_ref().map(|item| item.redacted).unwrap_or(false) {
                let _ = knowledge.delete_facts_for_session(&session_id_for_task)?;
            }
            Ok(result)
        },
    )
    .await
    {
        Ok(Ok(Some(result))) => {
            update_conversation_archive_metric(&state, &conversations);
            info!(
                target: "docdexd",
                request_id = %request_id.0,
                scope = %scope_label,
                latency_ms = started.elapsed().as_millis(),
                session_id = %session_id,
                redacted = result.redacted,
                "conversation redact succeeded"
            );
            log_conversation_audit(
                &state,
                "conversation.redact",
                "ok",
                &request_id.0,
                "/v1/conversations/:session_id/redact",
                "POST",
                StatusCode::OK,
                format!(
                    "scope={} session_id={} redacted={}",
                    scope_id, session_id, result.redacted
                ),
            );
            Json(ConversationRedactResponse { result }).into_response()
        }
        Ok(Ok(None)) => json_error_with_details(
            StatusCode::NOT_FOUND,
            ERR_CONVERSATION_NOT_FOUND,
            "conversation session not found",
            serde_json::json!({ "session_id": session_id }),
        ),
        Ok(Err(err)) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                request_id = %request_id.0,
                error = ?err,
                "conversation redact failed"
            );
            log_conversation_audit(
                &state,
                "conversation.redact",
                "error",
                &request_id.0,
                "/v1/conversations/:session_id/redact",
                "POST",
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("scope={} session_id={} error={}", scope_id, session_id, err),
            );
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "conversation redact failed",
            )
        }
        Err(err) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                request_id = %request_id.0,
                error = ?err,
                "conversation redact task join failed"
            );
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "conversation redact failed",
            )
        }
    }
}

pub(crate) async fn conversation_prune_handler(
    State(state): State<AppState>,
    axum::extract::Extension(request_id): axum::extract::Extension<RequestId>,
    headers: HeaderMap,
    Query(repo_id): Query<RepoIdQuery>,
    Json(req): Json<ConversationPruneRequest>,
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
    let policy = ConversationRetentionPolicy {
        manual_retention_days: req
            .manual_retention_days
            .unwrap_or(conversations.config.manual_retention_days),
        auto_capture_retention_days: req
            .auto_capture_retention_days
            .unwrap_or(conversations.config.auto_capture_retention_days),
        diary_retention_days: req
            .diary_retention_days
            .unwrap_or(conversations.config.diary_retention_days),
        hook_event_retention_days: req
            .hook_event_retention_days
            .unwrap_or(conversations.config.hook_event_retention_days),
        working_memory_retention_days: req
            .working_memory_retention_days
            .unwrap_or(conversations.config.working_memory_retention_days),
        episodic_rollup_retention_days: req
            .episodic_rollup_retention_days
            .unwrap_or(conversations.config.episodic_rollup_retention_days),
    };
    let apply = req.apply.unwrap_or(false);
    let started = Instant::now();
    let scope_label = scope.scope_label();
    let scope_id = scope.scope_id();
    let store = conversations.store.clone();
    let knowledge = conversations.knowledge.clone();
    let result = tokio::task::spawn_blocking(
        move || -> anyhow::Result<(ConversationPruneResult, u64, u64)> {
            let before = combined_archive_size_bytes(&store, &knowledge);
            let result = prune_with_knowledge(&store, &knowledge, &policy, apply, true)?;
            let after = combined_archive_size_bytes(&store, &knowledge);
            Ok((result, before, after))
        },
    )
    .await;
    match result {
        Ok(Ok((result, before_size, after_size))) => {
            if result.applied && result.has_deletions() {
                state.metrics.record_conversation_compaction(
                    result.deleted_sessions_total(),
                    result.deleted_diary_entries,
                    result.deleted_hook_events,
                    result.deleted_knowledge_facts,
                    before_size.saturating_sub(after_size),
                );
            }
            update_conversation_archive_metric(&state, &conversations);
            info!(
                target: "docdexd",
                request_id = %request_id.0,
                scope = %scope_label,
                latency_ms = started.elapsed().as_millis(),
                applied = result.applied,
                deleted_manual_sessions = result.deleted_manual_sessions,
                deleted_auto_sessions = result.deleted_auto_sessions,
                deleted_diary_entries = result.deleted_diary_entries,
                deleted_hook_events = result.deleted_hook_events,
                deleted_knowledge_facts = result.deleted_knowledge_facts,
                "conversation prune succeeded"
            );
            log_conversation_audit(
                &state,
                "conversation.prune",
                if result.applied { "ok" } else { "dry_run" },
                &request_id.0,
                "/v1/conversations/prune",
                "POST",
                StatusCode::OK,
                format!(
                    "scope={} applied={} manual_sessions={} auto_sessions={} diary_entries={} hook_events={} knowledge_facts={}",
                    scope_id,
                    result.applied,
                    result.deleted_manual_sessions,
                    result.deleted_auto_sessions,
                    result.deleted_diary_entries,
                    result.deleted_hook_events,
                    result.deleted_knowledge_facts
                ),
            );
            Json(ConversationPruneResponse { result }).into_response()
        }
        Ok(Err(err)) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                request_id = %request_id.0,
                error = ?err,
                "conversation prune failed"
            );
            log_conversation_audit(
                &state,
                "conversation.prune",
                "error",
                &request_id.0,
                "/v1/conversations/prune",
                "POST",
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("scope={} error={}", scope_id, err),
            );
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "conversation prune failed",
            )
        }
        Err(err) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                request_id = %request_id.0,
                error = ?err,
                "conversation prune task join failed"
            );
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "conversation prune failed",
            )
        }
    }
}

pub(crate) async fn conversation_delete_handler(
    State(state): State<AppState>,
    axum::extract::Extension(request_id): axum::extract::Extension<RequestId>,
    headers: HeaderMap,
    Query(repo_id): Query<RepoIdQuery>,
    AxumPath(session_id): AxumPath<String>,
) -> impl IntoResponse {
    let scope = match resolve_conversation_context(
        &state,
        &headers,
        repo_id.repo_id.as_deref(),
        None,
        repo_id.conversation_namespace.as_deref(),
        None,
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
    let session_id = session_id.trim().to_string();
    if session_id.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "session_id must not be empty",
        );
    }
    let started = Instant::now();
    let scope_label = scope.scope_label();
    let scope_id = scope.scope_id();
    let store = conversations.store.clone();
    let knowledge = conversations.knowledge.clone();
    let session_id_for_task = session_id.clone();
    match tokio::task::spawn_blocking(move || -> anyhow::Result<bool> {
        let deleted = store.delete_session(&session_id_for_task)?;
        if deleted {
            let _ = knowledge.delete_facts_for_session(&session_id_for_task)?;
        }
        Ok(deleted)
    })
    .await
    {
        Ok(Ok(true)) => {
            update_conversation_archive_metric(&state, &conversations);
            info!(
                target: "docdexd",
                request_id = %request_id.0,
                scope = %scope_label,
                latency_ms = started.elapsed().as_millis(),
                session_id = %session_id,
                "conversation delete succeeded"
            );
            log_conversation_audit(
                &state,
                "conversation.delete",
                "ok",
                &request_id.0,
                "/v1/conversations/:session_id",
                "DELETE",
                StatusCode::OK,
                format!("scope={} session_id={}", scope_id, session_id),
            );
            Json(ConversationDeleteResponse {
                session_id,
                deleted: true,
            })
            .into_response()
        }
        Ok(Ok(false)) => json_error_with_details(
            StatusCode::NOT_FOUND,
            ERR_CONVERSATION_NOT_FOUND,
            "conversation session not found",
            serde_json::json!({ "session_id": session_id }),
        ),
        Ok(Err(err)) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                request_id = %request_id.0,
                error = ?err,
                "conversation delete failed"
            );
            log_conversation_audit(
                &state,
                "conversation.delete",
                "error",
                &request_id.0,
                "/v1/conversations/:session_id",
                "DELETE",
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("scope={} session_id={} error={}", scope_id, session_id, err),
            );
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "conversation delete failed",
            )
        }
        Err(err) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                request_id = %request_id.0,
                error = ?err,
                "conversation delete task join failed"
            );
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "conversation delete failed",
            )
        }
    }
}

pub(crate) fn map_import_messages(
    messages: Option<Vec<ConversationImportMessage>>,
) -> Option<Vec<ConversationMessage>> {
    messages.map(|messages| {
        messages
            .into_iter()
            .map(|item| ConversationMessage {
                role: ConversationRole::from_str(&item.role),
                content: item.content,
                author: item.author,
                created_at_ms: item.created_at_ms,
                metadata: item.metadata.unwrap_or_else(|| serde_json::json!({})),
            })
            .collect::<Vec<_>>()
    })
}

fn build_personal_preferences_import_capture_request(
    scope_id: String,
    scope_label: String,
    payload: &crate::conversations::ConversationImport,
) -> crate::personal_preferences::PersonalPreferencesCaptureRequest {
    crate::personal_preferences::PersonalPreferencesCaptureRequest {
        source: payload.source.clone(),
        source_session_id: payload.source_session_id.clone(),
        capture_kind: Some("conversation_import".to_string()),
        title: payload.title.clone(),
        agent_id: payload.agent_id.clone(),
        transport: payload.transport.clone(),
        repo_id: Some(scope_id.clone()),
        repo_root: Some(scope_label.clone()),
        scope_id: Some(scope_id),
        scope_label: Some(scope_label),
        started_at_ms: payload.started_at_ms,
        ended_at_ms: payload.ended_at_ms,
        messages: payload
            .messages
            .clone()
            .into_iter()
            .map(
                |message| crate::personal_preferences::PersonalPreferencesMessage {
                    role: message.role.as_str().to_string(),
                    content: message.content,
                    created_at_ms: message.created_at_ms,
                    metadata: message.metadata,
                },
            )
            .collect(),
        transcript_text: None,
        summary_text: None,
        metadata: payload.metadata.clone(),
    }
}

fn log_conversation_audit(
    state: &AppState,
    event: &str,
    outcome: &str,
    request_id: &str,
    path: &str,
    method: &str,
    status: StatusCode,
    detail: String,
) {
    if let Some(audit) = state.audit.as_ref() {
        audit.log(
            event,
            outcome,
            Some(request_id),
            Some(path),
            Some(method),
            Some(status.as_u16()),
            None,
            Some(&detail),
        );
    }
}

fn update_conversation_archive_metric(
    state: &AppState,
    conversations: &crate::search::ConversationState,
) {
    let repo_total = state
        .repos
        .as_ref()
        .map(|repos| repos.conversation_archive_size_bytes_total())
        .unwrap_or_else(|| {
            combined_archive_size_bytes(&conversations.store, &conversations.knowledge)
        });
    let namespace_base_dir = if state.repos.is_some() {
        None
    } else {
        state.global_state_dir.clone().or_else(|| {
            crate::repo_manager::split_scoped_state_dir(state.indexer.state_dir())
                .map(|(base_dir, _, _)| base_dir)
        })
    };
    state.metrics.set_conversation_archive_size_bytes(
        crate::conversations::archive_size_bytes_total(repo_total, namespace_base_dir.as_deref()),
    );
}
