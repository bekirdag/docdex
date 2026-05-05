use crate::conversations::{
    delete_diary_entry, read_diary_entries, record_diary_entry_episode, write_diary_entry,
};
use crate::error::{ERR_INTERNAL_ERROR, ERR_INVALID_ARGUMENT, ERR_MEMORY_DISABLED};
use crate::http_api::{json_error, repo_error_response, resolve_conversation_context};
use crate::search::{AppState, RepoIdQuery, RequestId};
use axum::{
    extract::{Query, State},
    http::HeaderMap,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use serde_json::Value;
use std::time::Instant;
use tracing::{info, warn};

const DEFAULT_DIARY_LIMIT: usize = 20;
const MAX_DIARY_LIMIT: usize = 100;

#[derive(Deserialize)]
pub struct DiaryWriteRequest {
    #[serde(default)]
    pub agent_id: Option<String>,
    pub content: String,
    #[serde(default)]
    pub entry_type: Option<String>,
    #[serde(default)]
    pub source_session_id: Option<String>,
    #[serde(default)]
    pub metadata: Option<Value>,
    #[serde(default)]
    pub repo_id: Option<String>,
    #[serde(default, alias = "namespace")]
    pub conversation_namespace: Option<String>,
}

#[derive(Deserialize)]
pub struct DiaryReadQuery {
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
pub struct DiaryDeleteRequest {
    #[serde(default, alias = "id")]
    pub entry_id: Option<String>,
    #[serde(default)]
    pub repo_id: Option<String>,
    #[serde(default, alias = "namespace")]
    pub conversation_namespace: Option<String>,
}

pub(crate) async fn diary_write_handler(
    State(state): State<AppState>,
    axum::extract::Extension(request_id): axum::extract::Extension<RequestId>,
    headers: HeaderMap,
    Query(repo_id): Query<RepoIdQuery>,
    Json(req): Json<DiaryWriteRequest>,
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
            axum::http::StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            "conversation memory is disabled; enable [memory.conversations].enabled",
        );
    };
    let entry_type = req
        .entry_type
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("note")
        .to_string();
    if req.content.trim().is_empty() {
        return json_error(
            axum::http::StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "content must not be empty",
        );
    }
    let started = Instant::now();
    let scope_label = scope.scope_label();
    match write_diary_entry(
        conversations.store.clone(),
        req.agent_id.or_else(|| state.default_agent_id.clone()),
        entry_type,
        req.content,
        req.source_session_id,
        req.metadata.unwrap_or_else(|| serde_json::json!({})),
    )
    .await
    {
        Ok(entry) => {
            if let Err(err) =
                record_diary_entry_episode(conversations.knowledge.clone(), entry.clone()).await
            {
                state.metrics.inc_error();
                warn!(
                    target: "docdexd",
                    request_id = %request_id.0,
                    error = ?err,
                    "diary write episode projection failed"
                );
                return json_error(
                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    ERR_INTERNAL_ERROR,
                    "diary write failed",
                );
            }
            info!(
                target: "docdexd",
                request_id = %request_id.0,
                scope = %scope_label,
                latency_ms = started.elapsed().as_millis(),
                entry_id = %entry.entry_id,
                "diary write succeeded"
            );
            Json(entry).into_response()
        }
        Err(err) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                request_id = %request_id.0,
                error = ?err,
                "diary write failed"
            );
            json_error(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "diary write failed",
            )
        }
    }
}

pub(crate) async fn diary_read_handler(
    State(state): State<AppState>,
    axum::extract::Extension(request_id): axum::extract::Extension<RequestId>,
    headers: HeaderMap,
    Query(params): Query<DiaryReadQuery>,
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
            axum::http::StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            "conversation memory is disabled; enable [memory.conversations].enabled",
        );
    };
    if matches!(params.limit, Some(0)) {
        return json_error(
            axum::http::StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "limit must be greater than 0",
        );
    }
    let limit = params
        .limit
        .unwrap_or(DEFAULT_DIARY_LIMIT)
        .clamp(1, MAX_DIARY_LIMIT);
    let offset = params.offset.unwrap_or(0);
    let started = Instant::now();
    let scope_label = scope.scope_label();
    match read_diary_entries(conversations.store.clone(), params.agent_id, limit, offset).await {
        Ok(entries) => {
            info!(
                target: "docdexd",
                request_id = %request_id.0,
                scope = %scope_label,
                latency_ms = started.elapsed().as_millis(),
                returned = entries.entries.len(),
                total = entries.total,
                "diary read succeeded"
            );
            Json(entries).into_response()
        }
        Err(err) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                request_id = %request_id.0,
                error = ?err,
                "diary read failed"
            );
            json_error(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "diary read failed",
            )
        }
    }
}

pub(crate) async fn diary_delete_handler(
    State(state): State<AppState>,
    axum::extract::Extension(request_id): axum::extract::Extension<RequestId>,
    headers: HeaderMap,
    Query(repo_id): Query<RepoIdQuery>,
    Json(req): Json<DiaryDeleteRequest>,
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
            axum::http::StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            "conversation memory is disabled; enable [memory.conversations].enabled",
        );
    };
    let Some(entry_id) = req
        .entry_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
    else {
        return json_error(
            axum::http::StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "entry_id is required",
        );
    };
    let started = Instant::now();
    let scope_label = scope.scope_label();
    match delete_diary_entry(conversations.store.clone(), entry_id.clone()).await {
        Ok(deleted) => {
            info!(
                target: "docdexd",
                request_id = %request_id.0,
                scope = %scope_label,
                latency_ms = started.elapsed().as_millis(),
                entry_id = %entry_id,
                deleted,
                "diary delete succeeded"
            );
            Json(serde_json::json!({
                "entry_id": entry_id,
                "deleted": deleted
            }))
            .into_response()
        }
        Err(err) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                request_id = %request_id.0,
                error = ?err,
                "diary delete failed"
            );
            json_error(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "diary delete failed",
            )
        }
    }
}
