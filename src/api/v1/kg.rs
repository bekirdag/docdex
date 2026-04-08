use crate::error::{
    ERR_INTERNAL_ERROR, ERR_INVALID_ARGUMENT, ERR_KNOWLEDGE_EPISODE_NOT_FOUND, ERR_MEMORY_DISABLED,
};
use crate::search::{
    json_error, repo_error_response, resolve_conversation_context, AppState, RequestId,
};
use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use std::time::Instant;
use tracing::warn;

const DEFAULT_LIMIT: usize = 20;
const MAX_LIMIT: usize = 100;

#[derive(Debug, Deserialize)]
pub struct KgQueryRequest {
    #[serde(default, alias = "query")]
    pub q: Option<String>,
    #[serde(default)]
    pub relation: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub offset: Option<usize>,
    #[serde(default)]
    pub repo_id: Option<String>,
    #[serde(default, alias = "namespace")]
    pub conversation_namespace: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct KgTimelineRequest {
    pub entity: String,
    #[serde(default)]
    pub relation: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub repo_id: Option<String>,
    #[serde(default, alias = "namespace")]
    pub conversation_namespace: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct KgNodeSearchRequest {
    #[serde(default, alias = "query")]
    pub q: Option<String>,
    #[serde(default)]
    pub entity_type: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub offset: Option<usize>,
    #[serde(default)]
    pub repo_id: Option<String>,
    #[serde(default, alias = "namespace")]
    pub conversation_namespace: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct KgEdgeSearchRequest {
    #[serde(default, alias = "query")]
    pub q: Option<String>,
    #[serde(default)]
    pub relation: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub offset: Option<usize>,
    #[serde(default)]
    pub repo_id: Option<String>,
    #[serde(default, alias = "namespace")]
    pub conversation_namespace: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct KgEpisodeSearchRequest {
    #[serde(default, alias = "query")]
    pub q: Option<String>,
    #[serde(default)]
    pub source_type: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub offset: Option<usize>,
    #[serde(default)]
    pub repo_id: Option<String>,
    #[serde(default, alias = "namespace")]
    pub conversation_namespace: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct KgNeighborhoodRequest {
    pub entity: String,
    #[serde(default)]
    pub relation: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub repo_id: Option<String>,
    #[serde(default, alias = "namespace")]
    pub conversation_namespace: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct KgEntityLinksRequest {
    pub entity: String,
    #[serde(default)]
    pub link_type: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub repo_id: Option<String>,
    #[serde(default, alias = "namespace")]
    pub conversation_namespace: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct KgEpisodeRequest {
    #[serde(alias = "id")]
    pub episode_id: String,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub repo_id: Option<String>,
    #[serde(default, alias = "namespace")]
    pub conversation_namespace: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct KgDeleteEdgeRequest {
    #[serde(alias = "id")]
    pub edge_id: String,
    #[serde(default)]
    pub repo_id: Option<String>,
    #[serde(default, alias = "namespace")]
    pub conversation_namespace: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct KgDeleteEpisodeRequest {
    #[serde(alias = "id")]
    pub episode_id: String,
    #[serde(default)]
    pub repo_id: Option<String>,
    #[serde(default, alias = "namespace")]
    pub conversation_namespace: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct KgMaintenanceRequest {
    #[serde(default)]
    pub repo_id: Option<String>,
    #[serde(default, alias = "namespace")]
    pub conversation_namespace: Option<String>,
}

pub(crate) async fn kg_query_handler(
    State(state): State<AppState>,
    axum::extract::Extension(request_id): axum::extract::Extension<RequestId>,
    headers: HeaderMap,
    Query(params): Query<KgQueryRequest>,
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
    let relation = params
        .relation
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let limit = params.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let offset = params.offset.unwrap_or(0);
    let knowledge = conversations.knowledge.clone();
    let query_for_task = query.clone();
    let started = Instant::now();
    let scope_label = scope.scope_label();
    match tokio::task::spawn_blocking(move || {
        knowledge.query_facts(&query_for_task, relation.as_deref(), limit, offset)
    })
    .await
    {
        Ok(Ok(result)) => {
            tracing::info!(
                target: "docdexd",
                request_id = %request_id.0,
                scope = %scope_label,
                latency_ms = started.elapsed().as_millis(),
                returned = result.facts.len(),
                total = result.total,
                "kg query succeeded"
            );
            Json(result).into_response()
        }
        Ok(Err(err)) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                request_id = %request_id.0,
                error = ?err,
                "kg query failed"
            );
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "kg query failed",
            )
        }
        Err(err) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                request_id = %request_id.0,
                error = ?err,
                "kg query task join failed"
            );
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "kg query failed",
            )
        }
    }
}

pub(crate) async fn kg_search_nodes_handler(
    State(state): State<AppState>,
    axum::extract::Extension(request_id): axum::extract::Extension<RequestId>,
    headers: HeaderMap,
    Query(params): Query<KgNodeSearchRequest>,
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
    let entity_type = params
        .entity_type
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let limit = params.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let offset = params.offset.unwrap_or(0);
    let knowledge = conversations.knowledge.clone();
    let query_for_task = query.clone();
    let started = Instant::now();
    let scope_label = scope.scope_label();
    match tokio::task::spawn_blocking(move || {
        knowledge.search_nodes(&query_for_task, entity_type.as_deref(), limit, offset)
    })
    .await
    {
        Ok(Ok(result)) => {
            tracing::info!(
                target: "docdexd",
                request_id = %request_id.0,
                scope = %scope_label,
                latency_ms = started.elapsed().as_millis(),
                returned = result.nodes.len(),
                total = result.total,
                "kg node search succeeded"
            );
            Json(result).into_response()
        }
        Ok(Err(err)) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                request_id = %request_id.0,
                error = ?err,
                "kg node search failed"
            );
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "kg node search failed",
            )
        }
        Err(err) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                request_id = %request_id.0,
                error = ?err,
                "kg node search task join failed"
            );
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "kg node search failed",
            )
        }
    }
}

pub(crate) async fn kg_search_edges_handler(
    State(state): State<AppState>,
    axum::extract::Extension(request_id): axum::extract::Extension<RequestId>,
    headers: HeaderMap,
    Query(params): Query<KgEdgeSearchRequest>,
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
    let relation = params
        .relation
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let limit = params.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let offset = params.offset.unwrap_or(0);
    let knowledge = conversations.knowledge.clone();
    let query_for_task = query.clone();
    let started = Instant::now();
    let scope_label = scope.scope_label();
    match tokio::task::spawn_blocking(move || {
        knowledge.search_edges(&query_for_task, relation.as_deref(), limit, offset)
    })
    .await
    {
        Ok(Ok(result)) => {
            tracing::info!(
                target: "docdexd",
                request_id = %request_id.0,
                scope = %scope_label,
                latency_ms = started.elapsed().as_millis(),
                returned = result.edges.len(),
                total = result.total,
                "kg edge search succeeded"
            );
            Json(result).into_response()
        }
        Ok(Err(err)) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                request_id = %request_id.0,
                error = ?err,
                "kg edge search failed"
            );
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "kg edge search failed",
            )
        }
        Err(err) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                request_id = %request_id.0,
                error = ?err,
                "kg edge search task join failed"
            );
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "kg edge search failed",
            )
        }
    }
}

pub(crate) async fn kg_search_episodes_handler(
    State(state): State<AppState>,
    axum::extract::Extension(request_id): axum::extract::Extension<RequestId>,
    headers: HeaderMap,
    Query(params): Query<KgEpisodeSearchRequest>,
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
    let source_type = params
        .source_type
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let limit = params.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let offset = params.offset.unwrap_or(0);
    let knowledge = conversations.knowledge.clone();
    let query_for_task = query.clone();
    let started = Instant::now();
    let scope_label = scope.scope_label();
    match tokio::task::spawn_blocking(move || {
        knowledge.search_episodes(&query_for_task, source_type.as_deref(), limit, offset)
    })
    .await
    {
        Ok(Ok(result)) => {
            tracing::info!(
                target: "docdexd",
                request_id = %request_id.0,
                scope = %scope_label,
                latency_ms = started.elapsed().as_millis(),
                returned = result.episodes.len(),
                total = result.total,
                "kg episode search succeeded"
            );
            Json(result).into_response()
        }
        Ok(Err(err)) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                request_id = %request_id.0,
                error = ?err,
                "kg episode search failed"
            );
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "kg episode search failed",
            )
        }
        Err(err) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                request_id = %request_id.0,
                error = ?err,
                "kg episode search task join failed"
            );
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "kg episode search failed",
            )
        }
    }
}

pub(crate) async fn kg_timeline_handler(
    State(state): State<AppState>,
    axum::extract::Extension(request_id): axum::extract::Extension<RequestId>,
    headers: HeaderMap,
    Query(params): Query<KgTimelineRequest>,
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
    let entity = params.entity.trim().to_string();
    if entity.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "entity must not be empty",
        );
    }
    if matches!(params.limit, Some(0)) {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "limit must be greater than 0",
        );
    }
    let relation = params
        .relation
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let limit = params.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let knowledge = conversations.knowledge.clone();
    let entity_for_task = entity.clone();
    let started = Instant::now();
    let scope_label = scope.scope_label();
    match tokio::task::spawn_blocking(move || {
        knowledge.timeline_for_entity(&entity_for_task, relation.as_deref(), limit)
    })
    .await
    {
        Ok(Ok(result)) => {
            tracing::info!(
                target: "docdexd",
                request_id = %request_id.0,
                scope = %scope_label,
                latency_ms = started.elapsed().as_millis(),
                returned = result.events.len(),
                total = result.total,
                "kg timeline succeeded"
            );
            Json(result).into_response()
        }
        Ok(Err(err)) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                request_id = %request_id.0,
                error = ?err,
                "kg timeline failed"
            );
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "kg timeline failed",
            )
        }
        Err(err) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                request_id = %request_id.0,
                error = ?err,
                "kg timeline task join failed"
            );
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "kg timeline failed",
            )
        }
    }
}

pub(crate) async fn kg_neighborhood_handler(
    State(state): State<AppState>,
    axum::extract::Extension(request_id): axum::extract::Extension<RequestId>,
    headers: HeaderMap,
    Query(params): Query<KgNeighborhoodRequest>,
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
    let entity = params.entity.trim().to_string();
    if entity.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "entity must not be empty",
        );
    }
    if matches!(params.limit, Some(0)) {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "limit must be greater than 0",
        );
    }
    let relation = params
        .relation
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let limit = params.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let knowledge = conversations.knowledge.clone();
    let entity_for_task = entity.clone();
    let started = Instant::now();
    let scope_label = scope.scope_label();
    match tokio::task::spawn_blocking(move || {
        knowledge.neighborhood_for_entity(&entity_for_task, relation.as_deref(), limit)
    })
    .await
    {
        Ok(Ok(result)) => {
            tracing::info!(
                target: "docdexd",
                request_id = %request_id.0,
                scope = %scope_label,
                latency_ms = started.elapsed().as_millis(),
                returned = result.edges.len(),
                total = result.total,
                "kg neighborhood succeeded"
            );
            Json(result).into_response()
        }
        Ok(Err(err)) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                request_id = %request_id.0,
                error = ?err,
                "kg neighborhood failed"
            );
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "kg neighborhood failed",
            )
        }
        Err(err) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                request_id = %request_id.0,
                error = ?err,
                "kg neighborhood task join failed"
            );
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "kg neighborhood failed",
            )
        }
    }
}

pub(crate) async fn kg_episode_handler(
    State(state): State<AppState>,
    axum::extract::Extension(request_id): axum::extract::Extension<RequestId>,
    headers: HeaderMap,
    Query(params): Query<KgEpisodeRequest>,
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
    let episode_id = params.episode_id.trim().to_string();
    if episode_id.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "episode_id must not be empty",
        );
    }
    if matches!(params.limit, Some(0)) {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "limit must be greater than 0",
        );
    }
    let limit = params.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let knowledge = conversations.knowledge.clone();
    let episode_id_for_task = episode_id.clone();
    let started = Instant::now();
    let scope_label = scope.scope_label();
    match tokio::task::spawn_blocking(move || {
        knowledge.episode_details(&episode_id_for_task, limit)
    })
    .await
    {
        Ok(Ok(Some(result))) => {
            tracing::info!(
                target: "docdexd",
                request_id = %request_id.0,
                scope = %scope_label,
                latency_ms = started.elapsed().as_millis(),
                returned = result.edges.len(),
                total = result.total_edges,
                "kg episode fetch succeeded"
            );
            Json(result).into_response()
        }
        Ok(Ok(None)) => json_error(
            StatusCode::NOT_FOUND,
            ERR_KNOWLEDGE_EPISODE_NOT_FOUND,
            "knowledge episode not found",
        ),
        Ok(Err(err)) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                request_id = %request_id.0,
                error = ?err,
                "kg episode fetch failed"
            );
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "kg episode fetch failed",
            )
        }
        Err(err) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                request_id = %request_id.0,
                error = ?err,
                "kg episode fetch task join failed"
            );
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "kg episode fetch failed",
            )
        }
    }
}

pub(crate) async fn kg_entity_links_handler(
    State(state): State<AppState>,
    axum::extract::Extension(request_id): axum::extract::Extension<RequestId>,
    headers: HeaderMap,
    Query(params): Query<KgEntityLinksRequest>,
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
    let entity = match params
        .entity
        .trim()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .trim()
    {
        "" => {
            return json_error(
                StatusCode::BAD_REQUEST,
                ERR_INVALID_ARGUMENT,
                "entity must not be empty",
            );
        }
        value => value.to_string(),
    };
    if matches!(params.limit, Some(0)) {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "limit must be greater than 0",
        );
    }
    let link_type = params
        .link_type
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let limit = params.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let knowledge = conversations.knowledge.clone();
    let entity_for_task = entity.clone();
    let started = Instant::now();
    let scope_label = scope.scope_label();
    match tokio::task::spawn_blocking(move || {
        knowledge.entity_links_for_entity(&entity_for_task, link_type.as_deref(), limit)
    })
    .await
    {
        Ok(Ok(result)) => {
            tracing::info!(
                target: "docdexd",
                request_id = %request_id.0,
                scope = %scope_label,
                latency_ms = started.elapsed().as_millis(),
                returned = result.links.len(),
                total = result.total,
                "kg entity links succeeded"
            );
            Json(result).into_response()
        }
        Ok(Err(err)) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                request_id = %request_id.0,
                error = ?err,
                "kg entity links failed"
            );
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "kg entity links failed",
            )
        }
        Err(err) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                request_id = %request_id.0,
                error = ?err,
                "kg entity links task join failed"
            );
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "kg entity links failed",
            )
        }
    }
}

pub(crate) async fn kg_delete_edge_handler(
    State(state): State<AppState>,
    axum::extract::Extension(request_id): axum::extract::Extension<RequestId>,
    headers: HeaderMap,
    Json(req): Json<KgDeleteEdgeRequest>,
) -> impl IntoResponse {
    let scope = match resolve_conversation_context(
        &state,
        &headers,
        req.repo_id.as_deref(),
        None,
        req.conversation_namespace.as_deref(),
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
    let edge_id = req.edge_id.trim().to_string();
    if edge_id.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "edge_id must not be empty",
        );
    }
    let knowledge = conversations.knowledge.clone();
    let edge_id_for_task = edge_id.clone();
    let started = Instant::now();
    let scope_label = scope.scope_label();
    match tokio::task::spawn_blocking(move || knowledge.delete_edge(&edge_id_for_task)).await {
        Ok(Ok(result)) => {
            tracing::info!(
                target: "docdexd",
                request_id = %request_id.0,
                scope = %scope_label,
                latency_ms = started.elapsed().as_millis(),
                deleted = result.deleted,
                "kg edge delete succeeded"
            );
            Json(result).into_response()
        }
        Ok(Err(err)) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                request_id = %request_id.0,
                error = ?err,
                "kg edge delete failed"
            );
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "kg edge delete failed",
            )
        }
        Err(err) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                request_id = %request_id.0,
                error = ?err,
                "kg edge delete task join failed"
            );
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "kg edge delete failed",
            )
        }
    }
}

pub(crate) async fn kg_delete_episode_handler(
    State(state): State<AppState>,
    axum::extract::Extension(request_id): axum::extract::Extension<RequestId>,
    headers: HeaderMap,
    Json(req): Json<KgDeleteEpisodeRequest>,
) -> impl IntoResponse {
    let scope = match resolve_conversation_context(
        &state,
        &headers,
        req.repo_id.as_deref(),
        None,
        req.conversation_namespace.as_deref(),
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
    let episode_id = req.episode_id.trim().to_string();
    if episode_id.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "episode_id must not be empty",
        );
    }
    let knowledge = conversations.knowledge.clone();
    let episode_id_for_task = episode_id.clone();
    let started = Instant::now();
    let scope_label = scope.scope_label();
    match tokio::task::spawn_blocking(move || knowledge.delete_episode(&episode_id_for_task)).await
    {
        Ok(Ok(result)) => {
            tracing::info!(
                target: "docdexd",
                request_id = %request_id.0,
                scope = %scope_label,
                latency_ms = started.elapsed().as_millis(),
                deleted = result.deleted,
                "kg episode delete succeeded"
            );
            Json(result).into_response()
        }
        Ok(Err(err)) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                request_id = %request_id.0,
                error = ?err,
                "kg episode delete failed"
            );
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "kg episode delete failed",
            )
        }
        Err(err) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                request_id = %request_id.0,
                error = ?err,
                "kg episode delete task join failed"
            );
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "kg episode delete failed",
            )
        }
    }
}

pub(crate) async fn kg_rebuild_handler(
    State(state): State<AppState>,
    axum::extract::Extension(request_id): axum::extract::Extension<RequestId>,
    headers: HeaderMap,
    Json(req): Json<KgMaintenanceRequest>,
) -> impl IntoResponse {
    let scope = match resolve_conversation_context(
        &state,
        &headers,
        req.repo_id.as_deref(),
        None,
        req.conversation_namespace.as_deref(),
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
    let knowledge = conversations.knowledge.clone();
    let started = Instant::now();
    let scope_label = scope.scope_label();
    match tokio::task::spawn_blocking(move || knowledge.rebuild()).await {
        Ok(Ok(result)) => {
            tracing::info!(
                target: "docdexd",
                request_id = %request_id.0,
                scope = %scope_label,
                latency_ms = started.elapsed().as_millis(),
                "kg rebuild succeeded"
            );
            Json(result).into_response()
        }
        Ok(Err(err)) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                request_id = %request_id.0,
                error = ?err,
                "kg rebuild failed"
            );
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "kg rebuild failed",
            )
        }
        Err(err) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                request_id = %request_id.0,
                error = ?err,
                "kg rebuild task join failed"
            );
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "kg rebuild failed",
            )
        }
    }
}

pub(crate) async fn kg_clear_handler(
    State(state): State<AppState>,
    axum::extract::Extension(request_id): axum::extract::Extension<RequestId>,
    headers: HeaderMap,
    Json(req): Json<KgMaintenanceRequest>,
) -> impl IntoResponse {
    let scope = match resolve_conversation_context(
        &state,
        &headers,
        req.repo_id.as_deref(),
        None,
        req.conversation_namespace.as_deref(),
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
    let knowledge = conversations.knowledge.clone();
    let started = Instant::now();
    let scope_label = scope.scope_label();
    match tokio::task::spawn_blocking(move || knowledge.clear()).await {
        Ok(Ok(result)) => {
            tracing::info!(
                target: "docdexd",
                request_id = %request_id.0,
                scope = %scope_label,
                latency_ms = started.elapsed().as_millis(),
                "kg clear succeeded"
            );
            Json(result).into_response()
        }
        Ok(Err(err)) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                request_id = %request_id.0,
                error = ?err,
                "kg clear failed"
            );
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "kg clear failed",
            )
        }
        Err(err) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                request_id = %request_id.0,
                error = ?err,
                "kg clear task join failed"
            );
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "kg clear failed",
            )
        }
    }
}
