use axum::{
    extract::{Path as AxumPath, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fs,
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tracing::warn;
use uuid::Uuid;

use crate::auth::RepoOperation;
use crate::error::{ERR_INTERNAL_ERROR, ERR_INVALID_ARGUMENT, ERR_MEMORY_DISABLED};
use crate::http_api::{json_error, repo_error_response, resolve_repo_context};
use crate::index::Indexer;
use crate::search::{
    authorize_encrypted_repo_http, AppState, RankingSurface, RepoIdQuery, RequestId,
};

const FILES_DEFAULT_LIMIT: usize = 200;
const FILES_MAX_LIMIT: usize = 1000;
const INDEX_MAX_PATHS: usize = 1000;

#[derive(Debug, Deserialize)]
pub(crate) struct TreeQuery {
    #[serde(default)]
    repo_id: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    max_depth: Option<usize>,
    #[serde(default)]
    dirs_only: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct FilesQuery {
    #[serde(default)]
    repo_id: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    offset: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RepoOnlyQuery {
    #[serde(default)]
    repo_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct IndexCompatRequest {
    #[serde(default)]
    repo_id: Option<String>,
    #[serde(default)]
    paths: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct IndexDeleteCompatRequest {
    #[serde(default)]
    repo_id: Option<String>,
    #[serde(default)]
    paths: Vec<String>,
    #[serde(default)]
    delete_source: bool,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) struct IndexDeleteCompatResponse {
    repo_id: String,
    paths_total: usize,
    paths_deleted: usize,
    paths_failed: usize,
    errors: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct IndexJobQuery {
    #[serde(default)]
    repo_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub(crate) struct IndexJobStatus {
    job_id: String,
    repo_id: String,
    operation: String,
    status: String,
    queued_at_epoch_ms: u128,
    started_at_epoch_ms: Option<u128>,
    finished_at_epoch_ms: Option<u128>,
    paths_total: usize,
    paths_indexed: usize,
    #[serde(default)]
    paths_skipped: usize,
    paths_failed: usize,
    errors: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RagRequest {
    query: String,
    #[serde(default)]
    repo_id: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    include_libs: Option<bool>,
    #[serde(default)]
    context: Option<Value>,
}

pub(crate) async fn tree_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<TreeQuery>,
) -> Response {
    let repo = match super::shared::resolve_repo_with_index(
        &state,
        &headers,
        params.repo_id.as_deref(),
        None,
        false,
    )
    .await
    {
        Ok(repo) => repo,
        Err(response) => return response,
    };
    let rel_path = match normalize_optional_rel_path(params.path.as_deref()) {
        Ok(path) => path,
        Err(response) => return response,
    };
    let root = match tree_root(repo.indexer.repo_root(), rel_path.as_deref()) {
        Ok(path) => path,
        Err(response) => return response,
    };
    let options = crate::tree::TreeOptions {
        max_depth: params.max_depth.map(|value| value.clamp(1, 20)),
        dirs_only: params.dirs_only.unwrap_or(false),
        include_hidden: false,
        extra_excludes: Vec::new(),
    };
    match crate::tree::render_tree(&root, &options) {
        Ok(output) => Json(json!({
            "repo_id": repo.repo_id,
            "path": rel_path
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_default(),
            "tree": strip_symlink_targets(&output.tree),
            "excludes": output.excludes,
            "max_depth": options.max_depth,
            "dirs_only": options.dirs_only
        }))
        .into_response(),
        Err(err) => {
            state.metrics.inc_error();
            warn!(target: "docdexd", error = ?err, "tree render failed");
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "tree render failed",
            )
        }
    }
}

pub(crate) async fn files_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<FilesQuery>,
) -> Response {
    let repo = match super::shared::resolve_repo_with_index(
        &state,
        &headers,
        params.repo_id.as_deref(),
        None,
        false,
    )
    .await
    {
        Ok(repo) => repo,
        Err(response) => return response,
    };
    let limit = params
        .limit
        .unwrap_or(FILES_DEFAULT_LIMIT)
        .clamp(1, FILES_MAX_LIMIT);
    let offset = params.offset.unwrap_or(0);
    match repo.indexer.list_docs(offset, limit) {
        Ok((docs, total)) => Json(json!({
            "repo_id": repo.repo_id,
            "results": docs,
            "files": docs,
            "total": total,
            "limit": limit,
            "offset": offset
        }))
        .into_response(),
        Err(err) => {
            state.metrics.inc_error();
            warn!(target: "docdexd", error = ?err, "indexed file listing failed");
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "indexed file listing failed",
            )
        }
    }
}

pub(crate) async fn stats_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<RepoOnlyQuery>,
) -> Response {
    let repo = match resolve_repo_context(&state, &headers, params.repo_id.as_deref(), None, false)
    {
        Ok(repo) => repo,
        Err(err) => return repo_error_response(err),
    };
    let indexing_in_progress = match repo.indexer.indexing_in_progress() {
        Ok(value) => value,
        Err(err) => {
            state.metrics.inc_error();
            warn!(target: "docdexd", error = ?err, "index status lookup failed");
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "index status lookup failed",
            );
        }
    };
    let stats = repo.indexer.stats().ok();
    Json(json!({
        "repo_id": repo.repo_id,
        "status": if repo.indexer.index_ready() { "ready" } else if indexing_in_progress { "indexing" } else { "missing" },
        "ready": repo.indexer.index_ready(),
        "indexing_in_progress": indexing_in_progress,
        "num_docs": stats.as_ref().map(|value| value.num_docs),
        "index_size_bytes": stats.as_ref().map(|value| value.index_size_bytes),
        "segments": stats.as_ref().map(|value| value.segments),
        "avg_bytes_per_doc": stats.as_ref().map(|value| value.avg_bytes_per_doc),
        "generated_at_epoch_ms": stats.as_ref().map(|value| value.generated_at_epoch_ms),
        "last_updated_epoch_ms": stats.as_ref().and_then(|value| value.last_updated_epoch_ms)
    }))
    .into_response()
}

pub(crate) async fn repo_inspect_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<RepoOnlyQuery>,
) -> Response {
    let repo = match resolve_repo_context(&state, &headers, params.repo_id.as_deref(), None, false)
    {
        Ok(repo) => repo,
        Err(err) => return repo_error_response(err),
    };
    let status = match crate::repo_manager::inspect_repo(
        repo.indexer.repo_root(),
        Some(repo.indexer.state_dir()),
    ) {
        Ok(report) => serde_json::to_value(report.status).unwrap_or_else(|_| json!("unknown")),
        Err(err) => {
            state.metrics.inc_error();
            warn!(target: "docdexd", error = ?err, "repo inspect failed");
            json!("unknown")
        }
    };
    Json(json!({
        "repo_id": repo.repo_id,
        "legacy_repo_id": repo.legacy_repo_id,
        "status": status,
        "ready": repo.indexer.index_ready(),
        "indexing_in_progress": repo.indexer.indexing_in_progress().unwrap_or(false)
    }))
    .into_response()
}

pub(crate) async fn index_compat_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<IndexCompatRequest>,
) -> Response {
    let repo = match resolve_repo_context(&state, &headers, None, payload.repo_id.as_deref(), false)
    {
        Ok(repo) => repo,
        Err(err) => return repo_error_response(err),
    };
    if let Err(response) = super::shared::ensure_repo_index_writable(&repo) {
        return response;
    }
    let paths = match normalize_index_paths(&payload.paths) {
        Ok(paths) => paths,
        Err(response) => return response,
    };
    let job_id = Uuid::new_v4().to_string();
    let operation = if paths.is_empty() {
        "reindex_all"
    } else {
        "ingest_paths"
    };
    let status = IndexJobStatus {
        job_id: job_id.clone(),
        repo_id: repo.repo_id.clone(),
        operation: operation.to_string(),
        status: "queued".to_string(),
        queued_at_epoch_ms: now_epoch_ms(),
        started_at_epoch_ms: None,
        finished_at_epoch_ms: None,
        paths_total: paths.len(),
        paths_indexed: 0,
        paths_skipped: 0,
        paths_failed: 0,
        errors: Vec::new(),
    };
    let jobs_dir = index_jobs_dir(repo.indexer.state_dir());
    if let Err(err) = write_index_job_status(&jobs_dir, &status) {
        state.metrics.inc_error();
        warn!(target: "docdexd", error = ?err, "index job status write failed");
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_INTERNAL_ERROR,
            "index job status write failed",
        );
    }
    spawn_index_job(
        repo.indexer.clone(),
        jobs_dir,
        status.clone(),
        paths,
        state.metrics.clone(),
    );
    Json(status).into_response()
}

pub(crate) async fn index_delete_compat_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<IndexDeleteCompatRequest>,
) -> Response {
    let repo = match resolve_repo_context(&state, &headers, None, payload.repo_id.as_deref(), false)
    {
        Ok(repo) => repo,
        Err(err) => return repo_error_response(err),
    };
    if let Err(response) = authorize_encrypted_repo_http(
        &state,
        &headers,
        &repo,
        RepoOperation::Index,
        None,
        "/v1/index/delete",
    )
    .await
    {
        return response;
    }
    if let Err(response) = super::shared::ensure_repo_index_writable(&repo) {
        return response;
    }
    let paths = match normalize_index_paths(&payload.paths) {
        Ok(paths) => paths,
        Err(response) => return response,
    };
    if paths.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "paths must include at least one repo-relative path",
        );
    }

    let mut response = IndexDeleteCompatResponse {
        repo_id: repo.repo_id.clone(),
        paths_total: paths.len(),
        paths_deleted: 0,
        paths_failed: 0,
        errors: Vec::new(),
    };
    let repo_root = repo.indexer.repo_root().to_path_buf();
    for rel_path in paths {
        let full_path = repo_root.join(&rel_path);
        if payload.delete_source {
            match tokio::fs::remove_file(&full_path).await {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                Err(err) => {
                    state.metrics.inc_error();
                    response.paths_failed += 1;
                    response.errors.push(format!(
                        "{}: failed to remove source file: {}",
                        rel_path.display(),
                        err
                    ));
                    continue;
                }
            }
        }
        match repo.indexer.delete_file(full_path).await {
            Ok(()) => response.paths_deleted += 1,
            Err(err) => {
                state.metrics.inc_error();
                response.paths_failed += 1;
                response.errors.push(format!(
                    "{}: {}",
                    rel_path.display(),
                    safe_error_message(&err)
                ));
            }
        }
    }

    Json(response).into_response()
}

pub(crate) async fn index_job_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(job_id): AxumPath<String>,
    Query(params): Query<IndexJobQuery>,
) -> Response {
    let repo = match resolve_repo_context(&state, &headers, params.repo_id.as_deref(), None, false)
    {
        Ok(repo) => repo,
        Err(err) => return repo_error_response(err),
    };
    let job_id = match safe_segment(&job_id) {
        Some(value) => value,
        None => {
            return json_error(
                StatusCode::BAD_REQUEST,
                ERR_INVALID_ARGUMENT,
                "job_id is invalid",
            )
        }
    };
    let path = index_jobs_dir(repo.indexer.state_dir()).join(format!("{job_id}.json"));
    match fs::read_to_string(path) {
        Ok(content) => match serde_json::from_str::<IndexJobStatus>(&content) {
            Ok(status) if status.repo_id == repo.repo_id => Json(status).into_response(),
            Ok(_) => json_error(StatusCode::NOT_FOUND, "not_found", "index job not found"),
            Err(err) => {
                state.metrics.inc_error();
                warn!(target: "docdexd", error = ?err, "index job status parse failed");
                json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ERR_INTERNAL_ERROR,
                    "index job status parse failed",
                )
            }
        },
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            json_error(StatusCode::NOT_FOUND, "not_found", "index job not found")
        }
        Err(err) => {
            state.metrics.inc_error();
            warn!(target: "docdexd", error = ?err, "index job status read failed");
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "index job status read failed",
            )
        }
    }
}

pub(crate) async fn rag_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<RagRequest>,
) -> Response {
    let query = payload.query.trim();
    if query.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "query is required",
        );
    }
    let repo = match super::shared::resolve_repo_with_index(
        &state,
        &headers,
        None,
        payload.repo_id.as_deref(),
        false,
    )
    .await
    {
        Ok(repo) => repo,
        Err(response) => return response,
    };
    let limit = payload.limit.unwrap_or(8).clamp(1, 50);
    match crate::search::run_query(
        &repo.indexer,
        if payload.include_libs.unwrap_or(false) {
            repo.libs_indexer.as_deref()
        } else {
            None
        },
        query,
        limit,
        RankingSurface::Search,
    )
    .await
    {
        Ok(search) => Json(json!({
            "repo_id": repo.repo_id,
            "query": query,
            "mode": "retrieval_only",
            "context": payload.context,
            "search": search
        }))
        .into_response(),
        Err(err) => {
            state.metrics.inc_error();
            warn!(target: "docdexd", error = ?err, "rag retrieval failed");
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "rag retrieval failed",
            )
        }
    }
}

pub(crate) async fn repo_memory_recall_alias_handler(
    State(state): State<AppState>,
    request_id: axum::extract::Extension<RequestId>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let mut body = body;
    if body.get("top_k").is_none() {
        if let Some(limit) = body.get("limit").cloned() {
            body["top_k"] = limit;
        }
    }
    super::super::super::search::memory_recall_handler(
        State(state),
        request_id,
        headers,
        Query(RepoIdQuery {
            repo_id: None,
            conversation_namespace: None,
        }),
        Json(match deserialize_body(body) {
            Ok(value) => value,
            Err(response) => return response,
        }),
    )
    .await
    .into_response()
}

pub(crate) async fn repo_memory_save_alias_handler(
    State(state): State<AppState>,
    request_id: axum::extract::Extension<RequestId>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let mut body = body;
    if body.get("text").is_none() {
        if let Some(content) = body.get("content").cloned() {
            body["text"] = content;
        }
    }
    super::super::super::search::memory_store_handler(
        State(state),
        request_id,
        headers,
        Query(RepoIdQuery {
            repo_id: None,
            conversation_namespace: None,
        }),
        Json(match deserialize_body(body) {
            Ok(value) => value,
            Err(response) => return response,
        }),
    )
    .await
    .into_response()
}

pub(crate) async fn repo_memory_delete_alias_handler(
    State(state): State<AppState>,
    request_id: axum::extract::Extension<RequestId>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    super::super::super::search::memory_delete_handler(
        State(state),
        request_id,
        headers,
        Query(RepoIdQuery {
            repo_id: None,
            conversation_namespace: None,
        }),
        Json(match deserialize_body(body) {
            Ok(value) => value,
            Err(response) => return response,
        }),
    )
    .await
    .into_response()
}

pub(crate) async fn profile_get_alias_handler(
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> Response {
    let params = match deserialize_body(body) {
        Ok(value) => value,
        Err(response) => return response,
    };
    super::profile::profile_list_handler(State(state), Query(params))
        .await
        .into_response()
}

pub(crate) async fn profile_save_alias_handler(
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> Response {
    let mut body = body;
    if body.get("category").is_none() {
        body["category"] = json!("workflow");
    }
    let payload = match deserialize_body(body) {
        Ok(value) => value,
        Err(response) => return response,
    };
    super::profile::profile_save_handler(State(state), Json(payload))
        .await
        .into_response()
}

pub(crate) async fn profile_delete_alias_handler(
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> Response {
    let payload = match deserialize_body(body) {
        Ok(value) => value,
        Err(response) => return response,
    };
    super::profile::profile_delete_handler(State(state), Json(payload))
        .await
        .into_response()
}

pub(crate) async fn personal_preferences_search_alias_handler(
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> Response {
    let params = match deserialize_body(body) {
        Ok(value) => value,
        Err(response) => return response,
    };
    super::personal_preferences::personal_preferences_search_handler(State(state), Query(params))
        .await
        .into_response()
}

pub(crate) async fn personal_preferences_read_alias_handler(
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> Response {
    if let Some(capture_id) = string_field(&body, "capture_id") {
        return super::personal_preferences::personal_preferences_read_capture_handler(
            State(state),
            AxumPath(capture_id),
        )
        .await
        .into_response();
    }
    if let Some(claim_id) = string_field(&body, "claim_id") {
        return super::personal_preferences::personal_preferences_claim_read_handler(
            State(state),
            AxumPath(claim_id),
        )
        .await
        .into_response();
    }
    if let Some(snapshot_id) = string_field(&body, "snapshot_id") {
        return super::personal_preferences::personal_preferences_snapshot_read_handler(
            State(state),
            AxumPath(snapshot_id),
        )
        .await
        .into_response();
    }
    super::personal_preferences::personal_preferences_status_handler(State(state))
        .await
        .into_response()
}

pub(crate) async fn personal_preferences_write_alias_handler(
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> Response {
    if body.get("event_type").is_some() {
        let payload = match deserialize_body(body) {
            Ok(value) => value,
            Err(response) => return response,
        };
        return super::personal_preferences::personal_preferences_feedback_handler(
            State(state),
            Json(payload),
        )
        .await
        .into_response();
    }
    let Some(personal_preferences) = state.personal_preferences.as_ref() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            "personal preferences memory is disabled",
        );
    };
    let payload: crate::personal_preferences::PersonalPreferencesCaptureRequest =
        match deserialize_body(body) {
            Ok(value) => value,
            Err(response) => return response,
        };
    if payload.source.trim().is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "source is required",
        );
    }
    let store = personal_preferences.store.clone();
    let config = personal_preferences.config.clone();
    match tokio::task::spawn_blocking(move || {
        store.capture_conversation_with_options(
            payload,
            crate::personal_preferences::PersonalPreferencesCaptureOptions {
                queue_for_processing: config.digest_enabled,
                archive_raw_conversations: config.archive_raw_conversations,
                secret_scrubber_enabled: config.transcript_secret_scrubber_enabled,
                content_encryption_key_env: config.content_encryption_key_env.clone(),
            },
        )
    })
    .await
    {
        Ok(Ok(record)) => Json(record).into_response(),
        Ok(Err(err)) => {
            state.metrics.inc_error();
            warn!(target: "docdexd", error = ?err, "personal preferences capture failed");
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "personal preferences capture failed",
            )
        }
        Err(err) => {
            state.metrics.inc_error();
            warn!(target: "docdexd", error = ?err, "personal preferences capture task failed");
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "personal preferences capture failed",
            )
        }
    }
}

pub(crate) async fn personal_preferences_evaluate_alias_handler(
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> Response {
    let payload = match deserialize_body(body) {
        Ok(value) => value,
        Err(response) => return response,
    };
    super::personal_preferences::personal_preferences_clone_evaluate_handler(
        State(state),
        Json(payload),
    )
    .await
    .into_response()
}

pub(crate) async fn personal_preferences_delete_alias_handler(
    State(state): State<AppState>,
    Json(body): Json<Value>,
) -> Response {
    let Some(capture_id) = string_field(&body, "capture_id") else {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "capture_id is required",
        );
    };
    super::personal_preferences::personal_preferences_delete_handler(
        State(state),
        AxumPath(capture_id),
    )
    .await
    .into_response()
}

pub(crate) async fn conversation_list_alias_handler(
    State(state): State<AppState>,
    request_id: axum::extract::Extension<RequestId>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let params = match deserialize_body(body) {
        Ok(value) => value,
        Err(response) => return response,
    };
    super::conversations::conversation_list_handler(
        State(state),
        request_id,
        headers,
        Query(params),
    )
    .await
    .into_response()
}

pub(crate) async fn conversation_search_alias_handler(
    State(state): State<AppState>,
    request_id: axum::extract::Extension<RequestId>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let params = match deserialize_body(body) {
        Ok(value) => value,
        Err(response) => return response,
    };
    super::conversations::conversation_search_handler(
        State(state),
        request_id,
        headers,
        Query(params),
    )
    .await
    .into_response()
}

pub(crate) async fn conversation_read_alias_handler(
    State(state): State<AppState>,
    request_id: axum::extract::Extension<RequestId>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let Some(session_id) = session_id_from_body(&body) else {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "session_id is required",
        );
    };
    super::conversations::conversation_read_handler(
        State(state),
        request_id,
        headers,
        Query(repo_query_from_body(&body)),
        AxumPath(session_id),
    )
    .await
    .into_response()
}

pub(crate) async fn conversation_export_alias_handler(
    State(state): State<AppState>,
    request_id: axum::extract::Extension<RequestId>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let Some(session_id) = session_id_from_body(&body) else {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "session_id is required",
        );
    };
    super::conversations::conversation_export_handler(
        State(state),
        request_id,
        headers,
        Query(repo_query_from_body(&body)),
        AxumPath(session_id),
    )
    .await
    .into_response()
}

pub(crate) async fn conversation_redact_alias_handler(
    State(state): State<AppState>,
    request_id: axum::extract::Extension<RequestId>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let Some(session_id) = session_id_from_body(&body) else {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "session_id is required",
        );
    };
    super::conversations::conversation_redact_handler(
        State(state),
        request_id,
        headers,
        Query(repo_query_from_body(&body)),
        AxumPath(session_id),
    )
    .await
    .into_response()
}

pub(crate) async fn conversation_delete_alias_handler(
    State(state): State<AppState>,
    request_id: axum::extract::Extension<RequestId>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let Some(session_id) = session_id_from_body(&body) else {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "session_id is required",
        );
    };
    super::conversations::conversation_delete_handler(
        State(state),
        request_id,
        headers,
        Query(repo_query_from_body(&body)),
        AxumPath(session_id),
    )
    .await
    .into_response()
}

pub(crate) async fn diary_read_alias_handler(
    State(state): State<AppState>,
    request_id: axum::extract::Extension<RequestId>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let params = match deserialize_body(body) {
        Ok(value) => value,
        Err(response) => return response,
    };
    super::diary::diary_read_handler(State(state), request_id, headers, Query(params))
        .await
        .into_response()
}

pub(crate) async fn kg_query_alias_handler(
    State(state): State<AppState>,
    request_id: axum::extract::Extension<RequestId>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let params = match deserialize_body(body) {
        Ok(value) => value,
        Err(response) => return response,
    };
    super::kg::kg_query_handler(State(state), request_id, headers, Query(params))
        .await
        .into_response()
}

pub(crate) async fn kg_search_nodes_alias_handler(
    State(state): State<AppState>,
    request_id: axum::extract::Extension<RequestId>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let params = match deserialize_body(body) {
        Ok(value) => value,
        Err(response) => return response,
    };
    super::kg::kg_search_nodes_handler(State(state), request_id, headers, Query(params))
        .await
        .into_response()
}

pub(crate) async fn kg_search_edges_alias_handler(
    State(state): State<AppState>,
    request_id: axum::extract::Extension<RequestId>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let params = match deserialize_body(body) {
        Ok(value) => value,
        Err(response) => return response,
    };
    super::kg::kg_search_edges_handler(State(state), request_id, headers, Query(params))
        .await
        .into_response()
}

pub(crate) async fn kg_search_episodes_alias_handler(
    State(state): State<AppState>,
    request_id: axum::extract::Extension<RequestId>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let params = match deserialize_body(body) {
        Ok(value) => value,
        Err(response) => return response,
    };
    super::kg::kg_search_episodes_handler(State(state), request_id, headers, Query(params))
        .await
        .into_response()
}

pub(crate) async fn kg_timeline_alias_handler(
    State(state): State<AppState>,
    request_id: axum::extract::Extension<RequestId>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let params = match deserialize_body(body) {
        Ok(value) => value,
        Err(response) => return response,
    };
    super::kg::kg_timeline_handler(State(state), request_id, headers, Query(params))
        .await
        .into_response()
}

pub(crate) async fn kg_neighborhood_alias_handler(
    State(state): State<AppState>,
    request_id: axum::extract::Extension<RequestId>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let params = match deserialize_body(body) {
        Ok(value) => value,
        Err(response) => return response,
    };
    super::kg::kg_neighborhood_handler(State(state), request_id, headers, Query(params))
        .await
        .into_response()
}

pub(crate) async fn kg_entity_links_alias_handler(
    State(state): State<AppState>,
    request_id: axum::extract::Extension<RequestId>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let params = match deserialize_body(body) {
        Ok(value) => value,
        Err(response) => return response,
    };
    super::kg::kg_entity_links_handler(State(state), request_id, headers, Query(params))
        .await
        .into_response()
}

pub(crate) async fn kg_episode_alias_handler(
    State(state): State<AppState>,
    request_id: axum::extract::Extension<RequestId>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let params = match deserialize_body(body) {
        Ok(value) => value,
        Err(response) => return response,
    };
    super::kg::kg_episode_handler(State(state), request_id, headers, Query(params))
        .await
        .into_response()
}

pub(crate) async fn kg_delete_edge_alias_handler(
    State(state): State<AppState>,
    request_id: axum::extract::Extension<RequestId>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let payload = match deserialize_body(body) {
        Ok(value) => value,
        Err(response) => return response,
    };
    super::kg::kg_delete_edge_handler(State(state), request_id, headers, Json(payload))
        .await
        .into_response()
}

pub(crate) async fn kg_delete_episode_alias_handler(
    State(state): State<AppState>,
    request_id: axum::extract::Extension<RequestId>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let payload = match deserialize_body(body) {
        Ok(value) => value,
        Err(response) => return response,
    };
    super::kg::kg_delete_episode_handler(State(state), request_id, headers, Json(payload))
        .await
        .into_response()
}

fn deserialize_body<T: DeserializeOwned>(body: Value) -> Result<T, Response> {
    serde_json::from_value(body).map_err(|err| {
        json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            format!("invalid request body: {err}"),
        )
    })
}

fn repo_query_from_body(body: &Value) -> RepoIdQuery {
    RepoIdQuery {
        repo_id: string_field(body, "repo_id"),
        conversation_namespace: string_field(body, "conversation_namespace")
            .or_else(|| string_field(body, "namespace")),
    }
}

fn string_field(body: &Value, key: &str) -> Option<String> {
    body.get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

fn session_id_from_body(body: &Value) -> Option<String> {
    string_field(body, "session_id").or_else(|| string_field(body, "id"))
}

fn normalize_optional_rel_path(input: Option<&str>) -> Result<Option<PathBuf>, Response> {
    let Some(raw) = input.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let path = Path::new(raw);
    if path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "path must be repo-relative",
        ));
    }
    Ok(Some(path.to_path_buf()))
}

fn tree_root(repo_root: &Path, rel_path: Option<&Path>) -> Result<PathBuf, Response> {
    let root = match rel_path {
        Some(path) => repo_root.join(path),
        None => repo_root.to_path_buf(),
    };
    let canonical_root = repo_root.canonicalize().map_err(|err| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_INTERNAL_ERROR,
            format!("repo root unavailable: {err}"),
        )
    })?;
    let canonical = root.canonicalize().map_err(|err| {
        json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            format!("path unavailable: {err}"),
        )
    })?;
    if !canonical.starts_with(canonical_root) {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "path must stay inside the repo",
        ));
    }
    Ok(canonical)
}

fn normalize_index_paths(paths: &[String]) -> Result<Vec<PathBuf>, Response> {
    let mut normalized = Vec::new();
    for raw in paths
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .take(INDEX_MAX_PATHS)
    {
        let Some(path) = crate::path_utils::normalize_repo_relative_path_from_str(raw) else {
            return Err(json_error(
                StatusCode::BAD_REQUEST,
                ERR_INVALID_ARGUMENT,
                "paths must be repo-relative",
            ));
        };
        normalized.push(path);
    }
    Ok(normalized)
}

fn strip_symlink_targets(tree: &str) -> String {
    let mut out = tree
        .lines()
        .map(|line| {
            line.split_once(" -> ")
                .map(|(prefix, _)| prefix)
                .unwrap_or(line)
        })
        .collect::<Vec<_>>()
        .join("\n");
    if tree.ends_with('\n') {
        out.push('\n');
    }
    out
}

fn index_jobs_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("jobs").join("index")
}

fn index_job_path(jobs_dir: &Path, job_id: &str) -> PathBuf {
    jobs_dir.join(format!("{job_id}.json"))
}

fn write_index_job_status(jobs_dir: &Path, status: &IndexJobStatus) -> std::io::Result<()> {
    fs::create_dir_all(jobs_dir)?;
    let payload = serde_json::to_vec_pretty(status)?;
    fs::write(index_job_path(jobs_dir, &status.job_id), payload)
}

fn spawn_index_job(
    indexer: Arc<Indexer>,
    jobs_dir: PathBuf,
    mut status: IndexJobStatus,
    paths: Vec<PathBuf>,
    metrics: Arc<crate::metrics::Metrics>,
) {
    tokio::spawn(async move {
        status.status = "running".to_string();
        status.started_at_epoch_ms = Some(now_epoch_ms());
        let _ = write_index_job_status(&jobs_dir, &status);
        if paths.is_empty() {
            match indexer.reindex_all().await {
                Ok(()) => {
                    status.paths_indexed = indexer
                        .stats()
                        .ok()
                        .map(|stats| stats.num_docs as usize)
                        .unwrap_or(0);
                    status.status = "succeeded".to_string();
                }
                Err(err) => {
                    metrics.inc_error();
                    status.status = "failed".to_string();
                    status.errors.push(safe_error_message(&err));
                }
            }
        } else {
            let repo_root = indexer.repo_root().to_path_buf();
            for path in paths {
                let full_path = repo_root.join(&path);
                match indexer.ingest_file(full_path).await {
                    Ok(decision) if decision.should_index() => status.paths_indexed += 1,
                    Ok(_) => status.paths_skipped += 1,
                    Err(err) => {
                        metrics.inc_error();
                        status.paths_failed += 1;
                        status.errors.push(format!(
                            "{}: {}",
                            path.display(),
                            safe_error_message(&err)
                        ));
                    }
                }
            }
            status.status = if status.paths_failed == 0 {
                "succeeded"
            } else if status.paths_indexed == 0 {
                "failed"
            } else {
                "partial"
            }
            .to_string();
        }
        status.finished_at_epoch_ms = Some(now_epoch_ms());
        let _ = write_index_job_status(&jobs_dir, &status);
    });
}

fn safe_segment(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed
            .chars()
            .any(|ch| !(ch.is_ascii_alphanumeric() || ch == '-' || ch == '_'))
    {
        return None;
    }
    Some(trimmed.to_string())
}

fn safe_error_message(err: &impl std::fmt::Display) -> String {
    err.to_string().chars().take(240).collect()
}

fn now_epoch_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_millis())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tempfile::TempDir;

    #[test]
    fn normalize_optional_rel_path_rejects_parent_segments() {
        assert!(normalize_optional_rel_path(Some("../secret")).is_err());
        assert!(normalize_optional_rel_path(Some("/tmp/secret")).is_err());
        assert_eq!(
            normalize_optional_rel_path(Some("src/lib.rs")).unwrap(),
            Some(PathBuf::from("src/lib.rs"))
        );
    }

    #[test]
    fn strip_symlink_targets_removes_target_paths() {
        let tree = "repo\n|- link -> /private/path\n";
        assert_eq!(strip_symlink_targets(tree), "repo\n|- link\n");
    }

    #[tokio::test]
    async fn index_job_resolves_repo_relative_paths_and_tracks_skips() -> anyhow::Result<()> {
        let repo = TempDir::new()?;
        let state_root = TempDir::new()?;
        fs::write(repo.path().join("kept.md"), "INDEX_JOB_RELATIVE_TOKEN")?;
        fs::write(repo.path().join("skipped.unsupported"), "ignored")?;
        let config = crate::index::IndexConfig::with_overrides(
            repo.path(),
            Some(state_root.path().to_path_buf()),
            Vec::new(),
            Vec::new(),
            true,
        )?;
        let indexer = Arc::new(Indexer::with_config(repo.path().to_path_buf(), config)?);
        let jobs_dir = index_jobs_dir(indexer.state_dir());
        let status = IndexJobStatus {
            job_id: "relative-path-job".to_string(),
            repo_id: "test-repo".to_string(),
            operation: "ingest_paths".to_string(),
            status: "queued".to_string(),
            queued_at_epoch_ms: now_epoch_ms(),
            started_at_epoch_ms: None,
            finished_at_epoch_ms: None,
            paths_total: 2,
            paths_indexed: 0,
            paths_skipped: 0,
            paths_failed: 0,
            errors: Vec::new(),
        };
        spawn_index_job(
            Arc::clone(&indexer),
            jobs_dir.clone(),
            status,
            vec![
                PathBuf::from("kept.md"),
                PathBuf::from("skipped.unsupported"),
            ],
            Arc::new(crate::metrics::Metrics::default()),
        );

        let completed = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if let Ok(payload) = fs::read(index_job_path(&jobs_dir, "relative-path-job")) {
                    if let Ok(status) = serde_json::from_slice::<IndexJobStatus>(&payload) {
                        if status.finished_at_epoch_ms.is_some() {
                            break status;
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await?;

        assert_eq!(completed.status, "succeeded", "{completed:?}");
        assert_eq!(completed.paths_indexed, 1);
        assert_eq!(completed.paths_skipped, 1);
        assert_eq!(completed.paths_failed, 0);
        assert!(!indexer.search("INDEX_JOB_RELATIVE_TOKEN", 1)?.is_empty());
        Ok(())
    }
}
