use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::warn;

use crate::error::{AppError, ERR_INTERNAL_ERROR, ERR_INVALID_ARGUMENT};
use crate::http_api::{app_error_response, json_error, repo_error_response, resolve_repo_context};
use crate::indexer;
use crate::libs;
use crate::search::AppState;

#[derive(Deserialize)]
pub struct IndexRebuildRequest {
    #[serde(default)]
    pub repo_id: Option<String>,
    #[serde(default)]
    pub libs_sources: Option<String>,
}

#[derive(Deserialize)]
pub struct IndexIngestRequest {
    pub file: String,
    #[serde(default)]
    pub repo_id: Option<String>,
}

#[derive(Deserialize)]
pub struct IndexStatusQuery {
    #[serde(default)]
    pub repo_id: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub struct IndexStatusResponse {
    pub repo_id: String,
    pub repo_root: String,
    pub status: String,
    pub ready: bool,
    pub indexing_in_progress: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub docs_indexed: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_updated_epoch_ms: Option<u128>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index_size_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub segments: Option<usize>,
}

pub async fn index_rebuild_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(payload): axum::Json<IndexRebuildRequest>,
) -> Response {
    let repo = match resolve_repo_context(&state, &headers, payload.repo_id.as_deref(), None, false)
    {
        Ok(repo) => repo,
        Err(err) => return repo_error_response(err),
    };

    let options = match payload.libs_sources.as_deref().map(str::trim) {
        Some(value) if value.is_empty() => {
            return json_error(
                StatusCode::BAD_REQUEST,
                ERR_INVALID_ARGUMENT,
                "libs_sources must not be empty",
            )
        }
        Some(value) => {
            let path = PathBuf::from(value);
            match indexer::IndexingOptions::from_sources_path(path.as_path()) {
                Ok(options) => options,
                Err(err) => {
                    return json_error(
                        StatusCode::BAD_REQUEST,
                        ERR_INVALID_ARGUMENT,
                        format!("invalid libs_sources: {err}"),
                    )
                }
            }
        }
        None => indexer::IndexingOptions::none(),
    };

    if let Err(err) = repo.indexer.reindex_all().await {
        state.metrics.inc_error();
        warn!(target: "docdexd", error = ?err, "index rebuild failed");
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_INTERNAL_ERROR,
            "index rebuild failed",
        );
    }

    let libs_report = match options.libs_sources {
        None => None,
        Some(sources) => {
            let libs_dir = libs::libs_state_dir_from_index_state_dir(repo.indexer.state_dir());
            let libs_indexer = match libs::LibsIndexer::open_or_create(libs_dir) {
                Ok(indexer) => indexer,
                Err(err) => {
                    state.metrics.inc_error();
                    warn!(target: "docdexd", error = ?err, "libs index open failed");
                    return json_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        ERR_INTERNAL_ERROR,
                        "libs index unavailable",
                    );
                }
            };
            match libs_indexer.ingest_sources(repo.indexer.repo_root(), &sources.sources) {
                Ok(report) => Some(report),
                Err(err) => {
                    state.metrics.inc_error();
                    warn!(target: "docdexd", error = ?err, "libs ingest failed");
                    return json_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        ERR_INTERNAL_ERROR,
                        "libs ingest failed",
                    );
                }
            }
        }
    };

    let docs_indexed = repo.indexer.stats().ok().map(|stats| stats.num_docs);
    let report = indexer::IndexingReport {
        repo_root: repo.indexer.repo_root().to_path_buf(),
        state_dir: repo.indexer.state_dir().to_path_buf(),
        docs_indexed,
        libs_report,
    };
    Json(report).into_response()
}

pub async fn index_ingest_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(payload): axum::Json<IndexIngestRequest>,
) -> Response {
    let repo = match resolve_repo_context(&state, &headers, payload.repo_id.as_deref(), None, false)
    {
        Ok(repo) => repo,
        Err(err) => return repo_error_response(err),
    };

    let file = payload.file.trim();
    if file.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "file is required",
        );
    }
    let file_path = PathBuf::from(file);

    match repo.indexer.ingest_file(file_path).await {
        Ok(report) => Json(report).into_response(),
        Err(err) => {
            state.metrics.inc_error();
            warn!(target: "docdexd", error = ?err, "index ingest failed");
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "index ingest failed",
            )
        }
    }
}

pub async fn index_status_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<IndexStatusQuery>,
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
            if let Some(app) = err.downcast_ref::<AppError>() {
                return app_error_response(app);
            }
            warn!(target: "docdexd", error = ?err, "index status lookup failed");
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "index status lookup failed",
            );
        }
    };
    let ready = repo.indexer.index_ready();
    let status = if ready {
        "ready"
    } else if indexing_in_progress {
        "indexing"
    } else {
        "missing"
    };
    let stats = repo.indexer.stats().ok();

    let response = IndexStatusResponse {
        repo_id: repo.repo_id.clone(),
        repo_root: repo.indexer.repo_root().display().to_string(),
        status: status.to_string(),
        ready,
        indexing_in_progress,
        docs_indexed: stats.as_ref().map(|value| value.num_docs),
        last_updated_epoch_ms: stats.as_ref().and_then(|value| value.last_updated_epoch_ms),
        index_size_bytes: stats.as_ref().map(|value| value.index_size_bytes),
        segments: stats.as_ref().map(|value| value.segments),
    };

    Json(response).into_response()
}
