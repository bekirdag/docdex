use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
};
use serde::Deserialize;
use std::path::PathBuf;
use tracing::warn;

use crate::error::{ERR_INTERNAL_ERROR, ERR_INVALID_ARGUMENT};
use crate::indexer;
use crate::libs;
use crate::search::{json_error, repo_error_response, resolve_repo_context, AppState};

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
