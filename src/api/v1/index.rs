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
use crate::search::{json_error, resolve_repo_id, AppState};

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
    if let Err(err) = resolve_repo_id(
        &headers,
        payload.repo_id.as_deref(),
        None,
        state.indexer.as_ref(),
        false,
    ) {
        return json_error(err.status, err.code, err.message);
    }

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

    match indexer::reindex_repo(
        state.indexer.repo_root().to_path_buf(),
        state.indexer.config().clone(),
        options,
    )
    .await
    {
        Ok(report) => Json(report).into_response(),
        Err(err) => {
            state.metrics.inc_error();
            warn!(target: "docdexd", error = ?err, "index rebuild failed");
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "index rebuild failed",
            )
        }
    }
}

pub async fn index_ingest_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(payload): axum::Json<IndexIngestRequest>,
) -> Response {
    if let Err(err) = resolve_repo_id(
        &headers,
        payload.repo_id.as_deref(),
        None,
        state.indexer.as_ref(),
        false,
    ) {
        return json_error(err.status, err.code, err.message);
    }

    let file = payload.file.trim();
    if file.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "file is required",
        );
    }
    let file_path = PathBuf::from(file);

    match indexer::ingest_file(
        state.indexer.repo_root().to_path_buf(),
        state.indexer.config().clone(),
        file_path,
    )
    .await
    {
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
