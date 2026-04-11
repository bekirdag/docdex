use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::path::Path;
use tracing::warn;

use crate::error::{ERR_INTERNAL_ERROR, ERR_INVALID_ARGUMENT};
use crate::http_api::{json_error, repo_error_response, resolve_repo_context};
use crate::libs;
use crate::libs_source_resolver;
use crate::search::AppState;

#[derive(Deserialize)]
pub struct LibsRequest {
    #[serde(default)]
    pub repo_id: Option<String>,
    #[serde(default)]
    pub sources_path: Option<String>,
}

pub async fn libs_discover_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(payload): axum::Json<LibsRequest>,
) -> Response {
    let repo = match resolve_repo_context(&state, &headers, payload.repo_id.as_deref(), None, false)
    {
        Ok(repo) => repo,
        Err(err) => return repo_error_response(err),
    };

    let explicit = match payload.sources_path.as_deref().map(str::trim) {
        Some(value) if value.is_empty() => {
            return json_error(
                StatusCode::BAD_REQUEST,
                ERR_INVALID_ARGUMENT,
                "sources_path must not be empty",
            )
        }
        Some(value) => match read_sources_file(Path::new(value)) {
            Ok(value) => Some(value),
            Err(err) => {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    ERR_INVALID_ARGUMENT,
                    format!("invalid sources_path: {err}"),
                )
            }
        },
        None => None,
    };

    let resolver =
        libs_source_resolver::LibsSourceResolver::new(repo.indexer.repo_root().to_path_buf());
    match resolver.resolve(explicit.as_ref()) {
        Ok(resolution) => Json(resolution).into_response(),
        Err(err) => {
            state.metrics.inc_error();
            warn!(target: "docdexd", error = ?err, "libs discover failed");
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "libs discover failed",
            )
        }
    }
}

pub async fn libs_fetch_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(payload): axum::Json<LibsRequest>,
) -> Response {
    let repo = match resolve_repo_context(&state, &headers, payload.repo_id.as_deref(), None, false)
    {
        Ok(repo) => repo,
        Err(err) => return repo_error_response(err),
    };

    let explicit = match payload.sources_path.as_deref().map(str::trim) {
        Some(value) if value.is_empty() => {
            return json_error(
                StatusCode::BAD_REQUEST,
                ERR_INVALID_ARGUMENT,
                "sources_path must not be empty",
            )
        }
        Some(value) => match read_sources_file(Path::new(value)) {
            Ok(value) => Some(value),
            Err(err) => {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    ERR_INVALID_ARGUMENT,
                    format!("invalid sources_path: {err}"),
                )
            }
        },
        None => None,
    };

    let resolver =
        libs_source_resolver::LibsSourceResolver::new(repo.indexer.repo_root().to_path_buf());
    let resolution = match resolver.resolve(explicit.as_ref()) {
        Ok(resolution) => resolution,
        Err(err) => {
            state.metrics.inc_error();
            warn!(target: "docdexd", error = ?err, "libs discover failed");
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "libs discover failed",
            );
        }
    };

    let mut sources_file =
        libs_source_resolver::resolution_to_sources(&resolution, explicit.is_none());
    if let Some(explicit_file) = explicit {
        sources_file
            .sources
            .extend(explicit_file.sources.into_iter());
        sources_file.sources = dedupe_sources(sources_file.sources);
    }
    if sources_file.sources.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "no eligible libs sources discovered; provide sources_path or run libs discover",
        );
    }

    let libs_dir = libs::libs_state_dir_from_index_state_dir(repo.indexer.state_dir());
    let indexer = match libs::LibsIndexer::open_or_create(libs_dir) {
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
    match indexer.ingest_sources(repo.indexer.repo_root(), &sources_file.sources) {
        Ok(report) => Json(report).into_response(),
        Err(err) => {
            state.metrics.inc_error();
            warn!(target: "docdexd", error = ?err, "libs ingest failed");
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "libs ingest failed",
            )
        }
    }
}

pub async fn libs_ingest_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::Json(payload): axum::Json<LibsRequest>,
) -> Response {
    let repo = match resolve_repo_context(&state, &headers, payload.repo_id.as_deref(), None, false)
    {
        Ok(repo) => repo,
        Err(err) => return repo_error_response(err),
    };

    let sources_path = match payload.sources_path.as_deref().map(str::trim) {
        Some(value) if !value.is_empty() => value,
        _ => {
            return json_error(
                StatusCode::BAD_REQUEST,
                ERR_INVALID_ARGUMENT,
                "sources_path is required",
            )
        }
    };

    let sources_file = match read_sources_file(Path::new(sources_path)) {
        Ok(value) => value,
        Err(err) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                ERR_INVALID_ARGUMENT,
                format!("invalid sources_path: {err}"),
            )
        }
    };

    let libs_dir = libs::libs_state_dir_from_index_state_dir(repo.indexer.state_dir());
    let indexer = match libs::LibsIndexer::open_or_create(libs_dir) {
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
    match indexer.ingest_sources(repo.indexer.repo_root(), &sources_file.sources) {
        Ok(report) => Json(report).into_response(),
        Err(err) => {
            state.metrics.inc_error();
            warn!(target: "docdexd", error = ?err, "libs ingest failed");
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "libs ingest failed",
            )
        }
    }
}

fn read_sources_file(path: &Path) -> Result<libs::LibSourcesFile, anyhow::Error> {
    let raw = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&raw)?)
}

fn dedupe_sources(sources: Vec<libs::LibSource>) -> Vec<libs::LibSource> {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut deduped = Vec::new();
    for source in sources {
        let key = lib_source_key(&source);
        if seen.insert(key) {
            deduped.push(source);
        }
    }
    deduped
}

fn lib_source_key(source: &libs::LibSource) -> String {
    format!(
        "{}|{}|{}|{}|{}",
        source.library.trim(),
        source.version.as_deref().unwrap_or("").trim(),
        source.source.trim(),
        source.path.to_string_lossy(),
        source.title.as_deref().unwrap_or("").trim()
    )
}
