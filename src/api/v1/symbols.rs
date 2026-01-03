use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
};
use serde::Deserialize;
use std::path::{Component, Path, PathBuf};
use tracing::warn;

use crate::error::{
    ERR_INTERNAL_ERROR, ERR_INVALID_ARGUMENT, ERR_MISSING_DEPENDENCY, ERR_MISSING_INDEX,
    ERR_STALE_INDEX,
};
use crate::search::{json_error, resolve_repo_context, AppState};

#[derive(Deserialize)]
pub struct SymbolsQuery {
    #[serde(default, alias = "file")]
    pub path: Option<String>,
    #[serde(default)]
    pub repo_id: Option<String>,
}

#[derive(Deserialize)]
pub struct SymbolsStatusQuery {
    #[serde(default)]
    pub repo_id: Option<String>,
}

pub async fn symbols_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<SymbolsQuery>,
) -> Response {
    let repo = match resolve_repo_context(&state, &headers, params.repo_id.as_deref(), None, false)
    {
        Ok(repo) => repo,
        Err(err) => return json_error(err.status, err.code, err.message),
    };

    if !repo.indexer.config().symbols_enabled() {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MISSING_DEPENDENCY,
            "symbol extraction is unavailable",
        );
    }
    if let Ok(true) = repo.indexer.symbols_reindex_required() {
        return json_error(
            StatusCode::CONFLICT,
            ERR_STALE_INDEX,
            "symbols require reindex after parser version change; run `docdexd index --repo <path>`",
        );
    }

    let raw_path = match params.path.as_deref().map(str::trim) {
        Some(value) if !value.is_empty() => value,
        _ => {
            return json_error(
                StatusCode::BAD_REQUEST,
                ERR_INVALID_ARGUMENT,
                "path is required",
            )
        }
    };

    let rel_path = match normalize_rel_path(raw_path) {
        Some(value) => value,
        None => {
            return json_error(
                StatusCode::BAD_REQUEST,
                ERR_INVALID_ARGUMENT,
                "path must be repo-relative",
            )
        }
    };

    match repo.indexer.read_symbols(&rel_path) {
        Ok(Some(payload)) => Json(payload).into_response(),
        Ok(None) => json_error(
            StatusCode::NOT_FOUND,
            ERR_MISSING_INDEX,
            format!("no symbols record found for {rel_path}"),
        ),
        Err(err) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                error = ?err,
                path = %rel_path,
                "symbols lookup failed"
            );
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "symbols lookup failed",
            )
        }
    }
}

pub async fn symbols_status_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<SymbolsStatusQuery>,
) -> Response {
    let repo = match resolve_repo_context(&state, &headers, params.repo_id.as_deref(), None, false)
    {
        Ok(repo) => repo,
        Err(err) => return json_error(err.status, err.code, err.message),
    };

    if !repo.indexer.config().symbols_enabled() {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MISSING_DEPENDENCY,
            "symbol extraction is unavailable",
        );
    }

    match repo.indexer.symbols_parser_status() {
        Ok(payload) => Json(payload).into_response(),
        Err(err) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                error = ?err,
                "symbols status lookup failed"
            );
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "symbols status lookup failed",
            )
        }
    }
}

fn normalize_rel_path(input: &str) -> Option<String> {
    let path = Path::new(input);
    if path.is_absolute() {
        return None;
    }
    let mut clean = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => continue,
            Component::Normal(part) => clean.push(part),
            _ => return None,
        }
    }
    let clean_str = clean.to_string_lossy().replace('\\', "/");
    if clean_str.is_empty() {
        None
    } else {
        Some(clean_str)
    }
}
