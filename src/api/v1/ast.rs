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
use crate::search::{json_error, resolve_repo_id, AppState};

const DEFAULT_MAX_AST_NODES: usize = 20_000;
const HARD_MAX_AST_NODES: usize = 100_000;

#[derive(Deserialize)]
pub struct AstQuery {
    #[serde(default, alias = "file")]
    pub path: Option<String>,
    #[serde(default)]
    pub repo_id: Option<String>,
    #[serde(default, alias = "maxNodes")]
    pub max_nodes: Option<usize>,
}

pub async fn ast_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<AstQuery>,
) -> Response {
    if let Err(err) = resolve_repo_id(
        &headers,
        params.repo_id.as_deref(),
        None,
        state.indexer.as_ref(),
        false,
    ) {
        return json_error(err.status, err.code, err.message);
    }

    if !state.indexer.config().symbols_enabled() {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MISSING_DEPENDENCY,
            "ast extraction is unavailable",
        );
    }
    if let Ok(true) = state.indexer.symbols_reindex_required() {
        return json_error(
            StatusCode::CONFLICT,
            ERR_STALE_INDEX,
            "ast data require reindex after parser version change; run `docdexd index --repo <path>`",
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

    let max_nodes = params
        .max_nodes
        .unwrap_or(DEFAULT_MAX_AST_NODES)
        .min(HARD_MAX_AST_NODES)
        .max(1);

    match state.indexer.read_ast(&rel_path, max_nodes) {
        Ok(Some(payload)) => Json(payload).into_response(),
        Ok(None) => json_error(
            StatusCode::NOT_FOUND,
            ERR_MISSING_INDEX,
            format!("no ast record found for {rel_path}"),
        ),
        Err(err) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                error = ?err,
                path = %rel_path,
                "ast lookup failed"
            );
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "ast lookup failed",
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
