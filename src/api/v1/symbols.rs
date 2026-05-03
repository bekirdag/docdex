use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
};
use serde::Deserialize;
use tracing::warn;

use crate::error::{
    status_for_app_error, AppError, ERR_INTERNAL_ERROR, ERR_INVALID_ARGUMENT,
    ERR_MISSING_DEPENDENCY, ERR_MISSING_INDEX, ERR_REPO_ENCRYPTION_UNSUPPORTED, ERR_STALE_INDEX,
};
use crate::http_api::json_error;
use crate::search::AppState;

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

    if repo.indexer.config().repo_encryption().is_enabled() {
        return json_error(
            StatusCode::CONFLICT,
            ERR_REPO_ENCRYPTION_UNSUPPORTED,
            "symbol extraction is disabled when repository encryption is enabled",
        );
    }
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
            if let Some(app) = err.downcast_ref::<AppError>() {
                return json_error(
                    status_for_app_error(app.code),
                    app.code,
                    app.message.clone(),
                );
            }
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
    let repo = match super::shared::resolve_repo_request(
        &state,
        &headers,
        params.repo_id.as_deref(),
        None,
        false,
    ) {
        Ok(repo) => repo,
        Err(response) => return response,
    };

    if repo.indexer.config().repo_encryption().is_enabled() {
        return json_error(
            StatusCode::CONFLICT,
            ERR_REPO_ENCRYPTION_UNSUPPORTED,
            "symbol extraction is disabled when repository encryption is enabled",
        );
    }
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
            if let Some(app) = err.downcast_ref::<AppError>() {
                return json_error(
                    status_for_app_error(app.code),
                    app.code,
                    app.message.clone(),
                );
            }
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
    crate::path_utils::normalize_repo_relative_string(input)
}
