use axum::{
    extract::{Json, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::de::Deserializer;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use tracing::warn;

use crate::error::{
    status_for_app_error, AppError, ERR_INTERNAL_ERROR, ERR_INVALID_ARGUMENT,
    ERR_MISSING_DEPENDENCY, ERR_MISSING_INDEX, ERR_REPO_ENCRYPTION_UNSUPPORTED, ERR_STALE_INDEX,
};
use crate::http_api::json_error;
use crate::search::AppState;
use crate::symbols::{AstQuery as StoreAstQuery, AstSearchMode, SchemaCompatibleRange, SchemaInfo};

pub(crate) const DEFAULT_MAX_AST_NODES: usize = 20_000;
const HARD_MAX_AST_NODES: usize = 100_000;
const DEFAULT_AST_SEARCH_LIMIT: usize = 50;
const HARD_MAX_AST_SEARCH_LIMIT: usize = 500;
const DEFAULT_AST_QUERY_LIMIT: usize = 50;
const HARD_MAX_AST_QUERY_LIMIT: usize = 500;
const DEFAULT_AST_QUERY_SAMPLE_LIMIT: usize = 25;
const HARD_MAX_AST_QUERY_SAMPLE_LIMIT: usize = 500;

fn default_ast_search_schema() -> SchemaInfo {
    SchemaInfo {
        name: "docdex.ast_search".to_string(),
        version: 1,
        compatible: SchemaCompatibleRange { min: 1, max: 1 },
    }
}

fn default_ast_query_schema() -> SchemaInfo {
    SchemaInfo {
        name: "docdex.ast_query".to_string(),
        version: 1,
        compatible: SchemaCompatibleRange { min: 1, max: 1 },
    }
}

#[derive(Deserialize)]
pub struct AstQuery {
    #[serde(default, alias = "file")]
    pub path: Option<String>,
    #[serde(default)]
    pub repo_id: Option<String>,
    #[serde(default, alias = "maxNodes")]
    pub max_nodes: Option<usize>,
}

#[derive(Deserialize)]
pub struct AstSearchQuery {
    #[serde(default, alias = "kind", deserialize_with = "deserialize_kinds")]
    pub kinds: Vec<String>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default)]
    pub repo_id: Option<String>,
}

#[derive(Deserialize)]
pub struct AstQueryParams {
    #[serde(default)]
    pub repo_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AstQueryRequest {
    #[serde(default, alias = "kind")]
    pub kinds: Vec<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub field: Option<String>,
    #[serde(default, alias = "path_prefix")]
    pub path_prefix: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub limit: Option<usize>,
    #[serde(default, alias = "sample_limit")]
    pub sample_limit: Option<usize>,
    #[serde(default, alias = "repo_id")]
    pub repo_id: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AstSearchMatchItem {
    file: String,
    match_count: usize,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AstSearchResponseV1 {
    #[serde(default = "default_ast_search_schema")]
    schema: SchemaInfo,
    repo_id: String,
    kinds: Vec<String>,
    mode: String,
    limit: usize,
    truncated: bool,
    matches: Vec<AstSearchMatchItem>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AstQueryMatchItem {
    file: String,
    match_count: usize,
    samples: Vec<crate::symbols::AstNode>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AstQueryResponseV1 {
    #[serde(default = "default_ast_query_schema")]
    schema: SchemaInfo,
    repo_id: String,
    kinds: Vec<String>,
    mode: String,
    limit: usize,
    sample_limit: usize,
    truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    field: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    path_prefix: Option<String>,
    matches: Vec<AstQueryMatchItem>,
}

pub async fn ast_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<AstQuery>,
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
            "ast extraction is disabled when repository encryption is enabled",
        );
    }
    if !repo.indexer.config().symbols_enabled() {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MISSING_DEPENDENCY,
            "ast extraction is unavailable",
        );
    }
    if let Ok(true) = repo.indexer.symbols_reindex_required() {
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

    match repo.indexer.read_ast(&rel_path, max_nodes) {
        Ok(Some(payload)) => Json(payload).into_response(),
        Ok(None) => json_error(
            StatusCode::NOT_FOUND,
            ERR_MISSING_INDEX,
            format!("no ast record found for {rel_path}"),
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

pub async fn ast_search_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<AstSearchQuery>,
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
            "ast extraction is disabled when repository encryption is enabled",
        );
    }
    if !repo.indexer.config().symbols_enabled() {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MISSING_DEPENDENCY,
            "ast extraction is unavailable",
        );
    }
    if let Ok(true) = repo.indexer.symbols_reindex_required() {
        return json_error(
            StatusCode::CONFLICT,
            ERR_STALE_INDEX,
            "ast data require reindex after parser version change; run `docdexd index --repo <path>`",
        );
    }

    let kinds = normalize_kinds(params.kinds);
    if kinds.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "kinds is required",
        );
    }
    let mode = match params.mode.as_deref().map(str::trim) {
        None | Some("") | Some("any") => AstSearchMode::Any,
        Some("all") => AstSearchMode::All,
        Some(other) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                ERR_INVALID_ARGUMENT,
                format!("unsupported match mode: {other}"),
            )
        }
    };
    let limit = params
        .limit
        .unwrap_or(DEFAULT_AST_SEARCH_LIMIT)
        .clamp(1, HARD_MAX_AST_SEARCH_LIMIT);
    let search_limit = limit.saturating_add(1);

    let matches = match repo
        .indexer
        .search_ast_kinds_with_mode(&kinds, search_limit, mode)
    {
        Ok(matches) => matches,
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
                "ast search failed"
            );
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "ast search failed",
            );
        }
    };

    let truncated = matches.len() > limit;
    let matches = matches
        .into_iter()
        .take(limit)
        .map(|item| AstSearchMatchItem {
            file: item.file,
            match_count: item.match_count,
        })
        .collect::<Vec<_>>();

    let repo_id = match crate::symbols::repo_id_for_root(repo.indexer.repo_root()) {
        Ok(repo_id) => repo_id,
        Err(err) => {
            warn!(
                target: "docdexd",
                error = ?err,
                "ast search repo id lookup failed"
            );
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "ast search failed",
            );
        }
    };
    let mode_label = match mode {
        AstSearchMode::Any => "any",
        AstSearchMode::All => "all",
    };
    let payload = AstSearchResponseV1 {
        schema: default_ast_search_schema(),
        repo_id,
        kinds,
        mode: mode_label.to_string(),
        limit,
        truncated,
        matches,
    };

    Json(payload).into_response()
}

pub async fn ast_query_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AstQueryParams>,
    Json(params): Json<AstQueryRequest>,
) -> Response {
    let repo = match super::shared::resolve_repo_with_index(
        &state,
        &headers,
        query.repo_id.as_deref(),
        params.repo_id.as_deref(),
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
            "ast extraction is disabled when repository encryption is enabled",
        );
    }
    if !repo.indexer.config().symbols_enabled() {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MISSING_DEPENDENCY,
            "ast extraction is unavailable",
        );
    }
    if let Ok(true) = repo.indexer.symbols_reindex_required() {
        return json_error(
            StatusCode::CONFLICT,
            ERR_STALE_INDEX,
            "ast data require reindex after parser version change; run `docdexd index --repo <path>`",
        );
    }

    let kinds = normalize_kinds(params.kinds);
    if kinds.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "kinds is required",
        );
    }

    let mode = match params.mode.as_deref().map(str::trim) {
        None | Some("") | Some("any") => AstSearchMode::Any,
        Some("all") => AstSearchMode::All,
        Some(other) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                ERR_INVALID_ARGUMENT,
                format!("unsupported match mode: {other}"),
            )
        }
    };

    let name = params
        .name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string());
    let field = params
        .field
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string());

    let path_prefix = match params.path_prefix.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(value) => match normalize_path_prefix(value) {
            Some(path) => Some(path),
            None => {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    ERR_INVALID_ARGUMENT,
                    "path_prefix must be repo-relative",
                )
            }
        },
    };

    let limit = params
        .limit
        .unwrap_or(DEFAULT_AST_QUERY_LIMIT)
        .clamp(1, HARD_MAX_AST_QUERY_LIMIT);
    let sample_limit = params
        .sample_limit
        .unwrap_or(DEFAULT_AST_QUERY_SAMPLE_LIMIT)
        .clamp(1, HARD_MAX_AST_QUERY_SAMPLE_LIMIT);
    let search_limit = limit.saturating_add(1);

    let query = StoreAstQuery {
        kinds: kinds.clone(),
        name: name.clone(),
        field: field.clone(),
        path_prefix: path_prefix.clone(),
        mode,
        limit: search_limit,
        sample_limit,
    };

    let mut matches = match repo.indexer.query_ast(&query) {
        Ok(matches) => matches,
        Err(err) => {
            state.metrics.inc_error();
            if let Some(app) = err.downcast_ref::<AppError>() {
                return json_error(
                    status_for_app_error(app.code),
                    app.code,
                    app.message.clone(),
                );
            }
            warn!(target: "docdexd", error = ?err, "ast query failed");
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "ast query failed",
            );
        }
    };

    let truncated = matches.len() > limit;
    if truncated {
        matches.truncate(limit);
    }

    let repo_id = match crate::symbols::repo_id_for_root(repo.indexer.repo_root()) {
        Ok(repo_id) => repo_id,
        Err(err) => {
            warn!(
                target: "docdexd",
                error = ?err,
                "ast query repo id lookup failed"
            );
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "ast query failed",
            );
        }
    };
    let mode_label = match mode {
        AstSearchMode::Any => "any",
        AstSearchMode::All => "all",
    };
    let matches = matches
        .into_iter()
        .map(|entry| AstQueryMatchItem {
            file: entry.file,
            match_count: entry.match_count,
            samples: entry.samples,
        })
        .collect();
    let payload = AstQueryResponseV1 {
        schema: default_ast_query_schema(),
        repo_id,
        kinds,
        mode: mode_label.to_string(),
        limit,
        sample_limit,
        truncated,
        name,
        field,
        path_prefix,
        matches,
    };

    Json(payload).into_response()
}

fn normalize_rel_path(input: &str) -> Option<String> {
    crate::path_utils::normalize_repo_relative_string(input)
}

fn normalize_path_prefix(input: &str) -> Option<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }
    normalize_rel_path(trimmed)
}

fn normalize_kinds(raw: Vec<String>) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for value in raw {
        for part in value.split(',') {
            let trimmed = part.trim();
            if trimmed.is_empty() {
                continue;
            }
            let owned = trimmed.to_string();
            if seen.insert(owned.clone()) {
                out.push(owned);
            }
        }
    }
    out
}

fn deserialize_kinds<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum RawKinds {
        One(String),
        Many(Vec<String>),
    }

    let raw = RawKinds::deserialize(deserializer)?;
    let mut out = Vec::new();
    let mut push_split = |value: &str| {
        for part in value.split(',') {
            let trimmed = part.trim();
            if !trimmed.is_empty() {
                out.push(trimmed.to_string());
            }
        }
    };
    match raw {
        RawKinds::One(value) => push_split(&value),
        RawKinds::Many(values) => {
            for value in values {
                push_split(&value);
            }
        }
    }
    Ok(out)
}
