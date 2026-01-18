use axum::{
    extract::{Query, RawQuery, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::warn;

use crate::error::{AppError, ERR_INTERNAL_ERROR};
use crate::search::{json_error, status_for_app_error, AppState};

#[derive(Serialize)]
struct ImpactErrorResponse {
    error: ImpactErrorDetail,
}

#[derive(Serialize)]
struct ImpactErrorDetail {
    code: &'static str,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<serde_json::Value>,
}

#[derive(Deserialize)]
pub(crate) struct RepoIdQuery {
    #[serde(default)]
    repo_id: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct ImpactDiagnosticsQuery {
    #[serde(default)]
    file: Option<String>,
    #[serde(default)]
    repo_id: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    offset: Option<usize>,
}

const DIAGNOSTICS_DEFAULT_LIMIT: usize = 200;
const DIAGNOSTICS_MAX_LIMIT: usize = 1000;

fn invalid_argument_details(
    issues: Vec<crate::impact::InvalidFieldIssue>,
) -> crate::impact::InvalidArgumentDetails {
    crate::impact::InvalidArgumentDetails::new(issues)
}

fn invalid_argument_response(
    message: impl Into<String>,
    details: crate::impact::InvalidArgumentDetails,
) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ImpactErrorResponse {
            error: ImpactErrorDetail {
                code: "invalid_argument",
                message: message.into(),
                details: Some(serde_json::to_value(details).unwrap_or_else(|_| json!({}))),
            },
        }),
    )
        .into_response()
}

fn push_issue(
    issues: &mut Vec<crate::impact::InvalidFieldIssue>,
    field: &'static str,
    code: &'static str,
    message: impl Into<String>,
) {
    issues.push(crate::impact::InvalidFieldIssue {
        field,
        code,
        message: message.into(),
    });
}

fn parse_i64_param(
    issues: &mut Vec<crate::impact::InvalidFieldIssue>,
    field: &'static str,
    raw: &str,
) -> Option<i64> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        push_issue(
            issues,
            field,
            "must_be_integer",
            format!("{field} must be an integer"),
        );
        return None;
    }
    match trimmed.parse::<i64>() {
        Ok(value) => Some(value),
        Err(_) => {
            push_issue(
                issues,
                field,
                "must_be_integer",
                format!("{field} must be an integer"),
            );
            None
        }
    }
}

fn parse_impact_graph_query(
    raw_query: Option<&str>,
) -> std::result::Result<
    (String, crate::impact::ImpactQueryControls),
    crate::impact::InvalidArgumentError,
> {
    let mut issues: Vec<crate::impact::InvalidFieldIssue> = Vec::new();
    let mut file: Option<String> = None;
    let mut max_edges: Option<i64> = None;
    let mut max_depth: Option<i64> = None;
    let mut edge_types: Vec<String> = Vec::new();
    let mut edge_types_seen = false;

    let pairs = match raw_query {
        None => Vec::new(),
        Some(raw) if raw.is_empty() => Vec::new(),
        Some(raw) => match serde_urlencoded::from_str::<Vec<(String, String)>>(raw) {
            Ok(pairs) => pairs,
            Err(_) => {
                push_issue(
                    &mut issues,
                    "query",
                    "invalid_encoding",
                    "invalid query string encoding",
                );
                return Err(crate::impact::InvalidArgumentError {
                    details: invalid_argument_details(issues),
                });
            }
        },
    };

    for (key, value) in pairs {
        match key.as_str() {
            "file" => file = Some(value),
            "maxEdges" => max_edges = parse_i64_param(&mut issues, "maxEdges", &value),
            "maxDepth" => max_depth = parse_i64_param(&mut issues, "maxDepth", &value),
            "edgeTypes" => {
                edge_types_seen = true;
                for item in value.split(',') {
                    let trimmed = item.trim();
                    if trimmed.is_empty() {
                        push_issue(
                            &mut issues,
                            "edgeTypes",
                            "must_be_non_empty_string",
                            "edgeTypes entries must be non-empty strings",
                        );
                    } else {
                        edge_types.push(trimmed.to_string());
                    }
                }
            }
            _ => {}
        }
    }

    let source = file.unwrap_or_default();
    let source_trimmed = source.trim();
    if source_trimmed.is_empty() {
        push_issue(
            &mut issues,
            "file",
            "must_be_non_empty",
            "file must not be empty",
        );
    }

    if !issues.is_empty() {
        return Err(crate::impact::InvalidArgumentError {
            details: invalid_argument_details(issues),
        });
    }

    let raw_controls = crate::impact::ImpactQueryControlsRaw {
        max_edges,
        max_depth,
        edge_types: if edge_types_seen {
            Some(edge_types)
        } else {
            None
        },
    };
    let controls = raw_controls.validate()?;

    Ok((source_trimmed.to_string(), controls))
}

pub(crate) async fn impact_graph_handler(
    State(state): State<AppState>,
    RawQuery(raw): RawQuery,
    Query(repo_id): Query<RepoIdQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let (source, controls) = match parse_impact_graph_query(raw.as_deref()) {
        Ok(value) => value,
        Err(err) => {
            let message =
                if err.details.issues.len() == 1 && err.details.field_errors.contains_key("file") {
                    "file must not be empty"
                } else {
                    "invalid query parameters"
                };
            return invalid_argument_response(message, err.details);
        }
    };

    let repo = match crate::search::resolve_repo_context(
        &state,
        &headers,
        repo_id.repo_id.as_deref(),
        None,
        false,
    ) {
        Ok(repo) => repo,
        Err(err) => return json_error(err.status, err.code, err.message),
    };
    if let Err(err) = crate::index::ensure_indexed(repo.indexer.clone()).await {
        state.metrics.inc_error();
        if let Some(app) = err.downcast_ref::<AppError>() {
            return json_error(
                status_for_app_error(app.code),
                app.code,
                app.message.clone(),
            );
        }
        warn!(target: "docdexd", error = ?err, "indexing failed");
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_INTERNAL_ERROR,
            "indexing failed",
        );
    }

    let repo_id = match crate::symbols::repo_id_for_root(repo.indexer.repo_root()) {
        Ok(value) => value,
        Err(err) => {
            state.metrics.inc_error();
            warn!(target: "docdexd", error = ?err, "impact graph repo id unavailable");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ImpactErrorResponse {
                    error: ImpactErrorDetail {
                        code: "internal_error",
                        message: "repo identity unavailable".to_string(),
                        details: None,
                    },
                }),
            )
                .into_response();
        }
    };
    let store = crate::impact::ImpactGraphStore::new(repo.indexer.state_dir());
    let all_edges = match store.read_edges() {
        Ok(edges) => edges,
        Err(err) => {
            state.metrics.inc_error();
            warn!(target: "docdexd", error = ?err, "impact graph read failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ImpactErrorResponse {
                    error: ImpactErrorDetail {
                        code: "internal_error",
                        message: "impact graph unavailable".to_string(),
                        details: None,
                    },
                }),
            )
                .into_response();
        }
    };

    let traversal = crate::impact::traverse_impact(&source, &all_edges, &controls);
    let diagnostics = match store.read_diagnostics(&source) {
        Ok(value) => value,
        Err(err) => {
            state.metrics.inc_error();
            warn!(target: "docdexd", error = ?err, "impact diagnostics read failed");
            None
        }
    };
    let response =
        crate::impact::build_impact_response(&repo_id, &source, traversal, &controls, diagnostics);
    Json(response).into_response()
}

pub(crate) async fn impact_diagnostics_handler(
    State(state): State<AppState>,
    Query(params): Query<ImpactDiagnosticsQuery>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let repo = match crate::search::resolve_repo_context(
        &state,
        &headers,
        params.repo_id.as_deref(),
        None,
        false,
    ) {
        Ok(repo) => repo,
        Err(err) => return json_error(err.status, err.code, err.message),
    };
    if let Err(err) = crate::index::ensure_indexed(repo.indexer.clone()).await {
        state.metrics.inc_error();
        if let Some(app) = err.downcast_ref::<AppError>() {
            return json_error(
                status_for_app_error(app.code),
                app.code,
                app.message.clone(),
            );
        }
        warn!(target: "docdexd", error = ?err, "indexing failed");
        return json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_INTERNAL_ERROR,
            "indexing failed",
        );
    }

    let repo_id = match crate::symbols::repo_id_for_root(repo.indexer.repo_root()) {
        Ok(value) => value,
        Err(err) => {
            state.metrics.inc_error();
            warn!(target: "docdexd", error = ?err, "impact diagnostics repo id unavailable");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ImpactErrorResponse {
                    error: ImpactErrorDetail {
                        code: "internal_error",
                        message: "repo identity unavailable".to_string(),
                        details: None,
                    },
                }),
            )
                .into_response();
        }
    };

    let file = match params.file.as_deref().map(str::trim) {
        Some("") => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "invalid_argument",
                "file must not be empty",
            )
        }
        Some(value) => match normalize_rel_path(value) {
            Some(path) => Some(path),
            None => {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_argument",
                    "file must be repo-relative",
                )
            }
        },
        None => None,
    };

    let store = crate::impact::ImpactGraphStore::new(repo.indexer.state_dir());
    let diagnostics_map = match store.read_diagnostics_map() {
        Ok(map) => map,
        Err(err) => {
            state.metrics.inc_error();
            warn!(target: "docdexd", error = ?err, "impact diagnostics read failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ImpactErrorResponse {
                    error: ImpactErrorDetail {
                        code: "internal_error",
                        message: "impact diagnostics unavailable".to_string(),
                        details: None,
                    },
                }),
            )
                .into_response();
        }
    };

    let (entries, total, limit, offset) = if let Some(file) = file {
        let entry =
            diagnostics_map
                .get(&file)
                .cloned()
                .map(|diag| crate::impact::ImpactDiagnosticsEntry {
                    file: file.clone(),
                    diagnostics: diag,
                });
        let diagnostics = entry.into_iter().collect::<Vec<_>>();
        let count = diagnostics.len();
        (diagnostics, count, 1, 0)
    } else {
        let mut entries = diagnostics_map
            .into_iter()
            .map(|(file, diagnostics)| crate::impact::ImpactDiagnosticsEntry { file, diagnostics })
            .collect::<Vec<_>>();
        entries.sort_by(|a, b| a.file.cmp(&b.file));
        let total = entries.len();
        let limit = params
            .limit
            .unwrap_or(DIAGNOSTICS_DEFAULT_LIMIT)
            .min(DIAGNOSTICS_MAX_LIMIT)
            .max(1);
        let offset = params.offset.unwrap_or(0);
        let diagnostics = entries
            .into_iter()
            .skip(offset)
            .take(limit)
            .collect::<Vec<_>>();
        (diagnostics, total, limit, offset)
    };

    let response =
        crate::impact::build_impact_diagnostics_response(&repo_id, entries, total, limit, offset);
    Json(response).into_response()
}

fn normalize_rel_path(input: &str) -> Option<String> {
    let path = std::path::Path::new(input);
    if path.is_absolute() {
        return None;
    }
    let mut clean = std::path::PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => continue,
            std::path::Component::Normal(part) => clean.push(part),
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
