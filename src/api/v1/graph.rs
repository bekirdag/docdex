use axum::{
    extract::{Query, RawQuery, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::warn;

use crate::search::{json_error, AppState};

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
struct RepoIdQuery {
    #[serde(default)]
    repo_id: Option<String>,
}

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

pub async fn impact_graph_handler(
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

    if let Err(err) = crate::search::resolve_repo_id(
        &headers,
        repo_id.repo_id.as_deref(),
        None,
        state.indexer.as_ref(),
        false,
    ) {
        return json_error(err.status, err.code, err.message);
    }

    let repo_id = crate::symbols::repo_id_for_root(state.indexer.repo_root())
        .unwrap_or_else(|_| String::new());
    let store = crate::impact::ImpactGraphStore::new(state.indexer.state_dir());
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
    let response = crate::impact::build_impact_response(&repo_id, &source, traversal, &controls);
    Json(response).into_response()
}
