use axum::{
    extract::{Json, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::ErrorKind;
use tracing::warn;

use crate::error::{
    status_for_app_error, AppError, ERR_ENCRYPTED_OPERATION_DISABLED, ERR_INTERNAL_ERROR,
    ERR_INVALID_ARGUMENT,
};
use crate::http_api::json_error;
use crate::max_size::OPEN_MAX_BYTES;
use crate::search::AppState;

#[derive(Debug, Deserialize)]
pub struct OpenRequest {
    #[serde(default, alias = "file")]
    pub path: Option<String>,
    #[serde(default)]
    pub repo_id: Option<String>,
    #[serde(default, alias = "startLine")]
    pub start_line: Option<usize>,
    #[serde(default, alias = "endLine")]
    pub end_line: Option<usize>,
    #[serde(default)]
    pub clamp: Option<bool>,
    #[serde(default)]
    pub head: Option<usize>,
}

#[derive(Debug, Serialize)]
struct OpenResponse {
    path: String,
    start_line: usize,
    end_line: usize,
    total_lines: usize,
    content: String,
    repo_root: String,
    project_root: String,
}

pub async fn open_get_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<OpenRequest>,
) -> Response {
    open_response(state, headers, params).await
}

pub async fn open_post_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<OpenRequest>,
) -> Response {
    open_response(state, headers, payload).await
}

async fn open_response(state: AppState, headers: HeaderMap, payload: OpenRequest) -> Response {
    let repo = match super::shared::resolve_repo_request(
        &state,
        &headers,
        payload.repo_id.as_deref(),
        payload.repo_id.as_deref(),
        false,
    ) {
        Ok(repo) => repo,
        Err(response) => return response,
    };

    let repo_encryption = repo.indexer.config().repo_encryption();
    if repo_encryption.is_enabled() {
        if !repo_encryption.full_file_open_enabled {
            return json_error(
                StatusCode::CONFLICT,
                ERR_ENCRYPTED_OPERATION_DISABLED,
                "repository encryption full-file open is disabled by policy; use snippet/search access instead",
            );
        }
        if let Err(err) = repo_encryption.require_key() {
            if let Some(app) = err.downcast_ref::<AppError>() {
                return json_error(
                    status_for_app_error(app.code),
                    app.code,
                    app.message.clone(),
                );
            }
            warn!(target: "docdexd", error = ?err, "repository encryption key check failed");
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "repository encryption key check failed",
            );
        }
    }

    let raw_path = match payload.path.as_deref().map(str::trim) {
        Some(value) if !value.is_empty() => value,
        _ => {
            return json_error(
                StatusCode::BAD_REQUEST,
                ERR_INVALID_ARGUMENT,
                "path is required",
            )
        }
    };
    let rel_path = match crate::path_utils::normalize_repo_relative_path_from_str(raw_path) {
        Some(value) => value,
        None => {
            return json_error(
                StatusCode::BAD_REQUEST,
                ERR_INVALID_ARGUMENT,
                "path must be repo-relative and not contain parent components",
            )
        }
    };

    let repo_root = repo.indexer.repo_root().to_path_buf();
    let canonical_root = match repo_root.canonicalize() {
        Ok(value) => value,
        Err(err) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                error = ?err,
                repo_root = %repo_root.display(),
                "repo root canonicalization failed"
            );
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "repo root canonicalization failed",
            );
        }
    };
    let abs_path = repo_root.join(&rel_path);
    let canonical = match abs_path.canonicalize() {
        Ok(value) => value,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            return json_error(StatusCode::NOT_FOUND, "not_found", "file not found")
        }
        Err(err) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                error = ?err,
                path = %rel_path.display(),
                "file path canonicalization failed"
            );
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "file path canonicalization failed",
            );
        }
    };
    if !canonical.starts_with(&canonical_root) {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "path must be under repo root",
        );
    }

    let content = match fs::read_to_string(&canonical) {
        Ok(value) => value,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            return json_error(StatusCode::NOT_FOUND, "not_found", "file not found")
        }
        Err(err) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                error = ?err,
                path = %rel_path.display(),
                "file read failed"
            );
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "file read failed",
            );
        }
    };
    if content.len() > OPEN_MAX_BYTES {
        return json_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "max_content_exceeded",
            format!(
                "file too large ({} bytes > {} limit)",
                content.len(),
                OPEN_MAX_BYTES
            ),
        );
    }

    let lines: Vec<&str> = content.lines().collect();
    let total_lines = lines.len();
    if total_lines == 0 {
        return Json(OpenResponse {
            path: rel_path.display().to_string(),
            start_line: 0,
            end_line: 0,
            total_lines: 0,
            content: String::new(),
            repo_root: repo_root.display().to_string(),
            project_root: repo_root.display().to_string(),
        })
        .into_response();
    }

    let (start_line, end_line) = match resolve_open_range(
        total_lines,
        payload.start_line,
        payload.end_line,
        payload.head,
        payload.clamp.unwrap_or(false),
    ) {
        Ok(value) => value,
        Err(range) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                "invalid_range",
                format!(
                    "line range is invalid (start_line={}, end_line={}, total_lines={})",
                    range.start_line, range.end_line, range.total_lines
                ),
            )
        }
    };

    let start_idx = start_line.saturating_sub(1);
    let end_idx = end_line.saturating_sub(1);
    let slice = lines[start_idx..=end_idx].join("\n");
    Json(OpenResponse {
        path: rel_path.display().to_string(),
        start_line,
        end_line,
        total_lines,
        content: slice,
        repo_root: repo_root.display().to_string(),
        project_root: repo_root.display().to_string(),
    })
    .into_response()
}

#[derive(Debug, PartialEq, Eq)]
struct InvalidRange {
    start_line: usize,
    end_line: usize,
    total_lines: usize,
}

fn resolve_open_range(
    total_lines: usize,
    start_line: Option<usize>,
    end_line: Option<usize>,
    head: Option<usize>,
    clamp: bool,
) -> Result<(usize, usize), InvalidRange> {
    let mut start = start_line.unwrap_or(1).max(1);
    let mut end = end_line.unwrap_or(total_lines);
    let mut clamp = clamp;

    if let Some(head) = head {
        start = 1;
        end = head.max(1);
        clamp = true;
    }

    if clamp {
        if total_lines == 0 {
            return Ok((0, 0));
        }
        if start > total_lines {
            start = total_lines;
        }
        if end > total_lines {
            end = total_lines;
        }
        if end < start {
            end = start;
        }
        return Ok((start, end));
    }

    if end < start || start > total_lines || end > total_lines {
        return Err(InvalidRange {
            start_line: start,
            end_line: end,
            total_lines,
        });
    }
    Ok((start, end))
}

#[cfg(test)]
mod tests {
    use super::resolve_open_range;

    #[test]
    fn resolve_open_range_clamps_when_requested() {
        assert_eq!(
            resolve_open_range(10, Some(1), Some(25), None, true).expect("range"),
            (1, 10)
        );
    }

    #[test]
    fn resolve_open_range_head_sets_clamp() {
        assert_eq!(
            resolve_open_range(5, None, None, Some(20), false).expect("range"),
            (1, 5)
        );
    }

    #[test]
    fn resolve_open_range_errors_without_clamp() {
        let err = resolve_open_range(5, Some(1), Some(10), None, false)
            .expect_err("expected invalid range");
        assert_eq!(err.start_line, 1);
        assert_eq!(err.end_line, 10);
        assert_eq!(err.total_lines, 5);
    }
}
