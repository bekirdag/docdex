use axum::body::Body;
use axum::extract::{Query, State};
use axum::http::{header::CONTENT_TYPE, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;

use crate::dag::view as dag_view;
use crate::error::{ERR_INTERNAL_ERROR, ERR_INVALID_ARGUMENT};
use crate::search::{json_error, repo_error_response, resolve_repo_context, AppState};

#[derive(Deserialize)]
pub struct DagExportQuery {
    pub session_id: Option<String>,
    pub format: Option<String>,
    pub max_nodes: Option<u64>,
    #[serde(default)]
    pub repo_id: Option<String>,
}

pub async fn dag_export_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<DagExportQuery>,
) -> Response {
    let repo = match resolve_repo_context(&state, &headers, params.repo_id.as_deref(), None, false)
    {
        Ok(repo) => repo,
        Err(err) => return repo_error_response(err),
    };

    let session_id = match params.session_id.as_deref().map(str::trim) {
        Some(id) if !id.is_empty() => id.to_string(),
        _ => {
            return json_error(
                StatusCode::BAD_REQUEST,
                ERR_INVALID_ARGUMENT,
                "session_id is required",
            )
        }
    };

    let format = params
        .format
        .as_deref()
        .unwrap_or("json")
        .trim()
        .to_ascii_lowercase();
    let max_nodes = params
        .max_nodes
        .and_then(|value| usize::try_from(value).ok());

    match format.as_str() {
        "json" => match dag_view::export_session(
            repo.indexer.repo_root(),
            &session_id,
            Some(repo.indexer.state_dir().to_path_buf()),
            max_nodes,
        ) {
            Ok(payload) => axum::Json(payload).into_response(),
            Err(err) => json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                err.to_string(),
            ),
        },
        "text" => match dag_view::render_session_as_text(
            repo.indexer.repo_root(),
            &session_id,
            Some(repo.indexer.state_dir().to_path_buf()),
            max_nodes,
        ) {
            Ok(output) => text_response(output),
            Err(err) => json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                err.to_string(),
            ),
        },
        "dot" => match dag_view::render_session_as_dot(
            repo.indexer.repo_root(),
            &session_id,
            Some(repo.indexer.state_dir().to_path_buf()),
            max_nodes,
        ) {
            Ok(output) => text_response(output),
            Err(err) => json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                err.to_string(),
            ),
        },
        _ => json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "format must be json, text, or dot",
        ),
    }
}

fn text_response(body: String) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Body::from(body))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}
