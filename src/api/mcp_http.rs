use crate::api::v1::initialize::{parse_root_uri, resolve_initialize};
use crate::error::{AppError, ERR_INTERNAL_ERROR, ERR_INVALID_ARGUMENT, ERR_MISSING_DEPENDENCY};
use crate::search::{json_error, status_for_app_error, AppState};
use axum::extract::{Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Json, Response};
use serde::Deserialize;
use serde_json::Value;
use std::path::PathBuf;
use std::time::Duration;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;

const SESSION_HEADER: &str = "x-docdex-mcp-session";

#[derive(Deserialize)]
pub struct McpSessionQuery {
    #[serde(default)]
    session_id: Option<String>,
}

pub async fn mcp_request_handler(
    State(state): State<AppState>,
    Json(mut payload): Json<Value>,
) -> Response {
    let Some(router) = state.mcp_router.as_ref() else {
        return json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            ERR_MISSING_DEPENDENCY,
            "mcp proxy is not enabled",
        );
    };
    let method = extract_method(&payload).map(str::to_string);
    if method.as_deref() == Some("initialize") {
        normalize_initialize_payload(&mut payload);
    }
    let repo_root = match method {
        Some(method) if method == "initialize" => {
            match resolve_repo_for_mcp(&state, extract_init_root(&payload)) {
            Ok(root) => {
                router.set_default_repo(root.clone()).await;
                Some(root)
            }
            Err(err) => {
                return json_error(
                    status_for_app_error(err.code),
                    err.code,
                    err.message,
                );
            }
        }
        }
        _ => {
            if let Some(root_uri) = extract_project_root(&payload) {
                match resolve_repo_for_mcp(&state, Some(root_uri)) {
                    Ok(root) => Some(root),
                    Err(err) => {
                        return json_error(
                            status_for_app_error(err.code),
                            err.code,
                            err.message,
                        );
                    }
                }
            } else {
                None
            }
        }
    };
    match router.call(repo_root.as_deref(), payload).await {
        Ok(response) => Json(response).into_response(),
        Err(err) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_INTERNAL_ERROR,
            format!("mcp proxy failed: {err}"),
        ),
    }
}

pub async fn mcp_sse_handler(State(state): State<AppState>) -> Response {
    let Some(router) = state.mcp_router.as_ref() else {
        return json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            ERR_MISSING_DEPENDENCY,
            "mcp proxy is not enabled",
        );
    };
    let (session_id, rx) = router.create_session().await;
    let stream = ReceiverStream::new(rx).map(|payload| {
        Ok::<_, std::convert::Infallible>(Event::default().data(payload.to_string()))
    });
    let mut response = Sse::new(stream)
        .keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(15))
                .text("keepalive"),
        )
        .into_response();
    if let Ok(value) = HeaderValue::from_str(&session_id) {
        response.headers_mut().insert(SESSION_HEADER, value);
    }
    response
}

pub async fn mcp_message_handler(
    State(state): State<AppState>,
    Query(query): Query<McpSessionQuery>,
    headers: HeaderMap,
    Json(mut payload): Json<Value>,
) -> Response {
    let Some(router) = state.mcp_router.as_ref() else {
        return json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            ERR_MISSING_DEPENDENCY,
            "mcp proxy is not enabled",
        );
    };
    let session_id = query
        .session_id
        .or_else(|| header_session_id(&headers));
    let Some(session_id) = session_id else {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "missing session_id (header x-docdex-mcp-session or ?session_id=)",
        );
    };
    let method = extract_method(&payload).map(str::to_string);
    if method.as_deref() == Some("initialize") {
        normalize_initialize_payload(&mut payload);
        let repo_root = match resolve_repo_for_mcp(&state, extract_init_root(&payload)) {
            Ok(root) => root,
            Err(err) => {
                return json_error(
                    status_for_app_error(err.code),
                    err.code,
                    err.message,
                );
            }
        };
        if let Err(err) = router.bind_session(&session_id, &repo_root).await {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                format!("mcp proxy failed: {err}"),
            );
        }
    } else if let Some(root_uri) = extract_project_root(&payload) {
        match resolve_repo_for_mcp(&state, Some(root_uri)) {
            Ok(repo_root) => {
                if let Err(err) = router.bind_session(&session_id, &repo_root).await {
                    return json_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        ERR_INTERNAL_ERROR,
                        format!("mcp proxy failed: {err}"),
                    );
                }
            }
            Err(err) => {
                return json_error(
                    status_for_app_error(err.code),
                    err.code,
                    err.message,
                );
            }
        }
    } else if router.session_repo_root(&session_id).await.is_none() {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "missing initialize (call initialize with rootUri or send project_root)",
        );
    }
    match router.enqueue_for_session(&session_id, payload).await {
        Ok(ack) => Json(ack).into_response(),
        Err(err) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_INTERNAL_ERROR,
            format!("mcp proxy failed: {err}"),
        ),
    }
}

fn header_session_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get(SESSION_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string())
}

fn extract_method(payload: &Value) -> Option<&str> {
    payload.get("method").and_then(|value| value.as_str())
}

fn extract_init_root(payload: &Value) -> Option<String> {
    let params = payload.get("params")?.as_object()?;
    for key in ["rootUri", "workspace_root", "project_root", "repo_path"] {
        if let Some(value) = params.get(key).and_then(|value| value.as_str()) {
            return Some(value.to_string());
        }
    }
    None
}

fn extract_project_root(payload: &Value) -> Option<String> {
    let params = payload.get("params")?.as_object()?;
    for key in ["project_root", "repo_path", "rootUri", "workspace_root"] {
        if let Some(value) = params.get(key).and_then(|value| value.as_str()) {
            return Some(value.to_string());
        }
    }
    if let Some(args) = params.get("arguments").and_then(|value| value.as_object()) {
        for key in ["project_root", "repo_path"] {
            if let Some(value) = args.get(key).and_then(|value| value.as_str()) {
                return Some(value.to_string());
            }
        }
    }
    None
}

fn normalize_initialize_payload(payload: &mut Value) {
    let Some(params) = payload.get_mut("params").and_then(|value| value.as_object_mut()) else {
        return;
    };
    let root_uri = params
        .get("rootUri")
        .and_then(|value| value.as_str())
        .map(|value| value.to_string());
    if root_uri.is_none() {
        return;
    }
    if params.contains_key("workspace_root") || params.contains_key("project_root") {
        return;
    }
    let root_uri = root_uri.unwrap();
    let workspace_root = parse_root_uri(&root_uri)
        .map(|path| path.to_string_lossy().to_string())
        .unwrap_or(root_uri);
    params.insert("workspace_root".to_string(), Value::String(workspace_root));
}

fn resolve_repo_for_mcp(state: &AppState, root_uri: Option<String>) -> Result<PathBuf, AppError> {
    let init = resolve_initialize(state, root_uri.as_deref())?;
    Ok(PathBuf::from(init.repo_root))
}
