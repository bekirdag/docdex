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
use tracing::warn;

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
    if is_notification(&payload, method.as_deref()) {
        return StatusCode::NO_CONTENT.into_response();
    }
    if method.as_deref() == Some("initialize") {
        normalize_initialize_payload(&mut payload);
    }
    let require_repo = state
        .repos
        .as_ref()
        .map(|manager| state.multi_repo && manager.repo_count() > 1)
        .unwrap_or(false);
    let repo_root = match method {
        Some(method) if method == "initialize" => {
            let root_uri = extract_init_root(&payload);
            if require_repo && root_uri.is_none() {
                warn!(
                    target: "docdexd",
                    "mcp initialize missing rootUri while multiple repos are active; default repo will be used"
                );
            }
            match resolve_repo_for_mcp(&state, root_uri) {
                Ok(root) => {
                    if !state.multi_repo {
                        router.set_default_repo(root.clone()).await;
                    }
                    Some(root)
                }
                Err(err) => {
                    return json_error(status_for_app_error(err.code), err.code, err.message);
                }
            }
        }
        _ => {
            if let Some(root_uri) = extract_project_root(&payload) {
                match resolve_repo_for_mcp(&state, Some(root_uri)) {
                    Ok(root) => Some(root),
                    Err(err) => {
                        return json_error(status_for_app_error(err.code), err.code, err.message);
                    }
                }
            } else if require_repo {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    ERR_INVALID_ARGUMENT,
                    "missing project_root/repo_path (required when multiple repos are active)",
                );
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
    let session_id = query.session_id.or_else(|| header_session_id(&headers));
    let Some(session_id) = session_id else {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "missing session_id (header x-docdex-mcp-session or ?session_id=)",
        );
    };
    let method = extract_method(&payload).map(str::to_string);
    let require_repo = state
        .repos
        .as_ref()
        .map(|manager| state.multi_repo && manager.repo_count() > 1)
        .unwrap_or(false);
    if is_notification(&payload, method.as_deref()) {
        return StatusCode::NO_CONTENT.into_response();
    }
    if method.as_deref() == Some("initialize") {
        normalize_initialize_payload(&mut payload);
        let root_uri = extract_init_root(&payload);
        if require_repo && root_uri.is_none() {
            warn!(
                target: "docdexd",
                "mcp initialize missing rootUri while multiple repos are active; default repo will be used"
            );
        }
        let repo_root = match resolve_repo_for_mcp(&state, root_uri) {
            Ok(root) => root,
            Err(err) => {
                return json_error(status_for_app_error(err.code), err.code, err.message);
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
                return json_error(status_for_app_error(err.code), err.code, err.message);
            }
        }
    } else if router.session_repo_root(&session_id).await.is_none() {
        if require_repo {
            return json_error(
                StatusCode::BAD_REQUEST,
                ERR_INVALID_ARGUMENT,
                "missing project_root/repo_path (required when multiple repos are active)",
            );
        }
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

fn is_notification(payload: &Value, method: Option<&str>) -> bool {
    if payload.get("id").is_some() {
        return false;
    }
    match method {
        Some(name) if name.starts_with("notifications/") => true,
        Some("initialized") => true,
        _ => false,
    }
}

fn extract_init_root(payload: &Value) -> Option<String> {
    let params = payload.get("params")?.as_object()?;
    extract_root_from_params(params)
}

fn extract_project_root(payload: &Value) -> Option<String> {
    let params = payload.get("params")?.as_object()?;
    if let Some(root) = extract_root_from_params(params) {
        return Some(root);
    }
    if let Some(args) = params.get("arguments").and_then(|value| value.as_object()) {
        return extract_root_from_params(args);
    }
    None
}

fn normalize_initialize_payload(payload: &mut Value) {
    let Some(params) = payload
        .get_mut("params")
        .and_then(|value| value.as_object_mut())
    else {
        return;
    };
    let root_uri = params
        .get("rootUri")
        .and_then(|value| value.as_str())
        .map(|value| value.to_string())
        .or_else(|| extract_root_from_array(params.get("roots")))
        .or_else(|| extract_root_from_array(params.get("workspaceFolders")));
    if root_uri.is_none() {
        return;
    }
    if params.contains_key("workspace_root") || params.contains_key("project_root") {
        return;
    }
    let root_uri = root_uri.unwrap();
    if !params.contains_key("rootUri") {
        params.insert("rootUri".to_string(), Value::String(root_uri.clone()));
    }
    let workspace_root = parse_root_uri(&root_uri)
        .map(|path| path.to_string_lossy().to_string())
        .unwrap_or(root_uri);
    params.insert("workspace_root".to_string(), Value::String(workspace_root));
}

fn extract_root_from_params(params: &serde_json::Map<String, Value>) -> Option<String> {
    for key in [
        "rootUri",
        "workspace_root",
        "workspaceRoot",
        "project_root",
        "projectRoot",
        "repo_path",
        "repoPath",
        "rootPath",
        "root_path",
    ] {
        if let Some(value) = params.get(key).and_then(|value| value.as_str()) {
            return Some(value.to_string());
        }
    }
    if let Some(root) = extract_root_from_array(params.get("roots")) {
        return Some(root);
    }
    extract_root_from_array(params.get("workspaceFolders"))
}

fn extract_root_from_array(value: Option<&Value>) -> Option<String> {
    let roots = value?.as_array()?;
    for entry in roots {
        if let Some(value) = entry.as_str() {
            return Some(value.to_string());
        }
        if let Some(obj) = entry.as_object() {
            for key in ["uri", "rootUri", "path", "rootPath", "root_path"] {
                if let Some(value) = obj.get(key).and_then(|value| value.as_str()) {
                    return Some(value.to_string());
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;
    use url::Url;

    #[test]
    fn extract_init_root_accepts_roots_array() {
        let temp = TempDir::new().expect("temp dir");
        let repo_root = temp.path().join("repo");
        fs::create_dir_all(&repo_root).expect("create repo dir");
        let root_uri = Url::from_directory_path(&repo_root)
            .expect("file url")
            .to_string();
        let payload = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "roots": [
                    { "uri": root_uri }
                ]
            }
        });
        let root = extract_init_root(&payload);
        assert_eq!(root.as_deref(), Some(root_uri.as_str()));
    }

    #[test]
    fn extract_init_root_accepts_workspace_root() {
        let payload = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "workspaceRoot": "/workspace/project"
            }
        });
        let root = extract_init_root(&payload);
        assert_eq!(root.as_deref(), Some("/workspace/project"));
    }

    #[test]
    fn normalize_initialize_payload_sets_root_from_roots() {
        let temp = TempDir::new().expect("temp dir");
        let repo_root = temp.path().join("repo");
        fs::create_dir_all(&repo_root).expect("create repo dir");
        let expected_root_uri = Url::from_directory_path(&repo_root)
            .expect("file url")
            .to_string();
        let repo_root_str = repo_root.to_string_lossy().to_string();
        let mut payload = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "roots": [
                    { "uri": expected_root_uri }
                ]
            }
        });
        normalize_initialize_payload(&mut payload);
        let params = payload.get("params").and_then(|value| value.as_object());
        let root_uri = params
            .and_then(|params| params.get("rootUri"))
            .and_then(|value| value.as_str());
        let workspace_root = params
            .and_then(|params| params.get("workspace_root"))
            .and_then(|value| value.as_str());
        assert_eq!(root_uri, Some(expected_root_uri.as_str()));
        let resolved = workspace_root
            .map(PathBuf::from)
            .and_then(|path| path.canonicalize().ok())
            .unwrap_or_else(|| PathBuf::from(repo_root_str.as_str()));
        let expected = repo_root.canonicalize().expect("canonical repo root");
        assert_eq!(resolved, expected);
    }
}

fn resolve_repo_for_mcp(state: &AppState, root_uri: Option<String>) -> Result<PathBuf, AppError> {
    let init = resolve_initialize(state, root_uri.as_deref())?;
    Ok(PathBuf::from(init.repo_root))
}
