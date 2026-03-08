use crate::api::v1::initialize::{parse_root_uri, resolve_initialize};
use crate::error::{
    repo_resolution_details, AppError, ERR_INTERNAL_ERROR, ERR_INVALID_ARGUMENT,
    ERR_MISSING_DEPENDENCY, ERR_MISSING_REPO_PATH,
};
use crate::search::{json_error, json_error_with_details, status_for_app_error, AppState};
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
    Json(payload): Json<Value>,
) -> Response {
    let Some(router) = state.mcp_router.as_ref() else {
        return json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            ERR_MISSING_DEPENDENCY,
            "mcp proxy is not enabled",
        );
    };
    match payload {
        Value::Array(batch) => handle_mcp_batch(&state, router, batch).await,
        payload => match handle_mcp_single(&state, router, payload).await {
            Ok(Some(response)) => Json(response).into_response(),
            Ok(None) => StatusCode::NO_CONTENT.into_response(),
            Err(response) => response,
        },
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
    if is_notification(&payload, method.as_deref()) {
        return StatusCode::NO_CONTENT.into_response();
    }
    if method.as_deref() == Some("initialize") {
        normalize_initialize_payload(&mut payload);
        let root_uri = match extract_init_root(&payload) {
            Some(root_uri) => root_uri,
            None => {
                return json_error(
                    StatusCode::BAD_REQUEST,
                    ERR_INVALID_ARGUMENT,
                    "missing initialize rootUri (set params.rootUri or roots/workspaceFolders)",
                );
            }
        };
        let repo_root = match resolve_repo_for_mcp(&state, Some(root_uri)) {
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
    } else {
        let bound_root = router.session_repo_root(&session_id).await;
        if let Some(root_uri) = extract_project_root(&payload) {
            match resolve_repo_for_mcp(&state, Some(root_uri)) {
                Ok(repo_root) => {
                    let should_init = bound_root
                        .as_ref()
                        .map(|root| root != &repo_root)
                        .unwrap_or(true);
                    if let Err(err) = router.bind_session(&session_id, &repo_root).await {
                        return json_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            ERR_INTERNAL_ERROR,
                            format!("mcp proxy failed: {err}"),
                        );
                    }
                    if should_init {
                        if let Err(err) = router
                            .enqueue_internal_initialize(&session_id, &repo_root)
                            .await
                        {
                            return json_error(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                ERR_INTERNAL_ERROR,
                                format!("mcp proxy failed: {err}"),
                            );
                        }
                    }
                }
                Err(err) => {
                    return app_error_response(err);
                }
            }
        } else if bound_root.is_none() {
            return json_error(
                StatusCode::BAD_REQUEST,
                ERR_INVALID_ARGUMENT,
                "missing initialize (call initialize with rootUri before MCP requests)",
            );
        }
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

async fn handle_mcp_batch(
    state: &AppState,
    router: &crate::mcp::McpProxyRouter,
    batch: Vec<Value>,
) -> Response {
    if batch.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "mcp batch must contain at least one request",
        );
    }
    let mut responses = Vec::new();
    for payload in batch {
        match handle_mcp_single(state, router, payload).await {
            Ok(Some(response)) => responses.push(response),
            Ok(None) => {}
            Err(response) => return response,
        }
    }
    if responses.is_empty() {
        StatusCode::NO_CONTENT.into_response()
    } else {
        Json(Value::Array(responses)).into_response()
    }
}

async fn handle_mcp_single(
    state: &AppState,
    router: &crate::mcp::McpProxyRouter,
    mut payload: Value,
) -> Result<Option<Value>, Response> {
    if !payload.is_object() {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "mcp request must be a JSON object",
        ));
    }
    let method = extract_method(&payload).map(str::to_string);
    if is_notification(&payload, method.as_deref()) {
        return Ok(None);
    }
    if method.as_deref() == Some("initialize") {
        normalize_initialize_payload(&mut payload);
    }
    let repo_root = if method.as_deref() == Some("initialize") {
        let resolved = match extract_init_root(&payload) {
            Some(root_uri) => resolve_repo_for_mcp(state, Some(root_uri)),
            None => resolve_repo_for_mcp(state, None),
        };
        match resolved {
            Ok(root) => {
                ensure_initialize_root(&mut payload, &root);
                Some(root)
            }
            Err(err) => return Err(app_error_response(err)),
        }
    } else if let Some(root_uri) = extract_project_root(&payload) {
        match resolve_repo_for_mcp(state, Some(root_uri)) {
            Ok(root) => Some(root),
            Err(err) => {
                return Err(app_error_response(err));
            }
        }
    } else {
        match resolve_repo_for_mcp(state, None) {
            Ok(root) => Some(root),
            Err(err) => return Err(app_error_response(err)),
        }
    };
    match router.call(repo_root.as_deref(), payload).await {
        Ok(response) => Ok(Some(response)),
        Err(err) => Err(json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            ERR_INTERNAL_ERROR,
            format!("mcp proxy failed: {err}"),
        )),
    }
}

fn app_error_response(err: AppError) -> Response {
    let status = status_for_app_error(err.code);
    if let Some(details) = err.details {
        json_error_with_details(status, err.code, err.message, details)
    } else {
        json_error(status, err.code, err.message)
    }
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

fn ensure_initialize_root(payload: &mut Value, repo_root: &PathBuf) {
    let repo_root = repo_root.to_string_lossy().to_string();
    let Some(obj) = payload.as_object_mut() else {
        return;
    };
    let params = obj
        .entry("params".to_string())
        .or_insert_with(|| Value::Object(serde_json::Map::new()));
    let Some(params) = params.as_object_mut() else {
        return;
    };
    params
        .entry("workspace_root".to_string())
        .or_insert(Value::String(repo_root.clone()));
    params
        .entry("rootUri".to_string())
        .or_insert(Value::String(repo_root));
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
            let trimmed = value.trim();
            if trimmed.is_empty() {
                continue;
            }
            return Some(trimmed.to_string());
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
            let trimmed = value.trim();
            if trimmed.is_empty() {
                continue;
            }
            return Some(trimmed.to_string());
        }
        if let Some(obj) = entry.as_object() {
            for key in ["uri", "rootUri", "path", "rootPath", "root_path"] {
                if let Some(value) = obj.get(key).and_then(|value| value.as_str()) {
                    let trimmed = value.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    return Some(trimmed.to_string());
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::search::SecurityConfig;
    use axum::extract::{Query, State};
    use axum::http::{HeaderMap, HeaderValue, StatusCode};
    use http_body_util::BodyExt;
    use serde_json::json;
    use std::fs;
    use std::path::PathBuf;
    use std::sync::Arc;
    use tempfile::TempDir;
    use url::Url;

    async fn build_test_state() -> Result<(AppState, TempDir), Box<dyn std::error::Error>> {
        let temp = TempDir::new()?;
        fs::create_dir_all(temp.path())?;
        let state_dir = temp.path().join("state");
        let index_config = crate::index::IndexConfig::with_overrides(
            temp.path(),
            Some(state_dir),
            Vec::new(),
            Vec::new(),
            true,
        )?;
        let indexer = Arc::new(crate::index::Indexer::with_config(
            temp.path().to_path_buf(),
            index_config,
        )?);
        let repo_id = crate::repo_manager::repo_fingerprint_sha256(temp.path())?;
        let legacy_repo_id = crate::repo_manager::fingerprint::legacy_repo_id_for_root(temp.path());
        let security = SecurityConfig::from_options(
            None,
            &[],
            10,
            1024,
            1024,
            0,
            0,
            false,
            false,
            false,
            false,
            false,
        )?;
        let repo_args = crate::config::RepoArgs {
            repo: temp.path().to_path_buf(),
            state_dir: None,
            exclude_prefix: Vec::new(),
            exclude_dir: Vec::new(),
            enable_symbol_extraction: true,
        };
        let mcp_router = Some(
            crate::mcp::spawn_proxy_for_serve(
                repo_args,
                4,
                0,
                0,
                false,
                String::new(),
                String::new(),
                0,
                None,
                None,
                None,
                Arc::new(crate::metrics::DelegationMetrics::default()),
            )
            .await?,
        );
        let state = AppState {
            repo_id,
            legacy_repo_id,
            indexer,
            libs_indexer: None,
            security,
            access_log: false,
            audit: None,
            metrics: Arc::new(crate::metrics::Metrics::default()),
            delegation_metrics: Arc::new(crate::metrics::DelegationMetrics::default()),
            memory: None,
            profile_state: None,
            features: crate::config::FeatureFlagsConfig::default(),
            default_agent_id: None,
            max_answer_tokens: 256,
            llm_config: crate::config::LlmConfig {
                base_url: "http://127.0.0.1".to_string(),
                default_model: "test".to_string(),
                ..crate::config::LlmConfig::default()
            },
            llm_base_url: "http://127.0.0.1".to_string(),
            llm_default_model: "test".to_string(),
            global_state_dir: None,
            repos: None,
            multi_repo: false,
            require_repo_id: false,
            mcp_router,
        };
        Ok((state, temp))
    }

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

    #[test]
    fn extract_init_root_ignores_empty_strings() {
        let payload = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "rootUri": "",
                "workspaceRoot": "   ",
                "roots": [""]
            }
        });
        let root = extract_init_root(&payload);
        assert!(root.is_none());
    }

    #[tokio::test]
    async fn mcp_message_rejects_uninitialized_session() -> Result<(), Box<dyn std::error::Error>> {
        let (state, _temp) = build_test_state().await?;
        let router = state.mcp_router.as_ref().expect("mcp router").clone();
        let (session_id, _rx) = router.create_session().await;

        let mut headers = HeaderMap::new();
        headers.insert(SESSION_HEADER, HeaderValue::from_str(&session_id)?);
        let payload = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {}
        });
        let response = mcp_message_handler(
            State(state),
            Query(McpSessionQuery { session_id: None }),
            headers,
            Json(payload),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = response.into_body().collect().await?.to_bytes();
        let payload: serde_json::Value = serde_json::from_slice(&body)?;
        let message = payload
            .get("error")
            .and_then(|value| value.get("message"))
            .and_then(|value| value.as_str())
            .unwrap_or("");
        assert!(
            message.contains("initialize"),
            "expected initialize hint, got: {message}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn mcp_http_initialize_defaults_to_repo_root() -> Result<(), Box<dyn std::error::Error>> {
        let (state, _temp) = build_test_state().await?;
        let init_payload = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        });
        let init_response = mcp_request_handler(State(state.clone()), Json(init_payload)).await;
        assert!(init_response.status().is_success());
        let init_body = init_response.into_body().collect().await?.to_bytes();
        let init_value: serde_json::Value = serde_json::from_slice(&init_body)?;
        assert!(init_value.get("result").is_some());

        let tools_payload = json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        });
        let tools_response = mcp_request_handler(State(state), Json(tools_payload)).await;
        assert!(tools_response.status().is_success());
        let tools_body = tools_response.into_body().collect().await?.to_bytes();
        let tools_value: serde_json::Value = serde_json::from_slice(&tools_body)?;
        let tools = tools_value
            .get("result")
            .and_then(|value| value.get("tools"))
            .and_then(|value| value.as_array());
        assert!(tools.is_some());
        Ok(())
    }
}

fn resolve_repo_for_mcp(state: &AppState, root_uri: Option<String>) -> Result<PathBuf, AppError> {
    let mut root_uri = root_uri;
    if root_uri.is_none() && state.require_repo_id {
        // Allow MCP clients that omit rootUri (e.g. Codex) to initialize in daemon mode.
        root_uri = Some(state.indexer.repo_root().to_string_lossy().to_string());
    }
    if let Some(root_uri) = root_uri.as_deref() {
        let candidate = parse_root_uri(root_uri)?;
        if !candidate.exists() {
            let normalized = candidate.to_string_lossy().replace('\\', "/");
            let details = repo_resolution_details(normalized, None, None, Vec::new());
            return Err(
                AppError::new(ERR_MISSING_REPO_PATH, "repo path not found").with_details(details)
            );
        }
    }
    let init = resolve_initialize(state, root_uri.as_deref())?;
    Ok(PathBuf::from(init.repo_root))
}
