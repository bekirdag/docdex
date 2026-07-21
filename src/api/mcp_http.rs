use crate::api::v1::initialize::{parse_root_uri, resolve_initialize};
use crate::auth::RepoOperation;
use crate::error::status_for_app_error;
use crate::error::{
    repo_resolution_details, AppError, ERR_INTERNAL_ERROR, ERR_INVALID_ARGUMENT,
    ERR_MISSING_DEPENDENCY, ERR_MISSING_REPO, ERR_MISSING_REPO_PATH, ERR_RATE_LIMITED,
    ERR_SCOPE_DENIED,
};
use crate::http_api::{app_error_response, json_error};
use crate::search::AppState;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Json, Response};
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;
use tokio_stream::wrappers::ReceiverStream;

const MCP_SESSION_HEADER: &str = "mcp-session-id";
const LEGACY_SESSION_HEADER: &str = "x-docdex-mcp-session";

#[derive(Deserialize)]
pub struct McpSessionQuery {
    #[serde(default)]
    session_id: Option<String>,
}

struct McpCallOutcome {
    response: Option<Value>,
    issued_session_id: Option<String>,
}

struct McpSseStream {
    inner: ReceiverStream<Value>,
    router: std::sync::Arc<crate::mcp::McpProxyRouter>,
    session_id: String,
}

impl tokio_stream::Stream for McpSseStream {
    type Item = Result<Event, std::convert::Infallible>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        context: &mut TaskContext<'_>,
    ) -> Poll<Option<Self::Item>> {
        Pin::new(&mut self.inner)
            .poll_next(context)
            .map(|item| item.map(|payload| Ok(Event::default().data(payload.to_string()))))
    }
}

impl Drop for McpSseStream {
    fn drop(&mut self) {
        let router = self.router.clone();
        let session_id = self.session_id.clone();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                router.remove_session(&session_id).await;
            });
        }
    }
}

impl McpCallOutcome {
    fn into_response(self) -> Response {
        let Some(payload) = self.response else {
            return StatusCode::NO_CONTENT.into_response();
        };
        let mut response = Json(payload).into_response();
        if let Some(session_id) = self.issued_session_id {
            if let Ok(value) = HeaderValue::from_str(&session_id) {
                response
                    .headers_mut()
                    .insert(MCP_SESSION_HEADER, value.clone());
                response.headers_mut().insert(LEGACY_SESSION_HEADER, value);
            }
        }
        response
    }
}

pub async fn mcp_request_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Response {
    let Some(router) = state.mcp_router.as_ref() else {
        return json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            ERR_MISSING_DEPENDENCY,
            "mcp proxy is not enabled",
        );
    };
    let session_id = match header_session_id(&headers) {
        Ok(session_id) => session_id,
        Err(message) => {
            return json_error(StatusCode::BAD_REQUEST, ERR_INVALID_ARGUMENT, message);
        }
    };
    match payload {
        Value::Array(batch) => {
            handle_mcp_batch(&state, router, &headers, session_id.as_deref(), batch).await
        }
        payload => {
            match handle_mcp_single(&state, router, &headers, session_id.as_deref(), payload).await
            {
                Ok(outcome) => outcome.into_response(),
                Err(response) => response,
            }
        }
    }
}

pub async fn mcp_delete_handler(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(router) = state.mcp_router.as_ref() else {
        return json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            ERR_MISSING_DEPENDENCY,
            "mcp proxy is not enabled",
        );
    };
    let session_id = match header_session_id(&headers) {
        Ok(Some(session_id)) => session_id,
        Ok(None) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                ERR_INVALID_ARGUMENT,
                "missing MCP session header",
            );
        }
        Err(message) => {
            return json_error(StatusCode::BAD_REQUEST, ERR_INVALID_ARGUMENT, message);
        }
    };
    if router.remove_session(&session_id).await {
        StatusCode::NO_CONTENT.into_response()
    } else {
        json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "unknown or expired MCP session",
        )
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
    let (session_id, rx) = match router.create_session().await {
        Ok(session) => session,
        Err(err) => {
            return json_error(
                StatusCode::TOO_MANY_REQUESTS,
                ERR_RATE_LIMITED,
                format!("mcp session unavailable: {err}"),
            );
        }
    };
    let stream = McpSseStream {
        inner: ReceiverStream::new(rx),
        router: router.clone(),
        session_id: session_id.clone(),
    };
    let mut response = Sse::new(stream)
        .keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(15))
                .text("keepalive"),
        )
        .into_response();
    if let Ok(value) = HeaderValue::from_str(&session_id) {
        response
            .headers_mut()
            .insert(MCP_SESSION_HEADER, value.clone());
        response.headers_mut().insert(LEGACY_SESSION_HEADER, value);
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
    let header_session_id = match header_session_id(&headers) {
        Ok(session_id) => session_id,
        Err(message) => {
            return json_error(StatusCode::BAD_REQUEST, ERR_INVALID_ARGUMENT, message);
        }
    };
    if let (Some(query_session_id), Some(header_session_id)) =
        (query.session_id.as_deref(), header_session_id.as_deref())
    {
        if query_session_id != header_session_id {
            return json_error(
                StatusCode::BAD_REQUEST,
                ERR_INVALID_ARGUMENT,
                "conflicting MCP session identifiers",
            );
        }
    }
    let session_id = header_session_id.or(query.session_id);
    let Some(session_id) = session_id else {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "missing session_id (header mcp-session-id, legacy x-docdex-mcp-session, or ?session_id=)",
        );
    };
    let method = extract_method(&payload).map(str::to_string);
    let notification = is_notification(&payload, method.as_deref());
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
        if router
            .session_repo_root(&session_id)
            .await
            .is_some_and(|bound_root| bound_root != repo_root)
        {
            return json_error(
                StatusCode::BAD_REQUEST,
                ERR_INVALID_ARGUMENT,
                "MCP session is already bound to a different repository; create a new session",
            );
        }
        if let Err(err) = router.bind_session(&session_id, &repo_root).await {
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                format!("mcp proxy failed: {err}"),
            );
        }
    } else {
        let Some(bound_root) = router.session_repo_root(&session_id).await else {
            return json_error(
                StatusCode::BAD_REQUEST,
                ERR_INVALID_ARGUMENT,
                "missing initialize (call initialize with rootUri before MCP requests)",
            );
        };
        if let Some(root_uri) = extract_project_root(&payload) {
            match resolve_repo_for_mcp(&state, Some(root_uri)) {
                Ok(repo_root) => {
                    if repo_root != bound_root {
                        return json_error(
                            StatusCode::BAD_REQUEST,
                            ERR_INVALID_ARGUMENT,
                            "MCP session is bound to a different repository; create a new session",
                        );
                    }
                }
                Err(err) => {
                    return app_error_response(&err);
                }
            }
        }
        if let Err(response) =
            authorize_mcp_encrypted_repo(&state, &headers, &payload, Some(&bound_root)).await
        {
            return response;
        }
    }
    if notification {
        let result = if is_cancellation_notification(method.as_deref()) {
            router
                .call_for_session(&session_id, payload)
                .await
                .map(|_| ())
        } else {
            router.touch_bound_session(&session_id).await
        };
        return match result {
            Ok(()) => StatusCode::NO_CONTENT.into_response(),
            Err(err) => json_error(
                StatusCode::BAD_REQUEST,
                ERR_INVALID_ARGUMENT,
                format!("mcp notification failed: {err}"),
            ),
        };
    }
    match router.enqueue_for_session(&session_id, payload).await {
        Ok(ack) => Json(ack).into_response(),
        Err(err) => mcp_proxy_failure_response(err),
    }
}

fn mcp_proxy_failure_response(err: anyhow::Error) -> Response {
    if let Some(app_error) = err.downcast_ref::<AppError>() {
        return app_error_response(app_error);
    }
    json_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        ERR_INTERNAL_ERROR,
        format!("mcp proxy failed: {err}"),
    )
}

fn is_unbound_capability_request(method: Option<&str>) -> bool {
    matches!(
        method,
        Some(
            "tools/list"
                | "prompts/list"
                | "prompts/get"
                | "resources/list"
                | "resources/templates/list"
                | "ping"
        )
    )
}

fn is_unbound_global_tool_request(payload: &Value) -> bool {
    let method = extract_method(payload);
    if matches!(
        method,
        Some("docdex_get_profile" | "docdex_save_preference")
    ) {
        return true;
    }
    if method != Some("tools/call") {
        return false;
    }
    matches!(
        payload.pointer("/params/name").and_then(Value::as_str),
        Some("docdex_get_profile" | "docdex_save_preference")
    )
}

async fn call_unbound_request(
    router: &std::sync::Arc<crate::mcp::McpProxyRouter>,
    payload: Value,
) -> Result<McpCallOutcome, Response> {
    match extract_method(&payload) {
        Some("resources/list") => Ok(McpCallOutcome {
            response: Some(jsonrpc_result_response(
                &payload,
                json!({ "resources": [] }),
            )),
            issued_session_id: None,
        }),
        Some("ping") => Ok(McpCallOutcome {
            response: Some(jsonrpc_result_response(&payload, json!({}))),
            issued_session_id: None,
        }),
        _ => {
            let bootstrap_root = router.bootstrap_repo_root();
            let response = router
                .call(Some(bootstrap_root.as_path()), None, payload)
                .await
                .map_err(mcp_proxy_failure_response)?;
            Ok(McpCallOutcome {
                response: Some(response),
                issued_session_id: None,
            })
        }
    }
}

fn jsonrpc_result_response(payload: &Value, result: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": payload.get("id").cloned().unwrap_or(Value::Null),
        "result": result,
    })
}

fn header_session_id(headers: &HeaderMap) -> Result<Option<String>, &'static str> {
    let standard = session_header_value(headers, MCP_SESSION_HEADER)?;
    let legacy = session_header_value(headers, LEGACY_SESSION_HEADER)?;
    if let (Some(standard), Some(legacy)) = (standard.as_deref(), legacy.as_deref()) {
        if standard != legacy {
            return Err("conflicting MCP session headers");
        }
    }
    Ok(standard.or(legacy))
}

fn session_header_value(
    headers: &HeaderMap,
    name: &'static str,
) -> Result<Option<String>, &'static str> {
    let Some(value) = headers.get(name) else {
        return Ok(None);
    };
    let value = value
        .to_str()
        .map_err(|_| "invalid MCP session header")?
        .trim();
    if value.is_empty() {
        return Err("empty MCP session header");
    }
    Ok(Some(value.to_string()))
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

fn is_cancellation_notification(method: Option<&str>) -> bool {
    method == Some("notifications/cancelled")
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

fn extract_clone_routing_root(payload: &Value) -> Option<String> {
    let params = payload.get("params")?.as_object()?;
    let tool_name = params.get("name")?.as_str()?;
    if !tool_name.starts_with("docdex_clone_") {
        return None;
    }
    let arguments = params.get("arguments")?.as_object()?;
    for key in ["current_repo_root", "currentRepoRoot"] {
        if let Some(value) = arguments.get(key).and_then(Value::as_str) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

fn extract_stateless_routing_root(payload: &Value, require_repo_id: bool) -> Option<String> {
    extract_project_root(payload).or_else(|| {
        require_repo_id
            .then(|| extract_clone_routing_root(payload))
            .flatten()
    })
}

async fn handle_mcp_batch(
    state: &AppState,
    router: &std::sync::Arc<crate::mcp::McpProxyRouter>,
    headers: &HeaderMap,
    session_id: Option<&str>,
    batch: Vec<Value>,
) -> Response {
    if batch.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "mcp batch must contain at least one request",
        );
    }
    if batch
        .iter()
        .any(|payload| extract_method(payload) == Some("initialize"))
    {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "MCP initialize must be sent as a standalone request",
        );
    }
    let mut responses = Vec::new();
    for payload in batch {
        match handle_mcp_single(state, router, headers, session_id, payload).await {
            Ok(outcome) => {
                if let Some(response) = outcome.response {
                    responses.push(response);
                }
            }
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
    router: &std::sync::Arc<crate::mcp::McpProxyRouter>,
    headers: &HeaderMap,
    session_id: Option<&str>,
    mut payload: Value,
) -> Result<McpCallOutcome, Response> {
    if !payload.is_object() {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "mcp request must be a JSON object",
        ));
    }
    let method = extract_method(&payload).map(str::to_string);
    let notification = is_notification(&payload, method.as_deref());
    let cancellation_notification = is_cancellation_notification(method.as_deref());
    if notification && session_id.is_none() {
        if cancellation_notification {
            return Err(json_error(
                StatusCode::BAD_REQUEST,
                ERR_INVALID_ARGUMENT,
                "MCP cancellation requires a valid session header",
            ));
        }
        return Ok(McpCallOutcome {
            response: None,
            issued_session_id: None,
        });
    }
    if method.as_deref() == Some("initialize") {
        if session_id.is_some() {
            return Err(json_error(
                StatusCode::BAD_REQUEST,
                ERR_INVALID_ARGUMENT,
                "MCP initialize must not include an existing session header",
            ));
        }
        normalize_initialize_payload(&mut payload);
        let init_root = extract_init_root(&payload);
        let resolved = match init_root.clone() {
            Some(root_uri) => resolve_repo_for_mcp(state, Some(root_uri)),
            None => resolve_repo_for_mcp(state, None),
        };
        let repo_root = match resolved {
            Ok(root) => {
                ensure_initialize_root(&mut payload, &root);
                root
            }
            Err(err) if init_root.is_none() && err.code == ERR_MISSING_REPO => {
                let issued_session_id = router.create_direct_session().await.map_err(|err| {
                    json_error(
                        StatusCode::TOO_MANY_REQUESTS,
                        ERR_RATE_LIMITED,
                        format!("mcp session unavailable: {err}"),
                    )
                })?;
                let bootstrap_root = router.bootstrap_repo_root();
                let response = match router
                    .call(Some(bootstrap_root.as_path()), None, payload.clone())
                    .await
                {
                    Ok(response) => response,
                    Err(err) => {
                        router.remove_session(&issued_session_id).await;
                        return Err(mcp_proxy_failure_response(err));
                    }
                };
                if response.get("result").is_none() || response.get("error").is_some() {
                    router.remove_session(&issued_session_id).await;
                    return Ok(McpCallOutcome {
                        response: Some(response),
                        issued_session_id: None,
                    });
                }
                if let Err(err) = router
                    .set_pending_initialize(&issued_session_id, payload)
                    .await
                {
                    router.remove_session(&issued_session_id).await;
                    return Err(json_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        ERR_INTERNAL_ERROR,
                        format!("mcp proxy failed: {err}"),
                    ));
                }
                return Ok(McpCallOutcome {
                    response: Some(response),
                    issued_session_id: Some(issued_session_id),
                });
            }
            Err(err) => return Err(app_error_response(&err)),
        };
        authorize_mcp_encrypted_repo(state, headers, &payload, Some(&repo_root)).await?;
        let issued_session_id = router.create_direct_session().await.map_err(|err| {
            json_error(
                StatusCode::TOO_MANY_REQUESTS,
                ERR_RATE_LIMITED,
                format!("mcp session unavailable: {err}"),
            )
        })?;
        if let Err(err) = router.bind_session(&issued_session_id, &repo_root).await {
            router.remove_session(&issued_session_id).await;
            return Err(json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                format!("mcp proxy failed: {err}"),
            ));
        }
        let response = match router.call_for_session(&issued_session_id, payload).await {
            Ok(response) => response,
            Err(err) => {
                router.remove_session(&issued_session_id).await;
                return Err(mcp_proxy_failure_response(err));
            }
        };
        if response.get("result").is_none() || response.get("error").is_some() {
            router.remove_session(&issued_session_id).await;
            return Ok(McpCallOutcome {
                response: Some(response),
                issued_session_id: None,
            });
        }
        return Ok(McpCallOutcome {
            response: Some(response),
            issued_session_id: Some(issued_session_id),
        });
    }

    if let Some(session_id) = session_id {
        let bound_root = match router.session_repo_root(session_id).await {
            Some(bound_root) => bound_root,
            None => {
                if !router.session_exists(session_id).await {
                    return Err(json_error(
                        StatusCode::BAD_REQUEST,
                        ERR_INVALID_ARGUMENT,
                        "unknown or expired MCP session",
                    ));
                }
                if notification {
                    return Ok(McpCallOutcome {
                        response: None,
                        issued_session_id: None,
                    });
                }
                if is_unbound_capability_request(method.as_deref())
                    || is_unbound_global_tool_request(&payload)
                {
                    return call_unbound_request(router, payload).await;
                }
                let Some(root_uri) =
                    extract_stateless_routing_root(&payload, state.require_repo_id)
                else {
                    return Err(json_error(
                        StatusCode::BAD_REQUEST,
                        ERR_MISSING_REPO,
                        "missing repo binding (call initialize with rootUri or include project_root/repo_path in tool arguments)",
                    ));
                };
                let repo_root = resolve_repo_for_mcp(state, Some(root_uri))
                    .map_err(|err| app_error_response(&err))?;
                if let Err(err) = router.bind_session(session_id, &repo_root).await {
                    return Err(json_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        ERR_INTERNAL_ERROR,
                        format!("mcp proxy failed: {err}"),
                    ));
                }
                if let Some(mut pending_initialize) =
                    router.take_pending_initialize(session_id).await
                {
                    ensure_initialize_root(&mut pending_initialize, &repo_root);
                    if let Err(err) = router
                        .call_for_session(session_id, pending_initialize)
                        .await
                    {
                        return Err(mcp_proxy_failure_response(err));
                    }
                }
                repo_root
            }
        };
        if let Some(root_uri) = extract_project_root(&payload) {
            let requested_root = resolve_repo_for_mcp(state, Some(root_uri))
                .map_err(|err| app_error_response(&err))?;
            if requested_root != bound_root {
                return Err(json_error(
                    StatusCode::BAD_REQUEST,
                    ERR_INVALID_ARGUMENT,
                    "MCP session is bound to a different repository",
                ));
            }
        }
        authorize_mcp_encrypted_repo(state, headers, &payload, Some(&bound_root)).await?;
        if notification {
            let result = if cancellation_notification {
                router
                    .call_for_session(session_id, payload)
                    .await
                    .map(|_| ())
            } else {
                router.touch_bound_session(session_id).await
            };
            return match result {
                Ok(()) => Ok(McpCallOutcome {
                    response: None,
                    issued_session_id: None,
                }),
                Err(err) => Err(json_error(
                    StatusCode::BAD_REQUEST,
                    ERR_INVALID_ARGUMENT,
                    format!("mcp notification failed: {err}"),
                )),
            };
        }
        return match router.call_for_session(session_id, payload).await {
            Ok(response) => Ok(McpCallOutcome {
                response: Some(response),
                issued_session_id: None,
            }),
            Err(err) => Err(mcp_proxy_failure_response(err)),
        };
    }

    if notification {
        return Ok(McpCallOutcome {
            response: None,
            issued_session_id: None,
        });
    }

    let repo_root =
        if let Some(root_uri) = extract_stateless_routing_root(&payload, state.require_repo_id) {
            resolve_repo_for_mcp(state, Some(root_uri)).map_err(|err| app_error_response(&err))?
        } else {
            resolve_repo_for_mcp(state, None).map_err(|err| app_error_response(&err))?
        };
    authorize_mcp_encrypted_repo(state, headers, &payload, Some(&repo_root)).await?;
    match router.call(Some(&repo_root), None, payload).await {
        Ok(response) => Ok(McpCallOutcome {
            response: Some(response),
            issued_session_id: None,
        }),
        Err(err) => Err(mcp_proxy_failure_response(err)),
    }
}

async fn authorize_mcp_encrypted_repo(
    state: &AppState,
    headers: &HeaderMap,
    payload: &Value,
    repo_root: Option<&PathBuf>,
) -> Result<(), Response> {
    if !state.repo_encryption.is_enabled() || extract_method(payload) == Some("initialize") {
        return Ok(());
    }
    let Some(repo_root) = repo_root else {
        return Ok(());
    };
    let repo_id = match crate::repo_manager::repo_fingerprint_sha256(repo_root) {
        Ok(repo_id) => repo_id,
        Err(err) => {
            return Err(json_error(
                StatusCode::BAD_REQUEST,
                ERR_INVALID_ARGUMENT,
                format!("failed to resolve MCP repository id: {err}"),
            ));
        }
    };
    let operation = mcp_operation(payload).map_err(|err| app_error_response(&err))?;
    match state
        .auth
        .authorize_repo_access(headers, &repo_id, operation)
        .await
    {
        Ok(_) => Ok(()),
        Err(err) => Err(app_error_response(&err)),
    }
}

fn mcp_operation(payload: &Value) -> Result<RepoOperation, AppError> {
    match extract_method(payload) {
        Some("tools/call") => {
            let tool_name = payload
                .pointer("/params/name")
                .and_then(|value| value.as_str())
                .unwrap_or_default();
            crate::mcp_tool_policy::operation_for_tool(tool_name).ok_or_else(|| {
                AppError::new(
                    ERR_SCOPE_DENIED,
                    format!("MCP tool is not authorized for encrypted repositories: {tool_name}"),
                )
            })
        }
        Some("resources/read") => Ok(RepoOperation::Open),
        Some(
            "tools/list"
            | "prompts/list"
            | "prompts/get"
            | "resources/list"
            | "resources/templates/list"
            | "ping"
            | "notifications/initialized"
            | "notifications/cancelled",
        ) => Ok(RepoOperation::Capabilities),
        Some(method) => Err(AppError::new(
            ERR_SCOPE_DENIED,
            format!("MCP method is not authorized for encrypted repositories: {method}"),
        )),
        None => Err(AppError::new(
            ERR_SCOPE_DENIED,
            "MCP method is required for encrypted repository authorization",
        )),
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
        build_test_state_with_mcp_auth(None).await
    }

    async fn build_test_state_with_mcp_auth(
        mcp_auth_token: Option<&str>,
    ) -> Result<(AppState, TempDir), Box<dyn std::error::Error>> {
        let temp = TempDir::new()?;
        fs::create_dir_all(temp.path())?;
        let repo_root = temp.path().join("repo");
        fs::create_dir_all(&repo_root)?;
        let state_dir = temp.path().join("state");
        let index_config = crate::index::IndexConfig::with_overrides(
            &repo_root,
            Some(state_dir.clone()),
            Vec::new(),
            Vec::new(),
            true,
        )?;
        let indexer = Arc::new(crate::index::Indexer::with_config(
            repo_root.clone(),
            index_config,
        )?);
        let repo_id = crate::repo_manager::repo_fingerprint_sha256(&repo_root)?;
        let legacy_repo_id = crate::repo_manager::fingerprint::legacy_repo_id_for_root(&repo_root);
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
            repo: repo_root,
            state_dir: Some(state_dir),
            exclude_prefix: Vec::new(),
            exclude_dir: Vec::new(),
            enable_symbol_extraction: true,
        };
        let mcp_global_state_dir = temp.path().join("mcp-global");
        let mcp_personal_preferences_root = temp.path().join("mcp-personal-preferences");
        fs::create_dir_all(&mcp_global_state_dir)?;
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
                Some(mcp_global_state_dir),
                Some(crate::config::MemoryPersonalPreferencesConfig {
                    storage_root: mcp_personal_preferences_root.to_string_lossy().into_owned(),
                    ..crate::config::MemoryPersonalPreferencesConfig::default()
                }),
                mcp_auth_token.map(str::to_string),
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
            conversations: None,
            personal_preferences: None,
            profile_state: None,
            user_memory_sync: crate::config::MemoryUserSyncConfig::default(),
            user_memory_sync_identity: crate::user_memory_sync::UserMemorySyncIdentity::default(),
            features: crate::config::FeatureFlagsConfig::default(),
            auth: crate::auth::AuthRuntime::new_for_tests(
                crate::auth::AuthConfig::default(),
                temp.path(),
            ),
            repo_encryption: crate::repo_encryption::RepoEncryptionConfig::default(),
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
    fn clone_current_repo_root_only_routes_stateless_multi_repo_calls() {
        for key in ["current_repo_root", "currentRepoRoot"] {
            let mut arguments = serde_json::Map::new();
            arguments.insert(
                key.to_string(),
                Value::String("/workspace/project".to_string()),
            );
            let payload = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "docdex_clone_evaluate",
                    "arguments": Value::Object(arguments)
                }
            });
            assert!(extract_project_root(&payload).is_none());
            assert!(extract_stateless_routing_root(&payload, false).is_none());
            assert_eq!(
                extract_stateless_routing_root(&payload, true).as_deref(),
                Some("/workspace/project"),
                "key: {key}"
            );
        }

        let unrelated = json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "docdex_search",
                "arguments": { "current_repo_root": "/workspace/project" }
            }
        });
        assert!(extract_stateless_routing_root(&unrelated, true).is_none());
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

    #[test]
    fn encrypted_repo_mcp_operations_are_exact_and_fail_closed() {
        let tool_call = |name: &str| {
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": { "name": name, "arguments": {} }
            })
        };

        assert_eq!(
            mcp_operation(&tool_call("docdex_search")).expect("search policy"),
            RepoOperation::Search
        );
        assert_eq!(
            mcp_operation(&tool_call("docdex_index")).expect("index policy"),
            RepoOperation::Index
        );
        assert_eq!(
            mcp_operation(&tool_call("docdex_memory_save")).expect("memory policy"),
            RepoOperation::Admin
        );
        assert_eq!(
            mcp_operation(&json!({ "method": "resources/read" })).expect("resource policy"),
            RepoOperation::Open
        );
        assert_eq!(
            mcp_operation(&json!({ "method": "tools/list" })).expect("list policy"),
            RepoOperation::Capabilities
        );
        assert!(mcp_operation(&tool_call("docdex_search_and_delete")).is_err());
        assert!(mcp_operation(&json!({ "method": "unknown/method" })).is_err());
    }

    #[tokio::test]
    async fn mcp_message_rejects_uninitialized_session() -> Result<(), Box<dyn std::error::Error>> {
        let (state, _temp) = build_test_state().await?;
        let router = state.mcp_router.as_ref().expect("mcp router").clone();
        let (session_id, _rx) = router.create_session().await?;

        let mut headers = HeaderMap::new();
        headers.insert(LEGACY_SESSION_HEADER, HeaderValue::from_str(&session_id)?);
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
    async fn mcp_pending_overflow_maps_to_too_many_requests(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let response = mcp_proxy_failure_response(
            AppError::new(
                crate::error::ERR_BACKOFF_REQUIRED,
                "MCP session pending request limit reached",
            )
            .into(),
        );
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        let body = response.into_body().collect().await?.to_bytes();
        let payload: serde_json::Value = serde_json::from_slice(&body)?;
        assert_eq!(
            payload
                .get("error")
                .and_then(|value| value.get("code"))
                .and_then(Value::as_str),
            Some(crate::error::ERR_BACKOFF_REQUIRED)
        );
        Ok(())
    }

    #[tokio::test]
    async fn mcp_sse_drop_and_delete_reclaim_router_sessions(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (state, _temp) = build_test_state().await?;
        let router = state.mcp_router.as_ref().expect("mcp router").clone();

        let response = mcp_sse_handler(State(state.clone())).await;
        assert!(response.status().is_success());
        assert_eq!(router.session_count_for_tests().await, 1);
        drop(response);
        for _ in 0..50 {
            if router.session_count_for_tests().await == 0 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(router.session_count_for_tests().await, 0);

        let session_id = router.create_direct_session().await?;
        let mut headers = HeaderMap::new();
        headers.insert(MCP_SESSION_HEADER, HeaderValue::from_str(&session_id)?);
        let deleted = mcp_delete_handler(State(state.clone()), headers.clone()).await;
        assert_eq!(deleted.status(), StatusCode::NO_CONTENT);
        assert_eq!(router.session_count_for_tests().await, 0);
        let repeated = mcp_delete_handler(State(state), headers).await;
        assert_eq!(repeated.status(), StatusCode::BAD_REQUEST);
        Ok(())
    }

    #[tokio::test]
    async fn mcp_http_session_capacity_fails_busy_and_recovers(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (state, _temp) = build_test_state().await?;
        let router = state.mcp_router.as_ref().expect("mcp router").clone();
        router.set_max_sessions_for_tests(1);
        let held_session = router.create_direct_session().await?;
        let response = mcp_request_handler(
            State(state.clone()),
            HeaderMap::new(),
            Json(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {}
            })),
        )
        .await;
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(router.remove_session(&held_session).await);

        let recovered = mcp_request_handler(
            State(state),
            HeaderMap::new(),
            Json(json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "initialize",
                "params": {}
            })),
        )
        .await;
        assert!(recovered.status().is_success());
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
        let init_response =
            mcp_request_handler(State(state.clone()), HeaderMap::new(), Json(init_payload)).await;
        let init_status = init_response.status();
        let session_id = init_response
            .headers()
            .get(MCP_SESSION_HEADER)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        assert_eq!(
            init_response
                .headers()
                .get(LEGACY_SESSION_HEADER)
                .and_then(|value| value.to_str().ok()),
            session_id.as_deref()
        );
        let init_body = init_response.into_body().collect().await?.to_bytes();
        assert!(
            init_status.is_success(),
            "expected initialize success, got {init_status}: {}",
            String::from_utf8_lossy(&init_body)
        );
        let init_value: serde_json::Value = serde_json::from_slice(&init_body)?;
        assert!(init_value.get("result").is_some());
        let session_id = session_id.unwrap_or_else(|| {
            panic!(
                "initialize response omitted session header: {}",
                String::from_utf8_lossy(&init_body)
            )
        });

        let tools_payload = json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        });
        let mut tools_headers = HeaderMap::new();
        tools_headers.insert(MCP_SESSION_HEADER, HeaderValue::from_str(&session_id)?);
        let tools_response =
            mcp_request_handler(State(state), tools_headers, Json(tools_payload)).await;
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

    #[tokio::test]
    async fn mcp_http_forwards_scoped_cancellation_notifications(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (state, _temp) = build_test_state().await?;
        let init_response = mcp_request_handler(
            State(state.clone()),
            HeaderMap::new(),
            Json(json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {}
            })),
        )
        .await;
        assert!(init_response.status().is_success());
        let session_id = init_response
            .headers()
            .get(MCP_SESSION_HEADER)
            .and_then(|value| value.to_str().ok())
            .expect("initialize session header")
            .to_string();
        let mut headers = HeaderMap::new();
        headers.insert(MCP_SESSION_HEADER, HeaderValue::from_str(&session_id)?);

        let unknown_request = mcp_request_handler(
            State(state.clone()),
            headers.clone(),
            Json(json!({
                "jsonrpc": "2.0",
                "method": "notifications/cancelled",
                "params": { "requestId": 999 }
            })),
        )
        .await;
        assert_eq!(unknown_request.status(), StatusCode::NO_CONTENT);

        let malformed = mcp_request_handler(
            State(state.clone()),
            headers,
            Json(json!({
                "jsonrpc": "2.0",
                "method": "notifications/cancelled",
                "params": {}
            })),
        )
        .await;
        assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);

        let unscoped = mcp_request_handler(
            State(state),
            HeaderMap::new(),
            Json(json!({
                "jsonrpc": "2.0",
                "method": "notifications/cancelled",
                "params": { "requestId": 999 }
            })),
        )
        .await;
        assert_eq!(unscoped.status(), StatusCode::BAD_REQUEST);
        Ok(())
    }

    #[tokio::test]
    async fn mcp_http_auth_session_is_server_issued_and_client_isolated(
    ) -> Result<(), Box<dyn std::error::Error>> {
        Box::pin(assert_mcp_http_auth_session_is_server_issued_and_client_isolated()).await
    }

    async fn assert_mcp_http_auth_session_is_server_issued_and_client_isolated(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (state, _temp) = build_test_state_with_mcp_auth(Some("secret-token")).await?;
        let init_a = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "auth_token": "secret-token",
                "agent_id": "agent-a",
                "agent_model": "model-a"
            }
        });
        let response_a =
            mcp_request_handler(State(state.clone()), HeaderMap::new(), Json(init_a)).await;
        let status_a = response_a.status();
        let session_a_header = response_a
            .headers()
            .get(MCP_SESSION_HEADER)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let legacy_session_a = response_a
            .headers()
            .get(LEGACY_SESSION_HEADER)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let body_a = response_a.into_body().collect().await?.to_bytes();
        assert!(
            status_a.is_success(),
            "expected authenticated initialize success, got {status_a}: {}",
            String::from_utf8_lossy(&body_a)
        );
        let session_a = session_a_header.expect("session-a header");
        assert_eq!(legacy_session_a.as_deref(), Some(session_a.as_str()));
        let value_a: Value = serde_json::from_slice(&body_a)?;
        assert!(value_a.get("result").is_some());

        let tools_payload = json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        });
        let no_header = mcp_request_handler(
            State(state.clone()),
            HeaderMap::new(),
            Json(tools_payload.clone()),
        )
        .await;
        assert!(no_header.status().is_success());
        let no_header_body = no_header.into_body().collect().await?.to_bytes();
        let no_header_value: Value = serde_json::from_slice(&no_header_body)?;
        assert_eq!(
            no_header_value
                .pointer("/error/data/code")
                .and_then(Value::as_str),
            Some("unauthorized"),
            "an ephemeral request must not inherit initialize authorization"
        );

        let mut forged_headers = HeaderMap::new();
        forged_headers.insert(MCP_SESSION_HEADER, HeaderValue::from_static("mcp-forged"));
        let forged = mcp_request_handler(
            State(state.clone()),
            forged_headers,
            Json(tools_payload.clone()),
        )
        .await;
        assert_eq!(forged.status(), StatusCode::BAD_REQUEST);

        let mut session_a_headers = HeaderMap::new();
        session_a_headers.insert(MCP_SESSION_HEADER, HeaderValue::from_str(&session_a)?);
        let tools_a = mcp_request_handler(
            State(state.clone()),
            session_a_headers,
            Json(tools_payload.clone()),
        )
        .await;
        assert!(tools_a.status().is_success());
        let tools_a_body = tools_a.into_body().collect().await?.to_bytes();
        let tools_a_value: Value = serde_json::from_slice(&tools_a_body)?;
        assert!(tools_a_value.pointer("/result/tools").is_some());

        let init_b = json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "initialize",
            "params": {
                "auth_token": "secret-token",
                "agent_id": "agent-b",
                "agent_model": "model-b"
            }
        });
        let response_b =
            mcp_request_handler(State(state.clone()), HeaderMap::new(), Json(init_b)).await;
        assert!(response_b.status().is_success());
        let session_b = response_b
            .headers()
            .get(MCP_SESSION_HEADER)
            .and_then(|value| value.to_str().ok())
            .expect("session-b header")
            .to_string();
        assert_ne!(session_a, session_b);
        let body_b = response_b.into_body().collect().await?.to_bytes();
        let value_b: Value = serde_json::from_slice(&body_b)?;
        assert!(value_b.get("result").is_some());

        let router = state.mcp_router.as_ref().expect("mcp router");
        assert_eq!(
            router.session_state_for_tests(&session_a).await,
            Some((
                true,
                Some("agent-a".to_string()),
                Some("model-a".to_string())
            ))
        );
        assert_eq!(
            router.session_state_for_tests(&session_b).await,
            Some((
                true,
                Some("agent-b".to_string()),
                Some("model-b".to_string())
            ))
        );

        let mut session_b_headers = HeaderMap::new();
        session_b_headers.insert(LEGACY_SESSION_HEADER, HeaderValue::from_str(&session_b)?);
        let tools_b = mcp_request_handler(
            State(state.clone()),
            session_b_headers,
            Json(tools_payload.clone()),
        )
        .await;
        assert!(tools_b.status().is_success());
        let tools_b_body = tools_b.into_body().collect().await?.to_bytes();
        let tools_b_value: Value = serde_json::from_slice(&tools_b_body)?;
        assert!(tools_b_value.pointer("/result/tools").is_some());

        let mut conflict_headers = HeaderMap::new();
        conflict_headers.insert(MCP_SESSION_HEADER, HeaderValue::from_str(&session_a)?);
        conflict_headers.insert(LEGACY_SESSION_HEADER, HeaderValue::from_str(&session_b)?);
        let conflict = mcp_request_handler(
            State(state.clone()),
            conflict_headers,
            Json(tools_payload.clone()),
        )
        .await;
        assert_eq!(conflict.status(), StatusCode::BAD_REQUEST);

        let rejected_initialize = mcp_request_handler(
            State(state.clone()),
            HeaderMap::new(),
            Json(json!({
                "jsonrpc": "2.0",
                "id": 40,
                "method": "initialize",
                "params": { "auth_token": "wrong-token" }
            })),
        )
        .await;
        assert!(rejected_initialize.status().is_success());
        assert!(rejected_initialize
            .headers()
            .get(MCP_SESSION_HEADER)
            .is_none());
        assert!(rejected_initialize
            .headers()
            .get(LEGACY_SESSION_HEADER)
            .is_none());
        let rejected_body = rejected_initialize.into_body().collect().await?.to_bytes();
        let rejected_value: Value = serde_json::from_slice(&rejected_body)?;
        assert_eq!(
            rejected_value
                .pointer("/error/data/code")
                .and_then(Value::as_str),
            Some("unauthorized")
        );

        let mut reinitialize_headers = HeaderMap::new();
        reinitialize_headers.insert(MCP_SESSION_HEADER, HeaderValue::from_str(&session_a)?);
        let reinitialize = mcp_request_handler(
            State(state),
            reinitialize_headers,
            Json(json!({
                "jsonrpc": "2.0",
                "id": 4,
                "method": "initialize",
                "params": { "auth_token": "secret-token" }
            })),
        )
        .await;
        assert_eq!(reinitialize.status(), StatusCode::BAD_REQUEST);
        Ok(())
    }

    #[tokio::test]
    async fn mcp_http_batch_rejects_initialize_without_leaking_session_state(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (state, _temp) = build_test_state_with_mcp_auth(Some("secret-token")).await?;
        let payload = json!([
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": { "auth_token": "secret-token" }
            },
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
                "params": {}
            }
        ]);
        let response = mcp_request_handler(State(state), HeaderMap::new(), Json(payload)).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(response.headers().get(MCP_SESSION_HEADER).is_none());
        assert!(response.headers().get(LEGACY_SESSION_HEADER).is_none());
        Ok(())
    }

    #[tokio::test]
    async fn mcp_http_multi_repo_initialize_without_root_allows_startup_but_not_repo_tools(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (mut state, _temp) = build_test_state().await?;
        state.require_repo_id = true;
        let init_payload = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {}
        });

        let response =
            mcp_request_handler(State(state.clone()), HeaderMap::new(), Json(init_payload)).await;
        assert!(response.status().is_success());
        let session_id = response
            .headers()
            .get(MCP_SESSION_HEADER)
            .and_then(|value| value.to_str().ok())
            .expect("initialize session header")
            .to_string();
        let body = response.into_body().collect().await?.to_bytes();
        let value: serde_json::Value = serde_json::from_slice(&body)?;
        assert!(value.get("result").is_some());

        let mut headers = HeaderMap::new();
        headers.insert(MCP_SESSION_HEADER, HeaderValue::from_str(&session_id)?);
        let tools_response = mcp_request_handler(
            State(state.clone()),
            headers.clone(),
            Json(json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list",
                "params": {}
            })),
        )
        .await;
        assert!(tools_response.status().is_success());
        let tools_body = tools_response.into_body().collect().await?.to_bytes();
        let tools_value: serde_json::Value = serde_json::from_slice(&tools_body)?;
        assert!(tools_value.pointer("/result/tools").is_some());

        for (id, name, arguments) in [
            (
                3,
                "docdex_save_preference",
                json!({
                    "agent_id": "unbound-profile-test",
                    "category": "workflow",
                    "content": "Profile tools remain global in multi-repo mode."
                }),
            ),
            (
                4,
                "docdex_get_profile",
                json!({ "agent_id": "unbound-profile-test" }),
            ),
        ] {
            let profile_response = mcp_request_handler(
                State(state.clone()),
                headers.clone(),
                Json(json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "method": "tools/call",
                    "params": { "name": name, "arguments": arguments }
                })),
            )
            .await;
            assert!(profile_response.status().is_success(), "{name}");
            let profile_body = profile_response.into_body().collect().await?.to_bytes();
            let profile_value: serde_json::Value = serde_json::from_slice(&profile_body)?;
            assert!(
                profile_value.get("result").is_some(),
                "{name}: {profile_value}"
            );
            assert!(
                profile_value.get("error").is_none(),
                "{name}: {profile_value}"
            );
        }

        let missing_repo_response = mcp_request_handler(
            State(state),
            headers,
            Json(json!({
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {
                    "name": "docdex_stats",
                    "arguments": {}
                }
            })),
        )
        .await;
        assert_eq!(missing_repo_response.status(), StatusCode::BAD_REQUEST);
        let missing_repo_body = missing_repo_response
            .into_body()
            .collect()
            .await?
            .to_bytes();
        let missing_repo_value: serde_json::Value = serde_json::from_slice(&missing_repo_body)?;
        assert_eq!(
            missing_repo_value
                .pointer("/error/code")
                .and_then(Value::as_str),
            Some("missing_repo")
        );
        Ok(())
    }
}

fn resolve_repo_for_mcp(state: &AppState, root_uri: Option<String>) -> Result<PathBuf, AppError> {
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
