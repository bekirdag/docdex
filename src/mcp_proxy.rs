use anyhow::{anyhow, Context, Result};
use crate::mcp_server::McpService;
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use futures::StreamExt;
use reqwest::{Client, StatusCode};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, Mutex, Notify, RwLock};
use url::Url;

const MCP_PROXY_TIMEOUT_SECS: u64 = 30;
const MCP_INIT_TIMEOUT_SECS: u64 = 5;
const SESSION_CLEANUP_INTERVAL_SECS: u64 = 600;
const SESSION_IDLE_TIMEOUT_SECS: u64 = 3600;
const MCP_HTTP_SSE_PATH: &str = "/v1/mcp/sse";
const MCP_HTTP_MESSAGE_PATH: &str = "/v1/mcp/message";

pub struct McpProxy {
    service: Mutex<Option<McpService>>,
    sessions: RwLock<HashMap<String, SessionEntry>>,
    next_id: AtomicU64,
}

struct SessionEntry {
    sender: mpsc::Sender<Value>,
    last_active: Instant,
}

impl McpProxy {
    pub fn new(service: McpService) -> Arc<Self> {
        let proxy = Arc::new(Self {
            service: Mutex::new(Some(service)),
            sessions: RwLock::new(HashMap::new()),
            next_id: AtomicU64::new(1),
        });
        Self::spawn_session_cleanup(proxy.clone());
        proxy
    }

    fn spawn_session_cleanup(proxy: Arc<Self>) {
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(SESSION_CLEANUP_INTERVAL_SECS));
            loop {
                interval.tick().await;
                proxy.cleanup_sessions().await;
            }
        });
    }

    pub async fn call(&self, mut request: Value) -> Result<Value> {
        let _id = ensure_id(&mut request, &self.next_id)?;
        let resp = self
            .handle_request_with_timeout(request)
            .await?
            .context("mcp proxy response dropped")?;
        Ok(resp)
    }

    pub async fn is_alive(&self) -> bool {
        self.service.lock().await.is_some()
    }

    pub async fn enqueue_for_session(
        self: &Arc<Self>,
        session_id: &str,
        mut request: Value,
    ) -> Result<Value> {
        let (child_id, client_id) = assign_child_id(&mut request, &self.next_id)?;
        let session_id = session_id.to_string();
        let proxy = Arc::clone(self);
        tokio::spawn(async move {
            let response = proxy.handle_request(request).await;
            match response {
                Ok(Some(mut payload)) => {
                    replace_response_id(&mut payload, client_id);
                    proxy.dispatch_to_session(&session_id, payload).await;
                }
                Ok(None) => {}
                Err(err) => {
                    let payload = mcp_proxy_error_response(client_id, &err);
                    proxy.dispatch_to_session(&session_id, payload).await;
                }
            }
        });
        Ok(json!({
            "accepted": true,
            "id": child_id,
        }))
    }

    pub async fn shutdown(&self) {
        let mut service = self.service.lock().await;
        *service = None;
    }

    pub async fn create_session(&self) -> (String, mpsc::Receiver<Value>) {
        let session_id = format!("mcp-{}", uuid::Uuid::new_v4());
        let (tx, rx) = mpsc::channel(64);
        self.sessions.write().await.insert(
            session_id.clone(),
            SessionEntry {
                sender: tx,
                last_active: Instant::now(),
            },
        );
        (session_id, rx)
    }

    async fn handle_request(&self, request: Value) -> Result<Option<Value>> {
        let mut guard = self.service.lock().await;
        let service = guard.as_mut().ok_or_else(|| anyhow!("mcp proxy shutdown"))?;
        service.handle_json(request).await
    }

    async fn handle_request_with_timeout(&self, request: Value) -> Result<Option<Value>> {
        let mut guard = self.service.lock().await;
        let service = guard.as_mut().ok_or_else(|| anyhow!("mcp proxy shutdown"))?;
        match tokio::time::timeout(
            Duration::from_secs(MCP_PROXY_TIMEOUT_SECS),
            service.handle_json(request),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(anyhow!("mcp proxy timeout")),
        }
    }

    async fn dispatch_to_session(&self, session_id: &str, payload: Value) {
        let mut sessions = self.sessions.write().await;
        let Some(entry) = sessions.get_mut(session_id) else {
            return;
        };
        entry.last_active = Instant::now();
        if entry.sender.send(payload).await.is_err() {
            sessions.remove(session_id);
        }
    }

    async fn cleanup_sessions(&self) {
        let mut sessions = self.sessions.write().await;
        let now = Instant::now();
        sessions.retain(|_, entry| {
            now.duration_since(entry.last_active) < Duration::from_secs(SESSION_IDLE_TIMEOUT_SECS)
        });
    }
}

fn replace_response_id(payload: &mut Value, client_id: Value) {
    if let Some(obj) = payload.as_object_mut() {
        obj.insert("id".to_string(), client_id);
    }
}

fn mcp_proxy_error_response(client_id: Value, err: &anyhow::Error) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": client_id,
        "error": {
            "code": -32603,
            "message": format!("mcp proxy failed: {err}"),
        }
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InitOrigin {
    Internal,
    Client,
}

struct InitTracker {
    initialized: AtomicBool,
    pending_internal: Mutex<HashSet<String>>,
    pending_client: Mutex<HashSet<String>>,
    notify: Notify,
}

impl InitTracker {
    fn new() -> Self {
        Self {
            initialized: AtomicBool::new(false),
            pending_internal: Mutex::new(HashSet::new()),
            pending_client: Mutex::new(HashSet::new()),
            notify: Notify::new(),
        }
    }

    fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    fn mark_initialized(&self) {
        self.initialized.store(true, Ordering::SeqCst);
        self.notify.notify_waiters();
    }

    async fn mark_internal(&self, id: String) {
        self.pending_internal.lock().await.insert(id);
    }

    async fn clear_internal(&self, id: &str) {
        self.pending_internal.lock().await.remove(id);
    }

    async fn mark_client(&self, id: String) {
        self.pending_client.lock().await.insert(id);
    }

    async fn clear_client(&self, id: &str) {
        self.pending_client.lock().await.remove(id);
    }

    async fn handle_response(&self, id: &str) -> Option<InitOrigin> {
        if self.pending_internal.lock().await.remove(id) {
            self.initialized.store(true, Ordering::SeqCst);
            self.notify.notify_waiters();
            return Some(InitOrigin::Internal);
        }
        if self.pending_client.lock().await.remove(id) {
            self.initialized.store(true, Ordering::SeqCst);
            self.notify.notify_waiters();
            return Some(InitOrigin::Client);
        }
        None
    }

    async fn wait_for_init(&self) {
        if self.is_initialized() {
            return;
        }
        self.notify.notified().await;
    }
}

pub struct McpHttpProxy;

impl McpHttpProxy {
    pub async fn run(
        repo_root: PathBuf,
        base_url: String,
        auth_token: Option<String>,
    ) -> Result<()> {
        let stdin = tokio::io::stdin();
        let stdout = tokio::io::stdout();
        Self::run_with_io(repo_root, base_url, auth_token, stdin, stdout).await
    }

    pub async fn run_with_io<R, W>(
        repo_root: PathBuf,
        base_url: String,
        auth_token: Option<String>,
        input: R,
        output: W,
    ) -> Result<()>
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let repo_root = repo_root
            .canonicalize()
            .unwrap_or_else(|_| repo_root.clone());
        let root_uri = Url::from_directory_path(&repo_root)
            .map(|url| url.to_string())
            .unwrap_or_else(|_| repo_root.display().to_string());
        let timeout_ms = crate::cli::http_client::resolve_http_timeout_ms();
        let connect_timeout_ms =
            crate::cli::http_client::resolve_http_connect_timeout_ms(timeout_ms);
        let client = Client::builder()
            .connect_timeout(Duration::from_millis(connect_timeout_ms.max(1)))
            .build()
            .context("build MCP HTTP client")?;
        let base_url = base_url.trim().trim_end_matches('/').to_string();
        let session = open_sse_session(&client, &base_url, auth_token.as_deref()).await?;
        let init_tracker = Arc::new(InitTracker::new());
        let output = Arc::new(Mutex::new(output));
        let sse_handle = spawn_sse_reader(
            session.response,
            output.clone(),
            init_tracker.clone(),
        );

        let mut init_sent = false;
        let mut lines = BufReader::new(input).lines();
        while let Some(line) = lines.next_line().await? {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let value: Value = serde_json::from_str(trimmed)
                .with_context(|| "parse mcp request")?;
            let requests = normalize_requests(value)?;
            for mut request in requests {
                if !request.is_object() {
                    return Err(anyhow!("mcp request must be a JSON object"));
                }
                let method = request
                    .get("method")
                    .and_then(|value| value.as_str())
                    .unwrap_or_default();
                if method == "initialize" {
                    force_root_uri(&mut request, &root_uri)?;
                    let client_id = request.get("id").and_then(id_key);
                    if let Some(id) = client_id.as_deref() {
                        init_tracker.mark_client(id.to_string()).await;
                    } else if !init_sent {
                        send_internal_initialize(
                            &init_tracker,
                            &client,
                            &base_url,
                            &session.session_id,
                            &root_uri,
                            auth_token.as_deref(),
                            timeout_ms,
                        )
                        .await?;
                        init_sent = true;
                    }
                    match send_mcp_message(
                        &client,
                        &base_url,
                        &session.session_id,
                        auth_token.as_deref(),
                        &request,
                        timeout_ms,
                    )
                    .await?
                    {
                        SendOutcome::Ack => {
                            init_sent = true;
                        }
                        SendOutcome::Error(response) => {
                            if let Some(id) = client_id.as_deref() {
                                init_tracker.clear_client(id).await;
                            }
                            write_proxy_response(&output, &response).await?;
                            continue;
                        }
                    }
                    continue;
                }
                let has_root_hint = request_includes_root_hint(&request);
                if !init_tracker.is_initialized() && !has_root_hint {
                    if !init_sent {
                        send_internal_initialize(
                            &init_tracker,
                            &client,
                            &base_url,
                            &session.session_id,
                            &root_uri,
                            auth_token.as_deref(),
                            timeout_ms,
                        )
                        .await?;
                        init_sent = true;
                    }
                    let init_timeout = Duration::from_secs(MCP_INIT_TIMEOUT_SECS);
                    let _ =
                        tokio::time::timeout(init_timeout, init_tracker.wait_for_init()).await;
                }
                match send_mcp_message(
                    &client,
                    &base_url,
                    &session.session_id,
                    auth_token.as_deref(),
                    &request,
                    timeout_ms,
                )
                .await?
                {
                    SendOutcome::Ack => {
                        if has_root_hint && !init_tracker.is_initialized() {
                            init_tracker.mark_initialized();
                            init_sent = true;
                        }
                    }
                    SendOutcome::Error(response) => {
                        write_proxy_response(&output, &response).await?;
                        continue;
                    }
                }
            }
        }
        sse_handle.abort();
        Ok(())
    }
}

struct McpSseSession {
    session_id: String,
    response: reqwest::Response,
}

async fn open_sse_session(
    client: &Client,
    base_url: &str,
    auth_token: Option<&str>,
) -> Result<McpSseSession> {
    let url = format!("{base_url}{MCP_HTTP_SSE_PATH}");
    let mut req = client.get(url);
    if let Some(token) = auth_token {
        req = req.bearer_auth(token);
    }
    let response = req
        .send()
        .await
        .context("open mcp sse connection")?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow!(
            "mcp proxy failed to connect to daemon ({status}): {body}"
        ));
    }
    let session_id = response
        .headers()
        .get("x-docdex-mcp-session")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.to_string())
        .ok_or_else(|| anyhow!("mcp proxy missing session header from daemon"))?;
    Ok(McpSseSession {
        session_id,
        response,
    })
}

fn spawn_sse_reader<W>(
    response: reqwest::Response,
    output: Arc<Mutex<W>>,
    init_tracker: Arc<InitTracker>,
) -> tokio::task::JoinHandle<Result<()>>
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut buffer = String::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.context("read mcp sse chunk")?;
            buffer.push_str(&String::from_utf8_lossy(&chunk));
            for event in drain_sse_events(&mut buffer) {
                for data in extract_sse_data(&event) {
                    let trimmed = data.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    let Ok(value) = serde_json::from_str::<Value>(trimmed) else {
                        continue;
                    };
                    if let Some(id) = value.get("id").and_then(id_key) {
                        if let Some(origin) = init_tracker.handle_response(&id).await {
                            if origin == InitOrigin::Internal {
                                continue;
                            }
                        }
                    }
                    let mut guard = output.lock().await;
                    guard
                        .write_all(trimmed.as_bytes())
                        .await
                        .context("write mcp response")?;
                    guard.write_all(b"\n").await?;
                    guard.flush().await?;
                }
            }
        }
        Ok(())
    })
}

enum SendOutcome {
    Ack,
    Error(Value),
}

async fn send_mcp_message(
    client: &Client,
    base_url: &str,
    session_id: &str,
    auth_token: Option<&str>,
    payload: &Value,
    timeout_ms: u64,
) -> Result<SendOutcome> {
    let url = format!("{base_url}{MCP_HTTP_MESSAGE_PATH}");
    let mut req = client
        .post(url)
        .header("x-docdex-mcp-session", session_id)
        .json(payload);
    req = req.timeout(Duration::from_millis(timeout_ms.max(1)));
    if let Some(token) = auth_token {
        req = req.bearer_auth(token);
    }
    let response = req.send().await.context("send mcp request")?;
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if let Some(mapped) = http_error_to_mcp_response(payload, status, &body) {
            return Ok(SendOutcome::Error(mapped));
        }
        return Err(anyhow!("mcp proxy request failed ({status}): {body}"));
    }
    Ok(SendOutcome::Ack)
}

async fn send_mcp_message_internal(
    client: &Client,
    base_url: &str,
    session_id: &str,
    auth_token: Option<&str>,
    payload: &Value,
    timeout_ms: u64,
) -> Result<()> {
    match send_mcp_message(
        client,
        base_url,
        session_id,
        auth_token,
        payload,
        timeout_ms,
    )
    .await?
    {
        SendOutcome::Ack => Ok(()),
        SendOutcome::Error(response) => Err(anyhow!(
            "mcp proxy request failed: {}",
            serde_json::to_string(&response).unwrap_or_default()
        )),
    }
}

fn http_error_to_mcp_response(
    payload: &Value,
    status: StatusCode,
    body: &str,
) -> Option<Value> {
    let id = payload.get("id")?.clone();
    let mut message = format!("mcp proxy request failed ({status})");
    let mut data = serde_json::Map::new();
    let mut error_code: Option<String> = None;

    if let Ok(Value::Object(root)) = serde_json::from_str::<Value>(body) {
        if let Some(Value::Object(error)) = root.get("error") {
            if let Some(code) = error.get("code").and_then(|value| value.as_str()) {
                error_code = Some(code.to_string());
                data.insert("code".to_string(), Value::String(code.to_string()));
            }
            if let Some(text) = error.get("message").and_then(|value| value.as_str()) {
                message = text.to_string();
            }
            for (key, value) in error {
                if key == "code" || key == "message" {
                    continue;
                }
                data.insert(key.to_string(), value.clone());
            }
        }
    }

    if !data.contains_key("code") {
        data.insert("code".to_string(), Value::String("http_error".to_string()));
    }

    let mcp_code = match error_code.as_deref() {
        Some("internal_error") => -32603,
        Some(_) => -32602,
        None => {
            if status.is_client_error() {
                -32602
            } else {
                -32603
            }
        }
    };
    Some(json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": mcp_code,
            "message": message,
            "data": Value::Object(data),
        }
    }))
}

async fn send_internal_initialize(
    init_tracker: &InitTracker,
    client: &Client,
    base_url: &str,
    session_id: &str,
    root_uri: &str,
    auth_token: Option<&str>,
    timeout_ms: u64,
) -> Result<()> {
    let id = format!("docdex-init-{}", uuid::Uuid::new_v4());
    let payload = json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "initialize",
        "params": { "rootUri": root_uri }
    });
    let id_key = payload
        .get("id")
        .and_then(id_key)
        .ok_or_else(|| anyhow!("invalid init id"))?;
    init_tracker.mark_internal(id_key.clone()).await;
    if let Err(err) = send_mcp_message_internal(
        client,
        base_url,
        session_id,
        auth_token,
        &payload,
        timeout_ms,
    )
    .await
    {
        init_tracker.clear_internal(&id_key).await;
        return Err(err);
    }
    Ok(())
}

async fn write_proxy_response<W>(
    output: &Arc<Mutex<W>>,
    response: &Value,
) -> Result<()>
where
    W: AsyncWrite + Unpin + Send + 'static,
{
    let line = serde_json::to_string(response).context("serialize mcp proxy response")?;
    let mut guard = output.lock().await;
    guard
        .write_all(line.as_bytes())
        .await
        .context("write mcp response")?;
    guard.write_all(b"\n").await?;
    guard.flush().await?;
    Ok(())
}

fn normalize_requests(value: Value) -> Result<Vec<Value>> {
    match value {
        Value::Array(values) => Ok(values),
        value => Ok(vec![value]),
    }
}

fn force_root_uri(payload: &mut Value, root_uri: &str) -> Result<()> {
    let obj = payload
        .as_object_mut()
        .ok_or_else(|| anyhow!("mcp request must be a JSON object"))?;
    let params = obj.entry("params").or_insert_with(|| json!({}));
    if !params.is_object() {
        *params = json!({});
    }
    let params = params
        .as_object_mut()
        .ok_or_else(|| anyhow!("mcp params must be a JSON object"))?;
    params.insert("rootUri".to_string(), Value::String(root_uri.to_string()));
    Ok(())
}

fn drain_sse_events(buffer: &mut String) -> Vec<String> {
    let mut events = Vec::new();
    loop {
        let Some((pos, len)) = find_sse_boundary(buffer) else {
            break;
        };
        let event = buffer[..pos].to_string();
        buffer.drain(..pos + len);
        events.push(event);
    }
    events
}

fn find_sse_boundary(buffer: &str) -> Option<(usize, usize)> {
    let lf = buffer.find("\n\n").map(|pos| (pos, 2));
    let crlf = buffer.find("\r\n\r\n").map(|pos| (pos, 4));
    match (lf, crlf) {
        (Some(lf), Some(crlf)) => Some(if lf.0 < crlf.0 { lf } else { crlf }),
        (Some(lf), None) => Some(lf),
        (None, Some(crlf)) => Some(crlf),
        (None, None) => None,
    }
}

fn extract_sse_data(event: &str) -> Vec<String> {
    let mut data = Vec::new();
    for line in event.lines() {
        let trimmed = line.trim_end();
        if let Some(payload) = trimmed.strip_prefix("data:") {
            data.push(payload.trim_start().to_string());
        }
    }
    data
}

fn request_includes_root_hint(request: &Value) -> bool {
    let params = request.get("params").and_then(|value| value.as_object());
    let Some(params) = params else {
        return false;
    };
    if params_has_root_hint(params) {
        return true;
    }
    if let Some(args) = params.get("arguments").and_then(|value| value.as_object()) {
        return params_has_root_hint(args);
    }
    false
}

fn params_has_root_hint(params: &serde_json::Map<String, Value>) -> bool {
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
            if !value.trim().is_empty() {
                return true;
            }
        }
    }
    if array_has_root_hint(params.get("roots")) {
        return true;
    }
    array_has_root_hint(params.get("workspaceFolders"))
}

fn array_has_root_hint(value: Option<&Value>) -> bool {
    let Some(entries) = value.and_then(|value| value.as_array()) else {
        return false;
    };
    for entry in entries {
        if let Some(value) = entry.as_str() {
            if !value.trim().is_empty() {
                return true;
            }
            continue;
        }
        if let Some(obj) = entry.as_object() {
            for key in ["uri", "rootUri", "path", "rootPath", "root_path"] {
                if let Some(value) = obj.get(key).and_then(|value| value.as_str()) {
                    if !value.trim().is_empty() {
                        return true;
                    }
                }
            }
        }
    }
    false
}

fn ensure_id(request: &mut Value, counter: &AtomicU64) -> Result<Value> {
    let obj = request
        .as_object_mut()
        .ok_or_else(|| anyhow!("mcp request must be a JSON object"))?;
    if let Some(id) = obj.get("id") {
        return Ok(id.clone());
    }
    let id = Value::Number(counter.fetch_add(1, Ordering::Relaxed).into());
    obj.insert("id".to_string(), id.clone());
    Ok(id)
}

fn assign_child_id(request: &mut Value, counter: &AtomicU64) -> Result<(Value, Value)> {
    let obj = request
        .as_object_mut()
        .ok_or_else(|| anyhow!("mcp request must be a JSON object"))?;
    let client_id = obj.get("id").cloned();
    let child_id = Value::Number(counter.fetch_add(1, Ordering::Relaxed).into());
    obj.insert("id".to_string(), child_id.clone());
    Ok((child_id.clone(), client_id.unwrap_or(child_id)))
}

fn id_key(id: &Value) -> Option<String> {
    match id {
        Value::String(value) => Some(format!("s:{value}")),
        Value::Number(value) => Some(format!("n:{value}")),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::State;
    use axum::http::HeaderValue;
    use axum::response::sse::{Event, Sse};
    use axum::response::IntoResponse;
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use serde_json::json;
    use std::net::SocketAddr;
    use tempfile::TempDir;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::Mutex as TokioMutex;
    use tokio_stream::wrappers::ReceiverStream;

    #[derive(Clone)]
    struct TestState {
        events: mpsc::Sender<Value>,
        requests: mpsc::Sender<Value>,
        events_rx: Arc<TokioMutex<Option<mpsc::Receiver<Value>>>>,
    }

    async fn sse_handler(State(state): State<Arc<TestState>>) -> impl IntoResponse {
        let mut guard = state.events_rx.lock().await;
        let rx = guard
            .take()
            .expect("sse handler should only be called once in tests");
        let stream = ReceiverStream::new(rx).map(|payload| {
            Ok::<_, std::convert::Infallible>(Event::default().data(payload.to_string()))
        });
        let mut response = Sse::new(stream).into_response();
        response.headers_mut().insert(
            "x-docdex-mcp-session",
            HeaderValue::from_static("test-session"),
        );
        response
    }

    async fn message_handler(
        State(state): State<Arc<TestState>>,
        Json(payload): Json<Value>,
    ) -> impl IntoResponse {
        let _ = state.requests.send(payload.clone()).await;
        if let Some(id) = payload.get("id") {
            let response = json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": { "ok": true }
            });
            let _ = state.events.send(response).await;
        }
        Json(json!({ "accepted": true, "id": payload.get("id") }))
    }

    async fn spawn_test_server(state: Arc<TestState>) -> Result<Option<SocketAddr>> {
        let app = Router::new()
            .route("/v1/mcp/sse", get(sse_handler))
            .route("/v1/mcp/message", post(message_handler))
            .with_state(state);
        let listener = match TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => return Ok(None),
            Err(err) => return Err(err).context("bind test server"),
        };
        let addr = listener.local_addr()?;
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Ok(Some(addr))
    }

    #[tokio::test]
    async fn mcp_http_proxy_auto_initializes_and_forwards_response() -> Result<()> {
        let repo = TempDir::new()?;
        let repo_root = repo
            .path()
            .canonicalize()
            .unwrap_or_else(|_| repo.path().to_path_buf());
        let root_uri = Url::from_directory_path(&repo_root)
            .map(|url| url.to_string())
            .unwrap_or_else(|_| repo_root.display().to_string());

        let (event_tx, event_rx) = mpsc::channel(8);
        let (req_tx, mut req_rx) = mpsc::channel(8);
        let state = Arc::new(TestState {
            events: event_tx,
            requests: req_tx,
            events_rx: Arc::new(TokioMutex::new(Some(event_rx))),
        });
        let Some(addr) = spawn_test_server(state).await? else {
            eprintln!("skipping mcp proxy test: TCP bind not permitted in this environment");
            return Ok(());
        };
        let base_url = format!("http://{}", addr);

        let (mut input_writer, input_reader) = tokio::io::duplex(2048);
        let (output_writer, output_reader) = tokio::io::duplex(2048);
        let proxy_task = tokio::spawn(async move {
            McpHttpProxy::run_with_io(repo_root, base_url, None, input_reader, output_writer).await
        });

        input_writer
            .write_all(
                br#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#,
            )
            .await?;
        input_writer.write_all(b"\n").await?;

        let init_request = req_rx.recv().await.expect("init request");
        let tool_request = req_rx.recv().await.expect("tool request");
        assert_eq!(
            init_request.get("method").and_then(|v| v.as_str()),
            Some("initialize")
        );
        assert_eq!(
            init_request
                .get("params")
                .and_then(|v| v.get("rootUri"))
                .and_then(|v| v.as_str()),
            Some(root_uri.as_str())
        );
        assert_eq!(
            tool_request.get("method").and_then(|v| v.as_str()),
            Some("tools/list")
        );

        let mut output_line = String::new();
        let mut output_reader = tokio::io::BufReader::new(output_reader);
        output_reader.read_line(&mut output_line).await?;
        let response: Value = serde_json::from_str(output_line.trim())?;
        assert_eq!(response.get("id"), Some(&json!(1)));

        input_writer.shutdown().await?;
        proxy_task.await??;
        Ok(())
    }
}
