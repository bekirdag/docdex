use crate::error::{AppError, ERR_BACKOFF_REQUIRED};
use crate::mcp_server::McpService;
use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::env;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch, Mutex, OwnedMutexGuard, OwnedSemaphorePermit, RwLock, Semaphore};

const MCP_PROXY_TIMEOUT_SECS_DEFAULT: u64 = 30;
const MCP_PROXY_WEB_RESEARCH_TIMEOUT_SECS_DEFAULT: u64 = 120;
const MCP_PROXY_SEARCH_TIMEOUT_SECS_DEFAULT: u64 = 600;
const MCP_PROXY_DELEGATE_TIMEOUT_SECS_DEFAULT: u64 = 600;
const MCP_PROXY_MAX_INFLIGHT_DEFAULT: usize = 64;
const MCP_PROXY_MAX_PENDING_PER_SESSION_DEFAULT: usize = 64;
const SESSION_CLEANUP_INTERVAL_SECS: u64 = 600;
const SESSION_IDLE_TIMEOUT_SECS: u64 = 3600;

pub struct McpProxy {
    service: Mutex<Option<Arc<McpService>>>,
    sessions: RwLock<HashMap<String, SessionEntry>>,
    inflight: Arc<Semaphore>,
    max_pending_per_session: usize,
    next_id: AtomicU64,
}

struct SessionEntry {
    sender: mpsc::Sender<Value>,
    last_active: Instant,
    cancel: watch::Sender<bool>,
    serial: Arc<Mutex<()>>,
    requests: HashMap<String, watch::Sender<bool>>,
}

struct SessionRequest {
    session_cancel: watch::Receiver<bool>,
    request_cancel: watch::Receiver<bool>,
    serial: Arc<Mutex<()>>,
    request_key: String,
}

impl McpProxy {
    pub fn new(service: McpService) -> Arc<Self> {
        Self::new_with_limits(
            service,
            mcp_proxy_max_inflight(),
            mcp_proxy_max_pending_per_session(),
        )
    }

    fn new_with_limits(
        service: McpService,
        max_inflight: usize,
        max_pending_per_session: usize,
    ) -> Arc<Self> {
        let proxy = Arc::new(Self {
            service: Mutex::new(Some(Arc::new(service))),
            sessions: RwLock::new(HashMap::new()),
            inflight: Arc::new(Semaphore::new(max_inflight.max(1))),
            max_pending_per_session: max_pending_per_session.max(1),
            next_id: AtomicU64::new(1),
        });
        Self::spawn_session_cleanup(&proxy);
        proxy
    }

    fn spawn_session_cleanup(proxy: &Arc<Self>) {
        let proxy = Arc::downgrade(proxy);
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(SESSION_CLEANUP_INTERVAL_SECS));
            loop {
                interval.tick().await;
                let Some(proxy) = proxy.upgrade() else {
                    break;
                };
                proxy.cleanup_sessions().await;
            }
        });
    }

    pub async fn call(&self, session_id: Option<&str>, mut request: Value) -> Result<Value> {
        if is_cancelled_notification(&request) {
            let session_id =
                session_id.ok_or_else(|| anyhow!("MCP cancellation requires a bound session"))?;
            let request_id = cancellation_request_id(&request)?;
            let cancelled = self.cancel_session_request(session_id, request_id).await?;
            return Ok(json!({ "cancelled": cancelled }));
        }

        let id = ensure_id(&mut request, &self.next_id)?;
        let timeout = mcp_proxy_timeout_for_request(&request);
        let started = Instant::now();
        if let Some(session_id) = session_id {
            let mut session_request = self.begin_session_request(session_id, &id).await?;
            let session_guard = match acquire_session_turn(&mut session_request, timeout).await {
                Ok(guard) => guard,
                Err(err) => {
                    self.finish_session_request(session_id, &session_request.request_key)
                        .await;
                    return Err(err);
                }
            };
            let permit = match acquire_inflight(&self.inflight) {
                Ok(permit) => permit,
                Err(err) => {
                    drop(session_guard);
                    self.finish_session_request(session_id, &session_request.request_key)
                        .await;
                    return Err(err);
                }
            };
            let result = match remaining_request_timeout(timeout, started) {
                Ok(remaining) => {
                    self.handle_session_request_with_timeout(
                        session_id,
                        request,
                        remaining,
                        &mut session_request,
                    )
                    .await
                }
                Err(err) => Err(err),
            };
            drop(permit);
            drop(session_guard);
            self.finish_session_request(session_id, &session_request.request_key)
                .await;
            return Ok(result?.context("mcp proxy response dropped")?);
        }

        let _permit = acquire_inflight(&self.inflight)?;
        let resp = self
            .handle_request_with_timeout(None, request, timeout)
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
        let service = self
            .service
            .lock()
            .await
            .clone()
            .ok_or_else(|| anyhow!("mcp proxy shutdown"))?;
        let timeout = mcp_proxy_timeout_for_request(&request);
        let started = Instant::now();
        let mut session_request = self.begin_session_request(session_id, &client_id).await?;
        let session_id = session_id.to_string();
        let request_session_id = session_id.clone();
        let proxy = Arc::clone(self);
        tokio::spawn(async move {
            let response = match acquire_session_turn(&mut session_request, timeout).await {
                Ok(session_guard) => match acquire_inflight(&proxy.inflight) {
                    Ok(permit) => {
                        let response = match remaining_request_timeout(timeout, started) {
                            Ok(remaining) => tokio::select! {
                                biased;
                                _ = session_request.session_cancel.changed() => None,
                                _ = session_request.request_cancel.changed() => None,
                                response = timeout_result(
                                    remaining,
                                    service.handle_json_for_session(&request_session_id, request),
                                ) => Some(response),
                            },
                            Err(err) => Some(Err(err)),
                        };
                        // Response delivery and slow-session eviction must
                        // never consume a global request permit.
                        drop(permit);
                        drop(session_guard);
                        response
                    }
                    Err(err) => {
                        drop(session_guard);
                        Some(Err(err))
                    }
                },
                Err(err) if is_request_cancelled_error(&err) => None,
                Err(err) => Some(Err(err)),
            };

            proxy
                .finish_session_request(&session_id, &session_request.request_key)
                .await;
            let Some(response) = response else {
                return;
            };
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
        let (cancel, _cancel_rx) = watch::channel(false);
        self.sessions.write().await.insert(
            session_id.clone(),
            SessionEntry {
                sender: tx,
                last_active: Instant::now(),
                cancel,
                serial: Arc::new(Mutex::new(())),
                requests: HashMap::new(),
            },
        );
        (session_id, rx)
    }

    async fn handle_request_with_timeout(
        &self,
        session_id: Option<&str>,
        request: Value,
        timeout: Duration,
    ) -> Result<Option<Value>> {
        let service = self
            .service
            .lock()
            .await
            .clone()
            .ok_or_else(|| anyhow!("mcp proxy shutdown"))?;
        let request = async {
            match session_id {
                Some(session_id) => service.handle_json_for_session(session_id, request).await,
                None => service.handle_json(request).await,
            }
        };
        timeout_result(timeout, request).await
    }

    async fn handle_session_request_with_timeout(
        &self,
        session_id: &str,
        request: Value,
        timeout: Duration,
        session_request: &mut SessionRequest,
    ) -> Result<Option<Value>> {
        tokio::select! {
            biased;
            _ = session_request.session_cancel.changed() => Err(request_cancelled()),
            _ = session_request.request_cancel.changed() => Err(request_cancelled()),
            response = self.handle_request_with_timeout(Some(session_id), request, timeout) => response,
        }
    }

    async fn dispatch_to_session(&self, session_id: &str, payload: Value) {
        let should_evict = {
            let mut sessions = self.sessions.write().await;
            let Some(entry) = sessions.get_mut(session_id) else {
                return;
            };
            match entry.sender.try_send(payload) {
                Ok(()) => {
                    entry.last_active = Instant::now();
                    false
                }
                Err(_) => true,
            }
        };

        // A full or closed response channel means the client cannot make
        // progress. Evict it immediately instead of parking a request task.
        if should_evict {
            self.remove_session(session_id).await;
        }
    }

    async fn cleanup_sessions(&self) {
        let mut sessions = self.sessions.write().await;
        let now = Instant::now();
        let expired: Vec<String> = sessions
            .iter()
            .filter(|(_, entry)| {
                now.duration_since(entry.last_active)
                    >= Duration::from_secs(SESSION_IDLE_TIMEOUT_SECS)
            })
            .map(|(session_id, _)| session_id.clone())
            .collect();
        let expired: Vec<(String, SessionEntry)> = expired
            .into_iter()
            .filter_map(|session_id| {
                sessions
                    .remove(&session_id)
                    .map(|entry| (session_id, entry))
            })
            .collect();
        drop(sessions);
        if !expired.is_empty() {
            for (_, entry) in &expired {
                let _ = entry.cancel.send(true);
            }
            let service = self.service.lock().await.clone();
            if let Some(service) = service {
                for (session_id, _) in expired {
                    service.remove_session(&session_id).await;
                }
            }
        }
    }

    async fn begin_session_request(
        &self,
        session_id: &str,
        request_id: &Value,
    ) -> Result<SessionRequest> {
        let request_key = request_id_key(request_id)?;
        let mut sessions = self.sessions.write().await;
        let entry = sessions
            .get_mut(session_id)
            .ok_or_else(|| anyhow!("unknown or expired mcp proxy session"))?;
        if entry.requests.contains_key(&request_key) {
            return Err(anyhow!(
                "duplicate in-flight MCP request id for this session"
            ));
        }
        if entry.requests.len() >= self.max_pending_per_session {
            return Err(AppError::new(
                ERR_BACKOFF_REQUIRED,
                format!(
                    "MCP session has reached its pending request limit of {}; retry after an earlier request completes",
                    self.max_pending_per_session
                ),
            )
            .into());
        }
        let (request_cancel, request_cancel_rx) = watch::channel(false);
        entry.requests.insert(request_key.clone(), request_cancel);
        entry.last_active = Instant::now();
        Ok(SessionRequest {
            session_cancel: entry.cancel.subscribe(),
            request_cancel: request_cancel_rx,
            serial: entry.serial.clone(),
            request_key,
        })
    }

    async fn finish_session_request(&self, session_id: &str, request_key: &str) {
        if let Some(entry) = self.sessions.write().await.get_mut(session_id) {
            entry.requests.remove(request_key);
        }
    }

    async fn cancel_session_request(&self, session_id: &str, request_id: &Value) -> Result<bool> {
        let request_key = request_id_key(request_id)?;
        let mut sessions = self.sessions.write().await;
        let entry = sessions
            .get_mut(session_id)
            .ok_or_else(|| anyhow!("unknown or expired mcp proxy session"))?;
        entry.last_active = Instant::now();
        let Some(cancel) = entry.requests.get(&request_key) else {
            return Ok(false);
        };
        Ok(cancel.send(true).is_ok())
    }

    pub(crate) async fn touch_session(&self, session_id: &str) -> Result<()> {
        let mut sessions = self.sessions.write().await;
        let entry = sessions
            .get_mut(session_id)
            .ok_or_else(|| anyhow!("unknown or expired mcp proxy session"))?;
        entry.last_active = Instant::now();
        Ok(())
    }

    pub(crate) async fn remove_session(&self, session_id: &str) {
        let removed = self.sessions.write().await.remove(session_id);
        if let Some(entry) = removed {
            let _ = entry.cancel.send(true);
        }
        let service = self.service.lock().await.clone();
        if let Some(service) = service {
            service.remove_session(session_id).await;
        }
    }

    #[cfg(test)]
    pub(crate) async fn session_state_for_tests(
        &self,
        session_id: &str,
    ) -> Option<(bool, Option<String>, Option<String>)> {
        let service = self.service.lock().await.clone()?;
        service.session_state_for_tests(session_id).await
    }
}

fn acquire_inflight(inflight: &Arc<Semaphore>) -> Result<OwnedSemaphorePermit> {
    inflight
        .clone()
        .try_acquire_owned()
        .map_err(|_| anyhow!("mcp proxy busy: too many in-flight requests"))
}

async fn acquire_session_turn(
    request: &mut SessionRequest,
    timeout: Duration,
) -> Result<OwnedMutexGuard<()>> {
    let serial = request.serial.clone();
    tokio::select! {
        biased;
        _ = request.session_cancel.changed() => Err(request_cancelled()),
        _ = request.request_cancel.changed() => Err(request_cancelled()),
        _ = tokio::time::sleep(timeout) => {
            Err(anyhow!("mcp proxy timeout"))
        }
        guard = serial.lock_owned() => Ok(guard),
    }
}

fn request_cancelled() -> anyhow::Error {
    anyhow::Error::new(McpRequestCancelled)
}

fn is_request_cancelled_error(err: &anyhow::Error) -> bool {
    err.downcast_ref::<McpRequestCancelled>().is_some()
}

fn remaining_request_timeout(timeout: Duration, started: Instant) -> Result<Duration> {
    let remaining = timeout.saturating_sub(started.elapsed());
    if remaining.is_zero() {
        Err(anyhow!("mcp proxy timeout"))
    } else {
        Ok(remaining)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("mcp proxy request cancelled")]
struct McpRequestCancelled;

fn request_id_key(request_id: &Value) -> Result<String> {
    serde_json::to_string(request_id).context("serialize MCP request id")
}

fn is_cancelled_notification(request: &Value) -> bool {
    request.get("method").and_then(Value::as_str) == Some("notifications/cancelled")
        && request.get("id").is_none()
}

fn cancellation_request_id(request: &Value) -> Result<&Value> {
    request
        .get("params")
        .and_then(Value::as_object)
        .and_then(|params| params.get("requestId"))
        .ok_or_else(|| anyhow!("MCP cancellation notification is missing params.requestId"))
}

async fn timeout_result<T, F>(timeout: Duration, future: F) -> Result<T>
where
    F: Future<Output = Result<T>>,
{
    match tokio::time::timeout(timeout, future).await {
        Ok(result) => result,
        Err(_) => Err(anyhow!("mcp proxy timeout")),
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

fn mcp_proxy_timeout() -> Duration {
    let value = env::var("DOCDEX_MCP_PROXY_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(MCP_PROXY_TIMEOUT_SECS_DEFAULT);
    Duration::from_secs(value)
}

fn mcp_proxy_timeout_for_request(request: &Value) -> Duration {
    let base = mcp_proxy_timeout();
    if !is_web_research_request(request) {
        if is_search_request(request) && web_enabled() {
            let override_secs = mcp_proxy_search_timeout_secs();
            let override_duration = Duration::from_secs(override_secs);
            return if override_duration > base {
                override_duration
            } else {
                base
            };
        }
        if is_delegate_request(request) {
            let override_secs = mcp_proxy_delegate_timeout_secs();
            let override_duration = Duration::from_secs(override_secs);
            return if override_duration > base {
                override_duration
            } else {
                base
            };
        }
        return base;
    }
    let override_secs = env::var("DOCDEX_MCP_PROXY_WEB_RESEARCH_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(MCP_PROXY_WEB_RESEARCH_TIMEOUT_SECS_DEFAULT);
    let override_duration = Duration::from_secs(override_secs);
    if override_duration > base {
        override_duration
    } else {
        base
    }
}

fn is_web_research_request(request: &Value) -> bool {
    matches!(
        tool_name_for_request(request),
        Some("docdex_web_research") | Some("docdex.web_research")
    )
}

fn is_search_request(request: &Value) -> bool {
    matches!(
        tool_name_for_request(request),
        Some("docdex_search") | Some("docdex.search")
    )
}

fn is_delegate_request(request: &Value) -> bool {
    matches!(
        tool_name_for_request(request),
        Some("docdex_local_completion") | Some("docdex.local_completion")
    )
}

fn tool_name_for_request(request: &Value) -> Option<&str> {
    let method = request.get("method").and_then(Value::as_str);
    if method != Some("tools/call") {
        return None;
    }
    let params = request.get("params").and_then(Value::as_object)?;
    params.get("name").and_then(Value::as_str)
}

fn web_enabled() -> bool {
    match env::var("DOCDEX_WEB_ENABLED") {
        Ok(value) => {
            let value = value.trim().to_ascii_lowercase();
            !matches!(
                value.as_str(),
                "0" | "false" | "off" | "no" | "n" | "disable" | "disabled"
            )
        }
        Err(_) => true,
    }
}

fn mcp_proxy_search_timeout_secs() -> u64 {
    MCP_PROXY_SEARCH_TIMEOUT_SECS_DEFAULT
}

fn mcp_proxy_delegate_timeout_secs() -> u64 {
    MCP_PROXY_DELEGATE_TIMEOUT_SECS_DEFAULT
}

fn mcp_proxy_max_inflight() -> usize {
    env::var("DOCDEX_MCP_PROXY_MAX_INFLIGHT")
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(MCP_PROXY_MAX_INFLIGHT_DEFAULT)
}

fn mcp_proxy_max_pending_per_session() -> usize {
    env::var("DOCDEX_MCP_PROXY_MAX_PENDING_PER_SESSION")
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(MCP_PROXY_MAX_PENDING_PER_SESSION_DEFAULT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::IndexConfig;
    use crate::mcp_server::McpRuntimeOptions;
    use crate::metrics::DelegationMetrics;
    use crate::setup::test_support::ENV_LOCK;
    use parking_lot::ReentrantMutexGuard;
    use serde_json::json;
    use std::fs;
    use tempfile::TempDir;

    struct EnvGuard {
        key: &'static str,
        prev: Option<String>,
        _lock: ReentrantMutexGuard<'static, ()>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let lock = ENV_LOCK.lock();
            let prev = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self {
                key,
                prev,
                _lock: lock,
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            if let Some(ref value) = self.prev {
                std::env::set_var(self.key, value);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    fn tools_call(name: &str) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": {}
            }
        })
    }

    fn initialize_request(id: u64) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "initialize",
            "params": {}
        })
    }

    fn tools_list_request(id: u64) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/list",
            "params": {}
        })
    }

    fn cancellation_notification(request_id: u64) -> Value {
        json!({
            "jsonrpc": "2.0",
            "method": "notifications/cancelled",
            "params": {
                "requestId": request_id,
                "reason": "test cancellation"
            }
        })
    }

    fn build_test_proxy(
        max_inflight: usize,
    ) -> Result<(Arc<McpProxy>, TempDir), Box<dyn std::error::Error>> {
        build_test_proxy_with_limits(max_inflight, MCP_PROXY_MAX_PENDING_PER_SESSION_DEFAULT)
    }

    fn build_test_proxy_with_limits(
        max_inflight: usize,
        max_pending_per_session: usize,
    ) -> Result<(Arc<McpProxy>, TempDir), Box<dyn std::error::Error>> {
        let temp = TempDir::new()?;
        let repo_root = temp.path().join("repo");
        let state_root = temp.path().join("state");
        fs::create_dir_all(&repo_root)?;
        fs::create_dir_all(&state_root)?;
        fs::write(repo_root.join("README.md"), "# test\n")?;
        let config_path = temp.path().join("config.toml");
        let escaped_state_root = state_root.to_string_lossy().replace('\\', "\\\\");
        fs::write(
            &config_path,
            format!(
                "[core]\nglobal_state_dir = \"{escaped_state_root}\"\n[memory]\nenabled = false\n"
            ),
        )?;
        let index_config = IndexConfig::with_overrides(
            &repo_root,
            Some(state_root.join("repo-state")),
            Vec::new(),
            Vec::new(),
            true,
        )?;
        let config_path = config_path.to_string_lossy().to_string();
        let config_guard = EnvGuard::set("DOCDEX_CONFIG_PATH", &config_path);
        let service = McpService::new(
            repo_root,
            index_config,
            8,
            0,
            0,
            McpRuntimeOptions {
                memory_enabled: false,
                embedding_base_url: None,
                embedding_model: None,
                embedding_timeout_ms: Some(5_000),
                docdex_http_base_url: None,
                global_state_dir: Some(state_root.join("global")),
                personal_preferences_config: Some(crate::config::MemoryPersonalPreferencesConfig {
                    enabled: false,
                    ..Default::default()
                }),
            },
            None,
            Arc::new(DelegationMetrics::default()),
        )?;
        drop(config_guard);
        Ok((
            McpProxy::new_with_limits(service, max_inflight, max_pending_per_session),
            temp,
        ))
    }

    #[test]
    fn search_timeout_extends_when_web_enabled() {
        let _base = EnvGuard::set("DOCDEX_MCP_PROXY_TIMEOUT_SECS", "1");
        let _web = EnvGuard::set("DOCDEX_WEB_ENABLED", "1");
        let duration = mcp_proxy_timeout_for_request(&tools_call("docdex_search"));
        assert_eq!(duration.as_secs(), MCP_PROXY_SEARCH_TIMEOUT_SECS_DEFAULT);
    }

    #[test]
    fn search_timeout_skips_when_web_disabled() {
        let _base = EnvGuard::set("DOCDEX_MCP_PROXY_TIMEOUT_SECS", "1");
        let _web = EnvGuard::set("DOCDEX_WEB_ENABLED", "0");
        let duration = mcp_proxy_timeout_for_request(&tools_call("docdex_search"));
        assert_eq!(duration.as_secs(), 1);
    }

    #[test]
    fn delegate_timeout_extends() {
        let _base = EnvGuard::set("DOCDEX_MCP_PROXY_TIMEOUT_SECS", "1");
        let duration = mcp_proxy_timeout_for_request(&tools_call("docdex_local_completion"));
        assert_eq!(duration.as_secs(), MCP_PROXY_DELEGATE_TIMEOUT_SECS_DEFAULT);
    }

    #[tokio::test]
    async fn direct_call_respects_inflight_bound() -> Result<(), Box<dyn std::error::Error>> {
        let (proxy, _temp) = build_test_proxy(1)?;
        let _held_permit = proxy.inflight.clone().try_acquire_owned()?;
        let err = proxy
            .call(None, tools_call("docdex_capabilities"))
            .await
            .expect_err("saturated direct call must be rejected");
        assert!(err.to_string().contains("too many in-flight requests"));
        Ok(())
    }

    #[tokio::test]
    async fn direct_call_respects_request_timeout() -> Result<(), Box<dyn std::error::Error>> {
        let (proxy, _temp) = build_test_proxy(1)?;
        let service = proxy.service.lock().await.clone().expect("mcp service");
        let (session_id, _rx) = proxy.create_session().await;
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let blocked_service = service.clone();
        let blocked_session_id = session_id.clone();
        let blocker = tokio::spawn(async move {
            blocked_service
                .block_session_for_tests(&blocked_session_id, started_tx, release_rx)
                .await;
        });
        started_rx.await?;
        let timeout_guard = EnvGuard::set("DOCDEX_MCP_PROXY_TIMEOUT_SECS", "1");
        let err = proxy
            .call(
                Some(&session_id),
                json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/list",
                    "params": {}
                }),
            )
            .await
            .expect_err("slow direct call must time out");
        drop(timeout_guard);
        assert!(err.to_string().contains("mcp proxy timeout"));
        let _ = release_tx.send(());
        blocker.await?;
        Ok(())
    }

    #[tokio::test]
    async fn direct_call_refreshes_active_session_before_cleanup(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (proxy, _temp) = build_test_proxy(2)?;
        let (session_id, _rx) = proxy.create_session().await;
        proxy
            .call(
                Some(&session_id),
                json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {}
                }),
            )
            .await?;

        {
            let mut sessions = proxy.sessions.write().await;
            sessions
                .get_mut(&session_id)
                .expect("proxy session")
                .last_active = Instant::now()
                .checked_sub(Duration::from_secs(SESSION_IDLE_TIMEOUT_SECS + 1))
                .expect("stale timestamp");
        }

        proxy
            .call(
                Some(&session_id),
                json!({
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/list",
                    "params": {}
                }),
            )
            .await?;
        proxy.cleanup_sessions().await;

        assert!(proxy.sessions.read().await.contains_key(&session_id));
        assert!(proxy.session_state_for_tests(&session_id).await.is_some());
        Ok(())
    }

    #[tokio::test]
    async fn direct_call_rejects_unknown_session_before_service_state_is_created(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (proxy, _temp) = build_test_proxy(1)?;
        let err = proxy
            .call(
                Some("forged-session"),
                json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/list",
                    "params": {}
                }),
            )
            .await
            .expect_err("unknown direct session must fail closed");
        assert!(err.to_string().contains("unknown or expired"));
        assert!(proxy
            .session_state_for_tests("forged-session")
            .await
            .is_none());
        Ok(())
    }

    #[tokio::test]
    async fn removing_session_cancels_inflight_direct_call_and_releases_permit(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (proxy, _temp) = build_test_proxy(1)?;
        let service = proxy.service.lock().await.clone().expect("mcp service");
        let (session_id, _rx) = proxy.create_session().await;
        proxy.call(Some(&session_id), initialize_request(1)).await?;

        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let blocked_service = service.clone();
        let blocked_session_id = session_id.clone();
        let blocker = tokio::spawn(async move {
            blocked_service
                .block_session_for_tests(&blocked_session_id, started_tx, release_rx)
                .await;
        });
        started_rx.await?;

        let direct_proxy = proxy.clone();
        let direct_session_id = session_id.clone();
        let direct = tokio::spawn(async move {
            direct_proxy
                .call(Some(&direct_session_id), tools_list_request(2))
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while proxy.inflight.available_permits() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await?;

        proxy.remove_session(&session_id).await;
        let err = tokio::time::timeout(Duration::from_secs(1), direct)
            .await??
            .expect_err("session removal must cancel the direct call");
        assert!(err.to_string().contains("request cancelled"));
        assert_eq!(proxy.inflight.available_permits(), 1);
        assert!(!blocker.is_finished(), "service lock should remain blocked");

        let _ = release_tx.send(());
        blocker.await?;
        Ok(())
    }

    #[tokio::test]
    async fn protocol_cancellation_is_scoped_to_session_and_request_id(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (proxy, _temp) = build_test_proxy(2)?;
        let service = proxy.service.lock().await.clone().expect("mcp service");
        let (first_session, _first_rx) = proxy.create_session().await;
        let (second_session, _second_rx) = proxy.create_session().await;
        proxy
            .call(Some(&first_session), initialize_request(1))
            .await?;
        proxy
            .call(Some(&second_session), initialize_request(2))
            .await?;

        let (first_started_tx, first_started_rx) = tokio::sync::oneshot::channel();
        let (first_release_tx, first_release_rx) = tokio::sync::oneshot::channel();
        let first_blocked_service = service.clone();
        let first_blocked_session = first_session.clone();
        let first_blocker = tokio::spawn(async move {
            first_blocked_service
                .block_session_for_tests(&first_blocked_session, first_started_tx, first_release_rx)
                .await;
        });
        let (second_started_tx, second_started_rx) = tokio::sync::oneshot::channel();
        let (second_release_tx, second_release_rx) = tokio::sync::oneshot::channel();
        let second_blocked_service = service.clone();
        let second_blocked_session = second_session.clone();
        let second_blocker = tokio::spawn(async move {
            second_blocked_service
                .block_session_for_tests(
                    &second_blocked_session,
                    second_started_tx,
                    second_release_rx,
                )
                .await;
        });
        first_started_rx.await?;
        second_started_rx.await?;

        let first_proxy = proxy.clone();
        let first_call_session = first_session.clone();
        let mut first_call = tokio::spawn(async move {
            first_proxy
                .call(Some(&first_call_session), tools_list_request(77))
                .await
        });
        let second_proxy = proxy.clone();
        let second_call_session = second_session.clone();
        let second_call = tokio::spawn(async move {
            second_proxy
                .call(Some(&second_call_session), tools_list_request(77))
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while proxy.inflight.available_permits() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await?;

        let acknowledgement = proxy
            .call(Some(&first_session), cancellation_notification(77))
            .await?;
        assert_eq!(acknowledgement.get("cancelled"), Some(&Value::Bool(true)));
        let first_result = tokio::time::timeout(Duration::from_secs(1), &mut first_call).await??;
        let err = first_result.expect_err("targeted request must be cancelled");
        assert!(err.to_string().contains("request cancelled"));
        assert!(
            !second_call.is_finished(),
            "same request id in another session must remain active"
        );

        let _ = first_release_tx.send(());
        let _ = second_release_tx.send(());
        first_blocker.await?;
        second_blocker.await?;
        tokio::time::timeout(Duration::from_secs(1), second_call).await???;
        Ok(())
    }

    #[tokio::test]
    async fn one_session_backlog_does_not_park_global_permits(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (proxy, _temp) = build_test_proxy(2)?;
        let service = proxy.service.lock().await.clone().expect("mcp service");
        let (blocked_session, _blocked_rx) = proxy.create_session().await;
        let (healthy_session, _healthy_rx) = proxy.create_session().await;
        proxy
            .call(Some(&blocked_session), initialize_request(1))
            .await?;
        proxy
            .call(Some(&healthy_session), initialize_request(2))
            .await?;

        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let blocked_service = service.clone();
        let service_session = blocked_session.clone();
        let blocker = tokio::spawn(async move {
            blocked_service
                .block_session_for_tests(&service_session, started_tx, release_rx)
                .await;
        });
        started_rx.await?;

        let first_proxy = proxy.clone();
        let first_session = blocked_session.clone();
        let first = tokio::spawn(async move {
            first_proxy
                .call(Some(&first_session), tools_list_request(10))
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while proxy.inflight.available_permits() != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await?;

        let queued_proxy = proxy.clone();
        let queued_session = blocked_session.clone();
        let queued = tokio::spawn(async move {
            queued_proxy
                .call(Some(&queued_session), tools_list_request(11))
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let queued_requests = proxy
                    .sessions
                    .read()
                    .await
                    .get(&blocked_session)
                    .map(|entry| entry.requests.len())
                    .unwrap_or_default();
                if queued_requests == 2 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await?;
        assert_eq!(
            proxy.inflight.available_permits(),
            1,
            "queued work for one session must not consume another global permit"
        );

        tokio::time::timeout(
            Duration::from_secs(1),
            proxy.call(Some(&healthy_session), tools_list_request(12)),
        )
        .await??;

        let _ = release_tx.send(());
        blocker.await?;
        tokio::time::timeout(Duration::from_secs(1), first).await???;
        tokio::time::timeout(Duration::from_secs(1), queued).await???;
        Ok(())
    }

    #[tokio::test]
    async fn queued_sse_request_acknowledges_before_session_turn_is_available(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (proxy, _temp) = build_test_proxy(2)?;
        let service = proxy.service.lock().await.clone().expect("mcp service");
        let (session_id, _rx) = proxy.create_session().await;
        proxy.call(Some(&session_id), initialize_request(1)).await?;

        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let blocked_service = service.clone();
        let blocked_session = session_id.clone();
        let blocker = tokio::spawn(async move {
            blocked_service
                .block_session_for_tests(&blocked_session, started_tx, release_rx)
                .await;
        });
        started_rx.await?;

        proxy
            .enqueue_for_session(&session_id, tools_list_request(20))
            .await?;
        tokio::time::timeout(Duration::from_secs(1), async {
            while proxy.inflight.available_permits() != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await?;

        let acknowledgement = tokio::time::timeout(
            Duration::from_secs(1),
            proxy.enqueue_for_session(&session_id, tools_list_request(21)),
        )
        .await??;
        assert_eq!(
            acknowledgement.get("accepted"),
            Some(&Value::Bool(true)),
            "queued SSE request must be acknowledged before execution"
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let queued_requests = proxy
                    .sessions
                    .read()
                    .await
                    .get(&session_id)
                    .map(|entry| entry.requests.len())
                    .unwrap_or_default();
                if queued_requests == 2 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await?;
        assert_eq!(
            proxy.inflight.available_permits(),
            1,
            "queued SSE work must wait outside the global permit pool"
        );

        proxy.remove_session(&session_id).await;
        tokio::time::timeout(Duration::from_secs(1), async {
            while proxy.inflight.available_permits() != 2 {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        let _ = release_tx.send(());
        blocker.await?;
        Ok(())
    }

    #[tokio::test]
    async fn session_pending_request_limit_rejects_overflow_without_spawning_more_work(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (proxy, _temp) = build_test_proxy_with_limits(2, 2)?;
        let service = proxy.service.lock().await.clone().expect("mcp service");
        let (session_id, _rx) = proxy.create_session().await;
        proxy.call(Some(&session_id), initialize_request(1)).await?;

        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let blocked_service = service.clone();
        let blocked_session = session_id.clone();
        let blocker = tokio::spawn(async move {
            blocked_service
                .block_session_for_tests(&blocked_session, started_tx, release_rx)
                .await;
        });
        started_rx.await?;

        proxy
            .enqueue_for_session(&session_id, tools_list_request(30))
            .await?;
        proxy
            .enqueue_for_session(&session_id, tools_list_request(31))
            .await?;
        let err = proxy
            .enqueue_for_session(&session_id, tools_list_request(32))
            .await
            .expect_err("third pending request must be rejected");
        let app_error = err
            .downcast_ref::<AppError>()
            .expect("overflow must retain a typed backoff error");
        assert_eq!(app_error.code, ERR_BACKOFF_REQUIRED);
        assert_eq!(
            proxy
                .sessions
                .read()
                .await
                .get(&session_id)
                .expect("session")
                .requests
                .len(),
            2,
            "rejected work must not create a task or cancellation entry"
        );

        proxy.remove_session(&session_id).await;
        let _ = release_tx.send(());
        blocker.await?;
        Ok(())
    }

    #[tokio::test]
    async fn full_response_channel_evicts_session_and_releases_inflight_permit(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (proxy, _temp) = build_test_proxy(1)?;
        let (session_id, _rx) = proxy.create_session().await;
        let sender = proxy
            .sessions
            .read()
            .await
            .get(&session_id)
            .expect("proxy session")
            .sender
            .clone();
        for sequence in 0..64 {
            sender.try_send(json!({ "sequence": sequence }))?;
        }
        assert_eq!(sender.capacity(), 0, "test must saturate response channel");

        proxy
            .enqueue_for_session(
                &session_id,
                json!({
                    "jsonrpc": "2.0",
                    "id": 7,
                    "method": "tools/list",
                    "params": {}
                }),
            )
            .await?;

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if !proxy.sessions.read().await.contains_key(&session_id) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await?;
        assert_eq!(proxy.inflight.available_permits(), 1);
        assert!(proxy.session_state_for_tests(&session_id).await.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn removing_session_cancels_spawned_request_and_releases_permit(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (proxy, _temp) = build_test_proxy(1)?;
        let service = proxy.service.lock().await.clone().expect("mcp service");
        let (session_id, _rx) = proxy.create_session().await;
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let blocked_service = service.clone();
        let blocked_session_id = session_id.clone();
        let blocker = tokio::spawn(async move {
            blocked_service
                .block_session_for_tests(&blocked_session_id, started_tx, release_rx)
                .await;
        });
        started_rx.await?;

        proxy
            .enqueue_for_session(
                &session_id,
                json!({
                    "jsonrpc": "2.0",
                    "id": 8,
                    "method": "tools/list",
                    "params": {}
                }),
            )
            .await?;
        tokio::time::timeout(Duration::from_secs(1), async {
            while proxy.inflight.available_permits() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        assert_eq!(proxy.inflight.available_permits(), 0);

        proxy.remove_session(&session_id).await;
        tokio::time::timeout(Duration::from_secs(1), async {
            while proxy.inflight.available_permits() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        assert_eq!(proxy.inflight.available_permits(), 1);
        assert!(!blocker.is_finished(), "service lock should remain blocked");

        let _ = release_tx.send(());
        blocker.await?;
        Ok(())
    }
}
