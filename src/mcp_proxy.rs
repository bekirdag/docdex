use crate::mcp_server::McpService;
use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::env;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Mutex, RwLock};

const MCP_PROXY_TIMEOUT_SECS_DEFAULT: u64 = 30;
const MCP_PROXY_WEB_RESEARCH_TIMEOUT_SECS_DEFAULT: u64 = 120;
const MCP_PROXY_SEARCH_TIMEOUT_SECS_DEFAULT: u64 = 600;
const MCP_PROXY_DELEGATE_TIMEOUT_SECS_DEFAULT: u64 = 600;
const SESSION_CLEANUP_INTERVAL_SECS: u64 = 600;
const SESSION_IDLE_TIMEOUT_SECS: u64 = 3600;

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
        let service = guard
            .as_mut()
            .ok_or_else(|| anyhow!("mcp proxy shutdown"))?;
        service.handle_json(request).await
    }

    async fn handle_request_with_timeout(&self, request: Value) -> Result<Option<Value>> {
        let mut guard = self.service.lock().await;
        let service = guard
            .as_mut()
            .ok_or_else(|| anyhow!("mcp proxy shutdown"))?;
        let timeout = mcp_proxy_timeout_for_request(&request);
        match tokio::time::timeout(timeout, service.handle_json(request)).await {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup::test_support::ENV_LOCK;
    use parking_lot::ReentrantMutexGuard;
    use serde_json::json;

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
}
