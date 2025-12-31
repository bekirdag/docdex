use anyhow::{anyhow, Context, Result};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, ChildStdout};
use tokio::sync::{mpsc, oneshot, Mutex, RwLock};
use tracing::{debug, warn};

const MCP_PROXY_TIMEOUT_SECS: u64 = 30;
const SESSION_CLEANUP_INTERVAL_SECS: u64 = 600;
const SESSION_IDLE_TIMEOUT_SECS: u64 = 3600;

pub struct McpProxy {
    child: Mutex<Child>,
    stdin: Mutex<ChildStdin>,
    pending: Mutex<HashMap<String, oneshot::Sender<Value>>>,
    session_pending: Mutex<HashMap<String, String>>,
    sessions: RwLock<HashMap<String, SessionEntry>>,
    next_id: AtomicU64,
}

struct SessionEntry {
    sender: mpsc::Sender<Value>,
    last_active: Instant,
}

impl McpProxy {
    pub fn new(child: Child, stdin: ChildStdin, stdout: ChildStdout) -> Arc<Self> {
        let proxy = Arc::new(Self {
            child: Mutex::new(child),
            stdin: Mutex::new(stdin),
            pending: Mutex::new(HashMap::new()),
            session_pending: Mutex::new(HashMap::new()),
            sessions: RwLock::new(HashMap::new()),
            next_id: AtomicU64::new(1),
        });
        Self::spawn_reader(proxy.clone(), stdout);
        Self::spawn_session_cleanup(proxy.clone());
        proxy
    }

    fn spawn_reader(proxy: Arc<Self>, stdout: ChildStdout) {
        tokio::spawn(async move {
            let mut lines = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let payload = match serde_json::from_str::<Value>(trimmed) {
                    Ok(value) => value,
                    Err(err) => {
                        warn!(error = ?err, "mcp proxy: invalid JSON from child");
                        continue;
                    }
                };
                let id_value = payload.get("id");
                let Some(id_key) = id_value.and_then(id_key) else {
                    debug!("mcp proxy: response without id");
                    continue;
                };

                let pending = proxy.pending.lock().await.remove(&id_key);
                if let Some(sender) = pending {
                    let _ = sender.send(payload);
                    continue;
                }

                let session_id = proxy.session_pending.lock().await.remove(&id_key);
                if let Some(session_id) = session_id {
                    proxy.dispatch_to_session(&session_id, payload).await;
                }
            }
        });
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
        let id = ensure_id(&mut request, &self.next_id)?;
        let key = id_key(&id).ok_or_else(|| anyhow!("invalid JSON-RPC id"))?;
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(key, tx);
        if let Err(err) = self.send_request(&request).await {
            self.pending
                .lock()
                .await
                .remove(&id_key(&id).unwrap_or_default());
            return Err(err);
        }
        let resp = match tokio::time::timeout(Duration::from_secs(MCP_PROXY_TIMEOUT_SECS), rx).await
        {
            Ok(result) => result.context("mcp proxy response dropped")?,
            Err(_) => {
                self.pending
                    .lock()
                    .await
                    .remove(&id_key(&id).unwrap_or_default());
                return Err(anyhow!("mcp proxy timeout"));
            }
        };
        Ok(resp)
    }

    pub async fn is_alive(&self) -> bool {
        let mut child = self.child.lock().await;
        match child.try_wait() {
            Ok(Some(_)) => false,
            Ok(None) => true,
            Err(_) => false,
        }
    }

    pub async fn enqueue_for_session(&self, session_id: &str, mut request: Value) -> Result<Value> {
        let id = ensure_id(&mut request, &self.next_id)?;
        let key = id_key(&id).ok_or_else(|| anyhow!("invalid JSON-RPC id"))?;
        self.session_pending
            .lock()
            .await
            .insert(key, session_id.to_string());
        if let Err(err) = self.send_request(&request).await {
            self.session_pending
                .lock()
                .await
                .remove(&id_key(&id).unwrap_or_default());
            return Err(err);
        }
        Ok(json!({
            "accepted": true,
            "id": id,
        }))
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

    async fn send_request(&self, request: &Value) -> Result<()> {
        let mut stdin = self.stdin.lock().await;
        let payload = serde_json::to_string(request).context("serialize mcp request")?;
        stdin
            .write_all(payload.as_bytes())
            .await
            .context("write mcp request")?;
        stdin.write_all(b"\n").await.context("flush mcp request")?;
        stdin.flush().await.context("flush mcp request")?;
        Ok(())
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

fn id_key(id: &Value) -> Option<String> {
    match id {
        Value::String(value) => Some(format!("s:{value}")),
        Value::Number(value) => Some(format!("n:{value}")),
        _ => None,
    }
}
