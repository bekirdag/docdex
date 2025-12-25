use anyhow::{anyhow, Context, Result};
use futures::{SinkExt, StreamExt};
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::process::Command;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;
use url::Url;

use crate::browser_session::{BrowserSession, BrowserSessionOptions};
use crate::orchestrator::web_config::WebConfig;
use crate::util;

#[derive(Clone, Debug)]
pub struct ChromeFetchConfig {
    pub chrome_binary: PathBuf,
    pub headless: bool,
    pub user_agent: String,
    pub timeout: Duration,
}

#[derive(Clone, Debug)]
pub struct ChromeFetchResult {
    pub html: String,
    pub status: Option<u16>,
    pub final_url: Option<String>,
}

impl ChromeFetchConfig {
    pub fn from_web_config(config: &WebConfig) -> Option<Self> {
        let chrome_binary = config
            .chrome_binary_path
            .clone()
            .or_else(util::detect_chrome_binary)?;
        Some(Self {
            chrome_binary,
            headless: config.scraper_headless,
            user_agent: config.user_agent.clone(),
            timeout: config.page_load_timeout,
        })
    }
}

pub async fn fetch_dom(url: &Url, config: &ChromeFetchConfig) -> Result<ChromeFetchResult> {
    let mut command = Command::new(&config.chrome_binary);
    let user_data_dir = TempDir::new().context("create chrome user data directory")?;
    if config.headless {
        command.arg("--headless=new");
    }
    command.arg("--disable-gpu");
    command.arg("--disable-extensions");
    command.arg("--disable-dev-shm-usage");
    command.arg("--no-sandbox");
    command.arg("--no-first-run");
    command.arg("--no-default-browser-check");
    command.arg("--incognito");
    command.arg(format!(
        "--user-data-dir={}",
        user_data_dir.path().display()
    ));
    command.arg("--remote-debugging-address=127.0.0.1");
    command.arg("--remote-debugging-port=0");
    command.arg("--disable-background-timer-throttling");
    command.arg("--disable-backgrounding-occluded-windows");
    command.arg("--disable-renderer-backgrounding");
    command.arg("--run-all-compositor-stages-before-draw");
    command.arg(format!("--user-agent={}", config.user_agent));
    command.arg("about:blank");
    command.stdout(Stdio::null());
    command.stderr(Stdio::null());

    let timeout = if config.timeout.is_zero() {
        Duration::from_secs(15)
    } else {
        config.timeout
    };
    let session = BrowserSession::spawn(command, BrowserSessionOptions::default())
        .await
        .map_err(|err| anyhow!("chrome launch failed: {err}"))?;
    let target_url = url.clone();
    let fetch_result = session
        .run_scoped(
            timeout,
            std::future::pending::<()>(),
            async move {
                let _guard = user_data_dir;
                let deadline = Instant::now() + timeout;
                let port = wait_for_devtools_port(_guard.path(), remaining(deadline)).await?;
                let ws_url = create_cdp_target(port).await?;
                let result = fetch_dom_via_cdp(&ws_url, &target_url, remaining(deadline)).await?;
                Ok(result)
            },
        )
        .await
        .map_err(|err| anyhow!("chrome fetch failed: {err}"))?;
    Ok(fetch_result)
}

#[derive(Debug, Deserialize)]
struct DevtoolsTarget {
    #[serde(rename = "webSocketDebuggerUrl")]
    web_socket_debugger_url: String,
}

async fn wait_for_devtools_port(dir: &Path, timeout: Duration) -> Result<u16> {
    let port_file = dir.join("DevToolsActivePort");
    let start = Instant::now();
    loop {
        if let Ok(contents) = std::fs::read_to_string(&port_file) {
            if let Some(port_line) = contents.lines().next() {
                let port: u16 = port_line.trim().parse().context("parse devtools port")?;
                return Ok(port);
            }
        }
        if start.elapsed() >= timeout {
            return Err(anyhow!(
                "devtools port not available within {timeout:?}"
            ));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn remaining(deadline: Instant) -> Duration {
    deadline
        .checked_duration_since(Instant::now())
        .unwrap_or_else(|| Duration::from_millis(0))
}

async fn create_cdp_target(port: u16) -> Result<String> {
    let endpoint = format!("http://127.0.0.1:{port}/json/new");
    let target: DevtoolsTarget = reqwest::get(endpoint)
        .await
        .context("create devtools target")?
        .json()
        .await
        .context("parse devtools target response")?;
    Ok(target.web_socket_debugger_url)
}

struct CdpClient {
    ws: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    next_id: u64,
}

impl CdpClient {
    async fn connect(ws_url: &str) -> Result<Self> {
        let (ws, _) = connect_async(ws_url)
            .await
            .context("connect to devtools websocket")?;
        Ok(Self { ws, next_id: 1 })
    }

    async fn call(
        &mut self,
        method: &str,
        params: Value,
        tracker: Option<&mut NetworkIdleTracker>,
    ) -> Result<Value> {
        let id = self.next_id;
        self.next_id += 1;
        let payload = json!({
            "id": id,
            "method": method,
            "params": params,
        });
        self.ws
            .send(Message::Text(payload.to_string()))
            .await
            .context("send devtools command")?;
        loop {
            let msg = self
                .ws
                .next()
                .await
                .ok_or_else(|| anyhow!("devtools websocket closed"))??;
            let text = match msg {
                Message::Text(text) => text,
                Message::Binary(bin) => String::from_utf8(bin)
                    .context("decode devtools binary message")?,
                _ => continue,
            };
            let value: Value = serde_json::from_str(&text)
                .context("parse devtools message")?;
            if let Some(resp_id) = value.get("id").and_then(Value::as_u64) {
                if resp_id == id {
                    if let Some(err) = value.get("error") {
                        return Err(anyhow!(
                            "devtools error for {method}: {}",
                            err
                        ));
                    }
                    return Ok(value.get("result").cloned().unwrap_or(Value::Null));
                }
            }
            if let Some(method) = value.get("method").and_then(Value::as_str) {
                if let Some(tracker) = tracker {
                    tracker.handle(method, value.get("params"));
                }
            }
        }
    }

    async fn wait_for_network_idle(
        &mut self,
        tracker: &mut NetworkIdleTracker,
        timeout: Duration,
    ) -> Result<()> {
        let idle_delay = Duration::from_millis(800);
        let start = Instant::now();
        loop {
            let elapsed = start.elapsed();
            if elapsed >= timeout {
                return Err(anyhow!("network idle wait timed out after {timeout:?}"));
            }
            let idle_ready = tracker.inflight == 0
                && tracker.last_activity.elapsed() >= idle_delay
                && (tracker.saw_load || elapsed >= idle_delay);
            if idle_ready {
                return Ok(());
            }
            let remaining = timeout.saturating_sub(elapsed);
            let wait_for = if tracker.inflight == 0 {
                let idle_left = idle_delay.saturating_sub(tracker.last_activity.elapsed());
                idle_left.min(remaining)
            } else {
                Duration::from_millis(100).min(remaining)
            };
            match tokio::time::timeout(wait_for, self.ws.next()).await {
                Ok(Some(Ok(msg))) => {
                    let text = match msg {
                        Message::Text(text) => text,
                        Message::Binary(bin) => String::from_utf8(bin)
                            .context("decode devtools binary message")?,
                        _ => continue,
                    };
                    let value: Value = serde_json::from_str(&text)
                        .context("parse devtools message")?;
                    if let Some(method) = value.get("method").and_then(Value::as_str) {
                        tracker.handle(method, value.get("params"));
                    }
                }
                Ok(Some(Err(err))) => {
                    return Err(anyhow!("devtools websocket error: {err}"));
                }
                Ok(None) => return Err(anyhow!("devtools websocket closed")),
                Err(_) => {}
            }
        }
    }
}

struct NetworkIdleTracker {
    inflight: usize,
    last_activity: Instant,
    saw_load: bool,
    document_status: Option<u16>,
    document_url: Option<String>,
}

impl NetworkIdleTracker {
    fn new() -> Self {
        Self {
            inflight: 0,
            last_activity: Instant::now(),
            saw_load: false,
            document_status: None,
            document_url: None,
        }
    }

    fn handle(&mut self, method: &str, params: Option<&Value>) {
        match method {
            "Network.requestWillBeSent" => {
                self.inflight = self.inflight.saturating_add(1);
                self.last_activity = Instant::now();
            }
            "Network.loadingFinished" | "Network.loadingFailed" => {
                self.inflight = self.inflight.saturating_sub(1);
                self.last_activity = Instant::now();
            }
            "Network.responseReceived" => {
                if let Some(params) = params {
                    let resource_type = params.get("type").and_then(Value::as_str);
                    if matches!(resource_type, Some("Document")) {
                        if let Some(status) = params
                            .get("response")
                            .and_then(|value| value.get("status"))
                            .and_then(Value::as_f64)
                        {
                            self.document_status = Some(status as u16);
                        }
                        if let Some(url) = params
                            .get("response")
                            .and_then(|value| value.get("url"))
                            .and_then(Value::as_str)
                        {
                            self.document_url = Some(url.to_string());
                        }
                    }
                }
                self.last_activity = Instant::now();
            }
            "Page.loadEventFired" => {
                self.saw_load = true;
                self.last_activity = Instant::now();
            }
            _ => {}
        }
    }
}

async fn fetch_dom_via_cdp(
    ws_url: &str,
    url: &Url,
    timeout: Duration,
) -> Result<ChromeFetchResult> {
    let mut client = CdpClient::connect(ws_url).await?;
    client
        .call("Network.enable", json!({}), None)
        .await?;
    client.call("Page.enable", json!({}), None).await?;
    client
        .call("Runtime.enable", json!({}), None)
        .await?;

    let mut tracker = NetworkIdleTracker::new();
    client
        .call(
            "Page.navigate",
            json!({ "url": url.as_str() }),
            Some(&mut tracker),
        )
        .await?;
    client
        .wait_for_network_idle(&mut tracker, timeout)
        .await?;

    let eval = client
        .call(
            "Runtime.evaluate",
            json!({
                "expression": "document.documentElement.outerHTML",
                "returnByValue": true,
            }),
            None,
        )
        .await?;
    let value = eval
        .get("result")
        .and_then(|value| value.get("value"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    if value.is_empty() {
        return Err(anyhow!("devtools returned empty HTML"));
    }
    Ok(ChromeFetchResult {
        html: value.to_string(),
        status: tracker.document_status,
        final_url: tracker.document_url,
    })
}
