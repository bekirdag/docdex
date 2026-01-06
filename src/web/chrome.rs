use anyhow::{anyhow, Context, Result};
use futures::{SinkExt, StreamExt};
use serde_json::{json, Value};
use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tempfile::TempDir;
use tokio::process::Command;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;
use url::Url;

use crate::browser_session::{BrowserSession, BrowserSessionOptions};
use crate::orchestrator::web_config::WebConfig;
use crate::state_layout::ensure_state_dir_secure;
use crate::util;

#[derive(Clone, Debug)]
pub struct ChromeFetchConfig {
    pub chrome_binary: PathBuf,
    pub headless: bool,
    pub user_agent: String,
    pub timeout: Duration,
    pub user_data_dir: Option<PathBuf>,
}

#[derive(Clone, Debug)]
pub struct ChromeFetchResult {
    pub html: String,
    pub inner_text: Option<String>,
    pub text_content: Option<String>,
    pub status: Option<u16>,
    pub final_url: Option<String>,
}

const CHROME_THINK_DELAY_MIN_MS: u64 = 150;
const CHROME_THINK_DELAY_MAX_MS: u64 = 650;
const CHROME_WINDOW_SIZE: &str = "1920,1080";
const WEBDRIVER_OVERRIDE_SCRIPT: &str =
    "Object.defineProperty(navigator, 'webdriver', { get: () => undefined });";

enum UserDataDir {
    Temp(TempDir),
    Persistent(PathBuf),
}

impl UserDataDir {
    fn new(config: &ChromeFetchConfig) -> Result<Self> {
        if let Some(path) = config.user_data_dir.as_ref() {
            ensure_state_dir_secure(path)
                .with_context(|| format!("ensure chrome user data dir {}", path.display()))?;
            return Ok(UserDataDir::Persistent(path.clone()));
        }
        Ok(UserDataDir::Temp(
            TempDir::new().context("create chrome user data directory")?,
        ))
    }

    fn path(&self) -> &Path {
        match self {
            UserDataDir::Temp(dir) => dir.path(),
            UserDataDir::Persistent(path) => path.as_path(),
        }
    }

    fn clear_devtools_port(&self) {
        let port_file = self.path().join("DevToolsActivePort");
        let _ = fs::remove_file(port_file);
    }
}

fn chrome_common_args(config: &ChromeFetchConfig, user_data_dir: &Path) -> Vec<String> {
    let mut args = Vec::new();
    if config.headless {
        args.push("--headless=new".to_string());
    }
    args.push("--disable-gpu".to_string());
    args.push("--disable-extensions".to_string());
    args.push("--disable-dev-shm-usage".to_string());
    args.push("--disable-blink-features=AutomationControlled".to_string());
    args.push("--no-sandbox".to_string());
    args.push("--no-first-run".to_string());
    args.push("--no-default-browser-check".to_string());
    args.push("--remote-allow-origins=*".to_string());
    args.push(format!("--window-size={}", CHROME_WINDOW_SIZE));
    args.push(format!(
        "--user-data-dir={}",
        user_data_dir.display()
    ));
    args.push("--disable-background-timer-throttling".to_string());
    args.push("--disable-backgrounding-occluded-windows".to_string());
    args.push("--disable-renderer-backgrounding".to_string());
    args.push("--run-all-compositor-stages-before-draw".to_string());
    args.push(format!("--user-agent={}", config.user_agent));
    args
}

impl ChromeFetchConfig {
    pub fn from_web_config(config: &WebConfig) -> Option<Self> {
        let chrome_binary = util::detect_browser_binary(config.chrome_binary_path.as_deref())?.path;
        Some(Self {
            chrome_binary,
            headless: config.scraper_headless,
            user_agent: config.user_agent.clone(),
            timeout: config.page_load_timeout,
            user_data_dir: config.scraper_user_data_dir.clone(),
        })
    }
}

pub async fn fetch_dom(url: &Url, config: &ChromeFetchConfig) -> Result<ChromeFetchResult> {
    let mut command = Command::new(&config.chrome_binary);
    let user_data_dir = UserDataDir::new(config)?;
    user_data_dir.clear_devtools_port();
    let mut args = chrome_common_args(config, user_data_dir.path());
    let debug_port = pick_free_port().context("pick devtools port")?;
    args.push("--remote-debugging-address=127.0.0.1".to_string());
    args.push(format!("--remote-debugging-port={debug_port}"));
    command.args(args);
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
    let cdp_result = session
        .run_scoped(timeout, std::future::pending::<()>(), async move {
            let deadline = Instant::now() + timeout;
            let ws_url = create_cdp_target(debug_port, remaining(deadline)).await?;
            let result = fetch_dom_via_cdp(&ws_url, &target_url, remaining(deadline)).await?;
            Ok(result)
        })
        .await;
    match cdp_result {
        Ok(result) => Ok(result),
        Err(err) => {
            let fallback = fetch_dom_dump_dom(url, config).await;
            if let Ok(result) = fallback {
                return Ok(result);
            }
            Err(anyhow!("chrome fetch failed: {err}"))
        }
    }
}

async fn fetch_dom_dump_dom(url: &Url, config: &ChromeFetchConfig) -> Result<ChromeFetchResult> {
    let mut command = Command::new(&config.chrome_binary);
    let user_data_dir = UserDataDir::new(config)?;
    let args = chrome_common_args(config, user_data_dir.path());
    command.args(args);
    command.arg("--virtual-time-budget=15000");
    command.arg("--dump-dom");
    command.arg(url.as_str());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::null());

    let timeout = if config.timeout.is_zero() {
        Duration::from_secs(15)
    } else {
        config.timeout
    };
    let session = BrowserSession::spawn(command, BrowserSessionOptions::default())
        .await
        .map_err(|err| anyhow!("chrome launch failed: {err}"))?;
    let output = session
        .wait_for_output(timeout)
        .await
        .map_err(|err| anyhow!("chrome dump-dom failed: {err}"))?;
    let html = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if html.is_empty() {
        return Err(anyhow!("chrome dump-dom returned empty HTML"));
    }
    Ok(ChromeFetchResult {
        html,
        inner_text: None,
        text_content: None,
        status: None,
        final_url: Some(url.to_string()),
    })
}

fn remaining(deadline: Instant) -> Duration {
    deadline
        .checked_duration_since(Instant::now())
        .unwrap_or_else(|| Duration::from_millis(0))
}

fn pick_free_port() -> Result<u16> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).context("bind free port")?;
    let port = listener
        .local_addr()
        .context("resolve free port")?
        .port();
    Ok(port)
}

async fn create_cdp_target(port: u16, timeout: Duration) -> Result<String> {
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .context("build devtools client")?;
    let endpoint_new = format!("http://127.0.0.1:{port}/json/new");
    let endpoint_list = format!("http://127.0.0.1:{port}/json/list");
    let start = Instant::now();
    let mut last_err: Option<anyhow::Error> = None;
    loop {
        match fetch_devtools_ws_url(&client, &endpoint_new).await {
            Ok(Some(url)) => return Ok(url),
            Ok(None) => {}
            Err(err) => last_err = Some(err),
        }
        match fetch_devtools_ws_url(&client, &endpoint_list).await {
            Ok(Some(url)) => return Ok(url),
            Ok(None) => {}
            Err(err) => last_err = Some(err),
        }
        if start.elapsed() >= timeout {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        if start.elapsed() >= timeout {
            break;
        }
    }
    if let Some(err) = last_err.take() {
        return Err(err);
    }
    Err(anyhow!(
        "devtools websocket not available within {timeout:?}"
    ))
}

async fn fetch_devtools_ws_url(client: &reqwest::Client, endpoint: &str) -> Result<Option<String>> {
    let resp = client
        .get(endpoint)
        .send()
        .await
        .with_context(|| format!("fetch devtools endpoint {endpoint}"))?;
    let status = resp.status();
    let body = resp
        .text()
        .await
        .with_context(|| format!("read devtools endpoint {endpoint}"))?;
    if !status.is_success() {
        return Err(anyhow!(
            "devtools endpoint {endpoint} failed with status {status}"
        ));
    }
    let value: Value = match serde_json::from_str(&body) {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    Ok(extract_ws_url(&value))
}

fn extract_ws_url(value: &Value) -> Option<String> {
    if let Some(url) = value.get("webSocketDebuggerUrl").and_then(Value::as_str) {
        return Some(url.to_string());
    }
    if let Some(items) = value.as_array() {
        for item in items {
            if let Some(url) = item.get("webSocketDebuggerUrl").and_then(Value::as_str) {
                return Some(url.to_string());
            }
        }
    }
    None
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
        mut tracker: Option<&mut NetworkIdleTracker>,
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
                Message::Binary(bin) => {
                    String::from_utf8(bin).context("decode devtools binary message")?
                }
                _ => continue,
            };
            let value: Value = serde_json::from_str(&text).context("parse devtools message")?;
            if let Some(resp_id) = value.get("id").and_then(Value::as_u64) {
                if resp_id == id {
                    if let Some(err) = value.get("error") {
                        return Err(anyhow!("devtools error for {method}: {}", err));
                    }
                    return Ok(value.get("result").cloned().unwrap_or(Value::Null));
                }
            }
            if let Some(method) = value.get("method").and_then(Value::as_str) {
                if let Some(tracker) = tracker.as_deref_mut() {
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
                        Message::Binary(bin) => {
                            String::from_utf8(bin).context("decode devtools binary message")?
                        }
                        _ => continue,
                    };
                    let value: Value =
                        serde_json::from_str(&text).context("parse devtools message")?;
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
    client.call("Network.enable", json!({}), None).await?;
    client.call("Page.enable", json!({}), None).await?;
    client.call("Runtime.enable", json!({}), None).await?;
    inject_webdriver_override(&mut client).await?;

    let mut tracker = NetworkIdleTracker::new();
    let think_delay = random_delay_ms(CHROME_THINK_DELAY_MIN_MS, CHROME_THINK_DELAY_MAX_MS);
    if !think_delay.is_zero() {
        tokio::time::sleep(think_delay).await;
    }
    let nav_result = client
        .call(
            "Page.navigate",
            json!({ "url": url.as_str() }),
            Some(&mut tracker),
        )
        .await?;
    if let Some(error_text) = nav_result.get("errorText").and_then(Value::as_str) {
        return Err(anyhow!("navigation failed: {error_text}"));
    }
    client.wait_for_network_idle(&mut tracker, timeout).await?;

    let mut html = String::new();
    let mut final_url = tracker.document_url.clone();
    let min_text_len = 80usize;
    let poll_interval = Duration::from_millis(200);
    let start = Instant::now();
    loop {
        let href = eval_string(&mut client, "document.location.href").await?;
        if final_url.is_none() && !href.trim().is_empty() {
            final_url = Some(href.clone());
        }
        let ready_state = eval_string(&mut client, "document.readyState").await?;
        let text_len = eval_number(
            &mut client,
            "document.body ? document.body.innerText.length : 0",
        )
        .await?;
        let html_value = eval_string(&mut client, "document.documentElement.outerHTML").await?;
        if !html_value.trim().is_empty() {
            html = html_value;
        }
        let has_text = text_len >= min_text_len;
        let ready_complete = ready_state == "complete" && href != "about:blank";
        if has_text || ready_complete {
            break;
        }
        if start.elapsed() >= timeout {
            break;
        }
        tokio::time::sleep(poll_interval).await;
    }
    if html.trim().is_empty() {
        return Err(anyhow!("devtools returned empty HTML"));
    }
    let inner_text = capture_dom_text(&mut client, timeout, poll_interval, true).await?;
    let text_content = capture_dom_text(&mut client, timeout, poll_interval, false).await?;
    Ok(ChromeFetchResult {
        html,
        inner_text: if inner_text.is_empty() {
            None
        } else {
            Some(inner_text)
        },
        text_content: if text_content.is_empty() {
            None
        } else {
            Some(text_content)
        },
        status: tracker.document_status,
        final_url,
    })
}

async fn inject_webdriver_override(client: &mut CdpClient) -> Result<()> {
    client
        .call(
            "Page.addScriptToEvaluateOnNewDocument",
            json!({ "source": WEBDRIVER_OVERRIDE_SCRIPT }),
            None,
        )
        .await?;
    Ok(())
}

async fn eval_string(client: &mut CdpClient, expression: &str) -> Result<String> {
    let eval = client
        .call(
            "Runtime.evaluate",
            json!({
                "expression": expression,
                "returnByValue": true,
            }),
            None,
        )
        .await?;
    Ok(eval
        .get("result")
        .and_then(|value| value.get("value"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string())
}

async fn eval_number(client: &mut CdpClient, expression: &str) -> Result<usize> {
    let eval = client
        .call(
            "Runtime.evaluate",
            json!({
                "expression": expression,
                "returnByValue": true,
            }),
            None,
        )
        .await?;
    Ok(eval
        .get("result")
        .and_then(|value| value.get("value"))
        .and_then(Value::as_f64)
        .unwrap_or(0.0) as usize)
}

async fn capture_dom_text(
    client: &mut CdpClient,
    timeout: Duration,
    poll_interval: Duration,
    use_inner_text: bool,
) -> Result<String> {
    let start = Instant::now();
    let expression = if use_inner_text {
        "document.body ? document.body.innerText : \"\""
    } else {
        "document.body ? document.body.textContent : \"\""
    };
    let mut last_value = String::new();
    loop {
        let value = eval_string(client, expression).await.unwrap_or_default();
        if !value.trim().is_empty() {
            return Ok(value.trim().to_string());
        }
        if start.elapsed() >= timeout {
            return Ok(last_value.trim().to_string());
        }
        last_value = value;
        tokio::time::sleep(poll_interval).await;
    }
}

fn random_delay_ms(min_ms: u64, max_ms: u64) -> Duration {
    if max_ms <= min_ms {
        return Duration::from_millis(min_ms);
    }
    let span = max_ms - min_ms;
    let jitter = random_seed() % (span + 1);
    Duration::from_millis(min_ms + jitter)
}

fn random_seed() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chrome_common_args_include_stealth_flags() {
        let config = ChromeFetchConfig {
            chrome_binary: PathBuf::from("/bin/chrome"),
            headless: true,
            user_agent: "Mozilla/5.0 (X11; Linux x86_64)".to_string(),
            timeout: Duration::from_secs(5),
            user_data_dir: Some(PathBuf::from("profile_dir")),
        };
        let args = chrome_common_args(&config, Path::new("profile_dir"));
        assert!(args.contains(&"--headless=new".to_string()));
        assert!(args.contains(&"--disable-blink-features=AutomationControlled".to_string()));
        assert!(args.contains(&format!("--window-size={}", CHROME_WINDOW_SIZE)));
        assert!(args.contains(&"--user-data-dir=profile_dir".to_string()));
        assert!(!args.iter().any(|arg| arg == "--incognito"));
    }
}
