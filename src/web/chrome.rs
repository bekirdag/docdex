use anyhow::{anyhow, Context, Result};
use futures::{SinkExt, StreamExt};
use once_cell::sync::{Lazy, OnceCell};
use serde_json::{json, Value};
use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::{env, num::NonZeroUsize};
use tempfile::TempDir;
use tokio::process::Command;
use tokio::sync::Mutex;
use tokio::sync::Semaphore;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;
use url::Url;

use crate::browser_session::{BrowserSession, BrowserSessionOptions};
use crate::orchestrator::web_config::{default_scraper_user_data_dir, WebConfig};
use crate::state_layout::ensure_state_dir_secure;
use crate::util;
use crate::web::scraper::{
    global_tracker, init_global_from_env, ChromeSessionHandle, TrackedProcess,
};

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

#[derive(Clone, Debug, PartialEq, Eq)]
struct ChromeSessionConfig {
    chrome_binary: PathBuf,
    headless: bool,
    user_agent: String,
    user_data_dir: Option<PathBuf>,
}

impl ChromeSessionConfig {
    fn from_fetch_config(config: &ChromeFetchConfig) -> Self {
        Self {
            chrome_binary: config.chrome_binary.clone(),
            headless: config.headless,
            user_agent: config.user_agent.clone(),
            user_data_dir: config.user_data_dir.clone(),
        }
    }
}

struct ChromeInstance {
    session: BrowserSession,
    debug_port: u16,
    config: ChromeSessionConfig,
    _user_data_dir: UserDataDir,
    watchdog_handle: Option<ChromeSessionHandle>,
}

impl ChromeInstance {
    async fn spawn(
        fetch_config: &ChromeFetchConfig,
        session_config: ChromeSessionConfig,
    ) -> Result<Self> {
        let mut command = Command::new(&fetch_config.chrome_binary);
        let user_data_dir = UserDataDir::new(fetch_config)?;
        user_data_dir.clear_devtools_port();
        let mut args = chrome_common_args(fetch_config, user_data_dir.path());
        let debug_port = pick_free_port().context("pick devtools port")?;
        args.push("--remote-debugging-address=127.0.0.1".to_string());
        args.push(format!("--remote-debugging-port={debug_port}"));
        command.args(args);
        command.arg("about:blank");
        command.stdout(Stdio::null());
        command.stderr(Stdio::null());

        let session = BrowserSession::spawn(command, BrowserSessionOptions::default())
            .await
            .map_err(|err| anyhow!("chrome launch failed: {err}"))?;
        if let Err(err) =
            wait_for_cdp_ready(debug_port, Duration::from_millis(CHROME_STARTUP_TIMEOUT_MS)).await
        {
            let _ = session.abort().await;
            return Err(err.context("chrome devtools did not become ready"));
        }
        let watchdog_handle = resolve_watchdog_handle(&session, "chrome_persistent");

        Ok(Self {
            session,
            debug_port,
            config: session_config,
            _user_data_dir: user_data_dir,
            watchdog_handle,
        })
    }

    fn matches(&self, config: &ChromeSessionConfig) -> bool {
        &self.config == config
    }

    async fn is_healthy(&self) -> bool {
        if !self.session.is_alive() {
            return false;
        }
        probe_cdp(self.debug_port).await
    }

    async fn fetch_dom(&self, url: &Url, timeout: Duration) -> Result<ChromeFetchResult> {
        if let Some(handle) = &self.watchdog_handle {
            handle.heartbeat();
        }
        let deadline = Instant::now() + timeout;
        let target = create_cdp_target(self.debug_port, remaining(deadline)).await?;
        let result = fetch_dom_via_cdp(&target.ws_url, url, remaining(deadline)).await;
        if let Some(target_id) = target.target_id.as_deref() {
            let _ = close_cdp_target(self.debug_port, target_id).await;
        }
        if let Some(handle) = &self.watchdog_handle {
            handle.heartbeat();
        }
        result
    }

    async fn shutdown(&self) {
        if let Some(handle) = &self.watchdog_handle {
            handle.end();
        }
        let _ = self.session.abort().await;
    }
}

struct ChromeManager {
    state: Mutex<ChromeManagerState>,
}

struct ChromeManagerState {
    instance: Option<Arc<ChromeInstance>>,
}

impl ChromeManager {
    fn global() -> Arc<Self> {
        CHROME_MANAGER
            .get_or_init(|| {
                Arc::new(Self {
                    state: Mutex::new(ChromeManagerState { instance: None }),
                })
            })
            .clone()
    }

    async fn get_or_launch(&self, config: &ChromeFetchConfig) -> Result<Arc<ChromeInstance>> {
        let session_config = ChromeSessionConfig::from_fetch_config(config);
        let mut state = self.state.lock().await;
        if let Some(instance) = state.instance.as_ref() {
            if instance.matches(&session_config) && instance.is_healthy().await {
                return Ok(instance.clone());
            }
        }

        let instance = Arc::new(ChromeInstance::spawn(config, session_config).await?);
        let old = state.instance.replace(instance.clone());
        drop(state);
        if let Some(old_instance) = old {
            old_instance.shutdown().await;
        }
        Ok(instance)
    }

    async fn reset_if_current(&self, instance: &Arc<ChromeInstance>) -> bool {
        let old = {
            let mut state = self.state.lock().await;
            match state.instance.as_ref() {
                Some(current) if Arc::ptr_eq(current, instance) => state.instance.take(),
                _ => None,
            }
        };
        if let Some(instance) = old {
            instance.shutdown().await;
            return true;
        }
        false
    }

    async fn reset_if_unhealthy(&self, instance: &Arc<ChromeInstance>) -> bool {
        if instance.is_healthy().await {
            return false;
        }
        self.reset_if_current(instance).await
    }
}

static CHROME_MANAGER: OnceCell<Arc<ChromeManager>> = OnceCell::new();
static CHROME_FETCH_SEMAPHORE: Lazy<Semaphore> =
    Lazy::new(|| Semaphore::new(resolve_chrome_fetch_concurrency()));

const CHROME_THINK_DELAY_MIN_MS: u64 = 150;
const CHROME_THINK_DELAY_MAX_MS: u64 = 650;
const CHROME_WINDOW_SIZE: &str = "1920,1080";
const CHROME_HEALTH_CHECK_TIMEOUT_MS: u64 = 800;
const CHROME_STARTUP_TIMEOUT_MS: u64 = 10_000;
const CHROME_NETWORK_IDLE_MAX_MS: u64 = 6_000;
const CHROME_COOKIE_DISMISS_TIMEOUT_MS: u64 = 1_500;
const COOKIE_DISMISS_SCRIPT: &str = r#"(function () {
  const acceptWords = ["accept", "agree", "allow", "ok", "okay", "got it", "yes"];
  const cookieWords = ["cookie", "cookies", "consent", "gdpr", "privacy", "tracking"];
  const nodes = Array.from(
    document.querySelectorAll("button, a, input[type='button'], input[type='submit']")
  );
  for (const node of nodes) {
    const raw = (node.innerText || node.value || "").trim().toLowerCase();
    if (!raw) continue;
    const hasAccept = acceptWords.some((word) => raw.includes(word));
    const hasCookie = cookieWords.some((word) => raw.includes(word));
    if (hasAccept && (hasCookie || raw.length <= 16)) {
      node.click();
      return true;
    }
  }
  const selectors = [
    "[id*='cookie']",
    "[class*='cookie']",
    "[id*='consent']",
    "[class*='consent']",
    "[aria-label*='cookie']",
    "[aria-label*='consent']",
    "[data-testid*='cookie']",
    "[data-testid*='consent']",
  ];
  let removed = false;
  for (const selector of selectors) {
    document.querySelectorAll(selector).forEach((el) => {
      el.remove();
      removed = true;
    });
  }
  return removed;
})()"#;
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

fn resolve_watchdog_handle(
    session: &BrowserSession,
    session_id: &str,
) -> Option<ChromeSessionHandle> {
    let tracker = global_tracker().or_else(init_global_from_env)?;
    Some(tracker.register(session_id.to_string(), tracked_process(session)))
}

fn tracked_process(session: &BrowserSession) -> TrackedProcess {
    #[cfg(unix)]
    {
        TrackedProcess {
            pid: session.pid(),
            process_group_id: Some(session.process_group_id()),
        }
    }
    #[cfg(not(unix))]
    {
        TrackedProcess {
            pid: session.pid(),
            process_group_id: None,
        }
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
    args.push(format!("--user-data-dir={}", user_data_dir.display()));
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
        let user_data_dir = config
            .scraper_user_data_dir
            .clone()
            .or_else(|| default_scraper_user_data_dir(&config.scraper_engine));
        Some(Self {
            chrome_binary,
            headless: config.scraper_headless,
            user_agent: config.user_agent.clone(),
            timeout: config.page_load_timeout,
            user_data_dir,
        })
    }
}

pub async fn fetch_dom(url: &Url, config: &ChromeFetchConfig) -> Result<ChromeFetchResult> {
    let timeout = if config.timeout.is_zero() {
        Duration::from_secs(15)
    } else {
        config.timeout
    };
    let _permit = CHROME_FETCH_SEMAPHORE
        .acquire()
        .await
        .map_err(|_| anyhow!("chrome fetch semaphore closed"))?;
    let manager = ChromeManager::global();
    let instance = manager.get_or_launch(config).await?;
    match instance.fetch_dom(url, timeout).await {
        Ok(result) => Ok(result),
        Err(err) => {
            if manager.reset_if_unhealthy(&instance).await {
                if let Ok(next_instance) = manager.get_or_launch(config).await {
                    if let Ok(result) = next_instance.fetch_dom(url, timeout).await {
                        return Ok(result);
                    }
                }
            }
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
    let session = BrowserSession::spawn(command, BrowserSessionOptions::without_lock())
        .await
        .map_err(|err| anyhow!("chrome launch failed: {err}"))?;
    let watchdog_handle =
        resolve_watchdog_handle(&session, &format!("chrome_dump_dom_{}", session.pid()));
    let output = session.wait_for_output(timeout).await;
    if let Some(handle) = watchdog_handle {
        handle.end();
    }
    let output = output.map_err(|err| anyhow!("chrome dump-dom failed: {err}"))?;
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
    let port = listener.local_addr().context("resolve free port")?.port();
    Ok(port)
}

async fn probe_cdp(port: u16) -> bool {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_millis(CHROME_HEALTH_CHECK_TIMEOUT_MS))
        .build()
    {
        Ok(client) => client,
        Err(_) => return false,
    };
    let endpoint = format!("http://127.0.0.1:{port}/json/version");
    match client.get(endpoint).send().await {
        Ok(resp) => resp.status().is_success(),
        Err(_) => false,
    }
}

async fn wait_for_cdp_ready(port: u16, timeout: Duration) -> Result<()> {
    let start = Instant::now();
    loop {
        if probe_cdp(port).await {
            return Ok(());
        }
        if start.elapsed() >= timeout {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(anyhow!(
        "devtools endpoint not available within {timeout:?}"
    ))
}

fn resolve_chrome_fetch_concurrency() -> usize {
    let value = env::var("DOCDEX_WEB_MAX_CONCURRENT_BROWSER_FETCHES")
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(1);
    NonZeroUsize::new(value)
        .map(|value| value.get())
        .unwrap_or(1)
}

async fn create_cdp_target(port: u16, timeout: Duration) -> Result<CdpTarget> {
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .build()
        .context("build devtools client")?;
    let endpoint_new = format!("http://127.0.0.1:{port}/json/new");
    let endpoint_list = format!("http://127.0.0.1:{port}/json/list");
    let start = Instant::now();
    let mut last_err: Option<anyhow::Error> = None;
    loop {
        match fetch_devtools_target(&client, &endpoint_new).await {
            Ok(Some(target)) => return Ok(target),
            Ok(None) => {}
            Err(err) => last_err = Some(err),
        }
        match fetch_devtools_target(&client, &endpoint_list).await {
            Ok(Some(target)) => return Ok(target),
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

async fn fetch_devtools_target(
    client: &reqwest::Client,
    endpoint: &str,
) -> Result<Option<CdpTarget>> {
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
    Ok(extract_cdp_target(&value))
}

async fn close_cdp_target(port: u16, target_id: &str) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(CHROME_HEALTH_CHECK_TIMEOUT_MS))
        .build()
        .context("build devtools client")?;
    let endpoint = format!("http://127.0.0.1:{port}/json/close/{target_id}");
    let resp = client
        .get(&endpoint)
        .send()
        .await
        .with_context(|| format!("close devtools target {target_id}"))?;
    if !resp.status().is_success() {
        return Err(anyhow!(
            "devtools close target {target_id} failed with status {}",
            resp.status()
        ));
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct CdpTarget {
    ws_url: String,
    target_id: Option<String>,
}

fn extract_cdp_target(value: &Value) -> Option<CdpTarget> {
    if let Some(ws_url) = value.get("webSocketDebuggerUrl").and_then(Value::as_str) {
        let target_id = value
            .get("id")
            .and_then(Value::as_str)
            .map(|value| value.to_string());
        return Some(CdpTarget {
            ws_url: ws_url.to_string(),
            target_id,
        });
    }
    if let Some(items) = value.as_array() {
        for item in items {
            if let Some(ws_url) = item.get("webSocketDebuggerUrl").and_then(Value::as_str) {
                let target_id = item
                    .get("id")
                    .and_then(Value::as_str)
                    .map(|value| value.to_string());
                return Some(CdpTarget {
                    ws_url: ws_url.to_string(),
                    target_id,
                });
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
    ) -> Result<bool> {
        let idle_delay = Duration::from_millis(800);
        let start = Instant::now();
        loop {
            let elapsed = start.elapsed();
            if elapsed >= timeout {
                return Ok(false);
            }
            let idle_ready = tracker.inflight == 0
                && tracker.last_activity.elapsed() >= idle_delay
                && (tracker.saw_load || elapsed >= idle_delay);
            if idle_ready {
                return Ok(true);
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
    let deadline = Instant::now() + timeout;
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
    let idle_timeout = remaining(deadline).min(Duration::from_millis(CHROME_NETWORK_IDLE_MAX_MS));
    let _ = client
        .wait_for_network_idle(&mut tracker, idle_timeout)
        .await?;
    let dismissed = dismiss_cookie_banners(&mut client).await.unwrap_or(false);
    if dismissed {
        let follow_up =
            remaining(deadline).min(Duration::from_millis(CHROME_COOKIE_DISMISS_TIMEOUT_MS));
        if !follow_up.is_zero() {
            let _ = client
                .wait_for_network_idle(&mut tracker, follow_up)
                .await?;
        }
    }

    let mut html = String::new();
    let mut final_url = tracker.document_url.clone();
    let min_text_len = 80usize;
    let poll_interval = Duration::from_millis(200);
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
        if remaining(deadline).is_zero() {
            break;
        }
        let sleep_for = poll_interval.min(remaining(deadline));
        if sleep_for.is_zero() {
            break;
        }
        tokio::time::sleep(sleep_for).await;
    }
    if html.trim().is_empty() {
        return Err(anyhow!("devtools returned empty HTML"));
    }
    let inner_text =
        capture_dom_text(&mut client, remaining(deadline), poll_interval, true).await?;
    let text_content =
        capture_dom_text(&mut client, remaining(deadline), poll_interval, false).await?;
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

async fn dismiss_cookie_banners(client: &mut CdpClient) -> Result<bool> {
    let eval = client
        .call(
            "Runtime.evaluate",
            json!({
                "expression": COOKIE_DISMISS_SCRIPT,
                "returnByValue": true,
            }),
            None,
        )
        .await?;
    Ok(eval
        .get("result")
        .and_then(|value| value.get("value"))
        .and_then(Value::as_bool)
        .unwrap_or(false))
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
