use anyhow::{anyhow, Context, Result};
use fs4::FileExt;
use futures::{SinkExt, StreamExt};
use once_cell::sync::{Lazy, OnceCell};
use serde_json::{json, Value};
use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::{self, File, OpenOptions};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener as TokioTcpListener, TcpStream};
use tokio::process::Command;
use tokio::sync::Mutex;
use tokio::sync::Semaphore;
use tokio::task::{JoinHandle, JoinSet};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;
use tracing::warn;
use url::Url;

use crate::browser_session::{BrowserSession, BrowserSessionOptions};
use crate::orchestrator::web_config::{default_scraper_user_data_dir, WebConfig};
use crate::state_layout::ensure_state_dir_secure;
use crate::util;
use crate::web::policy::{
    parse_outbound_url, resolve_public_addresses, validate_outbound_url, OutboundUrlError,
};
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
    pub allow_no_sandbox: bool,
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
    allow_no_sandbox: bool,
    pinned_host: Option<String>,
    pinned_address: IpAddr,
    allowed_ports: Vec<u16>,
}

impl ChromeSessionConfig {
    fn from_fetch_config(config: &ChromeFetchConfig, url: &Url, pinned_address: IpAddr) -> Self {
        Self {
            chrome_binary: config.chrome_binary.clone(),
            headless: config.headless,
            user_agent: config.user_agent.clone(),
            user_data_dir: config.user_data_dir.clone(),
            allow_no_sandbox: config.allow_no_sandbox,
            pinned_host: normalized_url_host(url),
            pinned_address,
            allowed_ports: browser_allowed_ports(url),
        }
    }

    fn host_resolver_rule(&self) -> Option<String> {
        let host = self.pinned_host.as_deref()?;
        if host.parse::<IpAddr>().is_ok() {
            return None;
        }
        let address = match self.pinned_address {
            IpAddr::V4(address) => address.to_string(),
            IpAddr::V6(address) => format!("[{address}]"),
        };
        Some(format!("MAP {host} {address}"))
    }
}

struct ChromeInstance {
    session: BrowserSession,
    debug_port: u16,
    browser_ws_url: String,
    root_target: CdpTarget,
    browser_target_monitor: BrowserTargetMonitor,
    egress_proxy: Option<BrowserEgressProxy>,
    config: ChromeSessionConfig,
    _user_data_dir: UserDataDir,
    watchdog_handle: Option<ChromeSessionHandle>,
}

struct BrowserFetchGuard {
    session: BrowserSession,
    armed: bool,
    expected_shutdown: Option<Arc<AtomicBool>>,
}

impl BrowserFetchGuard {
    fn new(session: BrowserSession) -> Self {
        Self {
            session,
            armed: true,
            expected_shutdown: None,
        }
    }

    fn for_fetch(session: BrowserSession, expected_shutdown: Arc<AtomicBool>) -> Self {
        Self {
            session,
            armed: true,
            expected_shutdown: Some(expected_shutdown),
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for BrowserFetchGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Some(expected_shutdown) = &self.expected_shutdown {
            expected_shutdown.store(true, Ordering::Release);
        }
        self.session.terminate_tree_now();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            let session = self.session.clone();
            runtime.spawn(async move {
                let _ = session.abort().await;
            });
        }
    }
}

impl ChromeInstance {
    async fn spawn(
        fetch_config: &ChromeFetchConfig,
        session_config: ChromeSessionConfig,
    ) -> Result<Self> {
        let mut command = Command::new(&fetch_config.chrome_binary);
        let user_data_dir = UserDataDir::new(fetch_config)?;
        user_data_dir.clear_devtools_port();
        let egress_proxy = BrowserEgressProxy::start(&session_config).await?;
        let mut args = chrome_common_args(fetch_config, user_data_dir.path());
        if let Some(rule) = session_config.host_resolver_rule() {
            args.push(format!("--host-resolver-rules={rule}"));
        }
        args.push("--remote-debugging-address=127.0.0.1".to_string());
        args.push("--remote-debugging-port=0".to_string());
        args.push(format!(
            "--proxy-server=socks5://127.0.0.1:{}",
            egress_proxy.port()
        ));
        args.push("--proxy-bypass-list=<-loopback>".to_string());
        command.args(args);
        command.arg("about:blank");
        command.stdout(Stdio::null());
        command.stderr(Stdio::null());

        let session = BrowserSession::spawn(command, BrowserSessionOptions::default())
            .await
            .map_err(|err| anyhow!("chrome launch failed: {err}"))?;
        let endpoint = match wait_for_cdp_ready(
            &session,
            user_data_dir.path(),
            Duration::from_millis(CHROME_STARTUP_TIMEOUT_MS),
        )
        .await
        {
            Ok(endpoint) => endpoint,
            Err(err) => {
                let _ = session.abort().await;
                return Err(err.context("chrome devtools did not become ready"));
            }
        };
        let root_target = match prepare_initial_cdp_target(
            endpoint.port,
            Duration::from_millis(CHROME_HEALTH_CHECK_TIMEOUT_MS),
        )
        .await
        {
            Ok(target) => target,
            Err(err) => {
                let _ = session.abort().await;
                return Err(err.context("prepare root browser target"));
            }
        };
        let browser_target_monitor = match BrowserTargetMonitor::start(
            &endpoint.browser_ws_url,
            root_target.target_id.clone(),
            session.clone(),
        )
        .await
        {
            Ok(monitor) => monitor,
            Err(err) => {
                let _ = session.abort().await;
                return Err(err.context("configure browser-wide DevTools security"));
            }
        };
        let watchdog_handle = resolve_watchdog_handle(&session, "chrome_persistent");

        Ok(Self {
            session,
            debug_port: endpoint.port,
            browser_ws_url: endpoint.browser_ws_url,
            root_target,
            browser_target_monitor,
            egress_proxy: Some(egress_proxy),
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
        if self
            .egress_proxy
            .as_ref()
            .is_some_and(|proxy| !proxy.is_healthy())
        {
            return false;
        }
        if !self.browser_target_monitor.is_healthy() {
            return false;
        }
        probe_cdp(self.debug_port, &self.browser_ws_url).await
    }

    async fn fetch_dom(&self, url: &Url, timeout: Duration) -> Result<ChromeFetchResult> {
        if let Some(handle) = &self.watchdog_handle {
            handle.heartbeat();
        }
        if !self.browser_target_monitor.is_healthy() {
            return Err(anyhow!("browser target security monitor is unavailable"));
        }
        let mut cancellation_guard = BrowserFetchGuard::for_fetch(
            self.session.clone(),
            self.browser_target_monitor.expected_shutdown_signal(),
        );
        let deadline = Instant::now() + timeout;
        let result = fetch_dom_via_cdp(&self.root_target.ws_url, url, remaining(deadline)).await;
        if result.is_ok() {
            cancellation_guard.disarm();
        }
        if let Some(handle) = &self.watchdog_handle {
            handle.heartbeat();
        }
        result
    }

    async fn shutdown(&self) -> Result<()> {
        if let Some(handle) = &self.watchdog_handle {
            handle.end();
        }
        self.browser_target_monitor.abort();
        self.session
            .abort()
            .await
            .map_err(|err| anyhow!("chrome shutdown failed: {err}"))
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

    async fn get_or_launch(
        &self,
        config: &ChromeFetchConfig,
        url: &Url,
        pinned_address: IpAddr,
    ) -> Result<Arc<ChromeInstance>> {
        let session_config = ChromeSessionConfig::from_fetch_config(config, url, pinned_address);
        let mut state = self.state.lock().await;
        if let Some(instance) = state.instance.as_ref() {
            if instance.matches(&session_config) && instance.is_healthy().await {
                return Ok(instance.clone());
            }
        }

        if let Some(old_instance) = state.instance.take() {
            if let Err(err) = old_instance.shutdown().await {
                warn!(target: "docdexd", error = ?err, "failed to shut down replaced Chromium instance");
            }
        }
        let instance = Arc::new(ChromeInstance::spawn(config, session_config).await?);
        state.instance = Some(instance.clone());
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
            if let Err(err) = instance.shutdown().await {
                warn!(target: "docdexd", error = ?err, "failed to shut down reset Chromium instance");
            }
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

    async fn shutdown(&self) -> Result<()> {
        let instance = {
            let mut state = self.state.lock().await;
            state.instance.take()
        };
        if let Some(instance) = instance {
            instance.shutdown().await?;
        }
        Ok(())
    }
}

static CHROME_MANAGER: OnceCell<Arc<ChromeManager>> = OnceCell::new();
static NO_SANDBOX_WARNING: OnceCell<()> = OnceCell::new();
// A DNS-pinned Chromium instance is host-specific. Serialize fetches so a
// host switch cannot tear down an instance that is still serving another URL.
static CHROME_FETCH_SEMAPHORE: Lazy<Semaphore> = Lazy::new(|| Semaphore::new(1));

const CHROME_THINK_DELAY_MIN_MS: u64 = 150;
const CHROME_THINK_DELAY_MAX_MS: u64 = 650;
const CHROME_WINDOW_SIZE: &str = "1920,1080";
const CHROME_HEALTH_CHECK_TIMEOUT_MS: u64 = 800;
const CHROME_STARTUP_TIMEOUT_MS: u64 = 10_000;
const DEVTOOLS_RESPONSE_MAX_BYTES: usize = 64 * 1024;
const DEVTOOLS_ACTIVE_PORT_MAX_BYTES: u64 = 4 * 1024;
const CHROME_NETWORK_IDLE_MAX_MS: u64 = 6_000;
const CHROME_MAX_HTML_CHARS_DEFAULT: usize = 1_500_000;
const CHROME_MAX_TEXT_CHARS_DEFAULT: usize = 500_000;
const CHROME_MAX_CAPTURE_MULTIPLIER: usize = 4;
const CHROME_MAX_TRANSFER_BYTES_DEFAULT: u64 = 64 * 1024 * 1024;
const CHROME_MAX_REQUEST_BYTES_PER_TUNNEL: u64 = 8 * 1024 * 1024;
const CHROME_PROXY_MAX_CONNECTIONS: usize = 32;
const CHROME_PROXY_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const CHROME_PROFILE_LOCK_FILE: &str = ".docdex-profile.lock";
const COOKIE_DISMISS_SCRIPT: &str = r##"(function () {
  // Never click untrusted page controls. Suppress only elements that identify
  // themselves as consent overlays, keeping browser scraping observational.
  const selectors = [
    "#onetrust-consent-sdk",
    "#CybotCookiebotDialog",
    "#CybotCookiebotDialogBodyUnderlay",
    ".qc-cmp2-container",
    "[role='dialog'][id*='cookie' i]",
    "[role='dialog'][class*='cookie' i]",
    "[role='dialog'][id*='consent' i]",
    "[role='dialog'][class*='consent' i]",
    "[aria-modal='true'][aria-label*='cookie' i]",
    "[aria-modal='true'][aria-label*='consent' i]",
    "[role='dialog'][data-testid*='cookie' i]",
    "[role='dialog'][data-testid*='consent' i]",
  ];
  let removed = false;
  for (const selector of selectors) {
    document.querySelectorAll(selector).forEach((el) => {
      el.remove();
      removed = true;
    });
  }
  return removed;
})()"##;
const WEBDRIVER_OVERRIDE_SCRIPT: &str =
    "Object.defineProperty(navigator, 'webdriver', { get: () => undefined });";

struct BrowserEgressProxy {
    port: u16,
    remaining_transfer_bytes: Arc<AtomicU64>,
    task: JoinHandle<()>,
}

impl BrowserEgressProxy {
    async fn start(config: &ChromeSessionConfig) -> Result<Self> {
        let allowed_host = config
            .pinned_host
            .clone()
            .ok_or(OutboundUrlError::MissingHost)?;
        let listener = TokioTcpListener::bind(("127.0.0.1", 0))
            .await
            .context("bind Chromium egress proxy")?;
        let port = listener
            .local_addr()
            .context("resolve Chromium egress proxy address")?
            .port();
        let remaining_transfer_bytes = Arc::new(AtomicU64::new(resolve_chrome_transfer_limit()));
        let policy = Arc::new(BrowserProxyPolicy {
            allowed_host,
            pinned_address: config.pinned_address,
            allowed_ports: config.allowed_ports.clone(),
            remaining_transfer_bytes: Arc::clone(&remaining_transfer_bytes),
        });
        let task = tokio::spawn(run_browser_proxy(listener, policy));
        Ok(Self {
            port,
            remaining_transfer_bytes,
            task,
        })
    }

    fn port(&self) -> u16 {
        self.port
    }

    fn is_healthy(&self) -> bool {
        !self.task.is_finished() && self.remaining_transfer_bytes.load(Ordering::Acquire) > 0
    }
}

impl Drop for BrowserEgressProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct BrowserProxyPolicy {
    allowed_host: String,
    pinned_address: IpAddr,
    allowed_ports: Vec<u16>,
    remaining_transfer_bytes: Arc<AtomicU64>,
}

async fn run_browser_proxy(listener: TokioTcpListener, policy: Arc<BrowserProxyPolicy>) {
    let connection_limit = Arc::new(Semaphore::new(CHROME_PROXY_MAX_CONNECTIONS));
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else {
                    break;
                };
                let Ok(permit) = Arc::clone(&connection_limit).try_acquire_owned() else {
                    drop(stream);
                    continue;
                };
                let policy = Arc::clone(&policy);
                connections.spawn(async move {
                    let _permit = permit;
                    if let Err(err) = handle_browser_proxy_connection(stream, policy).await {
                        tracing::debug!(target: "docdexd", error = %err, "Chromium egress proxy rejected connection");
                    }
                });
            }
            completed = connections.join_next(), if !connections.is_empty() => {
                let _ = completed;
            }
        }
    }
}

async fn handle_browser_proxy_connection(
    mut client: TcpStream,
    policy: Arc<BrowserProxyPolicy>,
) -> Result<()> {
    let (requested_host, requested_port) =
        negotiate_browser_proxy(&mut client, CHROME_PROXY_CONNECT_TIMEOUT).await?;
    let requested_host = requested_host.trim_end_matches('.').to_ascii_lowercase();
    if requested_host != policy.allowed_host
        || !policy.allowed_ports.contains(&requested_port)
        || requested_port == 0
    {
        write_socks_failure(&mut client, 2).await;
        return Err(anyhow!(
            "SOCKS destination is outside the pinned browser policy"
        ));
    }

    let upstream_address = std::net::SocketAddr::new(policy.pinned_address, requested_port);
    let mut upstream = match tokio::time::timeout(
        CHROME_PROXY_CONNECT_TIMEOUT,
        TcpStream::connect(upstream_address),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => {
            write_socks_failure(&mut client, 5).await;
            return Err(err).context("connect pinned Chromium destination");
        }
        Err(_) => {
            write_socks_failure(&mut client, 4).await;
            return Err(anyhow!("pinned Chromium destination connection timed out"));
        }
    };
    client
        .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .context("write SOCKS success response")?;
    relay_browser_tunnel(&mut client, &mut upstream, &policy.remaining_transfer_bytes).await
}

async fn negotiate_browser_proxy(
    client: &mut TcpStream,
    timeout: Duration,
) -> Result<(String, u16)> {
    tokio::time::timeout(timeout, read_browser_proxy_request(client))
        .await
        .context("SOCKS handshake timeout")?
}

async fn read_browser_proxy_request(client: &mut TcpStream) -> Result<(String, u16)> {
    let mut greeting = [0u8; 2];
    client
        .read_exact(&mut greeting)
        .await
        .context("read SOCKS greeting")?;
    if greeting[0] != 5 || greeting[1] == 0 || greeting[1] > 32 {
        return Err(anyhow!("unsupported SOCKS greeting"));
    }
    let mut methods = vec![0u8; greeting[1] as usize];
    client
        .read_exact(&mut methods)
        .await
        .context("read SOCKS authentication methods")?;
    if !methods.contains(&0) {
        client.write_all(&[5, 0xff]).await.ok();
        return Err(anyhow!("SOCKS client did not offer no-authentication mode"));
    }
    client
        .write_all(&[5, 0])
        .await
        .context("write SOCKS greeting response")?;

    let mut request = [0u8; 4];
    client
        .read_exact(&mut request)
        .await
        .context("read SOCKS request")?;
    if request[0] != 5 || request[1] != 1 || request[2] != 0 {
        write_socks_failure(client, 7).await;
        return Err(anyhow!("unsupported SOCKS command"));
    }
    let requested_host = read_socks_host(client, request[3]).await?;
    let mut port_bytes = [0u8; 2];
    client
        .read_exact(&mut port_bytes)
        .await
        .context("read SOCKS destination port")?;
    let requested_port = u16::from_be_bytes(port_bytes);
    Ok((requested_host, requested_port))
}

async fn read_socks_host(client: &mut TcpStream, address_type: u8) -> Result<String> {
    match address_type {
        1 => {
            let mut bytes = [0u8; 4];
            client
                .read_exact(&mut bytes)
                .await
                .context("read SOCKS IPv4 address")?;
            Ok(std::net::Ipv4Addr::from(bytes).to_string())
        }
        3 => {
            let length = client.read_u8().await.context("read SOCKS host length")? as usize;
            if length == 0 {
                return Err(anyhow!("SOCKS destination host is empty"));
            }
            let mut bytes = vec![0u8; length];
            client
                .read_exact(&mut bytes)
                .await
                .context("read SOCKS destination host")?;
            String::from_utf8(bytes).context("SOCKS destination host is not UTF-8")
        }
        4 => {
            let mut bytes = [0u8; 16];
            client
                .read_exact(&mut bytes)
                .await
                .context("read SOCKS IPv6 address")?;
            Ok(std::net::Ipv6Addr::from(bytes).to_string())
        }
        _ => Err(anyhow!("unsupported SOCKS address type")),
    }
}

async fn write_socks_failure(client: &mut TcpStream, code: u8) {
    let _ = client.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0]).await;
}

async fn relay_browser_tunnel(
    client: &mut TcpStream,
    upstream: &mut TcpStream,
    transfer_budget: &AtomicU64,
) -> Result<()> {
    let (mut client_reader, mut client_writer) = client.split();
    let (mut upstream_reader, mut upstream_writer) = upstream.split();
    let request_to_upstream = async {
        let mut copied = 0u64;
        let mut buffer = [0u8; 16 * 1024];
        loop {
            let read = client_reader
                .read(&mut buffer)
                .await
                .context("read Chromium proxy request")?;
            if read == 0 {
                return Result::<()>::Ok(());
            }
            let tunnel_remaining = CHROME_MAX_REQUEST_BYTES_PER_TUNNEL.saturating_sub(copied);
            let tunnel_allowed = tunnel_remaining.min(read as u64);
            let allowed = reserve_transfer_bytes(transfer_budget, tunnel_allowed) as usize;
            if allowed > 0 {
                upstream_writer
                    .write_all(&buffer[..allowed])
                    .await
                    .context("relay Chromium proxy request")?;
                copied = copied.saturating_add(allowed as u64);
            }
            if allowed < read {
                if tunnel_allowed < read as u64 {
                    return Err(anyhow!("Chromium proxy request exceeded its byte limit"));
                }
                return Err(anyhow!("Chromium transfer budget exhausted"));
            }
        }
    };
    let response_to_client = async {
        let mut buffer = [0u8; 16 * 1024];
        loop {
            let read = upstream_reader
                .read(&mut buffer)
                .await
                .context("read Chromium proxy response")?;
            if read == 0 {
                return Result::<()>::Ok(());
            }
            let allowed = reserve_transfer_bytes(transfer_budget, read as u64) as usize;
            if allowed > 0 {
                client_writer
                    .write_all(&buffer[..allowed])
                    .await
                    .context("write Chromium proxy response")?;
            }
            if allowed < read {
                return Err(anyhow!("Chromium transfer budget exhausted"));
            }
        }
    };
    tokio::select! {
        result = request_to_upstream => result,
        result = response_to_client => result,
    }
}

fn reserve_transfer_bytes(remaining: &AtomicU64, requested: u64) -> u64 {
    let mut current = remaining.load(Ordering::Acquire);
    loop {
        let granted = current.min(requested);
        match remaining.compare_exchange_weak(
            current,
            current.saturating_sub(granted),
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return granted,
            Err(updated) => current = updated,
        }
    }
}

fn browser_allowed_ports(url: &Url) -> Vec<u16> {
    let mut ports = vec![80, 443];
    if let Some(port) = url.port_or_known_default() {
        ports.push(port);
    }
    ports.sort_unstable();
    ports.dedup();
    ports
}

fn resolve_chrome_transfer_limit() -> u64 {
    env::var("DOCDEX_WEB_CHROME_MAX_TRANSFER_BYTES")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(CHROME_MAX_TRANSFER_BYTES_DEFAULT)
        .clamp(1024 * 1024, 1024 * 1024 * 1024)
}

enum UserDataDir {
    Temp(TempDir),
    Persistent { path: PathBuf, _lock: File },
}

impl UserDataDir {
    fn new(config: &ChromeFetchConfig) -> Result<Self> {
        if let Some(path) = config.user_data_dir.as_ref() {
            ensure_state_dir_secure(path)
                .with_context(|| format!("ensure chrome user data dir {}", path.display()))?;
            let lock_path = path.join(CHROME_PROFILE_LOCK_FILE);
            let lock = OpenOptions::new()
                .create(true)
                .read(true)
                .write(true)
                .open(&lock_path)
                .with_context(|| format!("open chrome profile lock {}", lock_path.display()))?;
            if lock.try_lock_exclusive().is_err() {
                warn!(
                    target: "docdexd",
                    profile = %path.display(),
                    "Chromium profile is already reserved by another Docdex process; using an isolated temporary profile"
                );
                return Self::temporary();
            }
            match chromium_profile_ownership(path) {
                ChromiumProfileOwnership::Free => {}
                ChromiumProfileOwnership::ActiveOrUnknown => {
                    warn!(
                        target: "docdexd",
                        profile = %path.display(),
                        "Chromium profile is already owned by a browser; using an isolated temporary profile"
                    );
                    return Self::temporary();
                }
                ChromiumProfileOwnership::Stale => {
                    warn!(
                        target: "docdexd",
                        profile = %path.display(),
                        "Chromium profile has stale ownership markers; using an isolated temporary profile"
                    );
                    return Self::temporary();
                }
            }
            return Ok(UserDataDir::Persistent {
                path: path.clone(),
                _lock: lock,
            });
        }
        Self::temporary()
    }

    fn temporary() -> Result<Self> {
        Ok(UserDataDir::Temp(
            TempDir::new().context("create chrome user data directory")?,
        ))
    }

    fn path(&self) -> &Path {
        match self {
            UserDataDir::Temp(dir) => dir.path(),
            UserDataDir::Persistent { path, .. } => path.as_path(),
        }
    }

    fn clear_devtools_port(&self) {
        let port_file = self.path().join("DevToolsActivePort");
        let _ = fs::remove_file(port_file);
    }
}

enum ChromiumProfileOwnership {
    Free,
    ActiveOrUnknown,
    Stale,
}

fn chromium_profile_ownership(path: &Path) -> ChromiumProfileOwnership {
    let lock_path = path.join("SingletonLock");
    let metadata = match fs::symlink_metadata(&lock_path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return ChromiumProfileOwnership::Free;
        }
        Err(_) => return ChromiumProfileOwnership::ActiveOrUnknown,
    };
    if !metadata.file_type().is_symlink() {
        return ChromiumProfileOwnership::ActiveOrUnknown;
    }
    #[cfg(unix)]
    {
        let Ok(lock_target) = fs::read_link(&lock_path) else {
            return ChromiumProfileOwnership::ActiveOrUnknown;
        };
        let Some(pid) = lock_target
            .to_str()
            .and_then(|target| target.rsplit_once('-'))
            .and_then(|(_, pid)| pid.parse::<i32>().ok())
            .filter(|pid| *pid > 0)
        else {
            return ChromiumProfileOwnership::ActiveOrUnknown;
        };
        if unix_process_is_alive(pid) {
            ChromiumProfileOwnership::ActiveOrUnknown
        } else {
            ChromiumProfileOwnership::Stale
        }
    }
    #[cfg(not(unix))]
    {
        ChromiumProfileOwnership::ActiveOrUnknown
    }
}

#[cfg(unix)]
fn unix_process_is_alive(pid: i32) -> bool {
    if unsafe { nix::libc::kill(pid, 0) } == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() != Some(nix::libc::ESRCH)
}

fn resolve_watchdog_handle(
    session: &BrowserSession,
    session_id: &str,
) -> Option<ChromeSessionHandle> {
    let tracker = global_tracker().or_else(init_global_from_env)?;
    Some(tracker.register_browser_session(
        session_id.to_string(),
        tracked_process(session),
        session.clone(),
    ))
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
    args.push("--disable-background-networking".to_string());
    args.push("--dns-prefetch-disable".to_string());
    args.push("--disable-component-update".to_string());
    args.push("--disable-domain-reliability".to_string());
    args.push("--disable-sync".to_string());
    args.push("--disable-blink-features=AutomationControlled".to_string());
    if config.allow_no_sandbox {
        warn_no_sandbox_once();
        args.push("--no-sandbox".to_string());
    }
    args.push("--no-first-run".to_string());
    args.push("--no-default-browser-check".to_string());
    args.push("--disable-quic".to_string());
    args.push("--force-webrtc-ip-handling-policy=disable_non_proxied_udp".to_string());
    args.push(
        "--disable-features=NetworkPrediction,PreconnectToSearch,Prerender2,SpeculationRulesPrefetchProxy"
            .to_string(),
    );
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
            allow_no_sandbox: resolve_allow_no_sandbox(),
        })
    }
}

pub async fn fetch_dom(url: &Url, config: &ChromeFetchConfig) -> Result<ChromeFetchResult> {
    let addresses = resolve_public_addresses(url).await?;
    let pinned_address = addresses
        .iter()
        .filter(|address| address.is_ipv4())
        .min()
        .or_else(|| addresses.iter().min())
        .copied()
        .ok_or(OutboundUrlError::DnsResolutionFailed)?;
    let timeout = if config.timeout.is_zero() {
        Duration::from_secs(15)
    } else {
        config.timeout
    };
    let deadline = Instant::now() + timeout;
    let _permit = tokio::time::timeout(remaining(deadline), CHROME_FETCH_SEMAPHORE.acquire())
        .await
        .map_err(|_| anyhow!("chrome fetch queue timed out after {timeout:?}"))?
        .map_err(|_| anyhow!("chrome fetch semaphore closed"))?;
    let manager = ChromeManager::global();
    let instance = tokio::time::timeout(
        remaining(deadline),
        manager.get_or_launch(config, url, pinned_address),
    )
    .await
    .map_err(|_| anyhow!("chrome startup timed out after {timeout:?}"))??;
    let fetch_timeout = remaining(deadline);
    if fetch_timeout.is_zero() {
        return Err(anyhow!("chrome fetch deadline elapsed before navigation"));
    }
    match instance.fetch_dom(url, fetch_timeout).await {
        Ok(result) => validate_fetch_result(result).await,
        Err(err) => {
            if err.chain().any(|cause| cause.is::<OutboundUrlError>()) {
                return Err(err);
            }
            if manager.reset_if_unhealthy(&instance).await {
                let retry_budget = remaining(deadline);
                if !retry_budget.is_zero() {
                    if let Ok(Ok(next_instance)) = tokio::time::timeout(
                        retry_budget,
                        manager.get_or_launch(config, url, pinned_address),
                    )
                    .await
                    {
                        let retry_timeout = remaining(deadline);
                        if retry_timeout.is_zero() {
                            return Err(anyhow!("chrome fetch deadline elapsed before retry"));
                        }
                        match next_instance.fetch_dom(url, retry_timeout).await {
                            Ok(result) => return validate_fetch_result(result).await,
                            Err(retry_err)
                                if retry_err
                                    .chain()
                                    .any(|cause| cause.is::<OutboundUrlError>()) =>
                            {
                                return Err(retry_err);
                            }
                            Err(_) => {}
                        }
                    }
                }
            }
            Err(anyhow!("chrome fetch failed: {err}"))
        }
    }
}

/// Shut down the process-owned persistent Chromium instance.
///
/// Daemons intentionally keep the instance for reuse; short-lived CLI paths must
/// call this before their Tokio runtime exits because Rust does not drop statics.
pub async fn shutdown_global() -> Result<()> {
    if let Some(manager) = CHROME_MANAGER.get() {
        manager.shutdown().await?;
    }
    Ok(())
}

async fn validate_fetch_result(result: ChromeFetchResult) -> Result<ChromeFetchResult> {
    if let Some(final_url) = result.final_url.as_deref() {
        let parsed = Url::parse(final_url).map_err(|_| OutboundUrlError::InvalidUrl)?;
        validate_outbound_url(&parsed).await?;
    }
    Ok(result)
}

fn remaining(deadline: Instant) -> Duration {
    deadline
        .checked_duration_since(Instant::now())
        .unwrap_or_else(|| Duration::from_millis(0))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DevToolsEndpoint {
    port: u16,
    browser_ws_url: String,
}

async fn probe_cdp(port: u16, expected_browser_ws_url: &str) -> bool {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_millis(CHROME_HEALTH_CHECK_TIMEOUT_MS))
        .no_proxy()
        .build()
    {
        Ok(client) => client,
        Err(_) => return false,
    };
    let endpoint = format!("http://127.0.0.1:{port}/json/version");
    let Ok(resp) = client.get(endpoint).send().await else {
        return false;
    };
    if !resp.status().is_success() {
        return false;
    }
    let Ok(body) = read_async_response_limited(resp, DEVTOOLS_RESPONSE_MAX_BYTES).await else {
        return false;
    };
    let Ok(value) = serde_json::from_slice::<Value>(&body) else {
        return false;
    };
    value
        .get("webSocketDebuggerUrl")
        .and_then(Value::as_str)
        .is_some_and(|ws_url| {
            ws_url == expected_browser_ws_url
                && validate_devtools_ws_url(ws_url, port, "browser").is_ok()
        })
}

async fn wait_for_cdp_ready(
    session: &BrowserSession,
    user_data_dir: &Path,
    timeout: Duration,
) -> Result<DevToolsEndpoint> {
    let active_port_path = user_data_dir.join("DevToolsActivePort");
    let start = Instant::now();
    loop {
        if !session.is_alive() {
            return Err(anyhow!("Chromium exited before DevTools became ready"));
        }
        if let Ok(metadata) = fs::metadata(&active_port_path) {
            if metadata.len() > DEVTOOLS_ACTIVE_PORT_MAX_BYTES {
                return Err(anyhow!("DevToolsActivePort exceeds size limit"));
            }
            if let Ok(raw) = fs::read_to_string(&active_port_path) {
                if let Ok(endpoint) = parse_devtools_active_port(&raw) {
                    if probe_cdp(endpoint.port, &endpoint.browser_ws_url).await {
                        return Ok(endpoint);
                    }
                }
            }
        }
        if start.elapsed() >= timeout {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Err(anyhow!(
        "owned Chromium DevTools endpoint not available within {timeout:?}"
    ))
}

fn parse_devtools_active_port(raw: &str) -> Result<DevToolsEndpoint> {
    if raw.len() as u64 > DEVTOOLS_ACTIVE_PORT_MAX_BYTES {
        return Err(anyhow!("DevToolsActivePort exceeds size limit"));
    }
    let mut lines = raw.lines();
    let port = lines
        .next()
        .ok_or_else(|| anyhow!("DevToolsActivePort is missing its port"))?
        .trim()
        .parse::<u16>()
        .context("parse DevToolsActivePort port")?;
    if port == 0 {
        return Err(anyhow!("DevToolsActivePort contains port zero"));
    }
    let browser_path = lines
        .next()
        .ok_or_else(|| anyhow!("DevToolsActivePort is missing its browser path"))?
        .trim();
    if !browser_path.starts_with("/devtools/browser/")
        || browser_path.contains(['?', '#', '\\'])
        || browser_path.split('/').any(|part| part == "..")
    {
        return Err(anyhow!(
            "DevToolsActivePort contains an invalid browser path"
        ));
    }
    let browser_ws_url = format!("ws://127.0.0.1:{port}{browser_path}");
    validate_devtools_ws_url(&browser_ws_url, port, "browser")?;
    Ok(DevToolsEndpoint {
        port,
        browser_ws_url,
    })
}

fn validate_devtools_ws_url(raw: &str, expected_port: u16, target_kind: &str) -> Result<()> {
    let url = Url::parse(raw).context("parse DevTools websocket URL")?;
    if url.scheme() != "ws"
        || url.host_str() != Some("127.0.0.1")
        || url.port() != Some(expected_port)
        || url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(anyhow!(
            "DevTools websocket URL is not the owned loopback endpoint"
        ));
    }
    let expected_prefix = format!("/devtools/{target_kind}/");
    if !url.path().starts_with(&expected_prefix) || url.path().split('/').any(|part| part == "..") {
        return Err(anyhow!("DevTools websocket URL has an invalid target path"));
    }
    Ok(())
}

async fn read_async_response_limited(response: reqwest::Response, limit: usize) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(anyhow!("DevTools response exceeds {limit} bytes"));
    }
    let mut body = Vec::with_capacity(
        response
            .content_length()
            .unwrap_or_default()
            .min(limit as u64) as usize,
    );
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.context("read DevTools response")?;
        if body.len().saturating_add(chunk.len()) > limit {
            return Err(anyhow!("DevTools response exceeds {limit} bytes"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn resolve_allow_no_sandbox() -> bool {
    env::var("DOCDEX_CHROME_ALLOW_NO_SANDBOX")
        .ok()
        .and_then(|value| parse_boolish(&value))
        .unwrap_or(false)
}

fn warn_no_sandbox_once() {
    if NO_SANDBOX_WARNING.set(()).is_ok() {
        warn!(
            target: "docdexd",
            "Chromium sandbox is explicitly disabled by DOCDEX_CHROME_ALLOW_NO_SANDBOX; this weakens web-content isolation"
        );
    }
}

fn parse_boolish(raw: &str) -> Option<bool> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn resolve_capture_limit(key: &str, fallback: usize) -> usize {
    let configured = env::var(key)
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|value| *value > 0);
    clamp_capture_limit(configured, fallback)
}

fn clamp_capture_limit(configured: Option<usize>, fallback: usize) -> usize {
    configured.unwrap_or(fallback).clamp(
        1_024,
        fallback
            .saturating_mul(CHROME_MAX_CAPTURE_MULTIPLIER)
            .max(1_024),
    )
}

async fn prepare_initial_cdp_target(port: u16, timeout: Duration) -> Result<CdpTarget> {
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .no_proxy()
        .build()
        .context("build devtools client")?;
    let endpoint = format!("http://127.0.0.1:{port}/json/list");
    let resp = client
        .get(&endpoint)
        .send()
        .await
        .with_context(|| format!("fetch devtools endpoint {endpoint}"))?;
    let status = resp.status();
    let body = read_async_response_limited(resp, DEVTOOLS_RESPONSE_MAX_BYTES)
        .await
        .with_context(|| format!("read devtools endpoint {endpoint}"))?;
    if !status.is_success() {
        return Err(anyhow!(
            "devtools endpoint {endpoint} failed with status {status}"
        ));
    }
    let value: Value = serde_json::from_slice(&body)
        .with_context(|| format!("parse devtools endpoint {endpoint}"))?;
    let entries = value
        .as_array()
        .ok_or_else(|| anyhow!("devtools target list is not an array"))?;
    let mut root: Option<CdpTarget> = None;
    let mut close_ids = Vec::new();
    for entry in entries {
        let target_id = entry
            .get("id")
            .and_then(Value::as_str)
            .filter(|value| is_valid_cdp_target_id(value));
        let is_blank_page = entry.get("type").and_then(Value::as_str) == Some("page")
            && entry.get("url").and_then(Value::as_str) == Some("about:blank");
        if is_blank_page {
            let target = extract_cdp_target(entry, port)
                .ok_or_else(|| anyhow!("initial about:blank target is invalid"))?;
            if root.replace(target).is_some() {
                return Err(anyhow!("multiple initial about:blank page targets found"));
            }
        } else {
            let target_id = target_id
                .ok_or_else(|| anyhow!("devtools target list contained an invalid target id"))?;
            close_ids.push(target_id.to_string());
        }
    }
    let root = root.ok_or_else(|| anyhow!("initial about:blank page target is missing"))?;
    for target_id in close_ids {
        close_cdp_target(port, &target_id).await?;
    }
    Ok(root)
}

async fn close_cdp_target(port: u16, target_id: &str) -> Result<()> {
    if !is_valid_cdp_target_id(target_id) {
        return Err(anyhow!("invalid devtools target id"));
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(CHROME_HEALTH_CHECK_TIMEOUT_MS))
        .no_proxy()
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
    target_id: String,
}

fn extract_cdp_target(value: &Value, expected_port: u16) -> Option<CdpTarget> {
    if let Some(ws_url) = value.get("webSocketDebuggerUrl").and_then(Value::as_str) {
        validate_devtools_ws_url(ws_url, expected_port, "page").ok()?;
        let target_id = value
            .get("id")
            .and_then(Value::as_str)
            .filter(|value| is_valid_cdp_target_id(value))?
            .to_string();
        return Some(CdpTarget {
            ws_url: ws_url.to_string(),
            target_id,
        });
    }
    None
}

fn is_valid_cdp_target_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn protected_target_lifecycle_lost(
    protected_target_id: Option<&str>,
    protected_session_id: Option<&str>,
    params: &Value,
) -> bool {
    params
        .get("targetId")
        .and_then(Value::as_str)
        .is_some_and(|target_id| protected_target_id == Some(target_id))
        || params
            .get("sessionId")
            .and_then(Value::as_str)
            .is_some_and(|session_id| protected_session_id == Some(session_id))
}

struct CdpClient {
    ws: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    next_id: u64,
    pending_responses: HashMap<u64, Value>,
    ignored_response_ids: HashSet<u64>,
    pinned_host: Option<String>,
    blocked_document: Option<OutboundUrlError>,
    protected_target_id: Option<String>,
    protected_session_id: Option<String>,
    close_all_auxiliary_targets: bool,
}

struct BrowserTargetMonitor {
    task: JoinHandle<()>,
    expected_shutdown: Arc<AtomicBool>,
}

impl BrowserTargetMonitor {
    async fn start(
        ws_url: &str,
        protected_target_id: String,
        session: BrowserSession,
    ) -> Result<Self> {
        let mut client = CdpClient::connect(ws_url).await?;
        client.protected_target_id = Some(protected_target_id);
        client.close_all_auxiliary_targets = true;
        client
            .call(
                "Browser.setDownloadBehavior",
                json!({ "behavior": "deny", "eventsEnabled": false }),
                None,
            )
            .await
            .context("deny Chromium downloads")?;
        client
            .call(
                "Target.setDiscoverTargets",
                json!({ "discover": true }),
                None,
            )
            .await
            .context("enable browser target lifecycle discovery")?;
        client
            .call("Target.setAutoAttach", browser_auto_attach_params(), None)
            .await
            .context("enable browser-wide target interception")?;
        let expected_shutdown = Arc::new(AtomicBool::new(false));
        let task_expected_shutdown = Arc::clone(&expected_shutdown);
        let task = tokio::spawn(async move {
            let _fail_closed = BrowserFetchGuard::new(session);
            if let Err(err) = client.monitor_events().await {
                if !task_expected_shutdown.load(Ordering::Acquire) {
                    warn!(
                        target: "docdexd_browser_guard",
                        error = %err,
                        "browser-wide target monitor stopped"
                    );
                }
            }
        });
        Ok(Self {
            task,
            expected_shutdown,
        })
    }

    fn is_healthy(&self) -> bool {
        !self.task.is_finished()
    }

    fn expected_shutdown_signal(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.expected_shutdown)
    }

    fn abort(&self) {
        self.expected_shutdown.store(true, Ordering::Release);
        self.task.abort();
    }
}

impl Drop for BrowserTargetMonitor {
    fn drop(&mut self) {
        self.expected_shutdown.store(true, Ordering::Release);
        self.task.abort();
    }
}

impl CdpClient {
    async fn connect(ws_url: &str) -> Result<Self> {
        let (ws, _) = connect_async(ws_url)
            .await
            .context("connect to devtools websocket")?;
        Ok(Self {
            ws,
            next_id: 1,
            pending_responses: HashMap::new(),
            ignored_response_ids: HashSet::new(),
            pinned_host: None,
            blocked_document: None,
            protected_target_id: None,
            protected_session_id: None,
            close_all_auxiliary_targets: false,
        })
    }

    async fn monitor_events(&mut self) -> Result<()> {
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
                if !self.ignored_response_ids.remove(&resp_id) {
                    self.pending_responses.insert(resp_id, value);
                }
                continue;
            }
            if let Some(method) = value.get("method").and_then(Value::as_str) {
                let event_session_id = value
                    .get("sessionId")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                self.handle_event(
                    method,
                    value.get("params"),
                    event_session_id.as_deref(),
                    None,
                )
                .await?;
            }
        }
    }

    async fn call(
        &mut self,
        method: &str,
        params: Value,
        tracker: Option<&mut NetworkIdleTracker>,
    ) -> Result<Value> {
        self.call_in_session(method, params, None, tracker).await
    }

    async fn call_for_session(
        &mut self,
        session_id: &str,
        method: &str,
        params: Value,
    ) -> Result<Value> {
        self.call_in_session(method, params, Some(session_id), None)
            .await
    }

    async fn call_in_session(
        &mut self,
        method: &str,
        params: Value,
        session_id: Option<&str>,
        mut tracker: Option<&mut NetworkIdleTracker>,
    ) -> Result<Value> {
        let id = self.next_id;
        self.next_id += 1;
        let mut payload = json!({
            "id": id,
            "method": method,
            "params": params,
        });
        if let Some(session_id) = session_id {
            payload["sessionId"] = Value::String(session_id.to_string());
        }
        self.ws
            .send(Message::Text(payload.to_string()))
            .await
            .context("send devtools command")?;
        loop {
            if let Some(value) = self.pending_responses.remove(&id) {
                return parse_cdp_command_result(method, value);
            }
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
                    return parse_cdp_command_result(method, value);
                }
                if self.ignored_response_ids.remove(&resp_id) {
                    continue;
                }
                self.pending_responses.insert(resp_id, value);
                continue;
            }
            if let Some(method) = value.get("method").and_then(Value::as_str) {
                let event_session_id = value
                    .get("sessionId")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                self.handle_event(
                    method,
                    value.get("params"),
                    event_session_id.as_deref(),
                    tracker.as_deref_mut(),
                )
                .await?;
                if let Some(error) = self.take_blocked_document() {
                    return Err(error.into());
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
            let idle_ready = tracker.inflight.is_empty()
                && tracker.last_activity.elapsed() >= idle_delay
                && (tracker.saw_load || elapsed >= idle_delay);
            if idle_ready {
                return Ok(true);
            }
            let remaining = timeout.saturating_sub(elapsed);
            let wait_for = if tracker.inflight.is_empty() {
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
                    if let Some(resp_id) = value.get("id").and_then(Value::as_u64) {
                        if !self.ignored_response_ids.remove(&resp_id) {
                            self.pending_responses.insert(resp_id, value);
                        }
                        continue;
                    }
                    if let Some(method) = value.get("method").and_then(Value::as_str) {
                        let event_session_id = value
                            .get("sessionId")
                            .and_then(Value::as_str)
                            .map(str::to_string);
                        self.handle_event(
                            method,
                            value.get("params"),
                            event_session_id.as_deref(),
                            Some(tracker),
                        )
                        .await?;
                        if let Some(error) = self.take_blocked_document() {
                            return Err(error.into());
                        }
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

    async fn handle_event(
        &mut self,
        method: &str,
        params: Option<&Value>,
        session_id: Option<&str>,
        tracker: Option<&mut NetworkIdleTracker>,
    ) -> Result<()> {
        if method == "Fetch.requestPaused" {
            let main_frame_id = tracker.as_deref().map(NetworkIdleTracker::main_frame_id);
            if let Some((error, is_document)) = self
                .handle_paused_request(params, session_id, main_frame_id)
                .await?
            {
                if is_document {
                    self.blocked_document = Some(error);
                }
            }
        } else if method == "Target.attachedToTarget" {
            self.handle_attached_target(params).await?;
        } else if matches!(
            method,
            "Target.targetDestroyed" | "Target.targetCrashed" | "Target.detachedFromTarget"
        ) {
            self.ensure_protected_target_alive(method, params)?;
        }
        if let Some(tracker) = tracker {
            tracker.handle(method, params, session_id);
        }
        Ok(())
    }

    async fn handle_paused_request(
        &mut self,
        params: Option<&Value>,
        session_id: Option<&str>,
        main_frame_id: Option<&str>,
    ) -> Result<Option<(OutboundUrlError, bool)>> {
        let params = params.ok_or_else(|| anyhow!("missing Fetch.requestPaused params"))?;
        let request_id = params
            .get("requestId")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("missing paused request id"))?;
        let request = params
            .get("request")
            .ok_or_else(|| anyhow!("missing paused request"))?;
        let raw_url = request
            .get("url")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("missing paused request url"))?;
        let method = request
            .get("method")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("missing paused request method"))?;
        let is_document = is_main_document_request(params, main_frame_id);
        if !is_read_only_browser_method(method) {
            let error = OutboundUrlError::UnsafeBrowserMethod;
            self.fail_paused_request(request_id, session_id).await?;
            return Ok(Some((error, is_document)));
        }
        let parsed = match Url::parse(raw_url) {
            Ok(parsed) => parsed,
            Err(_) => {
                let error = OutboundUrlError::InvalidUrl;
                self.fail_paused_request(request_id, session_id).await?;
                return Ok(Some((error, is_document)));
            }
        };
        if !matches!(parsed.scheme(), "http" | "https") {
            // Fetch interception is configured for HTTP(S), but tolerate browser
            // internal data/blob URLs if Chromium reports one anyway.
            if matches!(parsed.scheme(), "about" | "blob" | "data") {
                self.continue_paused_request(request_id, session_id).await?;
                return Ok(None);
            }
            let error = OutboundUrlError::UnsupportedScheme;
            self.fail_paused_request(request_id, session_id).await?;
            return Ok(Some((error, is_document)));
        }
        let parsed = match parse_outbound_url(raw_url) {
            Ok(parsed) => parsed,
            Err(error) => {
                self.fail_paused_request(request_id, session_id).await?;
                return Ok(Some((error, is_document)));
            }
        };
        if !matches_pinned_host(self.pinned_host.as_deref(), &parsed) {
            let error = OutboundUrlError::CrossHostBrowserRequest;
            self.fail_paused_request(request_id, session_id).await?;
            return Ok(Some((error, is_document)));
        }
        // The local SOCKS gate connects this host only to the public IP selected
        // before launch. Re-resolving each subresource here would add latency
        // without changing the browser's actual destination.
        self.continue_paused_request(request_id, session_id).await?;
        Ok(None)
    }

    async fn continue_paused_request(
        &mut self,
        request_id: &str,
        session_id: Option<&str>,
    ) -> Result<()> {
        self.send_command_no_wait(
            "Fetch.continueRequest",
            json!({ "requestId": request_id }),
            session_id,
        )
        .await
    }

    async fn fail_paused_request(
        &mut self,
        request_id: &str,
        session_id: Option<&str>,
    ) -> Result<()> {
        self.send_command_no_wait(
            "Fetch.failRequest",
            json!({ "requestId": request_id, "errorReason": "BlockedByClient" }),
            session_id,
        )
        .await
    }

    async fn send_command_no_wait(
        &mut self,
        method: &str,
        params: Value,
        session_id: Option<&str>,
    ) -> Result<()> {
        let id = self.next_id;
        self.next_id += 1;
        self.ignored_response_ids.insert(id);
        let mut payload = json!({ "id": id, "method": method, "params": params });
        if let Some(session_id) = session_id {
            payload["sessionId"] = Value::String(session_id.to_string());
        }
        self.ws
            .send(Message::Text(payload.to_string()))
            .await
            .with_context(|| format!("send devtools command {method}"))
    }

    fn take_blocked_document(&mut self) -> Option<OutboundUrlError> {
        self.blocked_document.take()
    }

    async fn handle_attached_target(&mut self, params: Option<&Value>) -> Result<()> {
        let params = params.ok_or_else(|| anyhow!("missing Target.attachedToTarget params"))?;
        let session_id = params
            .get("sessionId")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("attached target is missing its session id"))?
            .to_string();
        let target_info = params
            .get("targetInfo")
            .ok_or_else(|| anyhow!("attached target is missing targetInfo"))?;
        let target_id = target_info
            .get("targetId")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("attached target is missing target id"))?
            .to_string();
        let target_type = target_info
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();

        if self.protected_target_id.as_deref() == Some(target_id.as_str()) {
            if target_type != "page" {
                return Err(anyhow!(
                    "protected browser target changed type to {target_type}"
                ));
            }
            self.protected_session_id = Some(session_id.clone());
            Box::pin(self.call_for_session(
                &session_id,
                "Runtime.runIfWaitingForDebugger",
                json!({}),
            ))
            .await?;
            return Ok(());
        }

        if self.close_all_auxiliary_targets || target_type != "iframe" {
            // Popups, workers, service workers, and unknown auxiliary targets are
            // unnecessary for DOM extraction. They start paused and are closed
            // before any script or network activity is allowed.
            Box::pin(self.call("Target.closeTarget", json!({ "targetId": target_id }), None))
                .await
                .with_context(|| format!("close unexpected CDP target type {target_type}"))?;
            return Ok(());
        }

        self.configure_attached_iframe(&session_id).await
    }

    fn ensure_protected_target_alive(&self, method: &str, params: Option<&Value>) -> Result<()> {
        let Some(params) = params else {
            return Ok(());
        };
        if protected_target_lifecycle_lost(
            self.protected_target_id.as_deref(),
            self.protected_session_id.as_deref(),
            params,
        ) {
            return Err(anyhow!(
                "protected browser target became unavailable ({method})"
            ));
        }
        Ok(())
    }

    async fn configure_attached_iframe(&mut self, session_id: &str) -> Result<()> {
        Box::pin(self.call_for_session(session_id, "Network.enable", json!({}))).await?;
        Box::pin(self.call_for_session(
            session_id,
            "Network.setBypassServiceWorker",
            json!({ "bypass": true }),
        ))
        .await?;
        Box::pin(self.call_for_session(
            session_id,
            "Network.setCacheDisabled",
            json!({ "cacheDisabled": true }),
        ))
        .await?;
        Box::pin(self.call_for_session(
            session_id,
            "Network.setBlockedURLs",
            blocked_transport_params(),
        ))
        .await?;
        Box::pin(self.call_for_session(session_id, "Fetch.enable", fetch_interception_params()))
            .await?;
        Box::pin(self.call_for_session(session_id, "Target.setAutoAttach", auto_attach_params()))
            .await?;
        Box::pin(self.call_for_session(session_id, "Runtime.runIfWaitingForDebugger", json!({})))
            .await?;
        Ok(())
    }
}

fn is_main_document_request(params: &Value, main_frame_id: Option<&str>) -> bool {
    matches!(
        params.get("resourceType").and_then(Value::as_str),
        Some("Document")
    ) && main_frame_id.is_some_and(|main_frame_id| {
        params.get("frameId").and_then(Value::as_str) == Some(main_frame_id)
    })
}

fn is_read_only_browser_method(method: &str) -> bool {
    method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD")
}

fn parse_cdp_command_result(method: &str, value: Value) -> Result<Value> {
    if let Some(err) = value.get("error") {
        return Err(anyhow!("devtools error for {method}: {err}"));
    }
    Ok(value.get("result").cloned().unwrap_or(Value::Null))
}

struct NetworkIdleTracker {
    main_frame_id: String,
    inflight: HashSet<String>,
    last_activity: Instant,
    saw_load: bool,
    document_status: Option<u16>,
    document_url: Option<String>,
}

impl NetworkIdleTracker {
    fn new(main_frame_id: String) -> Self {
        Self {
            main_frame_id,
            inflight: HashSet::new(),
            last_activity: Instant::now(),
            saw_load: false,
            document_status: None,
            document_url: None,
        }
    }

    fn main_frame_id(&self) -> &str {
        &self.main_frame_id
    }

    fn handle(&mut self, method: &str, params: Option<&Value>, session_id: Option<&str>) {
        match method {
            "Network.requestWillBeSent" => {
                if let Some(request_id) = params
                    .and_then(|params| params.get("requestId"))
                    .and_then(Value::as_str)
                {
                    self.inflight
                        .insert(network_request_key(session_id, request_id));
                }
                self.last_activity = Instant::now();
            }
            "Network.loadingFinished" | "Network.loadingFailed" => {
                if let Some(request_id) = params
                    .and_then(|params| params.get("requestId"))
                    .and_then(Value::as_str)
                {
                    self.inflight
                        .remove(&network_request_key(session_id, request_id));
                }
                self.last_activity = Instant::now();
            }
            "Network.responseReceived" => {
                if let Some(params) = params {
                    let resource_type = params.get("type").and_then(Value::as_str);
                    let is_main_document = matches!(resource_type, Some("Document"))
                        && params.get("frameId").and_then(Value::as_str)
                            == Some(self.main_frame_id.as_str());
                    if is_main_document {
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

fn network_request_key(session_id: Option<&str>, request_id: &str) -> String {
    format!("{}\0{request_id}", session_id.unwrap_or_default())
}

async fn fetch_dom_via_cdp(
    ws_url: &str,
    url: &Url,
    timeout: Duration,
) -> Result<ChromeFetchResult> {
    tokio::time::timeout(timeout, fetch_dom_via_cdp_inner(ws_url, url, timeout))
        .await
        .map_err(|_| anyhow!("chrome CDP fetch timed out after {timeout:?}"))?
}

async fn fetch_dom_via_cdp_inner(
    ws_url: &str,
    url: &Url,
    timeout: Duration,
) -> Result<ChromeFetchResult> {
    let deadline = Instant::now() + timeout;
    let mut client = CdpClient::connect(ws_url).await?;
    client.pinned_host = normalized_url_host(url);
    if client.pinned_host.is_none() {
        return Err(OutboundUrlError::MissingHost.into());
    }
    client.call("Network.enable", json!({}), None).await?;
    client
        .call(
            "Network.setBypassServiceWorker",
            json!({ "bypass": true }),
            None,
        )
        .await
        .context("bypass service workers for browser fetch")?;
    client
        .call(
            "Network.setCacheDisabled",
            json!({ "cacheDisabled": true }),
            None,
        )
        .await
        .context("disable Chromium cache for browser fetch")?;
    client.call("Page.enable", json!({}), None).await?;
    client.call("Runtime.enable", json!({}), None).await?;
    enable_cdp_non_http_transport_blocking(&mut client).await?;
    client
        .call("Fetch.enable", fetch_interception_params(), None)
        .await
        .context("enable CDP request interception")?;
    client
        .call("Target.setAutoAttach", auto_attach_params(), None)
        .await
        .context("enable recursive CDP target interception")?;
    inject_webdriver_override(&mut client).await?;

    let frame_tree = client.call("Page.getFrameTree", json!({}), None).await?;
    let main_frame_id = frame_tree
        .get("frameTree")
        .and_then(|value| value.get("frame"))
        .and_then(|value| value.get("id"))
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("devtools returned no main frame id"))?
        .to_string();
    let mut tracker = NetworkIdleTracker::new(main_frame_id);
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
    if let Some(error) = client.take_blocked_document() {
        return Err(error.into());
    }
    if let Some(error_text) = nav_result.get("errorText").and_then(Value::as_str) {
        return Err(anyhow!("navigation failed: {error_text}"));
    }
    let idle_timeout = remaining(deadline).min(Duration::from_millis(CHROME_NETWORK_IDLE_MAX_MS));
    let _ = client
        .wait_for_network_idle(&mut tracker, idle_timeout)
        .await?;
    if let Some(error) = client.take_blocked_document() {
        return Err(error.into());
    }
    let _ = dismiss_cookie_banners(&mut client).await;

    let mut html = String::new();
    let mut final_url = tracker.document_url.clone();
    let html_expression = bounded_string_expression(
        "document.documentElement ? document.documentElement.outerHTML : \"\"",
        resolve_capture_limit(
            "DOCDEX_WEB_CHROME_MAX_HTML_CHARS",
            CHROME_MAX_HTML_CHARS_DEFAULT,
        ),
    );
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
        let html_value = eval_string(&mut client, &html_expression).await?;
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
    if let Some(error) = client.take_blocked_document() {
        return Err(error.into());
    }
    let result = ChromeFetchResult {
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
    };
    neutralize_root_target(&mut client, deadline).await?;
    Ok(result)
}

async fn neutralize_root_target(client: &mut CdpClient, deadline: Instant) -> Result<()> {
    let navigation = client
        .call("Page.navigate", json!({ "url": "about:blank" }), None)
        .await
        .context("neutralize browser root target")?;
    if let Some(error_text) = navigation.get("errorText").and_then(Value::as_str) {
        return Err(anyhow!("root target neutralization failed: {error_text}"));
    }
    loop {
        let remaining = remaining(deadline);
        if remaining.is_zero() {
            return Err(anyhow!("root target neutralization timed out"));
        }
        let href = tokio::time::timeout(
            remaining.min(Duration::from_millis(250)),
            eval_string(client, "document.location.href"),
        )
        .await;
        if matches!(href, Ok(Ok(ref value)) if value == "about:blank") {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10).min(remaining)).await;
    }
}

async fn enable_cdp_non_http_transport_blocking(client: &mut CdpClient) -> Result<()> {
    // Scraping does not require non-HTTP transports. Blocking them also closes
    // WebSocket/file/FTP paths that the Fetch domain cannot reliably pause.
    client
        .call("Network.setBlockedURLs", blocked_transport_params(), None)
        .await
        .context("enable CDP non-HTTP transport blocking")?;
    Ok(())
}

fn blocked_transport_params() -> Value {
    json!({
        "urls": [
            "ws://*",
            "wss://*",
            "file://*",
            "ftp://*",
            "filesystem:*"
        ]
    })
}

fn fetch_interception_params() -> Value {
    json!({
        "patterns": [
            { "urlPattern": "*", "requestStage": "Request" }
        ]
    })
}

fn auto_attach_params() -> Value {
    json!({
        "autoAttach": true,
        "waitForDebuggerOnStart": true,
        "flatten": true,
        "filter": [
            { "type": "browser", "exclude": true },
            { "type": "tab", "exclude": true },
            {}
        ]
    })
}

fn browser_auto_attach_params() -> Value {
    json!({
        "autoAttach": true,
        "waitForDebuggerOnStart": true,
        "flatten": true,
        "filter": [
            { "type": "browser", "exclude": true },
            { "type": "tab", "exclude": true },
            {}
        ]
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
    let raw_expression = if use_inner_text {
        "document.body ? document.body.innerText : \"\""
    } else {
        "document.body ? document.body.textContent : \"\""
    };
    let expression = bounded_string_expression(
        raw_expression,
        resolve_capture_limit(
            "DOCDEX_WEB_CHROME_MAX_TEXT_CHARS",
            CHROME_MAX_TEXT_CHARS_DEFAULT,
        ),
    );
    let mut last_value = String::new();
    loop {
        let value = eval_string(client, &expression).await.unwrap_or_default();
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

fn bounded_string_expression(expression: &str, max_chars: usize) -> String {
    format!(
        "(() => {{ const value = ({expression}) || \"\"; return String(value).slice(0, {max_chars}); }})()"
    )
}

fn normalized_url_host(url: &Url) -> Option<String> {
    url.host_str()
        .map(|host| host.trim_end_matches('.').to_ascii_lowercase())
        .filter(|host| !host.is_empty())
}

fn matches_pinned_host(pinned_host: Option<&str>, url: &Url) -> bool {
    pinned_host == normalized_url_host(url).as_deref()
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
    fn browser_interception_allows_only_read_only_methods() {
        assert!(is_read_only_browser_method("GET"));
        assert!(is_read_only_browser_method("head"));
        for method in ["POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", ""] {
            assert!(
                !is_read_only_browser_method(method),
                "unexpectedly allowed {method}"
            );
        }
    }

    #[test]
    fn redirect_events_do_not_leak_network_idle_inflight_state() {
        let mut tracker = NetworkIdleTracker::new("main-frame".to_string());
        let request = json!({ "requestId": "request-1" });
        tracker.handle("Network.requestWillBeSent", Some(&request), None);
        tracker.handle("Network.requestWillBeSent", Some(&request), None);
        assert_eq!(tracker.inflight.len(), 1);
        tracker.handle("Network.loadingFinished", Some(&request), None);
        assert!(tracker.inflight.is_empty());
    }

    #[test]
    fn iframe_documents_cannot_override_root_navigation_metadata() {
        let mut tracker = NetworkIdleTracker::new("main-frame".to_string());
        let iframe = json!({
            "type": "Document",
            "frameId": "iframe",
            "response": { "status": 418, "url": "https://example.com/frame" }
        });
        tracker.handle(
            "Network.responseReceived",
            Some(&iframe),
            Some("iframe-session"),
        );
        assert_eq!(tracker.document_status, None);
        assert_eq!(tracker.document_url, None);

        let root = json!({
            "type": "Document",
            "frameId": "main-frame",
            "response": { "status": 200, "url": "https://example.com/root" }
        });
        tracker.handle("Network.responseReceived", Some(&root), None);
        assert_eq!(tracker.document_status, Some(200));
        assert_eq!(
            tracker.document_url.as_deref(),
            Some("https://example.com/root")
        );
    }

    #[test]
    fn only_the_main_frame_document_is_fatal_when_blocked() {
        let root = json!({ "resourceType": "Document", "frameId": "main-frame" });
        let iframe = json!({ "resourceType": "Document", "frameId": "iframe" });
        assert!(is_main_document_request(&root, Some("main-frame")));
        assert!(!is_main_document_request(&iframe, Some("main-frame")));
        assert!(!is_main_document_request(&root, None));
    }

    #[test]
    fn target_interception_filters_are_fail_closed_for_unknown_types() {
        for params in [browser_auto_attach_params(), auto_attach_params()] {
            let filters = params
                .get("filter")
                .and_then(Value::as_array)
                .expect("target filter");
            assert_eq!(
                filters,
                &[
                    json!({ "type": "browser", "exclude": true }),
                    json!({ "type": "tab", "exclude": true }),
                    json!({})
                ]
            );
        }
    }

    #[test]
    fn protected_target_lifecycle_loss_is_fail_closed() {
        let root = json!({ "targetId": "root-target" });
        let session = json!({ "sessionId": "root-session" });
        let other = json!({ "targetId": "other-target" });
        assert!(protected_target_lifecycle_lost(
            Some("root-target"),
            Some("root-session"),
            &root
        ));
        assert!(protected_target_lifecycle_lost(
            Some("root-target"),
            Some("root-session"),
            &session
        ));
        assert!(!protected_target_lifecycle_lost(
            Some("root-target"),
            Some("root-session"),
            &other
        ));
    }

    #[test]
    fn cookie_banner_suppression_never_activates_page_controls() {
        for active_operation in [".click(", ".submit(", "dispatchEvent("] {
            assert!(
                !COOKIE_DISMISS_SCRIPT.contains(active_operation),
                "cookie suppression must not perform {active_operation}"
            );
        }
        assert!(!COOKIE_DISMISS_SCRIPT.contains("input[type='submit']"));
        assert!(!COOKIE_DISMISS_SCRIPT.contains("button, a"));
    }

    #[tokio::test]
    async fn cdp_fetch_timeout_covers_unanswered_setup_commands() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind websocket listener");
        let address = listener.local_addr().expect("websocket address");
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept websocket");
            let mut websocket = tokio_tungstenite::accept_async(stream)
                .await
                .expect("accept websocket protocol");
            let _request = websocket
                .next()
                .await
                .expect("receive CDP request")
                .expect("valid CDP request");
            std::future::pending::<()>().await;
        });

        let timeout = Duration::from_millis(50);
        let started = Instant::now();
        let error = fetch_dom_via_cdp(
            &format!("ws://{address}"),
            &Url::parse("https://example.com/").expect("URL"),
            timeout,
        )
        .await
        .expect_err("unanswered CDP command must time out");
        assert!(error.to_string().contains("chrome CDP fetch timed out"));
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "CDP timeout exceeded its bounded test window"
        );
        server.abort();
    }

    #[tokio::test]
    async fn cdp_transport_blocking_failure_is_fatal() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind websocket listener");
        let address = listener.local_addr().expect("websocket address");
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept websocket");
            let mut websocket = tokio_tungstenite::accept_async(stream)
                .await
                .expect("accept websocket protocol");
            let request = websocket
                .next()
                .await
                .expect("receive CDP request")
                .expect("valid CDP request");
            let Message::Text(request) = request else {
                panic!("expected text CDP request");
            };
            let request: Value = serde_json::from_str(&request).expect("parse CDP request");
            assert_eq!(
                request.get("method").and_then(Value::as_str),
                Some("Network.setBlockedURLs")
            );
            let id = request.get("id").and_then(Value::as_u64).expect("CDP id");
            websocket
                .send(Message::Text(
                    json!({ "id": id, "error": { "message": "unsupported" } }).to_string(),
                ))
                .await
                .expect("send CDP error");
        });

        let mut client = CdpClient::connect(&format!("ws://{address}"))
            .await
            .expect("connect CDP client");
        let error = enable_cdp_non_http_transport_blocking(&mut client)
            .await
            .expect_err("missing security control must fail closed");
        assert!(error
            .to_string()
            .contains("enable CDP non-HTTP transport blocking"));
        server.await.expect("join websocket server");
    }

    #[tokio::test]
    async fn cdp_auto_attach_configures_iframe_before_resuming_it() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind websocket listener");
        let address = listener.local_addr().expect("websocket address");
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept websocket");
            let mut websocket = tokio_tungstenite::accept_async(stream)
                .await
                .expect("accept websocket protocol");
            let request = websocket
                .next()
                .await
                .expect("receive root command")
                .expect("valid root command");
            let Message::Text(request) = request else {
                panic!("expected text CDP request");
            };
            let request: Value = serde_json::from_str(&request).expect("parse root command");
            assert_eq!(
                request.get("method").and_then(Value::as_str),
                Some("Target.setAutoAttach")
            );
            let root_id = request.get("id").and_then(Value::as_u64).expect("root id");
            websocket
                .send(Message::Text(
                    json!({
                        "method": "Target.attachedToTarget",
                        "params": {
                            "sessionId": "iframe-session",
                            "targetInfo": {
                                "targetId": "iframe-target",
                                "type": "iframe",
                                "url": ""
                            },
                            "waitingForDebugger": true
                        }
                    })
                    .to_string(),
                ))
                .await
                .expect("send attached event");
            // Deliberately send the outer response before nested command
            // responses. The client must buffer it instead of deadlocking.
            websocket
                .send(Message::Text(
                    json!({ "id": root_id, "result": {} }).to_string(),
                ))
                .await
                .expect("send root response");

            let expected_methods = [
                "Network.enable",
                "Network.setBypassServiceWorker",
                "Network.setCacheDisabled",
                "Network.setBlockedURLs",
                "Fetch.enable",
                "Target.setAutoAttach",
                "Runtime.runIfWaitingForDebugger",
            ];
            for expected_method in expected_methods {
                let request = websocket
                    .next()
                    .await
                    .expect("receive iframe command")
                    .expect("valid iframe command");
                let Message::Text(request) = request else {
                    panic!("expected text CDP request");
                };
                let request: Value = serde_json::from_str(&request).expect("parse iframe command");
                assert_eq!(
                    request.get("method").and_then(Value::as_str),
                    Some(expected_method)
                );
                assert_eq!(
                    request.get("sessionId").and_then(Value::as_str),
                    Some("iframe-session")
                );
                let id = request.get("id").and_then(Value::as_u64).expect("child id");
                websocket
                    .send(Message::Text(json!({ "id": id, "result": {} }).to_string()))
                    .await
                    .expect("send iframe command response");
            }
        });

        let mut client = CdpClient::connect(&format!("ws://{address}"))
            .await
            .expect("connect CDP client");
        client.pinned_host = Some("example.com".to_string());
        client
            .call("Target.setAutoAttach", auto_attach_params(), None)
            .await
            .expect("auto-attach setup");
        server.await.expect("join websocket server");
    }

    #[tokio::test]
    async fn browser_monitor_closes_popup_before_completing_setup_command() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind websocket listener");
        let address = listener.local_addr().expect("websocket address");
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept websocket");
            let mut websocket = tokio_tungstenite::accept_async(stream)
                .await
                .expect("accept websocket protocol");
            let setup = websocket
                .next()
                .await
                .expect("receive setup command")
                .expect("valid setup command");
            let Message::Text(setup) = setup else {
                panic!("expected text CDP request");
            };
            let setup: Value = serde_json::from_str(&setup).expect("parse setup command");
            assert_eq!(
                setup.get("method").and_then(Value::as_str),
                Some("Browser.setDownloadBehavior")
            );
            let setup_id = setup.get("id").and_then(Value::as_u64).expect("setup id");

            websocket
                .send(Message::Text(
                    json!({
                        "method": "Target.attachedToTarget",
                        "params": {
                            "sessionId": "popup-session",
                            "targetInfo": {
                                "targetId": "popup-target",
                                "type": "page",
                                "url": "about:blank"
                            },
                            "waitingForDebugger": true
                        }
                    })
                    .to_string(),
                ))
                .await
                .expect("send popup event");

            let close = websocket
                .next()
                .await
                .expect("receive close command")
                .expect("valid close command");
            let Message::Text(close) = close else {
                panic!("expected text CDP request");
            };
            let close: Value = serde_json::from_str(&close).expect("parse close command");
            assert_eq!(
                close.get("method").and_then(Value::as_str),
                Some("Target.closeTarget")
            );
            assert_eq!(
                close.pointer("/params/targetId").and_then(Value::as_str),
                Some("popup-target")
            );
            let close_id = close.get("id").and_then(Value::as_u64).expect("close id");
            websocket
                .send(Message::Text(
                    json!({ "id": close_id, "result": { "success": true } }).to_string(),
                ))
                .await
                .expect("acknowledge popup close");
            websocket
                .send(Message::Text(
                    json!({ "id": setup_id, "result": {} }).to_string(),
                ))
                .await
                .expect("complete setup command");
        });

        let mut client = CdpClient::connect(&format!("ws://{address}"))
            .await
            .expect("connect CDP client");
        client.protected_target_id = Some("root-target".to_string());
        client.close_all_auxiliary_targets = true;
        client
            .call(
                "Browser.setDownloadBehavior",
                json!({ "behavior": "deny" }),
                None,
            )
            .await
            .expect("setup command completes after popup is closed");
        server.await.expect("join websocket server");
    }

    #[tokio::test]
    async fn blocked_main_document_returns_before_pending_navigation_response() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind websocket listener");
        let address = listener.local_addr().expect("websocket address");
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept websocket");
            let mut websocket = tokio_tungstenite::accept_async(stream)
                .await
                .expect("accept websocket protocol");
            let navigation = websocket
                .next()
                .await
                .expect("receive navigation command")
                .expect("valid navigation command");
            let Message::Text(navigation) = navigation else {
                panic!("expected text CDP request");
            };
            let navigation: Value =
                serde_json::from_str(&navigation).expect("parse navigation command");
            assert_eq!(
                navigation.get("method").and_then(Value::as_str),
                Some("Page.navigate")
            );
            websocket
                .send(Message::Text(
                    json!({
                        "method": "Fetch.requestPaused",
                        "params": {
                            "requestId": "unsafe-post",
                            "request": {
                                "url": "https://example.com/submit",
                                "method": "POST"
                            },
                            "resourceType": "Document",
                            "frameId": "main-frame"
                        }
                    })
                    .to_string(),
                ))
                .await
                .expect("send blocked request event");
            let fail = websocket
                .next()
                .await
                .expect("receive fail command")
                .expect("valid fail command");
            let Message::Text(fail) = fail else {
                panic!("expected text CDP request");
            };
            let fail: Value = serde_json::from_str(&fail).expect("parse fail command");
            assert_eq!(
                fail.get("method").and_then(Value::as_str),
                Some("Fetch.failRequest")
            );
            assert_eq!(
                fail.pointer("/params/requestId").and_then(Value::as_str),
                Some("unsafe-post")
            );
            // Deliberately never answer Page.navigate. The policy error must
            // preempt that pending response.
        });

        let mut client = CdpClient::connect(&format!("ws://{address}"))
            .await
            .expect("connect CDP client");
        client.pinned_host = Some("example.com".to_string());
        let mut tracker = NetworkIdleTracker::new("main-frame".to_string());
        let error = tokio::time::timeout(
            Duration::from_secs(1),
            client.call(
                "Page.navigate",
                json!({ "url": "https://example.com/" }),
                Some(&mut tracker),
            ),
        )
        .await
        .expect("blocked navigation returns promptly")
        .expect_err("unsafe POST must fail navigation");
        assert_eq!(
            error.downcast_ref::<OutboundUrlError>(),
            Some(&OutboundUrlError::UnsafeBrowserMethod)
        );
        server.await.expect("join websocket server");
    }

    #[test]
    fn chrome_common_args_include_stealth_flags() {
        let config = ChromeFetchConfig {
            chrome_binary: PathBuf::from("/bin/chrome"),
            headless: true,
            user_agent: "Mozilla/5.0 (X11; Linux x86_64)".to_string(),
            timeout: Duration::from_secs(5),
            user_data_dir: Some(PathBuf::from("profile_dir")),
            allow_no_sandbox: false,
        };
        let args = chrome_common_args(&config, Path::new("profile_dir"));
        assert!(args.contains(&"--headless=new".to_string()));
        assert!(args.contains(&"--disable-blink-features=AutomationControlled".to_string()));
        assert!(args.contains(&format!("--window-size={}", CHROME_WINDOW_SIZE)));
        assert!(args.contains(&"--user-data-dir=profile_dir".to_string()));
        assert!(!args.iter().any(|arg| arg == "--incognito"));
        assert!(!args.iter().any(|arg| arg == "--no-sandbox"));
        assert!(args.iter().any(|arg| arg == "--disable-quic"));
        assert!(args
            .iter()
            .any(|arg| arg == "--force-webrtc-ip-handling-policy=disable_non_proxied_udp"));
        assert!(!args
            .iter()
            .any(|arg| arg.starts_with("--remote-allow-origins")));
    }

    #[test]
    fn chrome_session_pins_dns_and_rejects_cross_host_requests() {
        let config = ChromeFetchConfig {
            chrome_binary: PathBuf::from("/bin/chrome"),
            headless: true,
            user_agent: "docdex-test".to_string(),
            timeout: Duration::from_secs(5),
            user_data_dir: None,
            allow_no_sandbox: false,
        };
        let url = Url::parse("https://public.example.net/page").expect("URL");
        let session = ChromeSessionConfig::from_fetch_config(
            &config,
            &url,
            "93.184.216.34".parse().expect("public IP"),
        );
        assert_eq!(
            session.host_resolver_rule().as_deref(),
            Some("MAP public.example.net 93.184.216.34")
        );
        assert!(matches_pinned_host(
            session.pinned_host.as_deref(),
            &Url::parse("https://public.example.net/asset").expect("same host URL")
        ));
        assert!(!matches_pinned_host(
            session.pinned_host.as_deref(),
            &Url::parse("https://cdn.example.net/asset").expect("cross host URL")
        ));
    }

    #[test]
    fn chrome_common_args_allow_no_sandbox_only_when_explicit() {
        let config = ChromeFetchConfig {
            chrome_binary: PathBuf::from("/bin/chrome"),
            headless: true,
            user_agent: "docdex-test".to_string(),
            timeout: Duration::from_secs(5),
            user_data_dir: Some(PathBuf::from("profile_dir")),
            allow_no_sandbox: true,
        };
        let args = chrome_common_args(&config, Path::new("profile_dir"));
        assert!(args.iter().any(|arg| arg == "--no-sandbox"));
    }

    #[test]
    fn bounded_dom_expression_limits_returned_value() {
        let expression = bounded_string_expression("document.body.innerText", 4096);
        assert!(expression.contains("slice(0, 4096)"));
        assert!(expression.contains("|| \"\""));
    }

    #[test]
    fn no_sandbox_opt_in_parser_is_explicit() {
        assert_eq!(parse_boolish("true"), Some(true));
        assert_eq!(parse_boolish("1"), Some(true));
        assert_eq!(parse_boolish("false"), Some(false));
        assert_eq!(parse_boolish("unexpected"), None);
    }

    #[test]
    fn user_data_dir_falls_back_when_chromium_owns_persistent_profile() {
        let profile = TempDir::new().expect("profile tempdir");
        fs::write(profile.path().join("SingletonLock"), b"owned")
            .expect("create Chromium singleton marker");
        let config = ChromeFetchConfig {
            chrome_binary: PathBuf::from("/bin/chrome"),
            headless: true,
            user_agent: "docdex-test".to_string(),
            timeout: Duration::from_secs(5),
            user_data_dir: Some(profile.path().to_path_buf()),
            allow_no_sandbox: false,
        };

        let selected = UserDataDir::new(&config).expect("select fallback profile");
        assert!(matches!(selected, UserDataDir::Temp(_)));
        assert_ne!(selected.path(), profile.path());
    }

    #[cfg(unix)]
    #[test]
    fn user_data_dir_falls_back_for_stale_chromium_singleton_markers() {
        use std::os::unix::fs::symlink;

        let profile = TempDir::new().expect("profile tempdir");
        let true_binary = ["/usr/bin/true", "/bin/true"]
            .iter()
            .map(Path::new)
            .find(|path| path.is_file())
            .expect("true binary");
        let mut child = std::process::Command::new(true_binary)
            .spawn()
            .expect("spawn exited owner");
        let stale_pid = child.id();
        child.wait().expect("wait for exited owner");
        symlink(
            format!("host-{stale_pid}"),
            profile.path().join("SingletonLock"),
        )
        .expect("stale lock");
        symlink("cookie", profile.path().join("SingletonCookie")).expect("stale cookie");
        symlink("socket", profile.path().join("SingletonSocket")).expect("stale socket");
        let config = ChromeFetchConfig {
            chrome_binary: PathBuf::from("/bin/chrome"),
            headless: true,
            user_agent: "docdex-test".to_string(),
            timeout: Duration::from_secs(5),
            user_data_dir: Some(profile.path().to_path_buf()),
            allow_no_sandbox: false,
        };

        let selected = UserDataDir::new(&config).expect("select safe fallback profile");
        assert!(matches!(selected, UserDataDir::Temp(_)));
        for marker in ["SingletonLock", "SingletonCookie", "SingletonSocket"] {
            assert!(fs::symlink_metadata(profile.path().join(marker)).is_ok());
        }
    }

    #[cfg(unix)]
    #[test]
    fn user_data_dir_does_not_remove_live_chromium_singleton_lock() {
        use std::os::unix::fs::symlink;

        let profile = TempDir::new().expect("profile tempdir");
        symlink(
            format!("host-{}", std::process::id()),
            profile.path().join("SingletonLock"),
        )
        .expect("live lock");
        let config = ChromeFetchConfig {
            chrome_binary: PathBuf::from("/bin/chrome"),
            headless: true,
            user_agent: "docdex-test".to_string(),
            timeout: Duration::from_secs(5),
            user_data_dir: Some(profile.path().to_path_buf()),
            allow_no_sandbox: false,
        };

        let selected = UserDataDir::new(&config).expect("select fallback profile");
        assert!(matches!(selected, UserDataDir::Temp(_)));
        assert!(fs::symlink_metadata(profile.path().join("SingletonLock")).is_ok());
    }

    #[test]
    fn user_data_dir_keeps_free_persistent_profile() {
        let profile = TempDir::new().expect("profile tempdir");
        let config = ChromeFetchConfig {
            chrome_binary: PathBuf::from("/bin/chrome"),
            headless: true,
            user_agent: "docdex-test".to_string(),
            timeout: Duration::from_secs(5),
            user_data_dir: Some(profile.path().to_path_buf()),
            allow_no_sandbox: false,
        };

        let selected = UserDataDir::new(&config).expect("reserve persistent profile");
        assert!(matches!(selected, UserDataDir::Persistent { .. }));
        assert_eq!(selected.path(), profile.path());
    }

    #[test]
    fn user_data_dir_serializes_docdex_owners_of_persistent_profile() {
        let profile = TempDir::new().expect("profile tempdir");
        let config = ChromeFetchConfig {
            chrome_binary: PathBuf::from("/bin/chrome"),
            headless: true,
            user_agent: "docdex-test".to_string(),
            timeout: Duration::from_secs(5),
            user_data_dir: Some(profile.path().to_path_buf()),
            allow_no_sandbox: false,
        };

        let first = UserDataDir::new(&config).expect("reserve persistent profile");
        assert!(matches!(first, UserDataDir::Persistent { .. }));
        let second = UserDataDir::new(&config).expect("select fallback profile");
        assert!(matches!(second, UserDataDir::Temp(_)));
        assert_ne!(second.path(), profile.path());
    }

    #[test]
    fn user_data_dir_releases_profile_reservation_on_drop() {
        let profile = TempDir::new().expect("profile tempdir");
        let config = ChromeFetchConfig {
            chrome_binary: PathBuf::from("/bin/chrome"),
            headless: true,
            user_agent: "docdex-test".to_string(),
            timeout: Duration::from_secs(5),
            user_data_dir: Some(profile.path().to_path_buf()),
            allow_no_sandbox: false,
        };

        let first = UserDataDir::new(&config).expect("reserve persistent profile");
        assert!(matches!(first, UserDataDir::Persistent { .. }));
        drop(first);

        let second = UserDataDir::new(&config).expect("reserve released profile");
        assert!(matches!(second, UserDataDir::Persistent { .. }));
        assert_eq!(second.path(), profile.path());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn manager_shutdown_terminates_owned_process_group() {
        let shell = ["/bin/sh", "/usr/bin/sh"]
            .iter()
            .map(Path::new)
            .find(|path| path.is_file())
            .expect("shell is available");
        let mut command = Command::new(shell);
        command.arg("-c").arg("sleep 30 & wait");
        command.stdout(Stdio::null());
        command.stderr(Stdio::null());
        let session = BrowserSession::spawn(command, BrowserSessionOptions::without_lock())
            .await
            .expect("spawn browser-like process tree");
        let pgid = session.process_group_id();
        let config = ChromeSessionConfig {
            chrome_binary: shell.to_path_buf(),
            headless: true,
            user_agent: "docdex-test".to_string(),
            user_data_dir: None,
            allow_no_sandbox: false,
            pinned_host: Some("example.com".to_string()),
            pinned_address: "93.184.216.34".parse().expect("public IP"),
            allowed_ports: vec![80, 443],
        };
        let instance = Arc::new(ChromeInstance {
            session,
            debug_port: 0,
            browser_ws_url: "ws://127.0.0.1:1/devtools/browser/test".to_string(),
            root_target: CdpTarget {
                ws_url: "ws://127.0.0.1:1/devtools/page/test".to_string(),
                target_id: "test-root".to_string(),
            },
            browser_target_monitor: BrowserTargetMonitor {
                task: tokio::spawn(std::future::pending()),
                expected_shutdown: Arc::new(AtomicBool::new(false)),
            },
            egress_proxy: None,
            config,
            _user_data_dir: UserDataDir::Temp(TempDir::new().expect("temp profile")),
            watchdog_handle: None,
        });
        let manager = ChromeManager {
            state: Mutex::new(ChromeManagerState {
                instance: Some(instance),
            }),
        };

        manager.shutdown().await.expect("shutdown process tree");
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            let rc = unsafe { nix::libc::killpg(pgid, 0) };
            if rc == -1 && std::io::Error::last_os_error().raw_os_error() == Some(nix::libc::ESRCH)
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "browser process group still exists after shutdown"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[test]
    fn devtools_active_port_must_describe_an_owned_loopback_browser_endpoint() {
        let endpoint = parse_devtools_active_port("32123\n/devtools/browser/abc-123\n")
            .expect("valid active port");
        assert_eq!(endpoint.port, 32123);
        assert_eq!(
            endpoint.browser_ws_url,
            "ws://127.0.0.1:32123/devtools/browser/abc-123"
        );
        for invalid in [
            "0\n/devtools/browser/id\n",
            "32123\n/devtools/page/id\n",
            "32123\n/devtools/browser/../page/id\n",
        ] {
            assert!(parse_devtools_active_port(invalid).is_err());
        }
        assert!(
            validate_devtools_ws_url("ws://127.0.0.1:32123/devtools/page/id", 32123, "page")
                .is_ok()
        );
        assert!(
            validate_devtools_ws_url("ws://localhost:32123/devtools/page/id", 32123, "page")
                .is_err()
        );
        assert!(
            validate_devtools_ws_url("ws://127.0.0.1:32124/devtools/page/id", 32123, "page")
                .is_err()
        );
    }

    #[test]
    fn transfer_budget_is_atomic_and_fail_closed() {
        let remaining = AtomicU64::new(5);
        assert_eq!(reserve_transfer_bytes(&remaining, 3), 3);
        assert_eq!(reserve_transfer_bytes(&remaining, 4), 2);
        assert_eq!(reserve_transfer_bytes(&remaining, 1), 0);
    }

    #[test]
    fn capture_limits_clamp_untrusted_environment_overrides() {
        assert_eq!(
            clamp_capture_limit(None, CHROME_MAX_HTML_CHARS_DEFAULT),
            CHROME_MAX_HTML_CHARS_DEFAULT
        );
        assert_eq!(
            clamp_capture_limit(Some(1), CHROME_MAX_HTML_CHARS_DEFAULT),
            1_024
        );
        assert_eq!(
            clamp_capture_limit(Some(usize::MAX), CHROME_MAX_HTML_CHARS_DEFAULT),
            CHROME_MAX_HTML_CHARS_DEFAULT * CHROME_MAX_CAPTURE_MULTIPLIER
        );
    }

    #[tokio::test]
    async fn socks_handshake_timeout_covers_partial_messages() {
        let listener = TokioTcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind SOCKS test listener");
        let address = listener.local_addr().expect("SOCKS test address");
        let mut client = TcpStream::connect(address)
            .await
            .expect("connect SOCKS test client");
        let (mut server, _) = listener.accept().await.expect("accept SOCKS test client");
        client
            .write_all(&[5, 1])
            .await
            .expect("write partial SOCKS greeting");

        let error = negotiate_browser_proxy(&mut server, Duration::from_millis(25))
            .await
            .expect_err("partial SOCKS greeting must time out");
        assert!(error.to_string().contains("SOCKS handshake timeout"));
    }

    #[tokio::test]
    async fn browser_egress_proxy_relays_only_the_pinned_host_and_port() {
        let upstream = TokioTcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind upstream");
        let upstream_port = upstream.local_addr().expect("upstream address").port();
        let upstream_task = tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.expect("accept upstream");
            let mut request = [0u8; 4];
            stream
                .read_exact(&mut request)
                .await
                .expect("read relay data");
            assert_eq!(&request, b"ping");
            stream.write_all(b"pong").await.expect("write relay data");
        });
        let config = ChromeSessionConfig {
            chrome_binary: PathBuf::from("/bin/chrome"),
            headless: true,
            user_agent: "docdex-test".to_string(),
            user_data_dir: None,
            allow_no_sandbox: false,
            pinned_host: Some("allowed.test".to_string()),
            pinned_address: "127.0.0.1".parse().expect("loopback IP"),
            allowed_ports: vec![upstream_port],
        };
        let proxy = BrowserEgressProxy::start(&config)
            .await
            .expect("start proxy");

        let mut denied = TcpStream::connect(("127.0.0.1", proxy.port()))
            .await
            .expect("connect denied client");
        socks_greet(&mut denied).await;
        write_socks_connect(&mut denied, "blocked.test", upstream_port).await;
        let mut denied_response = [0u8; 10];
        denied
            .read_exact(&mut denied_response)
            .await
            .expect("read denied response");
        assert_eq!(denied_response[1], 2);

        let mut allowed = TcpStream::connect(("127.0.0.1", proxy.port()))
            .await
            .expect("connect allowed client");
        socks_greet(&mut allowed).await;
        write_socks_connect(&mut allowed, "allowed.test", upstream_port).await;
        let mut allowed_response = [0u8; 10];
        allowed
            .read_exact(&mut allowed_response)
            .await
            .expect("read allowed response");
        assert_eq!(allowed_response[1], 0);
        allowed.write_all(b"ping").await.expect("write proxy data");
        let mut response = [0u8; 4];
        allowed
            .read_exact(&mut response)
            .await
            .expect("read proxy data");
        assert_eq!(&response, b"pong");
        upstream_task.await.expect("join upstream");
    }

    async fn socks_greet(stream: &mut TcpStream) {
        stream
            .write_all(&[5, 1, 0])
            .await
            .expect("write SOCKS greeting");
        let mut response = [0u8; 2];
        stream
            .read_exact(&mut response)
            .await
            .expect("read SOCKS greeting");
        assert_eq!(response, [5, 0]);
    }

    async fn write_socks_connect(stream: &mut TcpStream, host: &str, port: u16) {
        let mut request = vec![5, 1, 0, 3, host.len() as u8];
        request.extend_from_slice(host.as_bytes());
        request.extend_from_slice(&port.to_be_bytes());
        stream
            .write_all(&request)
            .await
            .expect("write SOCKS connect");
    }
}
