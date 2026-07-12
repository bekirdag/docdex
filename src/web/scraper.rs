#![allow(dead_code)]

use anyhow::{anyhow, Result};
use once_cell::sync::OnceCell;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::env;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};
use url::Url;

use crate::orchestrator::web_config::WebConfig;
use crate::util::{self, BrowserCandidate, BrowserSource};
use crate::web::browser_install;
use crate::web::chrome::{fetch_dom as fetch_dom_chrome, ChromeFetchConfig, ChromeFetchResult};

use crate::browser_session::BrowserSession;
use crate::metrics;

#[derive(Clone, Debug)]
pub struct ChromeWatchdogConfig {
    pub scan_interval: Duration,
    pub orphan_reap_after: Duration,
    pub graceful_shutdown_timeout: Duration,
    pub kill_timeout: Duration,
    pub max_session_age: Option<Duration>,
    pub unresponsive_timeout: Option<Duration>,
}

impl Default for ChromeWatchdogConfig {
    fn default() -> Self {
        Self {
            scan_interval: Duration::from_secs(5),
            orphan_reap_after: Duration::from_secs(30),
            graceful_shutdown_timeout: Duration::from_secs(2),
            kill_timeout: Duration::from_secs(2),
            max_session_age: Some(Duration::from_secs(7 * 24 * 60 * 60)),
            unresponsive_timeout: None,
        }
    }
}

impl ChromeWatchdogConfig {
    pub fn from_env() -> Option<Self> {
        let enabled = env_boolish("DOCDEX_CHROME_WATCHDOG_ENABLED").unwrap_or(true);
        if !enabled {
            return None;
        }

        let mut config = Self::default();
        if let Some(ms) = env_u64("DOCDEX_CHROME_WATCHDOG_SCAN_INTERVAL_MS") {
            config.scan_interval = Duration::from_millis(ms.max(10));
        }
        if let Some(ms) = env_u64("DOCDEX_CHROME_WATCHDOG_ORPHAN_REAP_AFTER_MS") {
            config.orphan_reap_after = Duration::from_millis(ms.max(0));
        }
        if let Some(ms) = env_u64("DOCDEX_CHROME_WATCHDOG_GRACEFUL_TIMEOUT_MS") {
            config.graceful_shutdown_timeout = Duration::from_millis(ms.max(10));
        }
        if let Some(ms) = env_u64("DOCDEX_CHROME_WATCHDOG_KILL_TIMEOUT_MS") {
            config.kill_timeout = Duration::from_millis(ms.max(10));
        }
        if let Some(ms) = env_u64("DOCDEX_CHROME_WATCHDOG_MAX_SESSION_AGE_MS") {
            config.max_session_age = Some(Duration::from_millis(ms.max(1)));
        }
        if let Some(ms) = env_u64("DOCDEX_CHROME_WATCHDOG_UNRESPONSIVE_TIMEOUT_MS") {
            config.unresponsive_timeout = Some(Duration::from_millis(ms.max(1)));
        }
        Some(config)
    }
}

fn env_u64(key: &str) -> Option<u64> {
    let raw = env::var(key).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    trimmed.parse::<u64>().ok()
}

fn env_boolish(key: &str) -> Option<bool> {
    let raw = env::var(key).ok()?;
    let trimmed = raw.trim().to_ascii_lowercase();
    match trimmed.as_str() {
        "1" | "true" | "t" | "yes" | "y" | "on" => Some(true),
        "0" | "false" | "f" | "no" | "n" | "off" => Some(false),
        _ => None,
    }
}

#[derive(Clone, Debug)]
pub struct TrackedProcess {
    pub pid: u32,
    pub process_group_id: Option<i32>,
}

#[derive(Clone, Debug)]
struct TrackedProcessIdentity {
    process: TrackedProcess,
    owned_session: Option<BrowserSession>,
    #[cfg(windows)]
    windows_handle: Option<Arc<WindowsProcessHandle>>,
}

impl TrackedProcessIdentity {
    fn capture(process: TrackedProcess) -> Self {
        #[cfg(windows)]
        {
            let windows_handle = match WindowsProcessHandle::open(process.pid) {
                Ok(handle) => Some(Arc::new(handle)),
                Err(err) => {
                    warn!(
                        target: "docdexd_browser_guard",
                        event = "chrome_watchdog_process_handle_open_failed",
                        pid = process.pid,
                        error = %err,
                        "watchdog will not terminate a Windows process without a stable handle"
                    );
                    None
                }
            };
            return Self {
                process,
                owned_session: None,
                windows_handle,
            };
        }

        #[cfg(not(windows))]
        Self {
            process,
            owned_session: None,
        }
    }

    fn pid(&self) -> u32 {
        self.process.pid
    }

    fn process_group_id(&self) -> Option<i32> {
        self.process.process_group_id
    }
}

#[cfg(windows)]
#[derive(Debug)]
struct WindowsProcessHandle {
    raw: windows_sys::Win32::Foundation::HANDLE,
}

#[cfg(windows)]
impl WindowsProcessHandle {
    fn open(pid: u32) -> Result<Self, String> {
        use windows_sys::Win32::System::Threading::{
            OpenProcess, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
        };

        let raw = unsafe { OpenProcess(PROCESS_SYNCHRONIZE | PROCESS_TERMINATE, 0, pid) };
        if raw == 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        Ok(Self { raw })
    }

    fn is_alive(&self) -> Result<bool, String> {
        use windows_sys::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
        use windows_sys::Win32::System::Threading::WaitForSingleObject;

        match unsafe { WaitForSingleObject(self.raw, 0) } {
            WAIT_TIMEOUT => Ok(true),
            WAIT_OBJECT_0 => Ok(false),
            status => Err(format!(
                "WaitForSingleObject returned unexpected status {status}: {}",
                std::io::Error::last_os_error()
            )),
        }
    }

    fn terminate(&self) -> Result<(), String> {
        use windows_sys::Win32::System::Threading::TerminateProcess;

        if unsafe { TerminateProcess(self.raw, 1) } == 0 {
            let err = std::io::Error::last_os_error();
            if matches!(self.is_alive(), Ok(false)) {
                return Ok(());
            }
            return Err(err.to_string());
        }
        Ok(())
    }
}

#[cfg(windows)]
impl Drop for WindowsProcessHandle {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.raw);
        }
    }
}

#[derive(Clone)]
pub struct ChromeProcessTracker {
    inner: Arc<Inner>,
}

impl ChromeProcessTracker {
    pub fn register(
        &self,
        session_id: impl Into<String>,
        process: TrackedProcess,
    ) -> ChromeSessionHandle {
        let session_id = session_id.into();
        let process_for_log = process.clone();
        let process = TrackedProcessIdentity::capture(process);
        let token;
        {
            let mut state = self.inner.state.lock();
            token = state.next_token;
            state.next_token = state.next_token.wrapping_add(1).max(1);

            if let Some(previous_token) = state.session_current.get(&session_id).copied() {
                if let Some(previous) = state.records.get_mut(&previous_token) {
                    previous.active = false;
                    previous.ended_at = Some(Instant::now());
                    previous.end_reason = Some(SessionEndReason::Replaced);
                }
            }

            state.session_current.insert(session_id.clone(), token);
            state.records.insert(
                token,
                SessionRecord {
                    session_id: session_id.clone(),
                    token,
                    process,
                    started_at: Instant::now(),
                    last_heartbeat: None,
                    active: true,
                    ended_at: None,
                    end_reason: None,
                    reaping: false,
                    last_reap_attempt: None,
                },
            );
        }

        info!(
            target: "docdexd_browser_guard",
            event = "chrome_watchdog_session_started",
            session_id = session_id.as_str(),
            token,
            pid = process_for_log.pid,
            pgid = process_for_log.process_group_id,
            "chrome watchdog tracking session"
        );

        ChromeSessionHandle {
            session_id,
            token,
            inner: Arc::clone(&self.inner),
        }
    }

    pub(crate) fn register_browser_session(
        &self,
        session_id: impl Into<String>,
        process: TrackedProcess,
        session: BrowserSession,
    ) -> ChromeSessionHandle {
        let handle = self.register(session_id, process);
        if let Some(record) = self.inner.state.lock().records.get_mut(&handle.token) {
            record.process.owned_session = Some(session);
        }
        handle
    }

    pub fn end_session(&self, session_id: &str) {
        let mut state = self.inner.state.lock();
        let Some(token) = state.session_current.get(session_id).copied() else {
            return;
        };
        if let Some(record) = state.records.get_mut(&token) {
            if record.active {
                record.active = false;
                record.ended_at = Some(Instant::now());
                record.end_reason = Some(SessionEndReason::Ended);
                info!(
                    target: "docdexd_browser_guard",
                    event = "chrome_watchdog_session_ended",
                    session_id = record.session_id.as_str(),
                    token = record.token,
                    pid = record.process.pid(),
                    pgid = record.process.process_group_id(),
                    reason = ?SessionEndReason::Ended,
                    "chrome watchdog session ended"
                );
            }
        }
    }

    pub fn heartbeat(&self, session_id: &str) {
        let mut state = self.inner.state.lock();
        let Some(token) = state.session_current.get(session_id).copied() else {
            return;
        };
        if let Some(record) = state.records.get_mut(&token) {
            if record.active {
                record.last_heartbeat = Some(Instant::now());
            }
        }
    }
}

#[derive(Clone)]
pub struct ChromeSessionHandle {
    session_id: String,
    token: u64,
    inner: Arc<Inner>,
}

impl ChromeSessionHandle {
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn pid(&self) -> u32 {
        let state = self.inner.state.lock();
        state
            .records
            .get(&self.token)
            .map(|record| record.process.pid())
            .unwrap_or(0)
    }

    pub fn heartbeat(&self) {
        let mut state = self.inner.state.lock();
        if let Some(record) = state.records.get_mut(&self.token) {
            if record.active {
                record.last_heartbeat = Some(Instant::now());
            }
        }
    }

    pub fn end(&self) {
        let mut state = self.inner.state.lock();
        if let Some(record) = state.records.get_mut(&self.token) {
            if record.active {
                record.active = false;
                record.ended_at = Some(Instant::now());
                record.end_reason = Some(SessionEndReason::Ended);
                info!(
                    target: "docdexd_browser_guard",
                    event = "chrome_watchdog_session_ended",
                    session_id = record.session_id.as_str(),
                    token = record.token,
                    pid = record.process.pid(),
                    pgid = record.process.process_group_id(),
                    reason = ?SessionEndReason::Ended,
                    "chrome watchdog session ended"
                );
            }
        }
    }
}

impl Drop for ChromeSessionHandle {
    fn drop(&mut self) {
        let mut state = self.inner.state.lock();
        if let Some(record) = state.records.get_mut(&self.token) {
            if record.active {
                record.active = false;
                record.ended_at = Some(Instant::now());
                record.end_reason = Some(SessionEndReason::Dropped);
                debug!(
                    target: "docdexd_browser_guard",
                    event = "chrome_watchdog_session_dropped",
                    session_id = record.session_id.as_str(),
                    token = record.token,
                    pid = record.process.pid(),
                    pgid = record.process.process_group_id(),
                    reason = ?SessionEndReason::Dropped,
                    "chrome watchdog session dropped"
                );
            }
        }
    }
}

pub struct ChromeWatchdog {
    tracker: ChromeProcessTracker,
    join: JoinHandle<()>,
}

impl ChromeWatchdog {
    pub fn start(config: ChromeWatchdogConfig) -> Self {
        let (tracker, inner) = new_tracker(config);

        let join = tokio::spawn(watchdog_loop(inner));
        Self { tracker, join }
    }

    pub fn tracker(&self) -> ChromeProcessTracker {
        self.tracker.clone()
    }

    pub async fn shutdown(self) {
        self.tracker.inner.shutdown.store(true, Ordering::Release);
        self.tracker.inner.shutdown_notify.notify_one();
        let _ = self.join.await;
    }
}

struct GlobalWatchdogState {
    tracker: ChromeProcessTracker,
    inner: Arc<Inner>,
    loop_started: AtomicBool,
}

struct GlobalWatchdogLoopGuard(Arc<GlobalWatchdogState>);

impl Drop for GlobalWatchdogLoopGuard {
    fn drop(&mut self) {
        self.0.loop_started.store(false, Ordering::Release);
    }
}

impl GlobalWatchdogState {
    fn ensure_loop_started(self: &Arc<Self>) -> bool {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return false;
        };
        if self
            .loop_started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return true;
        }
        let state = Arc::clone(self);
        handle.spawn(async move {
            let _reset = GlobalWatchdogLoopGuard(Arc::clone(&state));
            watchdog_loop(Arc::clone(&state.inner)).await;
        });
        true
    }
}

static GLOBAL_TRACKER: OnceCell<Arc<GlobalWatchdogState>> = OnceCell::new();
static GLOBAL_WATCHDOG_NO_RUNTIME_WARNING: OnceCell<()> = OnceCell::new();

/// Initializes a detached, process-wide watchdog tracker.
///
/// The watchdog loop is spawned onto the current Tokio runtime (if available).
/// If no runtime is available, the tracker is still initialized but no periodic
/// reaping will occur until `init_global` is called from within a runtime.
pub fn init_global(config: ChromeWatchdogConfig) -> ChromeProcessTracker {
    let state = GLOBAL_TRACKER.get_or_init(|| {
        let (tracker, inner) = new_tracker(config);
        Arc::new(GlobalWatchdogState {
            tracker,
            inner,
            loop_started: AtomicBool::new(false),
        })
    });
    if !state.ensure_loop_started() && GLOBAL_WATCHDOG_NO_RUNTIME_WARNING.set(()).is_ok() {
        warn!(
            target: "docdexd",
            "chrome watchdog initialized without a Tokio runtime; periodic reaping will start when it is next accessed from a runtime"
        );
    }
    state.tracker.clone()
}

pub fn init_global_from_env() -> Option<ChromeProcessTracker> {
    ChromeWatchdogConfig::from_env().map(init_global)
}

pub fn global_tracker() -> Option<ChromeProcessTracker> {
    let state = GLOBAL_TRACKER.get()?;
    state.ensure_loop_started();
    Some(state.tracker.clone())
}

fn new_tracker(config: ChromeWatchdogConfig) -> (ChromeProcessTracker, Arc<Inner>) {
    let inner = Arc::new(Inner {
        config,
        state: Mutex::new(State {
            next_token: 1,
            session_current: HashMap::new(),
            records: HashMap::new(),
        }),
        shutdown: AtomicBool::new(false),
        shutdown_notify: Notify::new(),
    });
    let tracker = ChromeProcessTracker {
        inner: Arc::clone(&inner),
    };
    (tracker, inner)
}

struct Inner {
    config: ChromeWatchdogConfig,
    state: Mutex<State>,
    shutdown: AtomicBool,
    shutdown_notify: Notify,
}

struct State {
    next_token: u64,
    session_current: HashMap<String, u64>,
    records: HashMap<u64, SessionRecord>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SessionEndReason {
    Dropped,
    Ended,
    Replaced,
}

struct SessionRecord {
    session_id: String,
    token: u64,
    process: TrackedProcessIdentity,
    started_at: Instant,
    last_heartbeat: Option<Instant>,
    active: bool,
    ended_at: Option<Instant>,
    end_reason: Option<SessionEndReason>,
    reaping: bool,
    last_reap_attempt: Option<Instant>,
}

#[derive(Debug, Clone, Copy)]
enum ReapReason {
    SessionOrphaned,
    SessionTooOld,
    SessionUnresponsive,
}

async fn watchdog_loop(inner: Arc<Inner>) {
    loop {
        if inner.shutdown.load(Ordering::Acquire) {
            break;
        }
        tokio::select! {
            _ = inner.shutdown_notify.notified() => {
                continue;
            }
            _ = tokio::time::sleep(inner.config.scan_interval) => {
                run_scan(&inner).await;
            }
        }
    }
}

async fn run_scan(inner: &Arc<Inner>) {
    let now = Instant::now();
    let mut candidates: Vec<(String, u64, TrackedProcessIdentity, ReapReason)> = Vec::new();
    let mut to_remove: Vec<u64> = Vec::new();

    {
        let mut state = inner.state.lock();
        for (token, record) in state.records.iter_mut() {
            if record.reaping {
                continue;
            }

            if !is_process_alive(&record.process) {
                metrics::global().inc_chrome_watchdog_reaped();
                debug!(
                    target: "docdexd",
                    session_id = record.session_id.as_str(),
                    pid = record.process.pid(),
                    "watchdog: tracked Chrome process already exited; removing record"
                );
                to_remove.push(*token);
                continue;
            }

            let reason = if !record.active {
                let ended_at = record.ended_at.unwrap_or(record.started_at);
                if now.saturating_duration_since(ended_at) >= inner.config.orphan_reap_after {
                    Some(ReapReason::SessionOrphaned)
                } else {
                    None
                }
            } else if inner
                .config
                .max_session_age
                .is_some_and(|ttl| now.saturating_duration_since(record.started_at) >= ttl)
            {
                Some(ReapReason::SessionTooOld)
            } else if inner.config.unresponsive_timeout.is_some() {
                // Safety: only enforce unresponsive timeouts when the session has opted into sending heartbeats.
                record.last_heartbeat.and_then(|last| {
                    inner.config.unresponsive_timeout.and_then(|timeout| {
                        (now.saturating_duration_since(last) >= timeout)
                            .then_some(ReapReason::SessionUnresponsive)
                    })
                })
            } else {
                None
            };

            if let Some(reason) = reason {
                record.reaping = true;
                record.last_reap_attempt = Some(now);
                candidates.push((
                    record.session_id.clone(),
                    record.token,
                    record.process.clone(),
                    reason,
                ));
            }
        }

        for token in &to_remove {
            let Some(record) = state.records.remove(token) else {
                continue;
            };
            if state
                .session_current
                .get(&record.session_id)
                .is_some_and(|current| *current == record.token)
            {
                state.session_current.remove(&record.session_id);
            }
        }
    }

    for (session_id, token, process, reason) in candidates {
        reap_one(inner, &session_id, token, process, reason).await;
    }
}

async fn reap_one(
    inner: &Arc<Inner>,
    session_id: &str,
    token: u64,
    process: TrackedProcessIdentity,
    reason: ReapReason,
) {
    let pid = process.pid();
    let pgid = process.process_group_id();

    metrics::global().inc_chrome_watchdog_reap_attempt();
    info!(
        target: "docdexd",
        event = "chrome_watchdog_reap_start",
        session_id,
        pid,
        pgid,
        ?reason,
        "watchdog: reaping orphaned/unhealthy Chrome process"
    );

    let result = terminate_process(
        &process,
        inner.config.graceful_shutdown_timeout,
        inner.config.kill_timeout,
    )
    .await;

    match &result {
        Ok(()) => debug!(
            target: "docdexd",
            event = "chrome_watchdog_reap_done",
            session_id,
            pid,
            "watchdog: terminate attempt complete"
        ),
        Err(err) => warn!(
            target: "docdexd",
            event = "chrome_watchdog_reap_done",
            session_id,
            pid,
            error = %err,
            "watchdog: terminate attempt failed"
        ),
    }

    let mut state = inner.state.lock();
    let Some(record) = state.records.get_mut(&token) else {
        return;
    };

    let owned_session_terminated = record.process.owned_session.is_some() && result.is_ok();
    if owned_session_terminated || !is_process_alive(&record.process) {
        metrics::global().inc_chrome_watchdog_reaped();
        let record = state.records.remove(&token).expect("present");
        if state
            .session_current
            .get(&record.session_id)
            .is_some_and(|current| *current == record.token)
        {
            state.session_current.remove(&record.session_id);
        }
    } else {
        metrics::global().inc_chrome_watchdog_reap_failure();
        record.reaping = false;
    }
}

fn is_process_alive(process: &TrackedProcessIdentity) -> bool {
    #[cfg(unix)]
    {
        if let Some(pgid) = process.process_group_id() {
            return process_group_alive(pgid);
        }
        return pid_alive(process.pid() as i32);
    }

    #[cfg(windows)]
    {
        let Some(handle) = process.windows_handle.as_deref() else {
            // Without a captured handle, the PID may have been reused. Treat liveness as unknown
            // and leave cleanup to BrowserSession rather than risking another process.
            return true;
        };
        return match handle.is_alive() {
            Ok(alive) => alive,
            Err(err) => {
                debug!(
                    target: "docdexd_browser_guard",
                    event = "chrome_watchdog_process_liveness_unknown",
                    pid = process.pid(),
                    error = %err,
                    "watchdog could not query stable Windows process handle"
                );
                true
            }
        };
    }

    #[cfg(all(not(unix), not(windows)))]
    {
        let _ = process;
        true
    }
}

async fn terminate_process(
    process: &TrackedProcessIdentity,
    graceful_timeout: Duration,
    kill_timeout: Duration,
) -> Result<(), String> {
    if let Some(session) = process.owned_session.as_ref() {
        session.abort().await.map_err(|error| error.to_string())?;
        return Ok(());
    }

    #[cfg(unix)]
    {
        if let Some(pgid) = process.process_group_id() {
            signal_process_group(pgid, nix::libc::SIGTERM);
            if wait_until_dead(process, graceful_timeout).await {
                return Ok(());
            }

            debug!(
                target: "docdexd",
                event = "chrome_watchdog_kill_escalation",
                pid = process.pid(),
                pgid,
                "watchdog escalating to SIGKILL"
            );
            signal_process_group(pgid, nix::libc::SIGKILL);
            if wait_until_dead(process, kill_timeout).await {
                return Ok(());
            }
            return Err("process group did not exit after SIGKILL".to_string());
        }

        signal_pid(process.pid() as i32, nix::libc::SIGTERM);
        if wait_until_dead(process, graceful_timeout).await {
            return Ok(());
        }
        debug!(
            target: "docdexd",
            event = "chrome_watchdog_kill_escalation",
            pid = process.pid(),
            "watchdog escalating to SIGKILL"
        );
        signal_pid(process.pid() as i32, nix::libc::SIGKILL);
        if wait_until_dead(process, kill_timeout).await {
            return Ok(());
        }
        return Err("process did not exit after SIGKILL".to_string());
    }

    #[cfg(windows)]
    {
        let handle = process.windows_handle.as_deref().ok_or_else(|| {
            "stable Windows process handle unavailable; refusing PID-based termination".to_string()
        })?;

        // Windows has no process-agnostic graceful signal. Give an already-closing process its
        // configured grace period, then terminate the exact kernel object captured at registration.
        if wait_until_dead(process, graceful_timeout).await {
            return Ok(());
        }
        debug!(
            target: "docdexd_browser_guard",
            event = "chrome_watchdog_kill_escalation",
            pid = process.pid(),
            "watchdog terminating stable Windows process handle"
        );
        handle.terminate()?;
        if wait_until_dead(process, kill_timeout).await {
            return Ok(());
        }
        Err("process did not exit after TerminateProcess".to_string())
    }

    #[cfg(all(not(unix), not(windows)))]
    {
        let _ = (process, graceful_timeout, kill_timeout);
        Err("process termination is not supported on this platform".to_string())
    }
}

async fn wait_until_dead(process: &TrackedProcessIdentity, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if !is_process_alive(process) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    !is_process_alive(process)
}

#[cfg(unix)]
fn pid_alive(pid: i32) -> bool {
    let rc = unsafe { nix::libc::kill(pid, 0) };
    if rc == 0 {
        return true;
    }
    let err = std::io::Error::last_os_error();
    match err.raw_os_error() {
        Some(code) if code == nix::libc::ESRCH => false,
        _ => true,
    }
}

#[cfg(unix)]
fn process_group_alive(pgid: i32) -> bool {
    let rc = unsafe { nix::libc::killpg(pgid, 0) };
    if rc == 0 {
        return true;
    }
    let err = std::io::Error::last_os_error();
    match err.raw_os_error() {
        Some(code) if code == nix::libc::ESRCH => false,
        _ => true,
    }
}

#[cfg(unix)]
fn signal_process_group(pgid: i32, signal: i32) {
    let rc = unsafe { nix::libc::killpg(pgid, signal) };
    if rc == -1 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(nix::libc::ESRCH) {
            debug!(target: "docdexd", "killpg({pgid},{signal}) failed: {err}");
        }
    }
}

#[cfg(unix)]
fn signal_pid(pid: i32, signal: i32) {
    let rc = unsafe { nix::libc::kill(pid, signal) };
    if rc == -1 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() != Some(nix::libc::ESRCH) {
            debug!(target: "docdexd", "kill({pid},{signal}) failed: {err}");
        }
    }
}

#[derive(Clone, Debug)]
pub enum ScraperEngine {
    Chrome { config: ChromeFetchConfig },
}

static MANAGED_BROWSER_MAINTENANCE_ACTIVE: AtomicBool = AtomicBool::new(false);

struct ManagedBrowserMaintenanceGuard;

impl Drop for ManagedBrowserMaintenanceGuard {
    fn drop(&mut self) {
        MANAGED_BROWSER_MAINTENANCE_ACTIVE.store(false, Ordering::Release);
    }
}

impl ScraperEngine {
    /// Resolve only an already-usable browser and schedule managed-browser
    /// maintenance independently of the caller. This keeps cache/direct-fetch
    /// request deadlines free of blocking installer work.
    pub fn from_web_config_if_available(config: &WebConfig) -> Option<Self> {
        warn_if_scraper_engine_is_unsupported(config);
        let detected = util::detect_browser_binary(config.chrome_binary_path.as_deref());
        let managed = should_refresh_managed_browser(detected.as_ref());
        let chrome_config = ChromeFetchConfig::from_web_config(config);
        if managed || chrome_config.is_none() {
            schedule_managed_browser_maintenance(config.scraper_auto_install);
        }
        chrome_config.map(|config| ScraperEngine::Chrome { config })
    }

    pub async fn from_web_config(config: &WebConfig) -> Result<Self> {
        warn_if_scraper_engine_is_unsupported(config);
        let detected = util::detect_browser_binary(config.chrome_binary_path.as_deref());
        if should_refresh_managed_browser(detected.as_ref()) {
            let refresh = tokio::task::spawn_blocking({
                let auto_install = config.scraper_auto_install;
                move || browser_install::install_or_refresh_managed(auto_install)
            })
            .await;
            match refresh {
                Ok(Ok(Some(result))) => info!(
                    path = %result.path.display(),
                    version = %result.version,
                    "validated managed Chromium refresh state for web scraper"
                ),
                Ok(Ok(None)) => {}
                Ok(Err(err)) => warn!(
                    error = %err,
                    "managed Chromium refresh failed; continuing with the validated detected binary"
                ),
                Err(err) => warn!(
                    error = %err,
                    "managed Chromium refresh task failed; continuing with the validated detected binary"
                ),
            }
        }
        let chrome_config = match ChromeFetchConfig::from_web_config(config) {
            Some(chrome_config) => chrome_config,
            None => match tokio::task::spawn_blocking({
                let auto_install = config.scraper_auto_install;
                move || browser_install::install_or_refresh_managed(auto_install)
            })
            .await
            .map_err(|err| anyhow!("browser install task failed: {err}"))?
            {
                Ok(Some(result)) => {
                    info!(
                        path = %result.path.display(),
                        version = %result.version,
                        "installed managed Chromium for web scraper"
                    );
                    let mut installed_config = config.clone();
                    installed_config.chrome_binary_path = Some(result.path);
                    ChromeFetchConfig::from_web_config(&installed_config).ok_or_else(|| {
                        anyhow!("managed Chromium install completed but binary is unavailable")
                    })?
                }
                Ok(None) => {
                    return Err(anyhow!(
                        "chromium browser not configured; run `docdexd browser install`"
                    ));
                }
                Err(err) => {
                    return Err(anyhow!(
                        "chromium browser not configured and auto-install failed: {err}"
                    ));
                }
            },
        };
        Ok(ScraperEngine::Chrome {
            config: chrome_config,
        })
    }

    pub async fn fetch_dom(&self, url: &Url) -> Result<ChromeFetchResult> {
        match self {
            ScraperEngine::Chrome { config } => fetch_dom_chrome(url, config).await,
        }
    }
}

fn should_refresh_managed_browser(candidate: Option<&BrowserCandidate>) -> bool {
    candidate.is_some_and(|candidate| candidate.source == BrowserSource::AutoInstall)
}

fn warn_if_scraper_engine_is_unsupported(config: &WebConfig) {
    let engine = config.scraper_engine.trim().to_ascii_lowercase();
    if !engine.is_empty()
        && engine != "chrome"
        && engine != "chromium"
        && engine != "chromium-browser"
    {
        warn!(
            "web scraper engine {} is not supported; using chromium",
            config.scraper_engine
        );
    }
}

fn schedule_managed_browser_maintenance(auto_install: bool) {
    if MANAGED_BROWSER_MAINTENANCE_ACTIVE
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }
    let spawned = std::thread::Builder::new()
        .name("docdex-browser-maintenance".to_string())
        .spawn(move || {
            let _guard = ManagedBrowserMaintenanceGuard;
            match browser_install::install_or_refresh_managed(auto_install) {
                Ok(Some(result)) => info!(
                    path = %result.path.display(),
                    version = %result.version,
                    "managed Chromium background maintenance completed"
                ),
                Ok(None) => {}
                Err(err) => warn!(
                    error = %err,
                    "managed Chromium background maintenance failed"
                ),
            }
        });
    if let Err(err) = spawned {
        MANAGED_BROWSER_MAINTENANCE_ACTIVE.store(false, Ordering::Release);
        warn!(
            error = %err,
            "failed to start managed Chromium background maintenance thread"
        );
    }
}

#[cfg(test)]
mod tests {
    #[cfg(any(unix, windows))]
    use super::*;

    #[test]
    fn only_the_selected_managed_browser_enters_the_refresh_path() {
        let mut candidate = BrowserCandidate {
            kind: util::BrowserKind::Chromium,
            name: "Docdex Chromium".to_string(),
            path: std::path::PathBuf::from("managed-chromium"),
            source: BrowserSource::AutoInstall,
            priority: 0,
        };
        assert!(should_refresh_managed_browser(Some(&candidate)));

        candidate.source = BrowserSource::Config;
        assert!(!should_refresh_managed_browser(Some(&candidate)));
        assert!(!should_refresh_managed_browser(None));
    }

    #[test]
    fn watchdog_loop_can_start_after_initialization_outside_a_runtime() {
        let (tracker, inner) = new_tracker(ChromeWatchdogConfig {
            scan_interval: Duration::from_millis(10),
            ..ChromeWatchdogConfig::default()
        });
        let state = Arc::new(GlobalWatchdogState {
            tracker,
            inner,
            loop_started: AtomicBool::new(false),
        });
        assert!(!state.ensure_loop_started());

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("test runtime");
        runtime.block_on(async {
            assert!(state.ensure_loop_started());
            assert!(state.loop_started.load(Ordering::Acquire));
            state.inner.shutdown.store(true, Ordering::Release);
            state.inner.shutdown_notify.notify_one();
            let deadline = Instant::now() + Duration::from_secs(1);
            while state.loop_started.load(Ordering::Acquire) && Instant::now() < deadline {
                tokio::task::yield_now().await;
            }
            assert!(!state.loop_started.load(Ordering::Acquire));
        });
    }

    #[tokio::test]
    #[cfg(windows)]
    async fn windows_watchdog_tracks_and_terminates_the_captured_process_handle() {
        use std::process::Stdio;

        let mut child = tokio::process::Command::new("ping")
            .args(["-n", "60", "127.0.0.1"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn ping");
        let pid = child.id().expect("ping pid");
        let process = TrackedProcessIdentity::capture(TrackedProcess {
            pid,
            process_group_id: None,
        });

        assert!(
            process.windows_handle.is_some(),
            "expected a stable Windows process handle"
        );
        assert!(is_process_alive(&process));

        terminate_process(&process, Duration::from_millis(1), Duration::from_secs(2))
            .await
            .expect("terminate captured process");
        let _ = tokio::time::timeout(Duration::from_secs(2), child.wait())
            .await
            .expect("child wait timeout")
            .expect("wait for ping");
        assert!(!is_process_alive(&process));
    }

    #[tokio::test]
    #[cfg(windows)]
    async fn windows_watchdog_refuses_pid_only_termination() {
        let process = TrackedProcessIdentity {
            process: TrackedProcess {
                pid: u32::MAX,
                process_group_id: None,
            },
            owned_session: None,
            windows_handle: None,
        };

        assert!(
            is_process_alive(&process),
            "unknown liveness must fail safe"
        );
        let err = terminate_process(&process, Duration::ZERO, Duration::ZERO)
            .await
            .expect_err("PID-only termination must be rejected");
        assert!(err.contains("refusing PID-based termination"));
    }

    #[cfg(unix)]
    fn resolve_shell() -> Option<std::path::PathBuf> {
        const CANDIDATES: [&str; 2] = ["/bin/sh", "/usr/bin/sh"];
        for candidate in CANDIDATES {
            let path = std::path::Path::new(candidate);
            if path.exists() {
                return Some(path.to_path_buf());
            }
        }
        if let Some(shell) = std::env::var_os("SHELL") {
            let path = std::path::PathBuf::from(shell);
            if path.exists() {
                return Some(path);
            }
        }
        None
    }

    #[cfg(unix)]
    fn shell_command() -> Option<tokio::process::Command> {
        let shell = resolve_shell()?;
        Some(tokio::process::Command::new(shell))
    }

    fn prometheus_counter(text: &str, name: &str) -> u64 {
        for line in text.lines() {
            if line.starts_with(name) {
                if let Some(value) = line.split_whitespace().nth(1) {
                    if let Ok(parsed) = value.parse::<u64>() {
                        return parsed;
                    }
                }
            }
        }
        0
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn reaps_orphaned_process_after_grace() {
        use std::io;
        use tempfile::TempDir;
        let before = crate::metrics::global().render_prometheus();
        let before_reaped = prometheus_counter(&before, "docdex_chrome_watchdog_reaped_total");

        let watchdog = ChromeWatchdog::start(ChromeWatchdogConfig {
            scan_interval: Duration::from_millis(50),
            orphan_reap_after: Duration::from_millis(100),
            graceful_shutdown_timeout: Duration::from_millis(100),
            kill_timeout: Duration::from_millis(200),
            max_session_age: None,
            unresponsive_timeout: None,
        });
        let tracker = watchdog.tracker();

        let temp = TempDir::new().expect("temp dir");
        let pid_file = temp.path().join("orphan.pid");

        let mut cmd = match shell_command() {
            Some(cmd) => cmd,
            None => {
                eprintln!("skipping: no POSIX shell found");
                return;
            }
        };
        cmd.arg("-c")
            .arg(r#"nohup sleep 1000 >/dev/null 2>&1 & echo $! > "$1""#)
            .arg("sh")
            .arg(pid_file.as_os_str());
        unsafe {
            cmd.pre_exec(|| {
                let rc = nix::libc::setsid();
                if rc == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = cmd.spawn().expect("spawn helper process");

        let deadline = Instant::now() + Duration::from_secs(2);
        let sleep_pid: u32 = loop {
            if let Ok(text) = std::fs::read_to_string(&pid_file) {
                if let Ok(pid) = text.trim().parse::<u32>() {
                    break pid;
                }
            }
            if Instant::now() > deadline {
                panic!("timed out waiting for orphan pid file");
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        };

        // Reap the helper so it doesn't become a zombie itself.
        let _ = tokio::time::timeout(Duration::from_secs(2), child.wait())
            .await
            .expect("helper wait timeout");

        let pgid = unsafe { nix::libc::getpgid(sleep_pid as i32) };
        if pgid == -1 {
            let err = io::Error::last_os_error();
            eprintln!("skipping: getpgid failed: {err}");
            watchdog.shutdown().await;
            return;
        }

        let handle = tracker.register(
            "session-orphan",
            TrackedProcess {
                pid: sleep_pid,
                process_group_id: Some(pgid),
            },
        );
        handle.end(); // Session ended, process still alive -> should be reaped.
        drop(handle);

        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline && process_group_alive(pgid) {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(
            !process_group_alive(pgid),
            "expected orphaned process group to be reaped"
        );

        let metrics_deadline = Instant::now() + Duration::from_secs(2);
        let after_reaped = loop {
            let snapshot = crate::metrics::global().render_prometheus();
            let value = prometheus_counter(&snapshot, "docdex_chrome_watchdog_reaped_total");
            if value >= before_reaped + 1 || Instant::now() > metrics_deadline {
                break value;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        };
        assert!(
            after_reaped >= before_reaped + 1,
            "expected watchdog reaped counter to increment"
        );

        watchdog.shutdown().await;
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn does_not_reap_active_session_without_opt_in_timeouts() {
        use std::io;
        use tempfile::TempDir;
        let watchdog = ChromeWatchdog::start(ChromeWatchdogConfig {
            scan_interval: Duration::from_millis(50),
            orphan_reap_after: Duration::from_millis(100),
            graceful_shutdown_timeout: Duration::from_millis(100),
            kill_timeout: Duration::from_millis(200),
            max_session_age: None,
            unresponsive_timeout: Some(Duration::from_millis(100)), // Opt-in, but requires heartbeats.
        });
        let tracker = watchdog.tracker();

        let temp = TempDir::new().expect("temp dir");
        let pid_file = temp.path().join("active.pid");

        let mut cmd = match shell_command() {
            Some(cmd) => cmd,
            None => {
                eprintln!("skipping: no POSIX shell found");
                return;
            }
        };
        cmd.arg("-c")
            .arg(r#"nohup sleep 1000 >/dev/null 2>&1 & echo $! > "$1""#)
            .arg("sh")
            .arg(pid_file.as_os_str());
        unsafe {
            cmd.pre_exec(|| {
                let rc = nix::libc::setsid();
                if rc == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = cmd.spawn().expect("spawn helper process");

        let deadline = Instant::now() + Duration::from_secs(2);
        let sleep_pid: u32 = loop {
            if let Ok(text) = std::fs::read_to_string(&pid_file) {
                if let Ok(pid) = text.trim().parse::<u32>() {
                    break pid;
                }
            }
            if Instant::now() > deadline {
                panic!("timed out waiting for orphan pid file");
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        };

        let _ = tokio::time::timeout(Duration::from_secs(2), child.wait())
            .await
            .expect("helper wait timeout");

        let pgid = unsafe { nix::libc::getpgid(sleep_pid as i32) };
        if pgid == -1 {
            let err = io::Error::last_os_error();
            eprintln!("skipping: getpgid failed: {err}");
            watchdog.shutdown().await;
            return;
        }

        let _handle = tracker.register(
            "session-active",
            TrackedProcess {
                pid: sleep_pid,
                process_group_id: Some(pgid),
            },
        );

        tokio::time::sleep(Duration::from_millis(250)).await;
        assert!(
            process_group_alive(pgid),
            "active session should not be reaped without opt-in heartbeats"
        );

        // End the session and ensure the watchdog does cleanup before shutdown.
        tracker.end_session("session-active");
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline && process_group_alive(pgid) {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }

        watchdog.shutdown().await;
    }
}
