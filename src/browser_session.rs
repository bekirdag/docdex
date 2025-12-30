#![allow(dead_code)]

use std::fs::{self, File, OpenOptions};
use std::future::Future;
use std::io;
use std::io::{Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::process::Output;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::sync::Notify;

use crate::metrics;
use crate::state_layout::{self, StateLayout};

#[cfg(test)]
static BROWSER_SESSION_TEST_EVENTS: std::sync::OnceLock<std::sync::Mutex<Vec<String>>> =
    std::sync::OnceLock::new();

#[cfg(test)]
fn record_test_event(name: &str) {
    let events = BROWSER_SESSION_TEST_EVENTS.get_or_init(|| std::sync::Mutex::new(Vec::new()));
    let mut guard = events.lock().unwrap();
    guard.push(name.to_string());
}

#[derive(Debug, Clone)]
pub struct BrowserSessionOptions {
    pub lock_file: Option<PathBuf>,
    pub graceful_shutdown_timeout: Duration,
    pub kill_timeout: Duration,
}

impl Default for BrowserSessionOptions {
    fn default() -> Self {
        Self {
            lock_file: default_lock_file_path(),
            graceful_shutdown_timeout: Duration::from_secs(2),
            kill_timeout: Duration::from_secs(2),
        }
    }
}

impl BrowserSessionOptions {
    pub fn without_lock() -> Self {
        Self {
            lock_file: None,
            ..Self::default()
        }
    }
}

#[derive(Debug, Clone, Error)]
pub enum BrowserSessionError {
    #[error("browser session cancelled")]
    Cancelled,
    #[error("browser session timed out after {0:?}")]
    TimedOut(Duration),
    #[error("browser session work failed: {0}")]
    WorkFailed(String),
    #[error("browser session launch failed: {0}")]
    LaunchFailed(String),
    #[error("browser session cleanup failed: {0}")]
    CleanupFailed(String),
}

#[derive(Debug)]
struct LockFile {
    path: PathBuf,
    _file: File,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BrowserLockMetadata {
    pid: Option<u32>,
    created_at_epoch_ms: u64,
}

const LOCK_STARTUP_GRACE: Duration = Duration::from_secs(30);
const LOCK_STALE_AGE: Duration = Duration::from_secs(300);

impl LockFile {
    fn write_metadata(&mut self, pid: Option<u32>) -> Result<(), BrowserSessionError> {
        let metadata = BrowserLockMetadata {
            pid,
            created_at_epoch_ms: now_epoch_ms(),
        };
        let data = serde_json::to_vec(&metadata)
            .map_err(|err| BrowserSessionError::LaunchFailed(err.to_string()))?;
        if let Err(err) = self._file.set_len(0) {
            return Err(BrowserSessionError::LaunchFailed(err.to_string()));
        }
        if let Err(err) = self._file.seek(SeekFrom::Start(0)) {
            return Err(BrowserSessionError::LaunchFailed(err.to_string()));
        }
        self._file
            .write_all(&data)
            .map_err(|err| BrowserSessionError::LaunchFailed(err.to_string()))?;
        self._file
            .flush()
            .map_err(|err| BrowserSessionError::LaunchFailed(err.to_string()))?;
        Ok(())
    }
}

#[derive(Debug)]
struct Inner {
    child: Mutex<Option<tokio::process::Child>>,
    pid: u32,
    #[cfg(unix)]
    pgid: i32,
    lock: Mutex<Option<LockFile>>,
    graceful_shutdown_timeout: Duration,
    kill_timeout: Duration,
    cleanup_started: AtomicBool,
    cleanup_result: Mutex<Option<Result<(), BrowserSessionError>>>,
    cleanup_notify: Notify,
}

#[derive(Clone, Debug)]
pub struct BrowserSession {
    inner: Arc<Inner>,
}

impl BrowserSession {
    pub async fn spawn(
        mut command: Command,
        opts: BrowserSessionOptions,
    ) -> Result<Self, BrowserSessionError> {
        let lock_path = opts.lock_file.clone();
        let mut lock = match opts.lock_file {
            Some(path) => Some(create_lock_file(&path).map_err(|err| {
                metrics::global().inc_browser_session_launch_failure();
                tracing::warn!(
                    target: "docdexd_browser_guard",
                    event = "browser_session_lock_failed",
                    lock_file = %path.display(),
                    error = %err,
                    "browser session lock failed"
                );
                err
            })?),
            None => None,
        };

        #[cfg(unix)]
        {
            unsafe {
                command.pre_exec(|| {
                    // New session/process-group so we can SIGTERM/SIGKILL the whole tree (Chrome spawns children).
                    let rc = nix::libc::setsid();
                    if rc == -1 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }

        let child = match command.spawn() {
            Ok(child) => child,
            Err(err) => {
                if let Some(lock) = lock.take() {
                    drop(lock);
                    if let Some(path) = lock_path.as_ref() {
                        let _ = fs::remove_file(path);
                    }
                }
                metrics::global().inc_browser_session_launch_failure();
                tracing::warn!(
                    target: "docdexd_browser_guard",
                    event = "browser_session_launch_failed",
                    lock_file = ?lock_path.as_ref().map(|p| p.display().to_string()),
                    error = %err,
                    "browser session launch failed"
                );
                return Err(BrowserSessionError::LaunchFailed(err.to_string()));
            }
        };
        let pid = child.id().ok_or_else(|| {
            metrics::global().inc_browser_session_launch_failure();
            BrowserSessionError::LaunchFailed("spawned process did not expose a PID".to_string())
        })?;

        if let Some(lock) = lock.as_mut() {
            if let Err(err) = lock.write_metadata(Some(pid)) {
                tracing::warn!(
                    target: "docdexd_browser_guard",
                    event = "browser_session_lock_metadata_failed",
                    lock_file = ?lock_path.as_ref().map(|p| p.display().to_string()),
                    error = %err,
                    "browser session lock metadata update failed"
                );
            }
        }

        metrics::global().inc_browser_session_active();
        #[cfg(unix)]
        tracing::info!(
            target: "docdexd_browser_guard",
            event = "browser_session_started",
            pid,
            pgid = pid as i32,
            lock_file = ?lock_path.as_ref().map(|p| p.display().to_string()),
            "browser session started"
        );
        #[cfg(not(unix))]
        tracing::info!(
            target: "docdexd_browser_guard",
            event = "browser_session_started",
            pid,
            lock_file = ?lock_path.as_ref().map(|p| p.display().to_string()),
            "browser session started"
        );
        #[cfg(test)]
        record_test_event("browser_session_started");

        Ok(Self {
            inner: Arc::new(Inner {
                child: Mutex::new(Some(child)),
                pid,
                #[cfg(unix)]
                pgid: pid as i32,
                lock: Mutex::new(lock),
                graceful_shutdown_timeout: opts.graceful_shutdown_timeout,
                kill_timeout: opts.kill_timeout,
                cleanup_started: AtomicBool::new(false),
                cleanup_result: Mutex::new(None),
                cleanup_notify: Notify::new(),
            }),
        })
    }

    pub fn pid(&self) -> u32 {
        self.inner.pid
    }

    #[cfg(unix)]
    pub fn process_group_id(&self) -> i32 {
        self.inner.pgid
    }

    pub async fn close(&self) -> Result<(), BrowserSessionError> {
        self.cleanup(false).await
    }

    pub async fn abort(&self) -> Result<(), BrowserSessionError> {
        self.cleanup(true).await
    }

    pub async fn wait_for_output(self, timeout: Duration) -> Result<Output, BrowserSessionError> {
        let _ = self.inner.cleanup_started.swap(true, Ordering::AcqRel);
        let mut child = self
            .inner
            .child
            .lock()
            .take()
            .ok_or_else(|| BrowserSessionError::CleanupFailed("child already taken".to_string()))?;
        let mut stdout_task = None;
        let mut stderr_task = None;
        if let Some(stdout) = child.stdout.take() {
            stdout_task = Some(tokio::spawn(read_all(stdout)));
        }
        if let Some(stderr) = child.stderr.take() {
            stderr_task = Some(tokio::spawn(read_all(stderr)));
        }

        let status = match tokio::time::timeout(timeout, child.wait()).await {
            Ok(Ok(status)) => Ok(status),
            Ok(Err(err)) => Err(BrowserSessionError::WorkFailed(err.to_string())),
            Err(_) => {
                #[cfg(unix)]
                signal_process_group(self.inner.pgid, nix::libc::SIGKILL);
                #[cfg(not(unix))]
                {
                    let _ = child.start_kill();
                }
                let _ = wait_with_timeout(&mut child, self.inner.kill_timeout).await;
                Err(BrowserSessionError::TimedOut(timeout))
            }
        };

        let output = match status {
            Ok(status) => {
                let stdout = join_bytes(stdout_task).await;
                let stderr = join_bytes(stderr_task).await;
                Ok(Output {
                    status,
                    stdout,
                    stderr,
                })
            }
            Err(err) => Err(err),
        };
        metrics::global().dec_browser_session_active();
        cleanup_lock(&self.inner);
        output
    }

    pub async fn run_scoped<T, Cancel, Work>(
        &self,
        timeout: Duration,
        cancel: Cancel,
        work: Work,
    ) -> Result<T, BrowserSessionError>
    where
        Cancel: Future<Output = ()> + Send,
        Work: Future<Output = anyhow::Result<T>> + Send,
        T: Send,
    {
        tokio::pin!(cancel);
        tokio::pin!(work);
        let timeout_sleep = tokio::time::sleep(timeout);
        tokio::pin!(timeout_sleep);

        let outcome = tokio::select! {
            res = &mut work => Outcome::Work(res),
            _ = &mut cancel => Outcome::Cancelled,
            _ = &mut timeout_sleep => Outcome::TimedOut,
        };

        let close_result = self.close().await;
        match close_result {
            Err(err) => Err(err),
            Ok(()) => match outcome {
                Outcome::Work(Ok(value)) => Ok(value),
                Outcome::Work(Err(err)) => Err(BrowserSessionError::WorkFailed(err.to_string())),
                Outcome::Cancelled => Err(BrowserSessionError::Cancelled),
                Outcome::TimedOut => Err(BrowserSessionError::TimedOut(timeout)),
            },
        }
    }

    async fn cleanup(&self, force_kill: bool) -> Result<(), BrowserSessionError> {
        if !self.inner.cleanup_started.swap(true, Ordering::AcqRel) {
            let result = cleanup_inner(&self.inner, force_kill).await;
            *self.inner.cleanup_result.lock() = Some(result.clone());
            self.inner.cleanup_notify.notify_waiters();
            return result;
        }

        loop {
            if let Some(result) = self.inner.cleanup_result.lock().clone() {
                return result;
            }
            self.inner.cleanup_notify.notified().await;
        }
    }
}

async fn read_all<R: tokio::io::AsyncRead + Unpin + Send + 'static>(
    mut reader: R,
) -> Vec<u8> {
    let mut buf = Vec::new();
    let _ = reader.read_to_end(&mut buf).await;
    buf
}

async fn join_bytes(
    handle: Option<tokio::task::JoinHandle<Vec<u8>>>,
) -> Vec<u8> {
    match handle {
        Some(handle) => handle.await.unwrap_or_default(),
        None => Vec::new(),
    }
}

impl Drop for BrowserSession {
    fn drop(&mut self) {
        if Arc::strong_count(&self.inner) != 1 {
            return;
        }

        if self.inner.cleanup_started.swap(true, Ordering::AcqRel) {
            return;
        }

        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let inner = Arc::clone(&self.inner);
            handle.spawn(async move {
                let result = cleanup_inner(&inner, true).await;
                *inner.cleanup_result.lock() = Some(result);
                inner.cleanup_notify.notify_waiters();
            });
        } else {
            best_effort_abort_sync(&self.inner);
        }
    }
}

#[derive(Debug)]
enum Outcome<T> {
    Work(anyhow::Result<T>),
    Cancelled,
    TimedOut,
}

fn create_lock_file(path: &PathBuf) -> Result<LockFile, BrowserSessionError> {
    if let Some(parent) = path.parent() {
        state_layout::ensure_state_dir_secure(parent)
            .map_err(|err| BrowserSessionError::LaunchFailed(err.to_string()))?;
    }
    for _ in 0..2 {
        match OpenOptions::new().create_new(true).write(true).open(path) {
            Ok(file) => {
                let mut lock = LockFile {
                    path: path.clone(),
                    _file: file,
                };
                lock.write_metadata(None)?;
                return Ok(lock);
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
                if try_remove_stale_lock(path)? {
                    continue;
                }
                return Err(BrowserSessionError::LaunchFailed(format!(
                    "lock already held: {}",
                    path.display()
                )));
            }
            Err(err) => {
                return Err(BrowserSessionError::LaunchFailed(err.to_string()));
            }
        }
    }
    Err(BrowserSessionError::LaunchFailed(format!(
        "lock already held: {}",
        path.display()
    )))
}

fn try_remove_stale_lock(path: &PathBuf) -> Result<bool, BrowserSessionError> {
    let metadata = read_lock_metadata(path);
    let age = metadata
        .as_ref()
        .and_then(|meta| age_from_epoch_ms(meta.created_at_epoch_ms))
        .or_else(|| lock_age(path));
    let stale = match metadata {
        Some(meta) => match meta.pid {
            Some(pid) => !pid_is_alive(pid),
            None => age.map(|age| age > LOCK_STARTUP_GRACE).unwrap_or(false),
        },
        None => age.map(|age| age > LOCK_STALE_AGE).unwrap_or(false),
    };

    if !stale {
        return Ok(false);
    }

    fs::remove_file(path).map_err(|err| {
        BrowserSessionError::LaunchFailed(format!(
            "failed to remove stale lock {}: {}",
            path.display(),
            err
        ))
    })?;
    tracing::warn!(
        target: "docdexd_browser_guard",
        event = "browser_session_lock_stale_removed",
        lock_file = %path.display(),
        "stale browser session lock removed"
    );
    Ok(true)
}

fn read_lock_metadata(path: &PathBuf) -> Option<BrowserLockMetadata> {
    let bytes = fs::read(path).ok()?;
    if bytes.is_empty() {
        return None;
    }
    match serde_json::from_slice::<BrowserLockMetadata>(&bytes) {
        Ok(metadata) => Some(metadata),
        Err(err) => {
            tracing::warn!(
                target: "docdexd_browser_guard",
                event = "browser_session_lock_metadata_invalid",
                lock_file = %path.display(),
                error = %err,
                "browser session lock metadata invalid"
            );
            None
        }
    }
}

fn lock_age(path: &PathBuf) -> Option<Duration> {
    let metadata = fs::metadata(path).ok()?;
    let modified = metadata.modified().ok()?;
    let now = SystemTime::now();
    now.duration_since(modified).ok()
}

fn age_from_epoch_ms(epoch_ms: u64) -> Option<Duration> {
    let now = now_epoch_ms();
    now.checked_sub(epoch_ms).map(Duration::from_millis)
}

fn now_epoch_ms() -> u64 {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    now.as_millis() as u64
}

#[cfg(unix)]
fn pid_is_alive(pid: u32) -> bool {
    let rc = unsafe { nix::libc::kill(pid as i32, 0) };
    if rc == 0 {
        return true;
    }
    let err = io::Error::last_os_error();
    match err.raw_os_error() {
        Some(code) if code == nix::libc::ESRCH => false,
        _ => true,
    }
}

#[cfg(not(unix))]
fn pid_is_alive(pid: u32) -> bool {
    let mut system = sysinfo::System::new();
    system.refresh_processes();
    system.process(sysinfo::Pid::from_u32(pid)).is_some()
}

fn default_lock_file_path() -> Option<PathBuf> {
    let config = crate::config::AppConfig::load_default().ok()?;
    let base_dir = config.core.global_state_dir?;
    let layout = StateLayout::new(base_dir);
    layout.ensure_global_dirs().ok()?;
    Some(layout.locks_dir().join("browser.lock"))
}

async fn cleanup_inner(inner: &Inner, force_kill: bool) -> Result<(), BrowserSessionError> {
    metrics::global().dec_browser_session_active();
    let pid = inner.pid;
    #[cfg(unix)]
    tracing::info!(
        target: "docdexd_browser_guard",
        event = "browser_session_cleanup_start",
        pid,
        pgid = inner.pgid,
        force_kill,
        graceful_timeout_ms = inner.graceful_shutdown_timeout.as_millis() as u64,
        kill_timeout_ms = inner.kill_timeout.as_millis() as u64,
        "browser session cleanup starting"
    );
    #[cfg(not(unix))]
    tracing::info!(
        target: "docdexd_browser_guard",
        event = "browser_session_cleanup_start",
        pid,
        force_kill,
        graceful_timeout_ms = inner.graceful_shutdown_timeout.as_millis() as u64,
        kill_timeout_ms = inner.kill_timeout.as_millis() as u64,
        "browser session cleanup starting"
    );

    let child = inner.child.lock().take();
    let Some(mut child) = child else {
        cleanup_lock(inner);
        return Ok(());
    };

    let terminate = async {
        if force_kill {
            #[cfg(unix)]
            signal_process_group(inner.pgid, nix::libc::SIGKILL);
            #[cfg(not(unix))]
            {
                let _ = child.start_kill();
            }
            return wait_with_timeout(&mut child, inner.kill_timeout).await;
        }

        #[cfg(unix)]
        signal_process_group(inner.pgid, nix::libc::SIGTERM);
        #[cfg(not(unix))]
        {
            let _ = child.start_kill();
        }

        match wait_with_timeout(&mut child, inner.graceful_shutdown_timeout).await {
            Ok(()) => Ok(()),
            Err(err) => {
                #[cfg(unix)]
                tracing::info!(
                    target: "docdexd_browser_guard",
                    event = "browser_session_kill_escalation",
                    pid,
                    pgid = inner.pgid,
                    error = %err,
                    "browser session escalating to SIGKILL"
                );
                #[cfg(not(unix))]
                tracing::info!(
                    target: "docdexd_browser_guard",
                    event = "browser_session_kill_escalation",
                    pid,
                    error = %err,
                    "browser session escalating to SIGKILL"
                );
                #[cfg(unix)]
                signal_process_group(inner.pgid, nix::libc::SIGKILL);
                #[cfg(not(unix))]
                {
                    let _ = child.start_kill();
                }
                wait_with_timeout(&mut child, inner.kill_timeout).await
            }
        }
    };

    let result = terminate.await;
    match result {
        Ok(()) => {
            cleanup_lock(inner);
            #[cfg(unix)]
            tracing::info!(
                target: "docdexd_browser_guard",
                event = "browser_session_cleanup_done",
                pid,
                pgid = inner.pgid,
                result = "ok",
                "browser session cleanup complete"
            );
            #[cfg(not(unix))]
            tracing::info!(
                target: "docdexd_browser_guard",
                event = "browser_session_cleanup_done",
                pid,
                result = "ok",
                "browser session cleanup complete"
            );
            #[cfg(test)]
            record_test_event("browser_session_cleanup_done");
            Ok(())
        }
        Err(err) => {
            metrics::global().inc_browser_session_cleanup_failure();
            #[cfg(unix)]
            tracing::warn!(
                target: "docdexd_browser_guard",
                event = "browser_session_cleanup_done",
                pid,
                pgid = inner.pgid,
                result = "error",
                error = %err,
                "browser session cleanup failed"
            );
            #[cfg(not(unix))]
            tracing::warn!(
                target: "docdexd_browser_guard",
                event = "browser_session_cleanup_done",
                pid,
                result = "error",
                error = %err,
                "browser session cleanup failed"
            );
            #[cfg(test)]
            record_test_event("browser_session_cleanup_done");
            Err(BrowserSessionError::CleanupFailed(err.to_string()))
        }
    }
}

async fn wait_with_timeout(
    child: &mut tokio::process::Child,
    timeout: Duration,
) -> Result<(), io::Error> {
    match tokio::time::timeout(timeout, child.wait()).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(err)) => Err(err),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "process did not exit in time",
        )),
    }
}

fn cleanup_lock(inner: &Inner) {
    let lock = inner.lock.lock().take();
    let Some(lock) = lock else { return };
    let path = lock.path.clone();
    drop(lock);
    if let Err(err) = fs::remove_file(&path) {
        tracing::debug!(
            target: "docdexd_browser_guard",
            event = "browser_session_lock_cleanup_failed",
            lock_file = %path.display(),
            error = %err,
            "browser session lock cleanup failed"
        );
    }
}

#[cfg(unix)]
fn signal_process_group(pgid: i32, signal: i32) {
    // If the process group is already gone, ignore.
    let rc = unsafe { nix::libc::killpg(pgid, signal) };
    if rc == -1 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(nix::libc::ESRCH) {
            tracing::debug!("killpg({pgid},{signal}) failed: {err}");
        }
    }
}

fn best_effort_abort_sync(inner: &Inner) {
    metrics::global().dec_browser_session_active();
    #[cfg(unix)]
    signal_process_group(inner.pgid, nix::libc::SIGKILL);
    #[cfg(not(unix))]
    {
        if let Some(mut child) = inner.child.lock().take() {
            let _ = child.start_kill();
        }
    }
    cleanup_lock(inner);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tier2::{
        classify_browser_session_failure, run_with_fallback, Tier2Config, Tier2Limiter,
        Tier2UnavailableReason,
    };
    use anyhow::anyhow;
    use std::time::Instant;
    use std::{collections::BTreeMap, sync::Mutex};
    use tempfile::TempDir;
    use tracing::Subscriber;
    use tracing_subscriber::layer::{Context, Layer};
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::{registry::LookupSpan, Registry};

    #[cfg(unix)]
    fn process_group_alive(pgid: i32) -> bool {
        let rc = unsafe { nix::libc::killpg(pgid, 0) };
        if rc == 0 {
            return true;
        }
        let err = io::Error::last_os_error();
        match err.raw_os_error() {
            Some(code) if code == nix::libc::ESRCH => false,
            _ => true,
        }
    }

    #[cfg(unix)]
    fn pid_alive(pid: i32) -> bool {
        let rc = unsafe { nix::libc::kill(pid, 0) };
        if rc == 0 {
            return true;
        }
        let err = io::Error::last_os_error();
        match err.raw_os_error() {
            Some(code) if code == nix::libc::ESRCH => false,
            _ => true,
        }
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn close_is_idempotent_and_kills_process_group() {
        let temp = TempDir::new().expect("temp dir");
        let lock_path = temp.path().join("locks").join("browser.lock");

        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg("sleep 1000");

        let session = BrowserSession::spawn(
            cmd,
            BrowserSessionOptions {
                lock_file: Some(lock_path),
                graceful_shutdown_timeout: Duration::from_millis(200),
                kill_timeout: Duration::from_millis(200),
            },
        )
        .await
        .expect("spawn browser session");

        let pgid = session.process_group_id();
        assert!(process_group_alive(pgid));

        let (r1, r2) = tokio::join!(session.close(), session.close());
        assert!(r1.is_ok(), "first close: {r1:?}");
        assert!(r2.is_ok(), "second close: {r2:?}");

        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline && process_group_alive(pgid) {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(!process_group_alive(pgid), "process group still alive");
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn scoped_timeout_triggers_cleanup() {
        let temp = TempDir::new().expect("temp dir");
        let lock_path = temp.path().join("locks").join("browser.lock");

        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg("sleep 1000");

        let session = BrowserSession::spawn(
            cmd,
            BrowserSessionOptions {
                lock_file: Some(lock_path),
                graceful_shutdown_timeout: Duration::from_millis(200),
                kill_timeout: Duration::from_millis(200),
            },
        )
        .await
        .expect("spawn browser session");

        let pgid = session.process_group_id();
        let result = session
            .run_scoped(
                Duration::from_millis(100),
                std::future::pending::<()>(),
                async {
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    Ok::<_, anyhow::Error>(())
                },
            )
            .await;

        assert!(matches!(result, Err(BrowserSessionError::TimedOut(_))));

        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline && process_group_alive(pgid) {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(!process_group_alive(pgid), "process group still alive");
    }

    #[tokio::test]
    #[cfg(unix)]
    async fn scoped_cancel_triggers_cleanup_and_kills_children() {
        let temp = TempDir::new().expect("temp dir");
        let lock_path = temp.path().join("locks").join("browser.lock");
        let pid_file = temp.path().join("child.pid");

        let mut cmd = Command::new("sh");
        cmd.arg("-c")
            .arg(r#"sleep 1000 & echo $! > "$1"; wait"#)
            .arg("sh")
            .arg(pid_file.as_os_str());

        let session = BrowserSession::spawn(
            cmd,
            BrowserSessionOptions {
                lock_file: Some(lock_path),
                graceful_shutdown_timeout: Duration::from_millis(200),
                kill_timeout: Duration::from_millis(200),
            },
        )
        .await
        .expect("spawn browser session");

        let pgid = session.process_group_id();

        let deadline = Instant::now() + Duration::from_secs(2);
        let child_pid = loop {
            if let Ok(bytes) = fs::read(&pid_file) {
                if let Ok(text) = String::from_utf8(bytes) {
                    if let Ok(pid) = text.trim().parse::<i32>() {
                        break pid;
                    }
                }
            }
            if Instant::now() > deadline {
                panic!("timed out waiting for child pid file");
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        };
        assert!(pid_alive(child_pid), "expected child sleep to be alive");

        let result = session
            .run_scoped(
                Duration::from_secs(10),
                tokio::time::sleep(Duration::from_millis(100)),
                async {
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    Ok::<_, anyhow::Error>(())
                },
            )
            .await;
        assert!(matches!(result, Err(BrowserSessionError::Cancelled)));

        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline && (process_group_alive(pgid) || pid_alive(child_pid)) {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        assert!(!process_group_alive(pgid), "process group still alive");
        assert!(!pid_alive(child_pid), "child process still alive");
    }

    #[test]
    fn tier2_reason_codes_cover_browser_session_failures() {
        let cases: Vec<(BrowserSessionError, Option<Tier2UnavailableReason>)> = vec![
            (
                BrowserSessionError::LaunchFailed("nope".to_string()),
                Some(Tier2UnavailableReason::StartupFailed),
            ),
            (
                BrowserSessionError::TimedOut(Duration::from_millis(5)),
                Some(Tier2UnavailableReason::Timeout),
            ),
            (
                BrowserSessionError::WorkFailed("boom".to_string()),
                Some(Tier2UnavailableReason::Crashed),
            ),
            (
                BrowserSessionError::CleanupFailed("boom".to_string()),
                Some(Tier2UnavailableReason::Crashed),
            ),
            (BrowserSessionError::Cancelled, None),
        ];

        for (err, expected) in cases {
            assert_eq!(
                classify_browser_session_failure(&err).map(|u| u.reason),
                expected,
                "case={err:?}"
            );
        }
    }

    #[tokio::test]
    async fn tier2_unavailable_triggers_fallback_without_crashing() {
        async fn expect_reason<T2Fut>(
            request_id: &str,
            config: Tier2Config,
            limiter: Option<&Tier2Limiter>,
            tier2: impl FnOnce() -> T2Fut,
            expected: Tier2UnavailableReason,
        ) where
            T2Fut: Future<Output = Result<String, anyhow::Error>>,
        {
            let result = run_with_fallback(request_id, config, limiter, tier2, || async {
                Ok::<_, anyhow::Error>("tier3".to_string())
            })
            .await
            .expect("run");
            assert_eq!(result.value, "tier3");
            assert_eq!(result.tier2_unavailable.unwrap().reason, expected);
        }

        expect_reason(
            "req-disabled",
            Tier2Config { enabled: false },
            None,
            || async { Ok::<_, anyhow::Error>("tier2".to_string()) },
            Tier2UnavailableReason::Disabled,
        )
        .await;

        let limiter = Tier2Limiter::new(1, Duration::from_millis(0));
        let _hold = limiter.acquire().await.expect("hold permit");
        expect_reason(
            "req-overload",
            Tier2Config::enabled(),
            Some(&limiter),
            || async { Ok::<_, anyhow::Error>("tier2".to_string()) },
            Tier2UnavailableReason::Overload,
        )
        .await;

        expect_reason(
            "req-timeout",
            Tier2Config::enabled(),
            None,
            || async {
                Err::<String, anyhow::Error>(
                    BrowserSessionError::TimedOut(Duration::from_millis(1)).into(),
                )
            },
            Tier2UnavailableReason::Timeout,
        )
        .await;

        expect_reason(
            "req-crashed",
            Tier2Config::enabled(),
            None,
            || async {
                Err::<String, anyhow::Error>(
                    BrowserSessionError::WorkFailed("boom".to_string()).into(),
                )
            },
            Tier2UnavailableReason::Crashed,
        )
        .await;

        expect_reason(
            "req-startup",
            Tier2Config::enabled(),
            None,
            || async {
                let cmd = Command::new("docdexd-definitely-not-a-real-command");
                let _session =
                    BrowserSession::spawn(cmd, BrowserSessionOptions::without_lock()).await?;
                Ok::<_, anyhow::Error>("tier2".to_string())
            },
            Tier2UnavailableReason::StartupFailed,
        )
        .await;
    }

    #[tokio::test]
    async fn tier2_does_not_swallow_non_browser_errors() {
        let err = run_with_fallback(
            "req-bug",
            Tier2Config::enabled(),
            None,
            || async { Err::<String, anyhow::Error>(anyhow!("boom")) },
            || async { Ok::<_, anyhow::Error>("tier3".to_string()) },
        )
        .await
        .expect_err("should fail");
        assert!(err.to_string().contains("boom"));
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

    #[tokio::test(flavor = "current_thread")]
    async fn launch_failure_increments_metric() {
        let before = crate::metrics::global().render_prometheus();
        let before_val =
            prometheus_counter(&before, "docdex_browser_session_launch_failures_total");

        let cmd = Command::new("docdexd-definitely-not-a-real-command");
        let err = BrowserSession::spawn(cmd, BrowserSessionOptions::without_lock())
            .await
            .expect_err("expected launch failure");
        assert!(matches!(err, BrowserSessionError::LaunchFailed(_)));

        let after = crate::metrics::global().render_prometheus();
        let after_val = prometheus_counter(&after, "docdex_browser_session_launch_failures_total");
        assert!(
            after_val >= before_val + 1,
            "expected launch failures counter to increment"
        );
    }

    #[derive(Default)]
    struct Captured {
        events: Mutex<Vec<BTreeMap<String, String>>>,
    }

    struct CaptureLayer(std::sync::Arc<Captured>);

    impl<S> Layer<S> for CaptureLayer
    where
        S: Subscriber + for<'a> LookupSpan<'a>,
    {
        fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
            let mut fields = BTreeMap::new();
            fields.insert("target".to_string(), event.metadata().target().to_string());
            struct Visitor<'a>(&'a mut BTreeMap<String, String>);
            impl tracing::field::Visit for Visitor<'_> {
                fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                    self.0.insert(field.name().to_string(), value.to_string());
                }

                fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
                    self.0.insert(field.name().to_string(), value.to_string());
                }

                fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
                    self.0.insert(field.name().to_string(), value.to_string());
                }

                fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
                    self.0.insert(field.name().to_string(), value.to_string());
                }

                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    self.0
                        .insert(field.name().to_string(), format!("{value:?}"));
                }
            }
            event.record(&mut Visitor(&mut fields));
            self.0.events.lock().unwrap().push(fields);
        }
    }

    #[test]
    #[cfg(unix)]
    fn emits_structured_session_lifecycle_logs() {
        if let Some(events) = BROWSER_SESSION_TEST_EVENTS.get() {
            events.lock().unwrap().clear();
        }
        let captured = std::sync::Arc::new(Captured::default());
        let subscriber = Registry::default()
            .with(tracing_subscriber::filter::LevelFilter::INFO)
            .with(CaptureLayer(captured.clone()));
        let dispatch = tracing::Dispatch::new(subscriber);
        let _guard = tracing::dispatcher::set_default(&dispatch);
        tracing::callsite::rebuild_interest_cache();
        tracing::info!(
            target: "docdexd_browser_guard",
            event = "test_capture",
            "capture layer smoke check"
        );

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let mut cmd = Command::new("sh");
            cmd.arg("-c").arg("sleep 1000");
            let session = BrowserSession::spawn(cmd, BrowserSessionOptions::without_lock())
                .await
                .expect("spawn");
            session.close().await.expect("close");
        });

        let events = captured.events.lock().unwrap();
        let capture_ok = events
            .iter()
            .any(|fields| fields.get("event").is_some_and(|v| v == "test_capture"));
        assert!(capture_ok, "capture layer did not record test event");
        let started = events.iter().any(|fields| {
            fields
                .get("event")
                .is_some_and(|v| v == "browser_session_started")
        });
        let cleaned = events.iter().any(|fields| {
            fields
                .get("event")
                .is_some_and(|v| v == "browser_session_cleanup_done")
        });
        let test_events = BROWSER_SESSION_TEST_EVENTS
            .get()
            .map(|events| events.lock().unwrap().clone())
            .unwrap_or_default();
        let started = started || test_events.iter().any(|v| v == "browser_session_started");
        let cleaned = cleaned || test_events.iter().any(|v| v == "browser_session_cleanup_done");
        if !(started && cleaned) {
            eprintln!(
                "[browser-session-test] events={events:?} test_events={test_events:?}"
            );
        }
        assert!(
            started && cleaned,
            "expected lifecycle logs in tracing events"
        );
    }
}
