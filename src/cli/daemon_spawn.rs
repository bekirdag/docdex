use crate::config::AppConfig;
use crate::daemon::lock;
use anyhow::{anyhow, Context, Result};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use sysinfo::{Pid, System};

#[cfg(unix)]
use std::os::unix::process::CommandExt;
#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x08000000;
#[cfg(windows)]
const DETACHED_PROCESS: u32 = 0x00000008;
#[cfg(windows)]
const CREATE_NEW_PROCESS_GROUP: u32 = 0x00000200;

const MCP_AUTO_START_TIMEOUT_SECS: u64 = 10;
const DAEMON_AUTO_START_TIMEOUT_SECS: u64 = 5;

#[cfg(windows)]
const DOCDEXD_PROCESS_NAMES: &[&str] = &["docdexd.exe", "docdexd"];
#[cfg(not(windows))]
const DOCDEXD_PROCESS_NAMES: &[&str] = &["docdexd"];

fn stop_docdexd_if_stale(pid: u32) -> bool {
    let mut system = System::new();
    system.refresh_processes();
    let Some(process) = system.process(Pid::from_u32(pid)) else {
        return false;
    };
    if !process_matches_docdexd(process) {
        return false;
    }
    process.kill()
}

fn process_matches_docdexd(process: &sysinfo::Process) -> bool {
    let name = process.name();
    if DOCDEXD_PROCESS_NAMES
        .iter()
        .any(|expected| name.eq_ignore_ascii_case(expected))
    {
        return true;
    }
    let Some(exe) = process.exe() else {
        return false;
    };
    let Some(file_name) = exe.file_name().and_then(|value| value.to_str()) else {
        return false;
    };
    DOCDEXD_PROCESS_NAMES
        .iter()
        .any(|expected| file_name.eq_ignore_ascii_case(expected))
}

pub fn ensure_daemon_running(config: &AppConfig, repo_hint: Option<PathBuf>) -> Result<()> {
    if std::env::var_os("DOCDEX_DISABLE_DAEMON_AUTO").is_some() {
        return Ok(());
    }
    let lock_path = lock::default_lock_path()?;
    let addr = parse_bind_addr(&config.server.http_bind_addr)?;
    if let Some(metadata) = lock::read_metadata(&lock_path)? {
        if metadata.port != 0 {
            let health_addr = SocketAddr::new(addr.ip(), metadata.port);
            if daemon_healthy(health_addr) {
                return Ok(());
            }
        }
        if metadata.pid != std::process::id() && stop_docdexd_if_stale(metadata.pid) {
            std::thread::sleep(Duration::from_millis(200));
        }
    }
    if daemon_healthy(addr) {
        return Ok(());
    }
    spawn_daemon(addr, repo_hint)?;
    let deadline = Instant::now() + Duration::from_secs(DAEMON_AUTO_START_TIMEOUT_SECS);
    while Instant::now() < deadline {
        if daemon_healthy(addr) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    Err(anyhow!(
        "docdex daemon did not become healthy within {}s on {}; check for port conflicts or run `docdexd daemon` manually",
        DAEMON_AUTO_START_TIMEOUT_SECS,
        addr
    ))
}

pub(crate) fn mcp_auto_start_enabled(requested: bool) -> Result<bool> {
    if !requested {
        return Ok(false);
    }
    if std::env::var_os("DOCDEX_DISABLE_DAEMON_AUTO").is_some() {
        return Err(anyhow!(
            "auto-start disabled via DOCDEX_DISABLE_DAEMON_AUTO; unset it or start the daemon manually with `docdexd daemon`"
        ));
    }
    if std::env::var_os("DOCDEX_HTTP_BASE_URL").is_some() {
        return Err(anyhow!(
            "DOCDEX_HTTP_BASE_URL is set; auto-start would be ignored. Unset it or start the daemon manually with `docdexd daemon`"
        ));
    }
    Ok(true)
}

pub fn ensure_daemon_running_for_mcp(repo_hint: Option<PathBuf>) -> Result<lock::DaemonLockMetadata> {
    let lock_path = lock::default_lock_path()?;
    let config = AppConfig::load_default().context("load config for MCP auto-start")?;
    let addr = parse_bind_addr(&config.server.http_bind_addr)?;
    let mut stopped_existing = false;
    if let Some(metadata) = lock::read_metadata(&lock_path)? {
        if metadata.port != 0 {
            let health_addr = SocketAddr::new(addr.ip(), metadata.port);
            if daemon_healthy(health_addr) {
                return Ok(metadata);
            }
        }
        if metadata.pid != std::process::id() && stop_docdexd_if_stale(metadata.pid) {
            std::thread::sleep(Duration::from_millis(200));
            stopped_existing = true;
        }
    }
    let timeout = Duration::from_secs(MCP_AUTO_START_TIMEOUT_SECS);
    if !stopped_existing && lock::read_metadata(&lock_path)?.is_some() {
        if let Some(metadata) = lock::wait_for_running_metadata_at_path(&lock_path, timeout)? {
            return Ok(metadata);
        }
    }
    spawn_daemon(addr, repo_hint.clone())?;
    if let Some(metadata) = lock::wait_for_running_metadata_at_path(&lock_path, timeout)? {
        return Ok(metadata);
    }
    Err(anyhow!(
        "docdex daemon did not become healthy within {}s; start it manually with `docdexd daemon`",
        MCP_AUTO_START_TIMEOUT_SECS
    ))
}

fn parse_bind_addr(value: &str) -> Result<SocketAddr> {
    value
        .parse::<SocketAddr>()
        .map_err(|_| anyhow!("invalid http_bind_addr: {value}"))
}

fn daemon_healthy(addr: SocketAddr) -> bool {
    let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(300)) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_millis(300)));
    let _ = stream.set_write_timeout(Some(Duration::from_millis(300)));
    let request = format!(
        "GET /healthz HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        addr.ip()
    );
    if std::io::Write::write_all(&mut stream, request.as_bytes()).is_err() {
        return false;
    }
    let mut buf = [0u8; 128];
    let Ok(read) = std::io::Read::read(&mut stream, &mut buf) else {
        return false;
    };
    if read == 0 {
        return false;
    }
    let head = std::str::from_utf8(&buf[..read]).unwrap_or("");
    let (status, body) = head.split_once("\r\n\r\n").unwrap_or((head, ""));
    let status_ok = status.starts_with("HTTP/1.1 200") || status.starts_with("HTTP/1.0 200");
    status_ok && body.trim() == "ok"
}

fn spawn_daemon(addr: SocketAddr, _repo_hint: Option<PathBuf>) -> Result<()> {
    let exe = std::env::current_exe().context("resolve docdexd path")?;
    let mut cmd = Command::new(exe);
    cmd.arg("daemon")
        .arg("--host")
        .arg(addr.ip().to_string())
        .arg("--port")
        .arg(addr.port().to_string())
        .arg("--log")
        .arg("warn")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(unix)]
    unsafe {
        cmd.pre_exec(|| {
            nix::unistd::setsid()
                .map(|_| ())
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))
        });
    }
    #[cfg(windows)]
    {
        cmd.creation_flags(CREATE_NO_WINDOW | DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP);
    }
    let _child = cmd.spawn().context("spawn daemon")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::mcp_auto_start_enabled;
    use crate::setup::test_support::ENV_LOCK;
    use std::sync::MutexGuard;

    struct EnvGuard {
        prev: Vec<(&'static str, Option<String>)>,
        _lock: MutexGuard<'static, ()>,
    }

    impl EnvGuard {
        fn set(vars: &[(&'static str, &str)]) -> Self {
            let lock = ENV_LOCK.lock().expect("env lock");
            let mut prev = Vec::new();
            for (key, value) in vars {
                let old = std::env::var(key).ok();
                std::env::set_var(key, value);
                prev.push((*key, old));
            }
            Self { prev, _lock: lock }
        }

        fn clear(keys: &[&'static str]) -> Self {
            let lock = ENV_LOCK.lock().expect("env lock");
            let mut prev = Vec::new();
            for key in keys {
                let old = std::env::var(key).ok();
                std::env::remove_var(key);
                prev.push((*key, old));
            }
            Self { prev, _lock: lock }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (key, value) in &self.prev {
                if let Some(value) = value {
                    std::env::set_var(key, value);
                } else {
                    std::env::remove_var(key);
                }
            }
        }
    }

    #[test]
    fn mcp_auto_start_disabled_when_not_requested() {
        let _env = EnvGuard::clear(&["DOCDEX_DISABLE_DAEMON_AUTO", "DOCDEX_HTTP_BASE_URL"]);
        assert_eq!(mcp_auto_start_enabled(false).unwrap(), false);
    }

    #[test]
    fn mcp_auto_start_enabled_when_requested() {
        let _env = EnvGuard::clear(&["DOCDEX_DISABLE_DAEMON_AUTO", "DOCDEX_HTTP_BASE_URL"]);
        assert_eq!(mcp_auto_start_enabled(true).unwrap(), true);
    }

    #[test]
    fn mcp_auto_start_rejects_disabled_env() {
        let _env = EnvGuard::set(&[("DOCDEX_DISABLE_DAEMON_AUTO", "1")]);
        let err = mcp_auto_start_enabled(true).unwrap_err().to_string();
        assert!(err.contains("DOCDEX_DISABLE_DAEMON_AUTO"));
    }

    #[test]
    fn mcp_auto_start_rejects_base_url_override() {
        let _env = EnvGuard::set(&[("DOCDEX_HTTP_BASE_URL", "http://127.0.0.1:3333")]);
        let err = mcp_auto_start_enabled(true).unwrap_err().to_string();
        assert!(err.contains("DOCDEX_HTTP_BASE_URL"));
    }
}
