use crate::config::AppConfig;
use crate::daemon::lock;
use anyhow::{anyhow, Context, Result};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

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

const DAEMON_AUTO_START_TIMEOUT_DEFAULT_SECS: u64 = 30;
const DAEMON_AUTO_START_TIMEOUT_ENV: &str = "DOCDEX_DAEMON_AUTO_START_TIMEOUT_SECS";

#[derive(Debug, PartialEq, Eq)]
enum ExistingDaemonAction {
    Ready,
    Wait,
    Start,
}

fn existing_daemon_action(healthy: bool, lock_owner_running: bool) -> ExistingDaemonAction {
    if healthy {
        ExistingDaemonAction::Ready
    } else if lock_owner_running {
        ExistingDaemonAction::Wait
    } else {
        ExistingDaemonAction::Start
    }
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
            let healthy = daemon_healthy(health_addr);
            let lock_owner_running =
                !healthy && lock::read_running_metadata_at_path(&lock_path)?.is_some();
            match existing_daemon_action(healthy, lock_owner_running) {
                ExistingDaemonAction::Ready => return Ok(()),
                ExistingDaemonAction::Wait => {
                    return wait_for_daemon_health(health_addr, daemon_auto_start_timeout_secs());
                }
                ExistingDaemonAction::Start => {}
            }
        }
    }
    if daemon_healthy(addr) {
        return Ok(());
    }
    spawn_daemon(addr, repo_hint)?;
    wait_for_daemon_health(addr, daemon_auto_start_timeout_secs())
}

fn wait_for_daemon_health(addr: SocketAddr, timeout_secs: u64) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    while Instant::now() < deadline {
        if daemon_healthy(addr) {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    Err(anyhow!(
        "docdex daemon did not become healthy within {}s on {}; check for port conflicts or run `docdexd daemon` manually",
        timeout_secs,
        addr
    ))
}

fn daemon_auto_start_timeout_secs() -> u64 {
    std::env::var(DAEMON_AUTO_START_TIMEOUT_ENV)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .map(|value| value.clamp(1, 300))
        .unwrap_or(DAEMON_AUTO_START_TIMEOUT_DEFAULT_SECS)
}

fn parse_bind_addr(value: &str) -> Result<SocketAddr> {
    value
        .parse::<SocketAddr>()
        .map_err(|_| anyhow!("invalid http_bind_addr: {value}"))
}

pub(crate) fn daemon_healthy(addr: SocketAddr) -> bool {
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
    let mut buf = Vec::with_capacity(256);
    let mut chunk = [0u8; 256];
    for _ in 0..8 {
        let Ok(read) = std::io::Read::read(&mut stream, &mut chunk) else {
            break;
        };
        if read == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..read]);
        if buf.len() >= 2048 {
            break;
        }
        if let Ok(text) = std::str::from_utf8(&buf) {
            if let Some((_status, body)) = text.split_once("\r\n\r\n") {
                if body.trim() == "ok" {
                    break;
                }
            }
        }
    }
    if buf.is_empty() {
        return false;
    }
    let head = std::str::from_utf8(&buf).unwrap_or("");
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
    use super::*;

    #[test]
    fn slow_live_daemon_is_waited_for_instead_of_replaced() {
        assert_eq!(
            existing_daemon_action(false, true),
            ExistingDaemonAction::Wait
        );
        assert_eq!(
            existing_daemon_action(false, false),
            ExistingDaemonAction::Start
        );
        assert_eq!(
            existing_daemon_action(true, true),
            ExistingDaemonAction::Ready
        );
    }
}
