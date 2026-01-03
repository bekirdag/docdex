use crate::config::AppConfig;
use anyhow::{anyhow, Context, Result};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

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

pub fn ensure_daemon_running(config: &AppConfig, repo_hint: Option<PathBuf>) -> Result<()> {
    if std::env::var_os("DOCDEX_DISABLE_DAEMON_AUTO").is_some() {
        return Ok(());
    }
    let addr = parse_bind_addr(&config.server.http_bind_addr)?;
    if daemon_healthy(addr) {
        return Ok(());
    }
    spawn_daemon(addr, repo_hint)?;
    Ok(())
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
    let mut buf = [0u8; 32];
    let Ok(read) = std::io::Read::read(&mut stream, &mut buf) else {
        return false;
    };
    if read == 0 {
        return false;
    }
    let head = std::str::from_utf8(&buf[..read]).unwrap_or("");
    head.starts_with("HTTP/1.1 200") || head.starts_with("HTTP/1.0 200")
}

fn spawn_daemon(addr: SocketAddr, repo_hint: Option<PathBuf>) -> Result<()> {
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
    if let Some(repo) = repo_hint {
        cmd.arg("--repo").arg(repo);
    }
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
