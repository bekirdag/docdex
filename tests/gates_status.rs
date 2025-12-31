mod common;

use common::{docdex_bin, pick_free_port};
use serde_json::Value;
use std::error::Error;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

fn write_repo(repo_root: &Path) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(repo_root.join("docs"))?;
    fs::write(repo_root.join("docs").join("readme.md"), "# Repo\n")?;
    Ok(())
}

struct ServerHarness {
    child: Child,
}

impl ServerHarness {
    fn spawn(
        state_root: &Path,
        home_dir: &Path,
        repo_root: &Path,
        host: &str,
        port: u16,
    ) -> Result<Self, Box<dyn Error>> {
        let repo_str = repo_root.to_string_lossy().to_string();
        let child = Command::new(docdex_bin())
            .env("DOCDEX_STATE_DIR", state_root)
            .env("HOME", home_dir)
            .env("DOCDEX_ENABLE_MCP", "0")
            .args([
                "serve",
                "--repo",
                repo_str.as_str(),
                "--host",
                host,
                "--port",
                &port.to_string(),
                "--log",
                "warn",
                "--secure-mode=false",
                "--access-log=false",
                "--enable-memory=false",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut server = Self { child };
        wait_for_health(host, port, &mut server.child)?;
        Ok(server)
    }

    fn shutdown(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
    }
}

#[test]
fn gates_status_payload_has_expected_shape() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    write_repo(repo.path())?;
    let state_root = TempDir::new()?;
    let home_dir = TempDir::new()?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let mut server =
        ServerHarness::spawn(state_root.path(), home_dir.path(), repo.path(), host, port)?;

    let body = http_get(host, port, "/v1/gates/status")?;
    let payload: Value = serde_json::from_str(&body)?;
    assert!(payload.get("generated_at").is_some());
    assert!(payload.get("http_requests_total").is_some());
    assert!(payload.get("http_errors_total").is_some());

    let gates = payload
        .get("gates")
        .and_then(|v| v.as_object())
        .ok_or("gates missing")?;
    for key in ["error_rate", "latency_p95_ms", "soak"] {
        let gate = gates
            .get(key)
            .and_then(|v| v.get("status"))
            .and_then(|v| v.as_str())
            .ok_or("gate status missing")?;
        assert!(
            matches!(gate, "pass" | "fail" | "unknown"),
            "unexpected gate status: {gate}"
        );
    }

    server.shutdown();
    Ok(())
}

fn wait_for_health(host: &str, port: u16, child: &mut Child) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait()? {
            let mut stderr = String::new();
            if let Some(mut pipe) = child.stderr.take() {
                let _ = pipe.read_to_string(&mut stderr);
            }
            return Err(format!("docdexd exited early ({status}): {stderr}").into());
        }
        if try_health_check(host, port)? {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(200));
    }
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        let _ = pipe.read_to_string(&mut stderr);
    }
    Err(format!("docdexd healthz endpoint did not respond in time; stderr: {stderr}").into())
}

fn http_get(host: &str, port: u16, path: &str) -> Result<String, Box<dyn Error>> {
    let addr = SocketAddr::new(host.parse()?, port);
    let mut stream = TcpStream::connect_timeout(&addr, Duration::from_secs(1))?;
    stream.set_read_timeout(Some(Duration::from_secs(1)))?;
    stream.set_write_timeout(Some(Duration::from_secs(1)))?;
    let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes())?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf)?;
    let response = String::from_utf8_lossy(&buf);
    let mut parts = response.splitn(2, "\r\n\r\n");
    let head = parts.next().unwrap_or("");
    if !head.starts_with("HTTP/1.1 200") && !head.starts_with("HTTP/1.0 200") {
        return Err(format!("unexpected response: {head}").into());
    }
    Ok(parts.next().unwrap_or("").to_string())
}

fn try_health_check(host: &str, port: u16) -> Result<bool, Box<dyn Error>> {
    let addr = SocketAddr::new(host.parse()?, port);
    let mut stream = match TcpStream::connect_timeout(&addr, Duration::from_millis(500)) {
        Ok(stream) => stream,
        Err(_) => return Ok(false),
    };
    stream.set_read_timeout(Some(Duration::from_millis(500)))?;
    stream.set_write_timeout(Some(Duration::from_millis(500)))?;
    let request = format!("GET /healthz HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    if stream.write_all(request.as_bytes()).is_err() {
        return Ok(false);
    }
    let mut buf = [0u8; 64];
    let read = match stream.read(&mut buf) {
        Ok(read) => read,
        Err(_) => return Ok(false),
    };
    if read == 0 {
        return Ok(false);
    }
    let header = std::str::from_utf8(&buf[..read]).unwrap_or("");
    Ok(header.starts_with("HTTP/1.1 200") || header.starts_with("HTTP/1.0 200"))
}
