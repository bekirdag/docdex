mod common;

use serde_json::Value;
use std::error::Error;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;
use tempfile::TempDir;

struct Daemon {
    child: Child,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn write_repo(repo_root: &Path) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(repo_root.join("src"))?;
    fs::write(repo_root.join("src").join("note.md"), "Docdex stdio test\n")?;
    Ok(())
}

fn pick_free_port() -> Option<u16> {
    match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => Some(listener.local_addr().ok()?.port()),
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping stdio bridge test: TCP bind not permitted");
            None
        }
        Err(err) => panic!("bind ephemeral port: {err}"),
    }
}

fn wait_for_health(host: &str, port: u16) -> Result<(), Box<dyn Error>> {
    common::wait_for_health(host, port)
}

fn start_daemon(state_root: &Path, repo_root: &Path, port: u16) -> Result<Daemon, Box<dyn Error>> {
    let lock_path = state_root.join("daemon.lock");
    let child = Command::new(common::docdex_bin())
        .env("DOCDEX_WEB_ENABLED", "0")
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("DOCDEX_STATE_DIR", state_root)
        .env("DOCDEX_DAEMON_LOCK_PATH", &lock_path)
        .env("DOCDEX_ENABLE_MCP", "1")
        .args([
            "serve",
            "--repo",
            repo_root.to_str().unwrap(),
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--log",
            "warn",
            "--secure-mode=false",
            "--enable-mcp",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    Ok(Daemon { child })
}

fn node_available() -> bool {
    Command::new("node")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn bridge_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("npm")
        .join("bin")
        .join("docdex-mcp-stdio.js")
}

#[test]
fn mcp_stdio_bridge_roundtrip() -> Result<(), Box<dyn Error>> {
    if !node_available() {
        eprintln!("skipping stdio bridge test: node not available");
        return Ok(());
    }

    let repo = TempDir::new()?;
    write_repo(repo.path())?;
    let state_root = TempDir::new()?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let _daemon = start_daemon(state_root.path(), repo.path(), port)?;
    wait_for_health(host, port)?;

    let mut child = Command::new("node")
        .arg(bridge_path())
        .env("DOCDEX_HTTP_BASE_URL", format!("http://{host}:{port}"))
        .env("DOCDEX_MCP_TRANSPORT", "http")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;

    let stdin = child.stdin.as_mut().ok_or("missing stdin")?;
    let init = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": { "rootUri": format!("file://{}", repo.path().display()) }
    });
    let tools = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    });
    writeln!(stdin, "{}", init)?;
    writeln!(stdin, "{}", tools)?;
    stdin.flush()?;

    let stdout = child.stdout.take().ok_or("missing stdout")?;
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let reader = BufReader::new(stdout);
        for line in reader.lines().flatten() {
            let _ = tx.send(line);
        }
    });

    let line1 = rx
        .recv_timeout(Duration::from_secs(10))
        .map_err(|_| "missing initialize response")?;
    let line2 = rx
        .recv_timeout(Duration::from_secs(10))
        .map_err(|_| "missing tools/list response")?;

    let resp1: Value = serde_json::from_str(&line1)?;
    let resp2: Value = serde_json::from_str(&line2)?;
    if resp1.get("result").is_none() {
        return Err(format!("initialize response missing result: {resp1}").into());
    }
    if resp2.get("result").is_none() {
        return Err(format!("tools/list response missing result: {resp2}").into());
    }

    let _ = child.kill();
    let _ = child.wait();
    Ok(())
}
