mod common;

use serde_json::json;
use std::error::Error;
use std::io::{BufRead, BufReader, Write};
use std::process::{ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

fn write_fixture(repo_root: &std::path::Path) -> Result<(), Box<dyn Error>> {
    std::fs::write(repo_root.join("README.md"), "# Docdex MCP soak\n")?;
    Ok(())
}

fn send(stdin: &mut ChildStdin, payload: serde_json::Value) -> Result<(), Box<dyn Error>> {
    let text = serde_json::to_string(&payload)?;
    stdin.write_all(text.as_bytes())?;
    stdin.write_all(b"\n")?;
    stdin.flush()?;
    Ok(())
}

fn recv(
    rx: &mpsc::Receiver<String>,
    timeout: Duration,
) -> Result<serde_json::Value, Box<dyn Error>> {
    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("timed out waiting for MCP response".into());
        }
        let line = rx.recv_timeout(remaining)?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        return Ok(serde_json::from_str(trimmed)?);
    }
}

#[test]
#[ignore]
fn mcp_stdio_soak_no_timeouts() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    write_fixture(repo.path())?;

    let mut cmd = Command::new(common::docdex_bin());
    cmd.env("DOCDEX_WEB_ENABLED", "0");
    cmd.env("DOCDEX_ENABLE_MEMORY", "0");
    cmd.args([
        "mcp",
        "--repo",
        repo.path().to_string_lossy().as_ref(),
        "--log",
        "warn",
    ]);
    cmd.env("DOCDEX_MCP_SERVER_BIN", common::mcp_server_bin());
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;

    let mut stdin = child.stdin.take().ok_or("failed to open MCP stdin")?;
    let stdout = child.stdout.take().ok_or("failed to open MCP stdout")?;

    let (tx, rx) = mpsc::channel::<String>();
    thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) => {
                    if tx.send(line).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    let timeout_secs = std::env::var("DOCDEX_MCP_SOAK_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(5)
        .max(1);
    let soak_secs = std::env::var("DOCDEX_MCP_SOAK_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(30)
        .max(1);
    let timeout = Duration::from_secs(timeout_secs);
    let deadline = Instant::now() + Duration::from_secs(soak_secs);

    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": { "workspace_root": repo.path().to_string_lossy() }
        }),
    )?;
    let init = recv(&rx, timeout)?;
    if init.get("result").is_none() {
        return Err(format!("unexpected initialize response: {init:?}").into());
    }

    send(
        &mut stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/list",
            "params": {}
        }),
    )?;
    let tools = recv(&rx, timeout)?;
    if tools.get("result").is_none() {
        return Err(format!("unexpected tools/list response: {tools:?}").into());
    }

    let mut counter = 3;
    while Instant::now() < deadline {
        send(
            &mut stdin,
            json!({
                "jsonrpc": "2.0",
                "id": counter,
                "method": "tools/list",
                "params": {}
            }),
        )?;
        counter += 1;
        let resp = recv(&rx, timeout)?;
        if resp.get("result").is_none() {
            return Err(format!("unexpected response during soak: {resp:?}").into());
        }
    }

    child.kill().ok();
    child.wait().ok();
    Ok(())
}
