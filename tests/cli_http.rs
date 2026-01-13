use serde_json::Value;
use std::error::Error;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

fn docdex_bin() -> PathBuf {
    std::env::set_var("DOCDEX_CLI_LOCAL", "1");
    std::env::set_var("DOCDEX_WEB_ENABLED", "0");
    assert_cmd::cargo::cargo_bin!("docdexd").to_path_buf()
}

fn pick_free_port() -> Option<u16> {
    match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => Some(listener.local_addr().ok()?.port()),
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping cli http tests: TCP bind not permitted");
            None
        }
        Err(err) => panic!("bind ephemeral port: {err}"),
    }
}

fn spawn_server(
    state_root: &Path,
    repo_root: &Path,
    host: &str,
    port: u16,
) -> Result<Child, Box<dyn Error>> {
    let repo_str = repo_root.to_string_lossy().to_string();
    let state_root_str = state_root.to_string_lossy().to_string();
    Ok(Command::new(docdex_bin())
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("DOCDEX_WEB_ENABLED", "0")
        .env("DOCDEX_ENABLE_MCP", "0")
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .args([
            "serve",
            "--repo",
            repo_str.as_str(),
            "--state-dir",
            state_root_str.as_str(),
            "--host",
            host,
            "--port",
            &port.to_string(),
            "--log",
            "warn",
            "--secure-mode=false",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?)
}

fn spawn_daemon(
    state_root: &Path,
    repo_root: &Path,
    lock_path: &Path,
    host: &str,
    port: u16,
) -> Result<Child, Box<dyn Error>> {
    let repo_str = repo_root.to_string_lossy().to_string();
    let state_root_str = state_root.to_string_lossy().to_string();
    Ok(Command::new(docdex_bin())
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("DOCDEX_WEB_ENABLED", "0")
        .env("DOCDEX_ENABLE_MCP", "0")
        .env("DOCDEX_DAEMON_LOCK_PATH", lock_path)
        .args([
            "daemon",
            "--repo",
            repo_str.as_str(),
            "--state-dir",
            state_root_str.as_str(),
            "--host",
            host,
            "--port",
            &port.to_string(),
            "--log",
            "warn",
            "--secure-mode=false",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?)
}

fn wait_for_health(host: &str, port: u16) -> Result<(), Box<dyn Error>> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(1))
        .build()?;
    let url = format!("http://{host}:{port}/healthz");
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        match client.get(&url).send() {
            Ok(resp) if resp.status().is_success() => return Ok(()),
            _ => thread::sleep(Duration::from_millis(200)),
        }
    }
    Err("docdexd healthz endpoint did not respond in time".into())
}

fn write_repo(repo_root: &Path) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(repo_root)?;
    fs::write(repo_root.join("doc.md"), "# Fixture\n\nHTTP_SEARCH_TOKEN\n")?;
    Ok(())
}

fn resolve_index_dir(state_root: &Path, repo_root: &Path) -> Result<PathBuf, Box<dyn Error>> {
    let output = Command::new(docdex_bin())
        .env("DOCDEX_WEB_ENABLED", "0")
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("DOCDEX_STATE_DIR", state_root)
        .args([
            "repo",
            "inspect",
            "--repo",
            repo_root.to_string_lossy().as_ref(),
        ])
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "docdexd repo inspect exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    let payload: Value = serde_json::from_slice(&output.stdout)?;
    let resolved = payload
        .get("resolvedIndexStateDir")
        .and_then(|value| value.as_str())
        .ok_or("missing resolvedIndexStateDir")?;
    Ok(PathBuf::from(resolved))
}

fn send_mcp_line(
    stdin: &mut std::process::ChildStdin,
    payload: Value,
) -> Result<(), Box<dyn Error>> {
    let text = serde_json::to_string(&payload)?;
    stdin.write_all(text.as_bytes())?;
    stdin.write_all(b"\n")?;
    stdin.flush()?;
    Ok(())
}

fn read_mcp_line(
    reader: &mut BufReader<std::process::ChildStdout>,
) -> Result<Value, Box<dyn Error>> {
    let mut line = String::new();
    reader.read_line(&mut line)?;
    if line.trim().is_empty() {
        return Err("unexpected empty response line from MCP proxy".into());
    }
    Ok(serde_json::from_str(&line)?)
}

fn read_lock_pid(lock_path: &Path) -> Option<u32> {
    let data = fs::read_to_string(lock_path).ok()?;
    let payload: Value = serde_json::from_str(&data).ok()?;
    payload
        .get("pid")
        .and_then(|value| value.as_u64())
        .map(|pid| pid as u32)
}

fn kill_pid(pid: u32) {
    #[cfg(unix)]
    {
        let _ = Command::new("kill")
            .arg("-TERM")
            .arg(pid.to_string())
            .status();
    }
    #[cfg(windows)]
    {
        let _ = Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/F"])
            .status();
    }
}

#[test]
fn cli_index_and_query_use_http() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    write_repo(repo.path())?;
    let state_root = TempDir::new()?;
    let local_state = TempDir::new()?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let mut server = spawn_server(state_root.path(), repo.path(), host, port)?;
    wait_for_health(host, port)?;

    let base_url = format!("http://{host}:{port}");

    let index_out = Command::new(docdex_bin())
        .env("DOCDEX_WEB_ENABLED", "0")
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("DOCDEX_HTTP_BASE_URL", &base_url)
        .env("DOCDEX_HTTP_TIMEOUT_MS", "5000")
        .env("DOCDEX_HTTP_CONNECT_TIMEOUT_MS", "5000")
        .env("DOCDEX_CLI_LOCAL", "0")
        .env("DOCDEX_STATE_DIR", local_state.path())
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .args(["index", "--repo", repo.path().to_string_lossy().as_ref()])
        .output()?;
    assert!(
        index_out.status.success(),
        "docdexd index failed: {}",
        String::from_utf8_lossy(&index_out.stderr)
    );

    let resolved_index = resolve_index_dir(state_root.path(), repo.path())?;
    assert!(
        resolved_index.join("meta.json").exists(),
        "expected server index metadata after HTTP index"
    );

    let query_out = Command::new(docdex_bin())
        .env("DOCDEX_WEB_ENABLED", "0")
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("DOCDEX_HTTP_BASE_URL", &base_url)
        .env("DOCDEX_HTTP_TIMEOUT_MS", "5000")
        .env("DOCDEX_HTTP_CONNECT_TIMEOUT_MS", "5000")
        .env("DOCDEX_CLI_LOCAL", "0")
        .env("DOCDEX_STATE_DIR", local_state.path())
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .args([
            "query",
            "--repo",
            repo.path().to_string_lossy().as_ref(),
            "--query",
            "HTTP_SEARCH_TOKEN",
            "--limit",
            "1",
        ])
        .output()?;
    assert!(
        query_out.status.success(),
        "docdexd query failed: {}",
        String::from_utf8_lossy(&query_out.stderr)
    );
    let payload: Value = serde_json::from_slice(&query_out.stdout)?;
    let hits = payload
        .get("hits")
        .and_then(|v| v.as_array())
        .map(|v| v.as_slice())
        .unwrap_or(&[]);
    assert!(!hits.is_empty(), "expected query hits via HTTP");

    server.kill().ok();
    server.wait().ok();
    Ok(())
}

#[test]
fn cli_query_errors_when_http_unavailable() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    write_repo(repo.path())?;
    let local_state = TempDir::new()?;
    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let base_url = format!("http://127.0.0.1:{port}");

    let query_out = Command::new(docdex_bin())
        .env("DOCDEX_WEB_ENABLED", "0")
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("DOCDEX_HTTP_BASE_URL", &base_url)
        .env("DOCDEX_HTTP_TIMEOUT_MS", "5000")
        .env("DOCDEX_HTTP_CONNECT_TIMEOUT_MS", "5000")
        .env("DOCDEX_CLI_LOCAL", "0")
        .env("DOCDEX_STATE_DIR", local_state.path())
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .args([
            "query",
            "--repo",
            repo.path().to_string_lossy().as_ref(),
            "--query",
            "HTTP_SEARCH_TOKEN",
            "--limit",
            "1",
        ])
        .output()?;
    assert!(
        !query_out.status.success(),
        "expected CLI query to fail without daemon"
    );
    let stderr = String::from_utf8_lossy(&query_out.stderr);
    assert!(
        stderr.contains("docdexd search failed"),
        "expected HTTP failure message, got: {stderr}"
    );
    Ok(())
}

#[test]
fn daemon_singleton_exits_when_running() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    write_repo(repo.path())?;
    let state_root = TempDir::new()?;
    let lock_dir = TempDir::new()?;
    let lock_path = lock_dir.path().join("daemon.lock");
    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let mut daemon = spawn_daemon(state_root.path(), repo.path(), &lock_path, host, port)?;
    wait_for_health(host, port)?;

    let output = Command::new(docdex_bin())
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("DOCDEX_WEB_ENABLED", "0")
        .env("DOCDEX_ENABLE_MCP", "0")
        .env("DOCDEX_DAEMON_LOCK_PATH", &lock_path)
        .args([
            "daemon",
            "--repo",
            repo.path().to_string_lossy().as_ref(),
            "--state-dir",
            state_root.path().to_string_lossy().as_ref(),
            "--host",
            host,
            "--port",
            &port.to_string(),
            "--log",
            "warn",
            "--secure-mode=false",
        ])
        .output()?;
    assert!(
        output.status.success(),
        "expected daemon singleton to exit 0"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("already running"),
        "expected already-running message, got: {combined}"
    );
    assert!(
        combined.contains("pid="),
        "expected pid in already-running message, got: {combined}"
    );
    assert!(
        combined.contains(&format!("port={port}")),
        "expected port in already-running message, got: {combined}"
    );

    daemon.kill().ok();
    daemon.wait().ok();
    Ok(())
}

#[test]
fn mcp_add_reports_live_endpoint_from_lock() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    write_repo(repo.path())?;
    let state_root = TempDir::new()?;
    let lock_dir = TempDir::new()?;
    let lock_path = lock_dir.path().join("daemon.lock");
    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let mut daemon = spawn_daemon(state_root.path(), repo.path(), &lock_path, host, port)?;
    wait_for_health(host, port)?;

    let output = Command::new(docdex_bin())
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("DOCDEX_WEB_ENABLED", "0")
        .env("DOCDEX_DAEMON_LOCK_PATH", &lock_path)
        .args([
            "mcp-add",
            "--agent",
            "grok",
            "--repo",
            repo.path().to_string_lossy().as_ref(),
            "--log",
            "warn",
            "--max-results",
            "8",
        ])
        .output()?;
    assert!(
        output.status.success(),
        "expected mcp-add to succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let expected = format!("http://127.0.0.1:{port}/v1/mcp/sse");
    assert!(
        stdout.contains(&expected),
        "expected mcp-add to include live endpoint {expected}, got: {stdout}"
    );
    assert!(
        stdout.contains("Legacy stdio proxy"),
        "expected legacy stdio guidance, got: {stdout}"
    );

    daemon.kill().ok();
    daemon.wait().ok();
    Ok(())
}

#[test]
fn mcp_auto_start_spawns_daemon_when_requested() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    write_repo(repo.path())?;
    let state_root = TempDir::new()?;
    let lock_dir = TempDir::new()?;
    let lock_path = lock_dir.path().join("daemon.lock");
    let config_dir = TempDir::new()?;
    let config_path = config_dir.path().join("config.toml");
    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    fs::write(
        &config_path,
        format!(
            "[server]\nhttp_bind_addr = \"127.0.0.1:{port}\"\nenable_mcp = true\n"
        ),
    )?;

    let mut child = Command::new(docdex_bin())
        .env("DOCDEX_WEB_ENABLED", "0")
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("DOCDEX_DAEMON_LOCK_PATH", &lock_path)
        .env("DOCDEX_CONFIG_PATH", &config_path)
        .env("DOCDEX_STATE_DIR", state_root.path())
        .env_remove("DOCDEX_DISABLE_DAEMON_AUTO")
        .env_remove("DOCDEX_HTTP_BASE_URL")
        .args([
            "mcp",
            "--repo",
            repo.path().to_string_lossy().as_ref(),
            "--log",
            "warn",
            "--max-results",
            "4",
            "--start-daemon",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;

    let mut stdin = child
        .stdin
        .take()
        .ok_or("failed to take MCP stdin")?;
    let stdout = child
        .stdout
        .take()
        .ok_or("failed to take MCP stdout")?;
    let mut reader = BufReader::new(stdout);

    send_mcp_line(
        &mut stdin,
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {}
        }),
    )?;
    let response = read_mcp_line(&mut reader)?;
    assert!(
        response.get("result").is_some(),
        "expected tools/list result, got: {response}"
    );

    child.kill().ok();
    child.wait().ok();

    if let Some(pid) = read_lock_pid(&lock_path) {
        kill_pid(pid);
    }
    Ok(())
}
