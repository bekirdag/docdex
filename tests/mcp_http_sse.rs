use reqwest::blocking::Client;
use serde_json::json;
use std::error::Error;
use std::fs;
use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

const MCP_HTTP_RESPONSE_TIMEOUT: Duration = Duration::from_secs(40);

struct Daemon {
    child: Child,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn docdex_bin() -> PathBuf {
    std::env::set_var("DOCDEX_CLI_LOCAL", "1");
    std::env::set_var("DOCDEX_WEB_ENABLED", "0");
    assert_cmd::cargo::cargo_bin!("docdexd").to_path_buf()
}

fn pick_free_port() -> Option<u16> {
    match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => Some(listener.local_addr().ok()?.port()),
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping test: TCP bind not permitted in this environment");
            None
        }
        Err(err) => panic!("bind ephemeral port: {err}"),
    }
}

fn wait_for_health(port: u16, timeout: Duration) -> Result<(), Box<dyn Error>> {
    let client = Client::builder().timeout(Duration::from_secs(1)).build()?;
    let url = format!("http://127.0.0.1:{port}/healthz");
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        match client.get(&url).send() {
            Ok(resp) if resp.status().is_success() => return Ok(()),
            _ => thread::sleep(Duration::from_millis(200)),
        }
    }
    Err("docdexd healthz endpoint did not respond in time".into())
}

fn write_repo(repo_root: &Path) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(repo_root.join(".git"))?;
    fs::write(repo_root.join("README.md"), "# Docdex\n")?;
    Ok(())
}

fn start_daemon(state_root: &Path, repo_root: &Path, port: u16) -> Result<Daemon, Box<dyn Error>> {
    let lock_path = state_root.join("daemon.lock");
    let child = Command::new(docdex_bin())
        .env("DOCDEX_WEB_ENABLED", "0")
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("DOCDEX_STATE_DIR", state_root)
        .env("DOCDEX_DAEMON_LOCK_PATH", &lock_path)
        .env("DOCDEX_ENABLE_MCP", "1")
        .args([
            "daemon",
            "--repo",
            repo_root.to_str().unwrap(),
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--log",
            "warn",
            "--secure-mode=false",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    Ok(Daemon { child })
}

fn start_daemon_with_health(
    state_root: &Path,
    repo_root: &Path,
) -> Result<Option<(Daemon, u16)>, Box<dyn Error>> {
    for _ in 0..3 {
        let Some(port) = pick_free_port() else {
            return Ok(None);
        };
        let daemon = start_daemon(state_root, repo_root, port)?;
        if wait_for_health(port, Duration::from_secs(20)).is_ok() {
            return Ok(Some((daemon, port)));
        }
    }
    Err("docdexd healthz endpoint did not respond in time".into())
}

fn read_next_sse(reader: &mut BufReader<reqwest::blocking::Response>) -> Option<serde_json::Value> {
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line).ok()? == 0 {
            return None;
        }
        let trimmed = line.trim();
        if let Some(payload) = trimmed.strip_prefix("data:") {
            let payload = payload.trim();
            if let Ok(value) = serde_json::from_str(payload) {
                return Some(value);
            }
            continue;
        }
    }
}

fn is_backoff_required(resp: &serde_json::Value) -> bool {
    let Some(error) = resp.get("error") else {
        return false;
    };
    let data = error.get("data");
    let code = data
        .and_then(|value| value.get("code"))
        .and_then(|value| value.as_str());
    if code == Some("backoff_required") {
        return true;
    }
    let nested_code = data
        .and_then(|value| value.get("error"))
        .and_then(|value| value.get("code"))
        .and_then(|value| value.as_str());
    if nested_code == Some("backoff_required") {
        return true;
    }
    data.and_then(|value| value.get("message"))
        .and_then(|value| value.as_str())
        .map(|message| message.to_ascii_lowercase().contains("backoff required"))
        .unwrap_or(false)
}

fn send_tools_call_with_backoff(
    client: &Client,
    reader: &mut BufReader<reqwest::blocking::Response>,
    session_id: &str,
    port: u16,
    payload: &serde_json::Value,
    timeout: Duration,
) -> Result<serde_json::Value, Box<dyn Error>> {
    let deadline = Instant::now() + timeout;
    loop {
        let ack = client
            .post(format!("http://127.0.0.1:{port}/v1/mcp/message"))
            .header("x-docdex-mcp-session", session_id)
            .json(payload)
            .send()?;
        assert!(ack.status().is_success());

        let resp = read_next_sse(reader).ok_or("missing tools response")?;
        if resp.get("result").is_some() {
            return Ok(resp);
        }
        if is_backoff_required(&resp) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(200));
            continue;
        }
        return Err(format!("tools/call failed: {resp}").into());
    }
}

fn normalize_windows_path(value: &str) -> String {
    if cfg!(windows) {
        let trimmed = value.trim();
        let without_prefix = trimmed.strip_prefix(r"\\?\").unwrap_or(trimmed);
        without_prefix.replace('/', "\\").to_ascii_lowercase()
    } else {
        value.trim().to_string()
    }
}

fn canonical_display(path: &Path) -> String {
    path.canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .display()
        .to_string()
}

#[test]
fn mcp_http_sse_roundtrip() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    let repo_other = TempDir::new()?;
    write_repo(repo.path())?;
    write_repo(repo_other.path())?;
    let state_dir = TempDir::new()?;
    let Some((_daemon, port)) = start_daemon_with_health(state_dir.path(), repo.path())? else {
        return Ok(());
    };

    let client = Client::builder()
        .timeout(MCP_HTTP_RESPONSE_TIMEOUT)
        .build()?;
    let sse_url = format!("http://127.0.0.1:{port}/v1/mcp/sse");
    let sse_resp = client.get(&sse_url).send()?;
    let session_id = sse_resp
        .headers()
        .get("x-docdex-mcp-session")
        .and_then(|value| value.to_str().ok())
        .ok_or("missing mcp session header")?
        .to_string();

    let mut reader = BufReader::new(sse_resp);

    let uninit_payload = json!({
        "jsonrpc": "2.0",
        "id": 0,
        "method": "tools/list",
        "params": {}
    });
    let uninit_resp = client
        .post(format!("http://127.0.0.1:{port}/v1/mcp/message"))
        .header("x-docdex-mcp-session", session_id.clone())
        .json(&uninit_payload)
        .send()?;
    assert_eq!(uninit_resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let uninit_body: serde_json::Value = uninit_resp.json()?;
    let uninit_message = uninit_body
        .get("error")
        .and_then(|value| value.get("message"))
        .and_then(|value| value.as_str())
        .unwrap_or("");
    assert!(
        uninit_message.contains("initialize"),
        "expected initialize hint, got: {uninit_message}"
    );

    let init_payload = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": { "workspace_root": repo_other.path() }
    });
    let init_ack = client
        .post(format!("http://127.0.0.1:{port}/v1/mcp/message"))
        .header("x-docdex-mcp-session", session_id.clone())
        .json(&init_payload)
        .send()?;
    let init_status = init_ack.status();
    let init_body = init_ack.text()?;
    assert!(
        init_status.is_success(),
        "initialize ack failed: {init_status}: {init_body}"
    );

    let init_resp = read_next_sse(&mut reader).ok_or("missing initialize response")?;
    assert!(
        init_resp.get("result").is_some(),
        "initialize result missing"
    );

    let tools_payload = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    });
    let tools_ack = client
        .post(format!("http://127.0.0.1:{port}/v1/mcp/message"))
        .header("x-docdex-mcp-session", session_id.clone())
        .json(&tools_payload)
        .send()?;
    assert!(tools_ack.status().is_success());

    let tools_resp = read_next_sse(&mut reader).ok_or("missing tools/list response")?;
    assert!(
        tools_resp.get("result").is_some(),
        "tools/list result missing"
    );

    let notify_payload = json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized",
        "params": {}
    });
    let notify_resp = client
        .post(format!("http://127.0.0.1:{port}/v1/mcp"))
        .json(&notify_payload)
        .send()?;
    assert_eq!(notify_resp.status(), reqwest::StatusCode::NO_CONTENT);

    let stats_payload = json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": { "name": "docdex_stats", "arguments": {} }
    });
    let stats_resp = send_tools_call_with_backoff(
        &client,
        &mut reader,
        &session_id,
        port,
        &stats_payload,
        MCP_HTTP_RESPONSE_TIMEOUT,
    )?;
    let stats_text = stats_resp
        .get("result")
        .and_then(|value| value.get("content"))
        .and_then(|value| value.as_array())
        .and_then(|value| value.first())
        .and_then(|value| value.get("text"))
        .and_then(|value| value.as_str())
        .ok_or_else(|| format!("stats response missing content: {stats_resp}"))?;
    let stats_json: serde_json::Value = serde_json::from_str(stats_text)
        .map_err(|err| format!("stats response invalid json ({err}): {stats_text}"))?;
    let project_root = stats_json
        .get("project_root")
        .and_then(|value| value.as_str())
        .ok_or_else(|| format!("stats response missing project_root: {stats_json}"))?;
    let expected_root = normalize_windows_path(&canonical_display(repo_other.path()));
    let reported_root = normalize_windows_path(project_root);
    assert!(
        reported_root.contains(&expected_root),
        "stats project_root mismatch: {project_root}"
    );

    let stats_override_payload = json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": { "name": "docdex_stats", "arguments": { "project_root": repo.path() } }
    });
    let stats_override_resp = send_tools_call_with_backoff(
        &client,
        &mut reader,
        &session_id,
        port,
        &stats_override_payload,
        MCP_HTTP_RESPONSE_TIMEOUT,
    )?;
    let stats_override_text = stats_override_resp
        .get("result")
        .and_then(|value| value.get("content"))
        .and_then(|value| value.as_array())
        .and_then(|value| value.first())
        .and_then(|value| value.get("text"))
        .and_then(|value| value.as_str())
        .ok_or_else(|| format!("stats override missing content: {stats_override_resp}"))?;
    let stats_override_json: serde_json::Value = serde_json::from_str(stats_override_text)
        .map_err(|err| format!("stats override invalid json ({err}): {stats_override_text}"))?;
    let override_root = stats_override_json
        .get("project_root")
        .and_then(|value| value.as_str())
        .ok_or_else(|| format!("stats override missing project_root: {stats_override_json}"))?;
    let expected_override_root = normalize_windows_path(&canonical_display(repo.path()));
    let reported_override_root = normalize_windows_path(override_root);
    assert!(
        reported_override_root.contains(&expected_override_root),
        "stats override project_root mismatch: {override_root}"
    );

    let stats_followup_payload = json!({
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": { "name": "docdex_stats", "arguments": {} }
    });
    let stats_followup_resp = send_tools_call_with_backoff(
        &client,
        &mut reader,
        &session_id,
        port,
        &stats_followup_payload,
        MCP_HTTP_RESPONSE_TIMEOUT,
    )?;
    let stats_followup_text = stats_followup_resp
        .get("result")
        .and_then(|value| value.get("content"))
        .and_then(|value| value.as_array())
        .and_then(|value| value.first())
        .and_then(|value| value.get("text"))
        .and_then(|value| value.as_str())
        .ok_or_else(|| format!("stats followup missing content: {stats_followup_resp}"))?;
    let stats_followup_json: serde_json::Value = serde_json::from_str(stats_followup_text)
        .map_err(|err| format!("stats followup invalid json ({err}): {stats_followup_text}"))?;
    let followup_root = stats_followup_json
        .get("project_root")
        .and_then(|value| value.as_str())
        .ok_or_else(|| format!("stats followup missing project_root: {stats_followup_json}"))?;
    let reported_followup_root = normalize_windows_path(followup_root);
    assert!(
        reported_followup_root.contains(&expected_override_root),
        "stats followup project_root mismatch: {followup_root}"
    );

    let legacy_stats_payload = json!({
        "jsonrpc": "2.0",
        "id": 6,
        "method": "docdex_stats",
        "params": { "project_root": repo.path() }
    });
    let legacy_stats_resp = send_tools_call_with_backoff(
        &client,
        &mut reader,
        &session_id,
        port,
        &legacy_stats_payload,
        MCP_HTTP_RESPONSE_TIMEOUT,
    )?;
    let legacy_stats_text = legacy_stats_resp
        .get("result")
        .and_then(|value| value.get("content"))
        .and_then(|value| value.as_array())
        .and_then(|value| value.first())
        .and_then(|value| value.get("text"))
        .and_then(|value| value.as_str())
        .ok_or_else(|| format!("legacy stats missing content: {legacy_stats_resp}"))?;
    let legacy_stats_json: serde_json::Value = serde_json::from_str(legacy_stats_text)
        .map_err(|err| format!("legacy stats invalid json ({err}): {legacy_stats_text}"))?;
    let legacy_root = legacy_stats_json
        .get("project_root")
        .and_then(|value| value.as_str())
        .ok_or_else(|| format!("legacy stats missing project_root: {legacy_stats_json}"))?;
    let reported_legacy_root = normalize_windows_path(legacy_root);
    assert!(
        reported_legacy_root.contains(&expected_override_root),
        "legacy stats project_root mismatch: {legacy_root}"
    );

    let legacy_dot_payload = json!({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "docdex.stats",
        "params": { "project_root": repo.path() }
    });
    let legacy_dot_resp = send_tools_call_with_backoff(
        &client,
        &mut reader,
        &session_id,
        port,
        &legacy_dot_payload,
        MCP_HTTP_RESPONSE_TIMEOUT,
    )?;
    let legacy_dot_text = legacy_dot_resp
        .get("result")
        .and_then(|value| value.get("content"))
        .and_then(|value| value.as_array())
        .and_then(|value| value.first())
        .and_then(|value| value.get("text"))
        .and_then(|value| value.as_str())
        .ok_or_else(|| format!("legacy dot stats missing content: {legacy_dot_resp}"))?;
    let legacy_dot_json: serde_json::Value = serde_json::from_str(legacy_dot_text)
        .map_err(|err| format!("legacy dot stats invalid json ({err}): {legacy_dot_text}"))?;
    let legacy_dot_root = legacy_dot_json
        .get("project_root")
        .and_then(|value| value.as_str())
        .ok_or_else(|| format!("legacy dot stats missing project_root: {legacy_dot_json}"))?;
    let reported_legacy_dot_root = normalize_windows_path(legacy_dot_root);
    assert!(
        reported_legacy_dot_root.contains(&expected_override_root),
        "legacy dot stats project_root mismatch: {legacy_dot_root}"
    );

    let direct_resp = client
        .post(format!("http://127.0.0.1:{port}/v1/mcp"))
        .json(&init_payload)
        .send()?;
    assert!(direct_resp.status().is_success());
    let direct_body: serde_json::Value = direct_resp.json()?;
    assert!(
        direct_body.get("result").is_some(),
        "direct initialize result missing"
    );

    Ok(())
}
