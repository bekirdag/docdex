use reqwest::blocking::Client;
use serde_json::Value;
use std::error::Error;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex, MutexGuard, OnceLock,
};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

fn mcp_local_completion_test_guard() -> MutexGuard<'static, ()> {
    static TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    TEST_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .expect("mcp local completion test lock poisoned")
}

fn docdex_bin() -> PathBuf {
    std::env::set_var("DOCDEX_CLI_LOCAL", "1");
    std::env::set_var("DOCDEX_WEB_ENABLED", "0");
    assert_cmd::cargo::cargo_bin!("docdexd").to_path_buf()
}

fn write_repo(repo_root: &Path) -> Result<(), Box<dyn Error>> {
    let src_dir = repo_root.join("src");
    std::fs::create_dir_all(&src_dir)?;
    std::fs::write(src_dir.join("main.rs"), "fn main() {}\n")?;
    Ok(())
}

fn run_index(state_root: &Path, repo_root: &Path) -> Result<(), Box<dyn Error>> {
    let output = Command::new(docdex_bin())
        .env("DOCDEX_WEB_ENABLED", "0")
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .args([
            "index",
            "--repo",
            repo_root.to_string_lossy().as_ref(),
            "--state-dir",
            state_root.to_string_lossy().as_ref(),
        ])
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "docdexd index failed: {}\nstdout: {}\nstderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(())
}

fn pick_free_port() -> Option<u16> {
    match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => Some(listener.local_addr().ok()?.port()),
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping mcp delegation test: TCP bind not permitted");
            None
        }
        Err(err) => panic!("bind ephemeral port: {err}"),
    }
}

fn wait_for_health(host: &str, port: u16) -> Result<(), Box<dyn Error>> {
    let client = Client::builder().timeout(Duration::from_secs(1)).build()?;
    let url = format!("http://{host}:{port}/healthz");
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        match client.get(&url).send() {
            Ok(resp) if resp.status().is_success() => return Ok(()),
            _ => thread::sleep(Duration::from_millis(200)),
        }
    }
    Err("docdexd healthz endpoint did not respond in time".into())
}

fn spawn_server(
    state_root: &Path,
    repo_root: &Path,
    port: u16,
    config_path: &Path,
) -> Result<Child, Box<dyn Error>> {
    let repo_arg = repo_root.to_string_lossy().to_string();
    let lock_path = state_root.join("daemon.lock");
    Ok(Command::new(docdex_bin())
        .env("DOCDEX_WEB_ENABLED", "0")
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("DOCDEX_ENABLE_MCP", "1")
        .env("DOCDEX_STATE_DIR", state_root)
        .env("DOCDEX_CONFIG_PATH", config_path)
        .env("DOCDEX_DAEMON_LOCK_PATH", &lock_path)
        .args([
            "serve",
            "--repo",
            repo_arg.as_str(),
            "--host",
            "127.0.0.1",
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

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct MockOllamaGuard {
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

#[derive(Clone, Copy)]
enum MockGenerateBehavior {
    Success,
    Failure,
}

impl Drop for MockOllamaGuard {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn handle_mock_ollama_request(
    mut stream: TcpStream,
    generate_behavior: MockGenerateBehavior,
) -> std::io::Result<()> {
    let mut buffer = [0u8; 4096];
    let read = stream.read(&mut buffer)?;
    if read == 0 {
        return Ok(());
    }
    let request = String::from_utf8_lossy(&buffer[..read]);
    let request_line = request.lines().next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");
    match (method, path) {
        ("GET", "/api/tags") => {
            write_http_response(&mut stream, 200, r#"{"models":[{"name":"test-model"}]}"#)
        }
        ("POST", "/api/generate") => match generate_behavior {
            MockGenerateBehavior::Success => {
                write_http_response(&mut stream, 200, r#"{"response":"ok"}"#)
            }
            MockGenerateBehavior::Failure => {
                write_http_response(&mut stream, 500, r#"{"error":"generate failed"}"#)
            }
        },
        _ => write_http_response(&mut stream, 404, r#"{"error":"not found"}"#),
    }
}

fn write_http_response(stream: &mut TcpStream, status: u16, body: &str) -> std::io::Result<()> {
    let status_text = match status {
        200 => "OK",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "OK",
    };
    let response = format!(
        "HTTP/1.1 {status} {status_text}\r\nContent-Type: application/json\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{body}",
        status = status,
        status_text = status_text,
        len = body.len(),
        body = body
    );
    stream.write_all(response.as_bytes())?;
    stream.flush()
}

fn spawn_mock_ollama(
    generate_behavior: MockGenerateBehavior,
) -> Result<(u16, MockOllamaGuard), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_handle = stop.clone();
    let handle = thread::spawn(move || {
        while !stop_handle.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let _ = handle_mock_ollama_request(stream, generate_behavior);
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(25));
                }
                Err(_) => break,
            }
        }
    });
    Ok((
        port,
        MockOllamaGuard {
            stop,
            handle: Some(handle),
        },
    ))
}

fn write_config(path: &Path, ollama_port: u16) -> Result<(), Box<dyn Error>> {
    let payload = format!(
        "[llm]\nprovider=\"ollama\"\nbase_url=\"http://127.0.0.1:{}\"\ndefault_model=\"test-model\"\n\n[llm.delegation]\nenabled=true\nmax_tokens=32\ntimeout_ms=2000\nmax_context_chars=200\n",
        ollama_port
    );
    std::fs::write(path, payload)?;
    Ok(())
}

#[test]
fn mcp_local_completion_tool_returns_output() -> Result<(), Box<dyn Error>> {
    let _serial = mcp_local_completion_test_guard();
    let temp = TempDir::new()?;
    let repo_root = temp.path().join("repo");
    let state_root = temp.path().join("state");
    std::fs::create_dir_all(&repo_root)?;
    std::fs::create_dir_all(&state_root)?;
    write_repo(&repo_root)?;
    run_index(&state_root, &repo_root)?;

    let (ollama_port, _ollama_guard) = spawn_mock_ollama(MockGenerateBehavior::Success)?;
    let config_path = temp.path().join("config.toml");
    write_config(&config_path, ollama_port)?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let child = spawn_server(&state_root, &repo_root, port, &config_path)?;
    let _guard = ChildGuard(child);
    wait_for_health("127.0.0.1", port)?;

    let client = Client::builder().timeout(Duration::from_secs(20)).build()?;
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "docdex_local_completion",
            "arguments": {
                "task_type": "format_code",
                "instruction": "Format",
                "context": "let  a=1;",
                "agent": "model:test-model"
            }
        }
    });
    let resp = client
        .post(format!("http://127.0.0.1:{port}/v1/mcp"))
        .json(&payload)
        .send()?;
    let status = resp.status();
    let body_text = resp.text()?;
    assert!(status.is_success(), "status={status} body={body_text}");
    let body: Value = serde_json::from_str(&body_text)?;
    let text = body
        .get("result")
        .and_then(|value| value.get("content"))
        .and_then(|value| value.as_array())
        .and_then(|value| value.first())
        .and_then(|value| value.get("text"))
        .and_then(|value| value.as_str())
        .ok_or("missing mcp tool response")?;
    let parsed: Value = serde_json::from_str(text)?;
    assert_eq!(parsed.get("output").and_then(|v| v.as_str()), Some("ok"));
    assert_eq!(
        parsed.get("adapter").and_then(|v| v.as_str()),
        Some("ollama")
    );

    let repo_telemetry: Value = client
        .get(format!("http://127.0.0.1:{port}/v1/telemetry/delegation"))
        .send()?
        .json()?;
    assert_eq!(
        repo_telemetry
            .get("delegate_requests_total")
            .and_then(|value| value.as_u64()),
        Some(1)
    );
    assert_eq!(
        repo_telemetry
            .get("delegate_offloaded_total")
            .and_then(|value| value.as_u64()),
        Some(1)
    );

    let all_telemetry: Value = client
        .get(format!(
            "http://127.0.0.1:{port}/v1/telemetry/delegation?all=true"
        ))
        .send()?
        .json()?;
    assert_eq!(
        all_telemetry
            .get("delegate_requests_total")
            .and_then(|value| value.as_u64()),
        Some(1)
    );
    assert_eq!(
        all_telemetry
            .get("delegate_offloaded_total")
            .and_then(|value| value.as_u64()),
        Some(1)
    );

    Ok(())
}

#[test]
fn mcp_local_completion_failure_updates_telemetry() -> Result<(), Box<dyn Error>> {
    let _serial = mcp_local_completion_test_guard();
    let temp = TempDir::new()?;
    let repo_root = temp.path().join("repo");
    let state_root = temp.path().join("state");
    std::fs::create_dir_all(&repo_root)?;
    std::fs::create_dir_all(&state_root)?;
    write_repo(&repo_root)?;
    run_index(&state_root, &repo_root)?;

    let (ollama_port, _ollama_guard) = spawn_mock_ollama(MockGenerateBehavior::Failure)?;
    let config_path = temp.path().join("config.toml");
    write_config(&config_path, ollama_port)?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let child = spawn_server(&state_root, &repo_root, port, &config_path)?;
    let _guard = ChildGuard(child);
    wait_for_health("127.0.0.1", port)?;

    let client = Client::builder().timeout(Duration::from_secs(20)).build()?;
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "docdex_local_completion",
            "arguments": {
                "task_type": "format_code",
                "instruction": "Format",
                "context": "let  a=1;",
                "agent": "model:test-model"
            }
        }
    });
    let resp = client
        .post(format!("http://127.0.0.1:{port}/v1/mcp"))
        .json(&payload)
        .send()?;
    let status = resp.status();
    let body_text = resp.text()?;
    assert!(status.is_success(), "status={status} body={body_text}");
    let body: Value = serde_json::from_str(&body_text)?;
    assert!(
        body.get("error").is_some(),
        "expected MCP tool error response"
    );

    let repo_telemetry: Value = client
        .get(format!("http://127.0.0.1:{port}/v1/telemetry/delegation"))
        .send()?
        .json()?;
    assert_eq!(
        repo_telemetry
            .get("delegate_requests_total")
            .and_then(|value| value.as_u64()),
        Some(1)
    );
    assert_eq!(
        repo_telemetry
            .get("delegate_failed_total")
            .and_then(|value| value.as_u64()),
        Some(1)
    );
    assert_eq!(
        repo_telemetry
            .get("delegate_offloaded_total")
            .and_then(|value| value.as_u64()),
        Some(0)
    );

    let all_telemetry: Value = client
        .get(format!(
            "http://127.0.0.1:{port}/v1/telemetry/delegation?all=true"
        ))
        .send()?
        .json()?;
    assert_eq!(
        all_telemetry
            .get("delegate_requests_total")
            .and_then(|value| value.as_u64()),
        Some(1)
    );
    assert_eq!(
        all_telemetry
            .get("delegate_failed_total")
            .and_then(|value| value.as_u64()),
        Some(1)
    );

    Ok(())
}
