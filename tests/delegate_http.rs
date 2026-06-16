use reqwest::blocking::Client;
use serde_json::Value;
use std::error::Error;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

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

fn is_permission_denied(err: &dyn Error) -> bool {
    let mut current = Some(err);
    while let Some(err) = current {
        let message = err.to_string();
        if message.contains("Operation not permitted") || message.contains("Permission denied") {
            return true;
        }
        current = err.source();
    }
    false
}

fn pick_free_port() -> Option<u16> {
    match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => Some(listener.local_addr().ok()?.port()),
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping delegate test: TCP bind not permitted");
            None
        }
        Err(err) => panic!("bind ephemeral port: {err}"),
    }
}

fn wait_for_health(host: &str, port: u16) -> Result<(), Box<dyn Error>> {
    let client = Client::builder().timeout(Duration::from_secs(1)).build()?;
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
        .env("DOCDEX_ENABLE_MCP", "0")
        .env("DOCDEX_DISABLE_MCODA_CLI", "1")
        .env("DOCDEX_STATE_DIR", state_root)
        .env("DOCDEX_CONFIG_PATH", config_path)
        .env("DOCDEX_DAEMON_LOCK_PATH", &lock_path)
        .env("HOME", state_root)
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

impl Drop for MockOllamaGuard {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn handle_mock_ollama_request(mut stream: TcpStream) -> std::io::Result<()> {
    let request_bytes = read_http_request(&mut stream)?;
    if request_bytes.is_empty() {
        return Ok(());
    }
    let request = String::from_utf8_lossy(&request_bytes);
    let request_line = request.lines().next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");
    match (method, path) {
        ("GET", "/api/tags") => {
            write_http_response(&mut stream, 200, r#"{"models":[{"name":"test-model"}]}"#)
        }
        ("POST", "/api/generate") => write_http_response(&mut stream, 200, r#"{"response":"ok"}"#),
        _ => write_http_response(&mut stream, 404, r#"{"error":"not found"}"#),
    }
}

fn read_http_request(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let mut expected_len = None;
    loop {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if expected_len.is_none() {
            if let Some(header_end) = find_header_end(&buffer) {
                let headers = String::from_utf8_lossy(&buffer[..header_end]);
                let content_length = headers.lines().find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    if name.trim().eq_ignore_ascii_case("content-length") {
                        value.trim().parse::<usize>().ok()
                    } else {
                        None
                    }
                });
                expected_len = Some(header_end + 4 + content_length.unwrap_or(0));
            }
        }
        if expected_len.is_some_and(|len| buffer.len() >= len) {
            break;
        }
    }
    Ok(buffer)
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn write_http_response(stream: &mut TcpStream, status: u16, body: &str) -> std::io::Result<()> {
    let status_text = match status {
        200 => "OK",
        404 => "Not Found",
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

fn spawn_mock_ollama() -> Result<(u16, MockOllamaGuard), Box<dyn Error>> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let port = listener.local_addr()?.port();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_handle = stop.clone();
    let handle = thread::spawn(move || {
        while !stop_handle.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let _ = handle_mock_ollama_request(stream);
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

fn write_config(path: &Path, state_root: &Path, ollama_port: u16) -> Result<(), Box<dyn Error>> {
    let payload = format!(
        "[core]\nglobal_state_dir=\"{}\"\n\n[llm]\nprovider=\"ollama\"\nbase_url=\"http://127.0.0.1:{}\"\ndefault_model=\"test-model\"\n\n[llm.delegation]\nenabled=true\nmax_tokens=32\ntimeout_ms=2000\nmax_context_chars=200\n",
        state_root.display(),
        ollama_port
    );
    std::fs::write(path, payload)?;
    Ok(())
}

#[test]
fn delegate_endpoint_returns_output() -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let repo_root = temp.path().join("repo");
    let state_root = temp.path().join("state");
    std::fs::create_dir_all(&repo_root)?;
    std::fs::create_dir_all(&state_root)?;
    write_repo(&repo_root)?;
    if let Err(err) = run_index(&state_root, &repo_root) {
        if is_permission_denied(err.as_ref()) {
            eprintln!("skipping delegate test: index permission denied");
            return Ok(());
        }
        return Err(err);
    }

    let (ollama_port, _ollama_guard) = match spawn_mock_ollama() {
        Ok(value) => value,
        Err(err) => {
            if is_permission_denied(err.as_ref()) {
                eprintln!("skipping delegate test: mock ollama permission denied");
                return Ok(());
            }
            return Err(err);
        }
    };
    let config_path = temp.path().join("config.toml");
    write_config(&config_path, &state_root, ollama_port)?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let child = match spawn_server(&state_root, &repo_root, port, &config_path) {
        Ok(child) => child,
        Err(err) => {
            if is_permission_denied(err.as_ref()) {
                eprintln!("skipping delegate test: serve permission denied");
                return Ok(());
            }
            return Err(err);
        }
    };
    let _guard = ChildGuard(child);
    wait_for_health("127.0.0.1", port)?;

    let client = Client::builder().timeout(Duration::from_secs(5)).build()?;
    let url = format!("http://127.0.0.1:{port}/v1/delegate");
    let resp = client
        .post(&url)
        .json(&serde_json::json!({
            "agent": "model:test-model",
            "task_type": "format_code",
            "instruction": "Format this code",
            "context": "let  a=1;"
        }))
        .send()?;
    assert!(resp.status().is_success());
    let body: Value = resp.json()?;
    assert_eq!(body.get("output").and_then(|v| v.as_str()), Some("ok"));
    assert_eq!(body.get("adapter").and_then(|v| v.as_str()), Some("ollama"));

    let bad_resp = client
        .post(&url)
        .json(&serde_json::json!({
            "task_type": "unknown",
            "instruction": "Format",
            "context": "x"
        }))
        .send()?;
    assert_eq!(bad_resp.status(), reqwest::StatusCode::BAD_REQUEST);

    Ok(())
}
