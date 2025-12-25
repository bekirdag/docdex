use axum::{routing::post, Json, Router};
use reqwest::blocking::Client;
use serde_json::{json, Value};
use std::error::Error;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::sync::oneshot;

fn docdex_bin() -> PathBuf {
    assert_cmd::cargo::cargo_bin!("docdexd").to_path_buf()
}

fn write_fixture_repo(repo_root: &Path) -> Result<(), Box<dyn Error>> {
    let docs_dir = repo_root.join("docs");
    std::fs::create_dir_all(&docs_dir)?;
    std::fs::write(docs_dir.join("overview.md"), "# Overview\n\nHello.\n")?;
    Ok(())
}

fn setup_repo() -> Result<TempDir, Box<dyn Error>> {
    let temp = TempDir::new()?;
    write_fixture_repo(temp.path())?;
    Ok(temp)
}

fn pick_free_port() -> Option<u16> {
    match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => Some(listener.local_addr().ok()?.port()),
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping HTTP tests: TCP bind not permitted in this environment");
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
    ollama_base_url: &str,
    embedding_model: &str,
    embedding_timeout_ms: u64,
) -> Result<Child, Box<dyn Error>> {
    let repo_str = repo_root.to_string_lossy().to_string();
    Ok(Command::new(docdex_bin())
        .env("DOCDEX_STATE_DIR", state_root)
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
            "--enable-memory=true",
            "--ollama-base-url",
            ollama_base_url,
            "--embedding-model",
            embedding_model,
            "--embedding-timeout-ms",
            &embedding_timeout_ms.to_string(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?)
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

struct MockOllama {
    base_url: String,
    shutdown: Option<oneshot::Sender<()>>,
    join: Option<thread::JoinHandle<()>>,
}

impl MockOllama {
    fn spawn(handler: axum::routing::MethodRouter) -> Result<Option<Self>, Box<dyn Error>> {
        let std_listener = match TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("skipping embedding tests: TCP bind not permitted in this environment");
                return Ok(None);
            }
            Err(err) => return Err(err.into()),
        };
        let addr = std_listener.local_addr()?;
        let (tx, rx) = oneshot::channel::<()>();
        let join = thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
            rt.block_on(async move {
                let app = Router::new().route("/api/embeddings", handler);
                let listener =
                    tokio::net::TcpListener::from_std(std_listener).expect("tokio listener");
                axum::serve(listener, app)
                    .with_graceful_shutdown(async move {
                        let _ = rx.await;
                    })
                    .await
                    .expect("mock ollama server");
            });
        });
        Ok(Some(Self {
            base_url: format!("http://{}", addr),
            shutdown: Some(tx),
            join: Some(join),
        }))
    }
}

impl Drop for MockOllama {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

struct McpHarness {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    reader: BufReader<std::process::ChildStdout>,
}

impl McpHarness {
    fn spawn(repo: &Path, envs: &[(&str, &str)]) -> Result<Self, Box<dyn Error>> {
        let repo_str = repo.to_string_lossy().to_string();
        let mut cmd = Command::new(docdex_bin());
        cmd.args([
            "mcp",
            "--repo",
            repo_str.as_str(),
            "--log",
            "warn",
            "--max-results",
            "4",
        ]);
        for (k, v) in envs {
            cmd.env(k, v);
        }
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let stdin = child
            .stdin
            .take()
            .ok_or("failed to take child stdin for MCP server")?;
        let stdout = child
            .stdout
            .take()
            .ok_or("failed to take child stdout for MCP server")?;
        Ok(Self {
            child,
            stdin,
            reader: BufReader::new(stdout),
        })
    }

    fn shutdown(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
    }
}

fn send_line(
    stdin: &mut std::process::ChildStdin,
    payload: serde_json::Value,
) -> Result<(), Box<dyn Error>> {
    let text = serde_json::to_string(&payload)?;
    stdin.write_all(text.as_bytes())?;
    stdin.write_all(b"\n")?;
    stdin.flush()?;
    Ok(())
}

fn read_line(
    reader: &mut BufReader<std::process::ChildStdout>,
) -> Result<serde_json::Value, Box<dyn Error>> {
    let mut line = String::new();
    reader.read_line(&mut line)?;
    if line.trim().is_empty() {
        return Err("unexpected empty response line from MCP server".into());
    }
    Ok(serde_json::from_str(&line)?)
}

fn mcp_error_data_code(resp: &Value) -> Option<&str> {
    resp.get("error")
        .and_then(|v| v.get("data"))
        .and_then(|v| v.get("code"))
        .and_then(|v| v.as_str())
}

#[test]
fn http_memory_store_timeout_returns_stable_code() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let Some(slow) = MockOllama::spawn(post(move || async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        (
            axum::http::StatusCode::OK,
            Json(json!({ "embedding": [0.1, 0.2] })),
        )
    }))?
    else {
        return Ok(());
    };

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let state_root = TempDir::new()?;
    let mut server = spawn_server(
        state_root.path(),
        repo.path(),
        host,
        port,
        &slow.base_url,
        "fake-embed",
        50,
    )?;
    wait_for_health(host, port)?;

    let client = Client::builder().timeout(Duration::from_secs(2)).build()?;
    let url = format!("http://{host}:{port}/v1/memory/store");
    let resp = client.post(&url).json(&json!({ "text": "hello" })).send()?;
    assert_eq!(resp.status().as_u16(), 504);
    let body: Value = resp.json()?;
    assert_eq!(
        body.get("error")
            .and_then(|v| v.get("code"))
            .and_then(|v| v.as_str()),
        Some("embedding_timeout")
    );
    assert!(
        !body.to_string().contains("hello"),
        "embedding input leaked in response body: {body}"
    );

    server.kill().ok();
    server.wait().ok();
    Ok(())
}

#[test]
fn mcp_memory_store_timeout_returns_stable_code() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let state_root = TempDir::new()?;
    let project_root = repo.path().to_string_lossy().to_string();
    let Some(slow) = MockOllama::spawn(post(|| async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        (
            axum::http::StatusCode::OK,
            Json(json!({ "embedding": [0.1, 0.2] })),
        )
    }))?
    else {
        return Ok(());
    };

    let state_root_str = state_root.path().to_string_lossy().to_string();
    let envs = vec![
        ("DOCDEX_STATE_DIR", state_root_str.as_str()),
        ("DOCDEX_ENABLE_MEMORY", "1"),
        ("DOCDEX_OLLAMA_BASE_URL", slow.base_url.as_str()),
        ("DOCDEX_EMBEDDING_MODEL", "fake-embed"),
        ("DOCDEX_EMBEDDING_TIMEOUT_MS", "50"),
    ];
    let mut mcp = McpHarness::spawn(repo.path(), &envs)?;
    send_line(
        &mut mcp.stdin,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": "docdex_memory_store", "arguments": { "text": "hello", "project_root": project_root.as_str() } }
        }),
    )?;
    let resp = read_line(&mut mcp.reader)?;
    assert_eq!(mcp_error_data_code(&resp), Some("embedding_timeout"));
    assert!(
        !resp.to_string().contains("hello"),
        "embedding input leaked in MCP error payload: {resp}"
    );
    mcp.shutdown();
    Ok(())
}

#[test]
fn invalid_model_is_explicit_and_daemon_stays_healthy() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let state_root = TempDir::new()?;
    let Some(mock) = MockOllama::spawn(post(|| async move {
        (
            axum::http::StatusCode::NOT_FOUND,
            Json(json!({ "error": "model not found" })),
        )
    }))?
    else {
        return Ok(());
    };

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let mut server = Command::new(docdex_bin())
        .env("DOCDEX_STATE_DIR", state_root.path())
        .args([
            "serve",
            "--repo",
            repo.path().to_string_lossy().as_ref(),
            "--host",
            host,
            "--port",
            &port.to_string(),
            "--log",
            "warn",
            "--secure-mode=false",
            "--enable-memory=true",
            "--ollama-base-url",
            mock.base_url.as_str(),
            "--embedding-model",
            "definitely-not-installed",
            "--embedding-timeout-ms",
            "200",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    wait_for_health(host, port)?;

    let client = Client::builder().timeout(Duration::from_secs(2)).build()?;
    let store_url = format!("http://{host}:{port}/v1/memory/store");
    let resp = client
        .post(&store_url)
        .json(&json!({ "text": "hello" }))
        .send()?;
    assert_eq!(resp.status().as_u16(), 400);
    let body: Value = resp.json()?;
    assert_eq!(
        body.get("error")
            .and_then(|v| v.get("code"))
            .and_then(|v| v.as_str()),
        Some("embedding_model_not_found")
    );
    assert!(
        !body.to_string().contains("hello"),
        "embedding input leaked in response body: {body}"
    );

    let health_url = format!("http://{host}:{port}/healthz");
    let health = client.get(&health_url).send()?;
    assert!(health.status().is_success());

    server.kill().ok();
    server.wait().ok();
    Ok(())
}

#[test]
fn memory_metadata_includes_embedding_model() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let state_root = TempDir::new()?;
    let Some(mock) = MockOllama::spawn(post(|| async move {
        (
            axum::http::StatusCode::OK,
            Json(json!({ "embedding": [1.0, 0.0] })),
        )
    }))?
    else {
        return Ok(());
    };

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let mut server = Command::new(docdex_bin())
        .env("DOCDEX_STATE_DIR", state_root.path())
        .args([
            "serve",
            "--repo",
            repo.path().to_string_lossy().as_ref(),
            "--host",
            host,
            "--port",
            &port.to_string(),
            "--log",
            "warn",
            "--secure-mode=false",
            "--enable-memory=true",
            "--ollama-base-url",
            mock.base_url.as_str(),
            "--embedding-model",
            "test-embed-model",
            "--embedding-timeout-ms",
            "200",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    wait_for_health(host, port)?;

    let client = Client::builder().timeout(Duration::from_secs(2)).build()?;
    let store_url = format!("http://{host}:{port}/v1/memory/store");
    let store: Value = client
        .post(&store_url)
        .json(&json!({ "text": "hello", "metadata": { "source": "test" } }))
        .send()?
        .json()?;
    assert!(store.get("id").is_some());

    let recall_url = format!("http://{host}:{port}/v1/memory/recall");
    let recall: Value = client
        .post(&recall_url)
        .json(&json!({ "query": "anything", "top_k": 1 }))
        .send()?
        .json()?;
    let meta = recall
        .get("results")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|v| v.get("metadata"))
        .cloned()
        .unwrap_or(json!({}));
    assert_eq!(
        meta.get("embeddingModel").and_then(|v| v.as_str()),
        Some("test-embed-model")
    );
    assert_eq!(
        meta.get("embeddingProvider").and_then(|v| v.as_str()),
        Some("ollama")
    );
    assert_eq!(meta.get("source").and_then(|v| v.as_str()), Some("test"));

    server.kill().ok();
    server.wait().ok();
    Ok(())
}

#[test]
fn cli_timeout_error_is_machine_readable() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let state_root = TempDir::new()?;
    let Some(slow) = MockOllama::spawn(post(|| async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        (
            axum::http::StatusCode::OK,
            Json(json!({ "embedding": [0.1, 0.2] })),
        )
    }))?
    else {
        return Ok(());
    };

    let output = Command::new(docdex_bin())
        .env("DOCDEX_STATE_DIR", state_root.path())
        .args([
            "memory-store",
            "--repo",
            repo.path().to_string_lossy().as_ref(),
            "--text",
            "hello",
            "--ollama-base-url",
            slow.base_url.as_str(),
            "--embedding-model",
            "fake-embed",
            "--embedding-timeout-ms",
            "50",
        ])
        .output()?;
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("\"code\":\"embedding_timeout\""),
        "expected machine-readable embedding_timeout error; got stderr={stderr}"
    );
    assert!(
        !stderr.contains("hello"),
        "embedding input leaked in CLI stderr: {stderr}"
    );
    Ok(())
}
