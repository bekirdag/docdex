#![allow(dead_code)]

use std::error::Error;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Once;
use std::thread;
use std::time::{Duration, Instant};

use axum::{routing::post, Json, Router};
use reqwest::blocking::Client;
use serde_json::Value;
use tokio::sync::oneshot;

static BUILD_MCP_SERVER: Once = Once::new();

pub fn mcp_server_bin() -> PathBuf {
    if let Ok(path) = std::env::var("DOCDEX_MCP_SERVER_BIN") {
        return PathBuf::from(path);
    }
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_docdex-mcp-server") {
        return PathBuf::from(path);
    }
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let target_dir = std::env::var("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| manifest_dir.join("target"));
    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "debug".to_string());
    let exe_name = format!("docdex-mcp-server{}", std::env::consts::EXE_SUFFIX);
    let candidate = target_dir.join(&profile).join(&exe_name);
    if candidate.exists() {
        return candidate;
    }
    BUILD_MCP_SERVER.call_once(|| {
        let status = Command::new("cargo")
            .args(["build", "-p", "docdex-mcp-server"])
            .status()
            .expect("failed to run cargo build -p docdex-mcp-server");
        assert!(status.success(), "cargo build -p docdex-mcp-server failed");
    });
    if candidate.exists() {
        return candidate;
    }
    panic!(
        "docdex-mcp-server binary not found at {}",
        candidate.display()
    );
}

pub fn toml_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

pub fn docdex_bin() -> PathBuf {
    std::env::set_var("DOCDEX_CLI_LOCAL", "1");
    assert_cmd::cargo::cargo_bin!("docdexd").to_path_buf()
}

pub fn pick_free_port() -> Option<u16> {
    match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => Some(listener.local_addr().ok()?.port()),
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping test: TCP bind not permitted in this environment");
            None
        }
        Err(err) => panic!("bind ephemeral port: {err}"),
    }
}

pub fn wait_for_health(host: &str, port: u16) -> Result<(), Box<dyn Error>> {
    let client = Client::builder().timeout(Duration::from_secs(1)).build()?;
    let url = format!("http://{host}:{port}/healthz");
    let timeout_secs = std::env::var("DOCDEX_TEST_HEALTH_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(20);
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    while Instant::now() < deadline {
        match client.get(&url).send() {
            Ok(resp) if resp.status().is_success() => return Ok(()),
            _ => thread::sleep(Duration::from_millis(200)),
        }
    }
    Err("docdexd healthz endpoint did not respond in time".into())
}

pub struct MockOllama {
    pub base_url: String,
    shutdown: Option<oneshot::Sender<()>>,
    join: Option<thread::JoinHandle<()>>,
}

impl MockOllama {
    pub fn spawn() -> Result<Option<Self>, Box<dyn Error>> {
        Self::spawn_with_embedding(vec![0.1, 0.2, 0.3, 0.4])
    }

    pub fn spawn_with_embedding(embedding: Vec<f32>) -> Result<Option<Self>, Box<dyn Error>> {
        let std_listener = match TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => listener,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                eprintln!("skipping mock ollama: TCP bind not permitted in this environment");
                return Ok(None);
            }
            Err(err) => return Err(err.into()),
        };
        std_listener.set_nonblocking(true)?;
        let addr = std_listener.local_addr()?;
        let (tx, rx) = oneshot::channel::<()>();
        let join = thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
            rt.block_on(async move {
                let app = Router::new()
                    .route("/api/embeddings", post(mock_embeddings))
                    .route("/api/generate", post(mock_generate))
                    .with_state(embedding);
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

async fn mock_embeddings(
    axum::extract::State(embedding): axum::extract::State<Vec<f32>>,
    Json(_payload): Json<Value>,
) -> (axum::http::StatusCode, Json<Value>) {
    (
        axum::http::StatusCode::OK,
        Json(serde_json::json!({ "embedding": embedding })),
    )
}

async fn mock_generate(Json(payload): Json<Value>) -> (axum::http::StatusCode, Json<Value>) {
    let prompt = payload
        .get("prompt")
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .to_string();
    (
        axum::http::StatusCode::OK,
        Json(serde_json::json!({ "response": prompt })),
    )
}
