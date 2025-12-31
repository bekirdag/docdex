use axum::{routing::post, Json, Router};
use docdexd::profiles::{PreferenceCategory, ProfileManager};
use reqwest::blocking::Client;
use serde_json::{json, Value};
use std::error::Error;
use std::ffi::OsStr;
use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::sync::oneshot;

fn docdex_bin() -> PathBuf {
    std::env::set_var("DOCDEX_CLI_LOCAL", "1");
    assert_cmd::cargo::cargo_bin!("docdexd").to_path_buf()
}

fn run_docdex<I, S>(state_root: &Path, home_dir: &Path, args: I) -> Result<Vec<u8>, Box<dyn Error>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = Command::new(docdex_bin())
        .env("DOCDEX_STATE_DIR", state_root)
        .env("HOME", home_dir)
        .args(args)
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "docdexd exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(output.stdout)
}

fn pick_free_port() -> Option<u16> {
    match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => Some(listener.local_addr().ok()?.port()),
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping default agent test: TCP bind not permitted in this environment");
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

fn write_repo(repo_root: &Path) -> Result<(), Box<dyn Error>> {
    let docs_dir = repo_root.join("docs");
    fs::create_dir_all(&docs_dir)?;
    fs::write(docs_dir.join("readme.md"), "# Repo\n\nHello\n")?;
    Ok(())
}

fn write_config(
    home_dir: &Path,
    global_state_dir: &Path,
    llm_base_url: &str,
    embedding_dim: usize,
    default_agent_id: &str,
) -> Result<(), Box<dyn Error>> {
    let config_dir = home_dir.join(".docdex");
    fs::create_dir_all(&config_dir)?;
    let config_path = config_dir.join("config.toml");
    let payload = format!(
        "[core]\nglobal_state_dir = \"{}\"\n\n[llm]\nbase_url = \"{}\"\ndefault_model = \"fake-model\"\n\n[memory.profile]\nembedding_dim = {}\nembedding_model = \"fake-embed\"\n\n[server]\ndefault_agent_id = \"{}\"\n",
        global_state_dir.display(),
        llm_base_url,
        embedding_dim,
        default_agent_id
    );
    fs::write(config_path, payload)?;
    Ok(())
}

fn seed_profile(
    global_state_dir: &Path,
    embedding_dim: usize,
    agent_id: &str,
) -> Result<(), Box<dyn Error>> {
    let manager = ProfileManager::new(global_state_dir, embedding_dim)?;
    let now_ms = 1_700_000_000_000i64;
    manager.create_agent(agent_id, "test", now_ms)?;
    let embedding = vec![0.1; embedding_dim];
    manager.add_preference(
        agent_id,
        "Use tabs for indentation",
        &embedding,
        PreferenceCategory::Style,
        now_ms,
    )?;
    Ok(())
}

struct MockOllama {
    base_url: String,
    shutdown: Option<oneshot::Sender<()>>,
    join: Option<thread::JoinHandle<()>>,
}

impl MockOllama {
    fn spawn() -> Result<Option<Self>, Box<dyn Error>> {
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
                    .route("/api/generate", post(mock_generate));
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

async fn mock_embeddings(Json(_payload): Json<Value>) -> (axum::http::StatusCode, Json<Value>) {
    (
        axum::http::StatusCode::OK,
        Json(json!({ "embedding": [0.1, 0.2, 0.3, 0.4] })),
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
        Json(json!({ "response": prompt })),
    )
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
        ollama_base_url: &str,
    ) -> Result<Self, Box<dyn Error>> {
        let repo_str = repo_root.to_string_lossy().to_string();
        let child = Command::new(docdex_bin())
            .env("DOCDEX_STATE_DIR", state_root)
            .env("DOCDEX_ENABLE_MCP", "0")
            .env("HOME", home_dir)
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
                "--ollama-base-url",
                ollama_base_url,
                "--embedding-model",
                "fake-embed",
                "--embedding-timeout-ms",
                "200",
            ])
            .spawn()?;
        wait_for_health(host, port)?;
        Ok(Self { child })
    }

    fn shutdown(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
    }
}

#[test]
fn default_agent_fallback_includes_profile_context() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    write_repo(repo.path())?;

    let state_root = TempDir::new()?;
    let home_dir = TempDir::new()?;
    let Some(mock) = MockOllama::spawn()? else {
        return Ok(());
    };

    let embedding_dim = 4;
    let global_state_dir = home_dir.path().join(".docdex").join("state");
    let agent_id = "agent-default-test";
    write_config(
        home_dir.path(),
        &global_state_dir,
        &mock.base_url,
        embedding_dim,
        agent_id,
    )?;
    seed_profile(&global_state_dir, embedding_dim, agent_id)?;

    run_docdex(
        state_root.path(),
        home_dir.path(),
        ["index", "--repo", repo.path().to_string_lossy().as_ref()],
    )?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let mut server = ServerHarness::spawn(
        state_root.path(),
        home_dir.path(),
        repo.path(),
        host,
        port,
        &mock.base_url,
    )?;

    let client = Client::builder().timeout(Duration::from_secs(3)).build()?;
    let chat_url = format!("http://{host}:{port}/v1/chat/completions");
    let payload = json!({
        "model": "fake-model",
        "messages": [{ "role": "user", "content": "profile" }],
        "docdex": { "compress_results": true }
    });
    let response: Value = client.post(&chat_url).json(&payload).send()?.json()?;
    let content = response
        .get("choices")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|choice| choice.get("message"))
        .and_then(|message| message.get("content"))
        .and_then(|v| v.as_str())
        .ok_or("missing chat completion content")?;
    let compressed: Value = serde_json::from_str(content)?;
    let profile_items = compressed
        .get("results")
        .and_then(|v| v.get("profile"))
        .and_then(|v| v.as_array())
        .ok_or("missing profile results for default agent")?;
    let found = profile_items.iter().any(|item| {
        item.get("content")
            .and_then(|v| v.as_str())
            .map(|text| text.contains("Use tabs for indentation"))
            .unwrap_or(false)
    });
    assert!(
        found,
        "expected default agent profile preference in context"
    );

    server.shutdown();
    Ok(())
}
