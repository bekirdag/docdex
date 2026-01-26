mod common;

use axum::{routing::post, Json, Router};
use common::{docdex_bin, pick_free_port, wait_for_health};
use docdexd::profiles::{PreferenceCategory, ProfileManager};
use docdexd::repo_manager::repo_fingerprint_sha256;
use reqwest::blocking::Client;
use serde_json::{json, Value};
use std::error::Error;
use std::fs;
use std::net::TcpListener;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::sync::oneshot;

fn write_repo(repo_root: &Path) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(repo_root.join("docs"))?;
    fs::create_dir_all(repo_root.join("src"))?;
    fs::write(repo_root.join("docs").join("readme.md"), "# Repo\n")?;
    fs::write(repo_root.join("src").join("safe.ts"), "const ok = true;\n")?;
    Ok(())
}

struct ServerHarness {
    child: Child,
}

impl ServerHarness {
    fn spawn(
        state_root: &Path,
        repo_root: &Path,
        host: &str,
        port: u16,
    ) -> Result<Self, Box<dyn Error>> {
        let repo_str = repo_root.to_string_lossy().to_string();
        let child = Command::new(docdex_bin())
            .env("DOCDEX_WEB_ENABLED", "0")
            .env("DOCDEX_ENABLE_MEMORY", "0")
            .env("DOCDEX_DAEMON_LOCK_PATH", state_root.join("daemon.lock"))
            .env("DOCDEX_STATE_DIR", state_root)
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
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        wait_for_health(host, port)?;
        Ok(Self { child })
    }

    fn shutdown(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
    }
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

async fn mock_generate(Json(_payload): Json<Value>) -> (axum::http::StatusCode, Json<Value>) {
    let response = json!({
        "action": "ADD",
        "target_preference_id": null,
        "new_content": "Use Vitest",
        "reasoning": "test"
    })
    .to_string();
    (
        axum::http::StatusCode::OK,
        Json(json!({ "response": response })),
    )
}

fn write_config(
    home_dir: &Path,
    global_state_dir: &Path,
    llm_base_url: &str,
    embedding_dim: usize,
) -> Result<(), Box<dyn Error>> {
    let config_dir = home_dir.join(".docdex");
    fs::create_dir_all(&config_dir)?;
    let config_path = config_dir.join("config.toml");
    let payload = format!(
        "[core]\nglobal_state_dir = \"{}\"\n\n[llm]\nbase_url = \"{}\"\ndefault_model = \"fake-model\"\n\n[memory.profile]\nembedding_dim = {}\nembedding_model = \"fake-embed\"\n\n[features]\nhooks = true\nproject_map = true\nworkflow_prompt = true\n",
        crate::common::toml_path(global_state_dir),
        llm_base_url,
        embedding_dim
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
        "Use TypeScript tooling",
        &embedding,
        PreferenceCategory::Tooling,
        now_ms,
    )?;
    manager.add_preference(
        agent_id,
        "No any types",
        &embedding,
        PreferenceCategory::Constraint,
        now_ms,
    )?;
    Ok(())
}

fn run_index(state_root: &Path, home_dir: &Path, repo_root: &Path) -> Result<(), Box<dyn Error>> {
    let repo_str = repo_root.to_string_lossy().to_string();
    let output = Command::new(docdex_bin())
        .env("DOCDEX_WEB_ENABLED", "0")
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("DOCDEX_DAEMON_LOCK_PATH", state_root.join("daemon.lock"))
        .env("DOCDEX_STATE_DIR", state_root)
        .env("HOME", home_dir)
        .args(["index", "--repo", repo_str.as_str()])
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "docdexd index failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(())
}

struct FeatureServerHarness {
    child: Child,
}

impl FeatureServerHarness {
    fn spawn(
        state_root: &Path,
        home_dir: &Path,
        repo_root: &Path,
        host: &str,
        port: u16,
        embedding_base_url: &str,
    ) -> Result<Self, Box<dyn Error>> {
        let repo_str = repo_root.to_string_lossy().to_string();
        let child = Command::new(docdex_bin())
            .env("DOCDEX_WEB_ENABLED", "0")
            .env("DOCDEX_ENABLE_MEMORY", "0")
            .env("DOCDEX_DAEMON_LOCK_PATH", state_root.join("daemon.lock"))
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
                "--embedding-base-url",
                embedding_base_url,
                "--embedding-model",
                "fake-embed",
                "--embedding-timeout-ms",
                "200",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        wait_for_health(host, port)?;
        Ok(Self { child })
    }

    fn shutdown(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
    }
}

fn parse_metric(payload: &str, name: &str) -> Option<f64> {
    for line in payload.lines() {
        if line.starts_with(name) {
            let value = line.split_whitespace().nth(1)?;
            return value.parse::<f64>().ok();
        }
    }
    None
}

fn wait_for_metric(
    client: &Client,
    url: &str,
    name: &str,
    min_value: f64,
) -> Result<(), Box<dyn Error>> {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        let payload = client.get(url).send()?.text()?;
        if let Some(value) = parse_metric(&payload, name) {
            if value >= min_value {
                return Ok(());
            }
        }
        thread::sleep(Duration::from_millis(200));
    }
    Err(format!("metric {name} did not reach {min_value}").into())
}

#[test]
fn metrics_endpoint_exposes_prometheus_counters() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    write_repo(repo.path())?;
    let state_root = TempDir::new()?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let mut server = ServerHarness::spawn(state_root.path(), repo.path(), host, port)?;

    let client = Client::builder().timeout(Duration::from_secs(3)).build()?;
    let url = format!("http://{host}:{port}/metrics");
    let payload = client.get(url).send()?.text()?;
    assert!(payload.contains("docdex_rate_limit_denies_total"));
    assert!(payload.contains("docdex_errors_total"));
    assert!(payload.contains("docdex_profile_budget_drops_total"));
    assert!(payload.contains("docdex_delegate_token_savings_total"));
    assert!(payload.contains("docdex_delegate_offloaded_total"));
    assert!(payload.contains("docdex_delegate_local_tokens_total"));
    assert!(payload.contains("docdex_delegate_primary_tokens_total"));
    assert!(payload.contains("docdex_delegate_local_cost_micros_total"));
    assert!(payload.contains("docdex_delegate_primary_cost_micros_total"));
    assert!(payload.contains("docdex_delegate_cost_savings_micros_total"));
    assert!(payload.contains("docdex_delegate_local_enforced_failures_total"));

    server.shutdown();
    Ok(())
}

#[test]
fn metrics_counters_increment_for_profile_hooks_and_map() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    write_repo(repo.path())?;

    let state_root = TempDir::new()?;
    let home_dir = TempDir::new()?;
    let Some(mock) = MockOllama::spawn()? else {
        return Ok(());
    };

    let embedding_dim = 4;
    let global_state_dir = home_dir.path().join(".docdex").join("state");
    write_config(
        home_dir.path(),
        &global_state_dir,
        &mock.base_url,
        embedding_dim,
    )?;
    seed_profile(&global_state_dir, embedding_dim, "agent-metrics")?;

    run_index(state_root.path(), home_dir.path(), repo.path())?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let mut server = FeatureServerHarness::spawn(
        state_root.path(),
        home_dir.path(),
        repo.path(),
        host,
        port,
        &mock.base_url,
    )?;

    let client = Client::builder().timeout(Duration::from_secs(3)).build()?;
    let metrics_url = format!("http://{host}:{port}/metrics");
    let chat_url = format!("http://{host}:{port}/v1/chat/completions");
    let hook_url = format!("http://{host}:{port}/v1/hooks/validate");
    let profile_url = format!("http://{host}:{port}/v1/profile/save");

    let chat_payload = json!({
        "model": "fake-model",
        "messages": [{ "role": "user", "content": "Summarize the repo" }],
        "docdex": { "agent_id": "agent-metrics", "compress_results": false, "limit": 2 }
    });
    let resp = client.post(&chat_url).json(&chat_payload).send()?;
    assert!(resp.status().is_success());
    let resp = client.post(&chat_url).json(&chat_payload).send()?;
    assert!(resp.status().is_success());

    let repo_id = repo_fingerprint_sha256(repo.path())?;
    let resp = client
        .post(&hook_url)
        .header("x-docdex-repo-id", repo_id)
        .json(&json!({ "files": ["src/safe.ts"] }))
        .send()?;
    assert!(resp.status().is_success());

    let resp = client
        .post(&profile_url)
        .json(&json!({
            "agent_id": "agent-metrics",
            "category": "style",
            "content": "Prefer concise answers"
        }))
        .send()?;
    assert!(resp.status().is_success());

    wait_for_metric(
        &client,
        &metrics_url,
        "docdex_profile_recall_requests_total",
        1.0,
    )?;
    wait_for_metric(
        &client,
        &metrics_url,
        "docdex_project_map_cache_misses_total",
        1.0,
    )?;
    wait_for_metric(
        &client,
        &metrics_url,
        "docdex_project_map_cache_hits_total",
        1.0,
    )?;
    wait_for_metric(&client, &metrics_url, "docdex_hook_checks_total", 1.0)?;
    wait_for_metric(
        &client,
        &metrics_url,
        "docdex_profile_evolution_decisions_total",
        1.0,
    )?;

    server.shutdown();
    Ok(())
}
