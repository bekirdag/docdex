#![allow(dead_code)]

use std::error::Error;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{Read, Seek, SeekFrom};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use axum::{routing::post, Json, Router};
use reqwest::blocking::Client;
use serde_json::Value;
use tokio::sync::oneshot;

pub fn toml_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

pub fn docdex_bin() -> PathBuf {
    std::env::set_var("DOCDEX_CLI_LOCAL", "1");
    std::env::set_var("DOCDEX_WEB_ENABLED", "0");
    assert_cmd::cargo::cargo_bin!("docdexd").to_path_buf()
}

pub fn write_basic_repo(repo_root: &Path) -> Result<(), Box<dyn Error>> {
    std::fs::create_dir_all(repo_root.join(".git"))?;
    std::fs::write(repo_root.join("README.md"), "# Repo\n")?;
    Ok(())
}

pub fn write_basic_config(home_dir: &Path, global_state_dir: &Path) -> Result<(), Box<dyn Error>> {
    let config_dir = home_dir.join(".docdex");
    std::fs::create_dir_all(&config_dir)?;
    std::fs::write(
        config_dir.join("config.toml"),
        format!(
            "[core]\nglobal_state_dir = \"{}\"\n",
            toml_path(global_state_dir)
        ),
    )?;
    Ok(())
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
    wait_for_health_inner(host, port, None)
}

fn wait_for_health_inner(
    host: &str,
    port: u16,
    mut child: Option<&mut Child>,
) -> Result<(), Box<dyn Error>> {
    let client = Client::builder().timeout(Duration::from_secs(1)).build()?;
    let url = format!("http://{host}:{port}/healthz");
    let timeout_secs = std::env::var("DOCDEX_TEST_HEALTH_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(60);
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    while Instant::now() < deadline {
        if let Some(child) = child.as_deref_mut() {
            if let Some(status) = child.try_wait()? {
                return Err(format!("docdexd exited before healthz was ready: {status}").into());
            }
        }
        match client.get(&url).send() {
            Ok(resp) if resp.status().is_success() => return Ok(()),
            _ => thread::sleep(Duration::from_millis(200)),
        }
    }
    Err("docdexd healthz endpoint did not respond in time".into())
}

fn read_log_tail(path: &Path, max_bytes: u64) -> String {
    let Ok(mut file) = File::open(path) else {
        return String::new();
    };
    let len = file.metadata().map(|meta| meta.len()).unwrap_or_default();
    let start = len.saturating_sub(max_bytes);
    if file.seek(SeekFrom::Start(start)).is_err() {
        return String::new();
    }
    let mut bytes = Vec::with_capacity((len - start).min(max_bytes) as usize);
    if file.read_to_end(&mut bytes).is_err() {
        return String::new();
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

pub struct TestServerHarness {
    child: Option<Child>,
}

impl TestServerHarness {
    pub fn spawn_basic(
        state_root: &Path,
        home_dir: &Path,
        repo_root: &Path,
        host: &str,
        port: u16,
        enable_mcp: bool,
    ) -> Result<Self, Box<dyn Error>> {
        Self::spawn_with_env(state_root, home_dir, repo_root, host, port, enable_mcp, &[])
    }

    pub fn spawn_with_env(
        state_root: &Path,
        home_dir: &Path,
        repo_root: &Path,
        host: &str,
        port: u16,
        enable_mcp: bool,
        extra_env: &[(&str, &str)],
    ) -> Result<Self, Box<dyn Error>> {
        let repo_arg = repo_root.to_string_lossy().to_string();
        fs::create_dir_all(state_root)?;
        let xdg_config_home = home_dir.join(".config");
        let app_data = home_dir.join("AppData").join("Roaming");
        let local_app_data = home_dir.join("AppData").join("Local");
        fs::create_dir_all(&xdg_config_home)?;
        fs::create_dir_all(&app_data)?;
        fs::create_dir_all(&local_app_data)?;
        let stderr_path = state_root.join(format!("docdexd-test-{port}.stderr.log"));
        let stderr_file = File::create(&stderr_path)?;
        let mut command = Command::new(docdex_bin());
        command
            .env("DOCDEX_WEB_ENABLED", "0")
            .env("DOCDEX_ENABLE_MEMORY", "0")
            .env("DOCDEX_ENABLE_MCP", if enable_mcp { "1" } else { "0" })
            .env("DOCDEX_STATE_DIR", state_root)
            .env("DOCDEX_DAEMON_LOCK_PATH", state_root.join("daemon.lock"))
            .env("DOCDEX_DISABLE_MCODA_CLI", "1")
            .env("HOME", home_dir)
            .env("USERPROFILE", home_dir)
            .env("XDG_CONFIG_HOME", &xdg_config_home)
            .env("APPDATA", &app_data)
            .env("LOCALAPPDATA", &local_app_data)
            .args([
                "serve",
                "--repo",
                repo_arg.as_str(),
                "--host",
                host,
                "--port",
                &port.to_string(),
                "--log",
                "warn",
                "--secure-mode=false",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr_file));
        for (key, value) in extra_env {
            command.env(key, value);
        }
        let mut child = command.spawn()?;
        if let Err(err) = wait_for_health_inner(host, port, Some(&mut child)) {
            let _ = child.kill();
            let _ = child.wait();
            let stderr = read_log_tail(&stderr_path, 16 * 1024);
            let detail = if stderr.trim().is_empty() {
                String::new()
            } else {
                format!("; stderr tail:\n{stderr}")
            };
            return Err(format!("{err}{detail}").into());
        }
        Ok(Self { child: Some(child) })
    }

    pub fn shutdown(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl Drop for TestServerHarness {
    fn drop(&mut self) {
        self.shutdown();
    }
}

pub fn run_docdex_json<I, S>(
    home_dir: &Path,
    base_url: &str,
    args: I,
) -> Result<Value, Box<dyn Error>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = Command::new(docdex_bin())
        .env("DOCDEX_WEB_ENABLED", "0")
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("DOCDEX_HTTP_BASE_URL", base_url)
        .env("DOCDEX_DISABLE_MCODA_CLI", "1")
        .env("HOME", home_dir)
        .env("USERPROFILE", home_dir)
        .env("XDG_CONFIG_HOME", home_dir.join(".config"))
        .env("APPDATA", home_dir.join("AppData").join("Roaming"))
        .env("LOCALAPPDATA", home_dir.join("AppData").join("Local"))
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
    Ok(serde_json::from_slice(&output.stdout)?)
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
