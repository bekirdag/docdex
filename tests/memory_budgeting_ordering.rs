use axum::{routing::post, Json, Router};
use reqwest::blocking::Client;
use serde_json::{json, Value};
use std::error::Error;
use std::ffi::OsStr;
use std::fs;
use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::sync::oneshot;

fn strip_ansi(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' && matches!(chars.peek(), Some('[')) {
            chars.next();
            while let Some(next) = chars.next() {
                if next == 'm' {
                    break;
                }
            }
            continue;
        }
        out.push(ch);
    }
    out
}

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
            eprintln!("skipping HTTP tests: TCP bind not permitted in this environment");
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
    let body = std::iter::repeat("budget")
        .take(120)
        .collect::<Vec<_>>()
        .join(" ");
    fs::write(docs_dir.join("alpha.md"), format!("# Alpha\n\n{body}\n"))?;
    fs::write(docs_dir.join("beta.md"), format!("# Beta\n\n{body}\n"))?;
    Ok(())
}

fn write_config(
    home_dir: &Path,
    llm_base_url: &str,
    max_answer_tokens: u32,
) -> Result<(), Box<dyn Error>> {
    let config_dir = home_dir.join(".docdex");
    fs::create_dir_all(&config_dir)?;
    let config_path = config_dir.join("config.toml");
    let payload = format!(
        "[llm]\nbase_url = \"{}\"\ndefault_model = \"fake-model\"\nmax_answer_tokens = {}\n",
        llm_base_url, max_answer_tokens
    );
    fs::write(config_path, payload)?;
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
    log_lines: Arc<Mutex<Vec<String>>>,
    log_handle: Option<thread::JoinHandle<()>>,
}

impl ServerHarness {
    fn spawn(
        state_root: &Path,
        home_dir: &Path,
        repo_root: &Path,
        host: &str,
        port: u16,
        ollama_base_url: &str,
        embedding_model: &str,
    ) -> Result<Self, Box<dyn Error>> {
        let repo_str = repo_root.to_string_lossy().to_string();
        let mut child = Command::new(docdex_bin())
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
                "info",
                "--secure-mode=false",
                "--enable-memory=true",
                "--ollama-base-url",
                ollama_base_url,
                "--embedding-model",
                embedding_model,
                "--embedding-timeout-ms",
                "200",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
        let stderr = child
            .stderr
            .take()
            .ok_or("failed to capture docdexd stderr")?;
        let log_lines = Arc::new(Mutex::new(Vec::new()));
        let log_capture = Arc::clone(&log_lines);
        let log_handle = thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines() {
                match line {
                    Ok(line) => {
                        let cleaned = strip_ansi(&line);
                        log_capture.lock().ok().map(|mut logs| logs.push(cleaned));
                    }
                    Err(_) => break,
                }
            }
        });
        wait_for_health(host, port)?;
        Ok(Self {
            child,
            log_lines,
            log_handle: Some(log_handle),
        })
    }

    fn wait_for_log(&self, needle: &str, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if self
                .log_lines
                .lock()
                .map(|logs| logs.iter().any(|line| line.contains(needle)))
                .unwrap_or(false)
            {
                return true;
            }
            thread::sleep(Duration::from_millis(50));
        }
        false
    }

    fn drain_logs(&self) -> Vec<String> {
        self.log_lines
            .lock()
            .map(|logs| logs.clone())
            .unwrap_or_default()
    }

    fn shutdown(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
        if let Some(handle) = self.log_handle.take() {
            let _ = handle.join();
        }
    }
}

#[test]
fn e2e_chat_budgeting_logs_and_ordering() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    write_repo(repo.path())?;

    let state_root = TempDir::new()?;
    let home_dir = TempDir::new()?;
    let Some(mock) = MockOllama::spawn()? else {
        return Ok(());
    };

    write_config(home_dir.path(), &mock.base_url, 8)?;

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
        "fake-embed",
    )?;

    let client = Client::builder().timeout(Duration::from_secs(3)).build()?;
    let store_url = format!("http://{host}:{port}/v1/memory/store");
    let texts = [
        "remember budget alpha context",
        "remember budget beta context",
    ];
    for text in texts {
        let resp = client
            .post(&store_url)
            .json(&json!({ "text": text }))
            .send()?;
        assert!(
            resp.status().is_success(),
            "memory store failed with status {}",
            resp.status()
        );
    }

    let chat_url = format!("http://{host}:{port}/v1/chat/completions");
    let payload = json!({
        "model": "fake-model",
        "messages": [{ "role": "user", "content": "budget" }],
        "docdex": { "limit": 5 }
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

    let memory_pos = content
        .find("Memory context:")
        .ok_or("missing Memory context in prompt")?;
    let local_pos = content
        .find("Top local matches")
        .ok_or("missing local context header in prompt")?;
    assert!(
        memory_pos < local_pos,
        "expected Memory context to precede local context: {content}"
    );

    let log_ok = server.wait_for_log("memory_dropped=", Duration::from_secs(5))
        && server.wait_for_log("context pruned to fit token budget", Duration::from_secs(5));
    assert!(
        log_ok,
        "expected token budget drop log, got: {}",
        server.drain_logs().join("\n")
    );

    server.shutdown();
    Ok(())
}
