use crate::cli::http_client::CliHttpClient;
use crate::config::{self, RepoArgs};
use crate::repo_manager;
use anyhow::{Context, Result};
use hyper::http::StatusCode;
use reqwest::Method;
#[cfg(unix)]
use hyper::body::Bytes;
#[cfg(unix)]
use hyper::client::conn::http1;
#[cfg(unix)]
use hyper::header::{AUTHORIZATION, CONTENT_TYPE};
#[cfg(unix)]
use hyper::Method as HyperMethod;
#[cfg(unix)]
use hyper::Request;
#[cfg(unix)]
use http_body_util::{BodyExt, Full};
#[cfg(unix)]
use hyper_util::rt::TokioIo;
#[cfg(unix)]
use tokio::net::UnixStream;
#[cfg(unix)]
use tokio::time::timeout;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;
#[cfg(unix)]
use std::time::Duration;

#[derive(Serialize)]
struct HookValidateRequest {
    files: Vec<String>,
}

#[derive(Deserialize)]
struct HookValidateResponse {
    status: String,
    #[serde(default)]
    errors: Vec<HookViolation>,
}

struct HookValidateOutcome {
    status: StatusCode,
    payload: HookValidateResponse,
}

#[derive(Deserialize)]
struct HookViolation {
    message: String,
    #[serde(default)]
    file: Option<String>,
    #[serde(default)]
    line: Option<u32>,
}

pub(crate) async fn run(command: crate::cli::HookCommand) -> Result<()> {
    match command {
        crate::cli::HookCommand::PreCommit { repo } => run_pre_commit(repo).await,
    }
}

async fn run_pre_commit(repo: RepoArgs) -> Result<()> {
    let repo_root = repo.repo_root();
    let files = collect_staged_files(&repo_root)?;
    let socket_path = resolve_hook_socket_path()?;

    let mut outcome: Option<HookValidateOutcome> = None;
    if let Some(path) = socket_path {
        #[cfg(unix)]
        match send_hook_unix(&repo_root, &files, &path).await {
            Ok(result) => {
                outcome = Some(result);
            }
            Err(err) if is_connect_or_timeout(&err) => {
                outcome = None;
            }
            Err(err) => {
                return Err(err).context("hook validate unix socket request failed");
            }
        }
        #[cfg(not(unix))]
        {
            eprintln!(
                "Docdex hook socket configured but unix sockets are unsupported; falling back to HTTP"
            );
        }
    }

    let outcome = match outcome {
        Some(result) => result,
        None => match send_hook_http(&repo_root, &files).await {
            Ok(result) => result,
            Err(err) if is_connect_or_timeout(&err) => {
                eprintln!("Docdex daemon not found; skipping semantic checks");
                return Ok(());
            }
            Err(err) => return Err(err).context("hook validate request failed"),
        },
    };

    handle_hook_outcome(outcome)
}

fn resolve_hook_socket_path() -> Result<Option<PathBuf>> {
    let config = config::AppConfig::load_default()?;
    let trimmed = config.server.hook_socket_path.trim();
    if trimmed.is_empty() {
        Ok(None)
    } else {
        Ok(Some(PathBuf::from(trimmed)))
    }
}

async fn send_hook_http(repo_root: &Path, files: &[String]) -> Result<HookValidateOutcome> {
    let client = CliHttpClient::new()?;
    let request = client.request(Method::POST, "/v1/hooks/validate");
    let request = client.with_repo(request, repo_root)?;
    send_hook_request(request.json(&HookValidateRequest {
        files: files.to_vec(),
    }))
    .await
}

#[cfg(unix)]
async fn send_hook_unix(
    repo_root: &Path,
    files: &[String],
    socket_path: &Path,
) -> Result<HookValidateOutcome> {
    let payload = serde_json::to_vec(&HookValidateRequest {
        files: files.to_vec(),
    })?;
    let timeout_ms = env_u64("DOCDEX_HTTP_TIMEOUT_MS").unwrap_or(30_000);
    let response = timeout(Duration::from_millis(timeout_ms.max(1)), async {
        let stream = UnixStream::connect(socket_path).await?;
        let io = TokioIo::new(stream);
        let (mut sender, conn) = http1::handshake(io).await?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let repo_id = repo_manager::repo_fingerprint_sha256(repo_root)?;
        let mut builder = Request::builder()
            .method(HyperMethod::POST)
            .uri("http://localhost/v1/hooks/validate")
            .header(CONTENT_TYPE, "application/json")
            .header("x-docdex-repo-id", repo_id);
        if let Some(token) = env_non_empty("DOCDEX_AUTH_TOKEN") {
            builder = builder.header(AUTHORIZATION, format!("Bearer {token}"));
        }
        let request = builder.body(Full::new(Bytes::from(payload)))?;
        let response = sender.send_request(request).await?;
        let status = response.status();
        let body = response.into_body().collect().await?.to_bytes();
        let payload: HookValidateResponse =
            serde_json::from_slice(&body).context("hook validate response parse failed")?;
        Ok::<_, anyhow::Error>(HookValidateOutcome { status, payload })
    })
    .await;

    match response {
        Ok(result) => result,
        Err(err) => Err(err.into()),
    }
}

async fn send_hook_request(request: reqwest::RequestBuilder) -> Result<HookValidateOutcome> {
    let response = request.send().await?;
    let status = response.status();
    let payload: HookValidateResponse = response
        .json()
        .await
        .context("hook validate response parse failed")?;
    Ok(HookValidateOutcome { status, payload })
}

fn handle_hook_outcome(outcome: HookValidateOutcome) -> Result<()> {
    if !outcome.status.is_success() {
        anyhow::bail!("hook validation failed with status {}", outcome.status);
    }
    if outcome.payload.status.eq_ignore_ascii_case("pass") {
        return Ok(());
    }
    eprintln!("Docdex hook failed:");
    for error in outcome.payload.errors {
        match (error.file.as_deref(), error.line) {
            (Some(file), Some(line)) => eprintln!("- {}:{} {}", file, line, error.message),
            (Some(file), None) => eprintln!("- {} {}", file, error.message),
            _ => eprintln!("- {}", error.message),
        }
    }
    std::process::exit(1);
}

fn is_connect_or_timeout(err: &anyhow::Error) -> bool {
    err.chain().any(|source| {
        if source.is::<tokio::time::error::Elapsed>() {
            return true;
        }
        if let Some(io_err) = source.downcast_ref::<std::io::Error>() {
            return matches!(
                io_err.kind(),
                std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::NotFound
                    | std::io::ErrorKind::TimedOut
            );
        }
        source
            .downcast_ref::<reqwest::Error>()
            .map(|inner| inner.is_connect() || inner.is_timeout())
            .unwrap_or(false)
    })
}

#[cfg(unix)]
fn env_non_empty(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[cfg(unix)]
fn env_u64(key: &str) -> Option<u64> {
    env_non_empty(key)?.parse::<u64>().ok()
}

fn collect_staged_files(repo_root: &Path) -> Result<Vec<String>> {
    let output = Command::new("git")
        .current_dir(repo_root)
        .args(["diff", "--cached", "--name-only"])
        .output()
        .context("run git diff --cached --name-only")?;
    if !output.status.success() {
        anyhow::bail!(
            "git diff --cached failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let stdout = String::from_utf8(output.stdout)?;
    let files = stdout
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
        .map(|line| line.to_string())
        .collect::<Vec<_>>();
    Ok(files)
}
