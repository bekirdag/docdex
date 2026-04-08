use super::decode_json_or_error;
use crate::cli::http_client::CliHttpClient;
use crate::config::{self, RepoArgs};
#[cfg(unix)]
use crate::repo_manager;
use anyhow::{Context, Result};
#[cfg(unix)]
use http_body_util::{BodyExt, Full};
#[cfg(unix)]
use hyper::body::Bytes;
#[cfg(unix)]
use hyper::client::conn::http1;
#[cfg(unix)]
use hyper::header::{AUTHORIZATION, CONTENT_TYPE};
use hyper::http::StatusCode;
#[cfg(unix)]
use hyper::Method as HyperMethod;
#[cfg(unix)]
use hyper::Request;
#[cfg(unix)]
use hyper_util::rt::TokioIo;
use reqwest::Method;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
#[cfg(unix)]
use std::time::Duration;
#[cfg(unix)]
use tokio::net::UnixStream;
#[cfg(unix)]
use tokio::time::timeout;

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
        crate::cli::HookCommand::Conversation {
            scope,
            action,
            source,
            source_session_id,
            title,
            agent_id,
            transport,
            format,
            transcript,
            summary_text,
            wait_for_processing,
        } => {
            run_conversation(
                scope,
                action,
                source,
                source_session_id,
                title,
                agent_id,
                transport,
                format,
                transcript,
                summary_text,
                wait_for_processing,
            )
            .await
        }
    }
}

async fn run_pre_commit(repo: RepoArgs) -> Result<()> {
    let repo_root = repo.repo_root();
    let files = collect_staged_files(&repo_root)?;
    let socket_path = resolve_hook_socket_path()?;

    let outcome = match socket_path {
        Some(_path) => {
            #[cfg(unix)]
            {
                match send_hook_unix(&repo_root, &files, &_path).await {
                    Ok(result) => Some(result),
                    Err(err) if is_connect_or_timeout(&err) => None,
                    Err(err) => {
                        return Err(err).context("hook validate unix socket request failed");
                    }
                }
            }
            #[cfg(not(unix))]
            {
                eprintln!("Docdex hook socket configured but unix sockets are unsupported; falling back to HTTP");
                None
            }
        }
        None => None,
    };

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

async fn run_conversation(
    scope: crate::cli::ConversationScopeArgs,
    action: String,
    source: Option<String>,
    source_session_id: Option<String>,
    title: Option<String>,
    agent_id: Option<String>,
    transport: Option<String>,
    format: String,
    transcript: Option<PathBuf>,
    summary_text: Option<String>,
    wait_for_processing: bool,
) -> Result<()> {
    let transcript_text = match transcript {
        Some(path) => Some(fs::read_to_string(path)?),
        None => None,
    };
    if transcript_text
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_none()
        && summary_text
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_none()
    {
        anyhow::bail!("conversation hook requires --transcript or --summary-text");
    }
    let payload = json!({
        "action": action,
        "source": source,
        "source_session_id": source_session_id,
        "title": title,
        "agent_id": agent_id,
        "transport": transport,
        "format": format,
        "transcript_text": transcript_text,
        "summary_text": summary_text,
        "wait_for_processing": wait_for_processing,
    });
    let socket_path = resolve_hook_socket_path()?;
    let value = match socket_path {
        Some(_path) => {
            #[cfg(unix)]
            {
                match send_json_unix(
                    scope.repo_root().as_deref(),
                    scope.conversation_namespace(),
                    &_path,
                    "/v1/hooks/conversation",
                    &payload,
                )
                .await
                {
                    Ok(result) => result,
                    Err(err) if is_connect_or_timeout(&err) => {
                        send_json_http(&scope, "/v1/hooks/conversation", &payload).await?
                    }
                    Err(err) => {
                        return Err(err).context("conversation hook unix socket request failed");
                    }
                }
            }
            #[cfg(not(unix))]
            {
                send_json_http(&scope, "/v1/hooks/conversation", &payload).await?
            }
        }
        None => send_json_http(&scope, "/v1/hooks/conversation", &payload).await?,
    };
    println!("{}", serde_json::to_string_pretty(&value)?);
    Ok(())
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
    client.ensure_repo(repo_root).await?;
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

async fn send_json_http(
    scope: &crate::cli::ConversationScopeArgs,
    path: &str,
    payload: &serde_json::Value,
) -> Result<serde_json::Value> {
    let client = CliHttpClient::new()?;
    client.ensure_conversation_scope(scope).await?;
    let mut req = client.request(Method::POST, path).json(payload);
    req = client.with_conversation_scope(req, scope)?;
    decode_json_or_error(req.send().await?, path).await
}

#[cfg(unix)]
async fn send_json_unix(
    repo_root: Option<&Path>,
    conversation_namespace: Option<&str>,
    socket_path: &Path,
    path: &str,
    payload: &serde_json::Value,
) -> Result<serde_json::Value> {
    let payload = serde_json::to_vec(payload)?;
    let timeout_ms = env_u64("DOCDEX_HTTP_TIMEOUT_MS").unwrap_or(30_000);
    let response = timeout(Duration::from_millis(timeout_ms.max(1)), async {
        let stream = UnixStream::connect(socket_path).await?;
        let io = TokioIo::new(stream);
        let (mut sender, conn) = http1::handshake(io).await?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        let mut builder = Request::builder()
            .method(HyperMethod::POST)
            .uri(format!("http://localhost{}", path))
            .header(CONTENT_TYPE, "application/json");
        if let Some(repo_root) = repo_root {
            let repo_id = repo_manager::repo_fingerprint_sha256(repo_root)?;
            builder = builder.header("x-docdex-repo-id", repo_id);
        }
        if let Some(namespace) = conversation_namespace {
            builder = builder.header("x-docdex-conversation-namespace", namespace);
        }
        if let Some(token) = env_non_empty("DOCDEX_AUTH_TOKEN") {
            builder = builder.header(AUTHORIZATION, format!("Bearer {token}"));
        }
        let request = builder.body(Full::new(Bytes::from(payload)))?;
        let response = sender.send_request(request).await?;
        let status = response.status();
        let body = response.into_body().collect().await?.to_bytes();
        if !status.is_success() {
            anyhow::bail!(
                "request failed ({}): {}",
                status,
                String::from_utf8_lossy(&body)
            );
        }
        Ok::<_, anyhow::Error>(serde_json::from_slice(&body)?)
    })
    .await;

    match response {
        Ok(result) => result,
        Err(err) => Err(err.into()),
    }
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
