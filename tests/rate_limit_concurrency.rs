use reqwest::blocking::Client;
use reqwest::header::RETRY_AFTER;
use serde_json::Value;
use std::collections::HashSet;
use std::error::Error;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

type BoxError = Box<dyn Error + Send + Sync>;
const MAX_RATE_LIMIT_MESSAGE_BYTES: usize = 256;

fn docdex_bin() -> PathBuf {
    assert_cmd::cargo::cargo_bin!("docdexd").to_path_buf()
}

fn write_fixture_repo(repo_root: &Path) -> Result<(), BoxError> {
    let docs_dir = repo_root.join("docs");
    std::fs::create_dir_all(&docs_dir)?;
    std::fs::write(
        docs_dir.join("overview.md"),
        r#"
# Platform Overview

Our roadmap includes authentication, billing, and observability upgrades.
        "#,
    )?;
    Ok(())
}

fn setup_repo() -> Result<TempDir, BoxError> {
    let temp = TempDir::new()?;
    write_fixture_repo(temp.path())?;
    Ok(temp)
}

fn run_docdex<I, S>(state_root: &Path, args: I) -> Result<std::process::Output, BoxError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    Ok(Command::new(docdex_bin())
        .env("DOCDEX_STATE_DIR", state_root)
        .args(args)
        .output()?)
}

fn pick_free_port() -> Option<u16> {
    match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => Some(listener.local_addr().ok()?.port()),
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping HTTP rate-limit concurrency tests: TCP bind not permitted");
            None
        }
        Err(err) => panic!("bind ephemeral port: {err}"),
    }
}

fn spawn_server_with_args(
    state_root: &Path,
    repo: &Path,
    host: &str,
    port: u16,
    extra_args: &[&str],
) -> Result<Child, BoxError> {
    let repo_str = repo.to_string_lossy().to_string();
    let mut cmd = Command::new(docdex_bin());
    cmd.args([
        "serve",
        "--repo",
        repo_str.as_str(),
        "--host",
        host,
        "--port",
        &port.to_string(),
        "--log",
        "warn",
    ]);
    cmd.env("DOCDEX_STATE_DIR", state_root);
    cmd.args(extra_args);
    Ok(cmd
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?)
}

fn wait_for_health(host: &str, port: u16) -> Result<(), BoxError> {
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

fn assert_http_rate_limit_payload(body: &Value) -> Result<HashSet<String>, BoxError> {
    let top = body
        .as_object()
        .ok_or("rate-limit response must be a JSON object")?;
    if top.len() != 1 || !top.contains_key("error") {
        return Err(format!("unexpected top-level keys: {:?}", top.keys()).into());
    }

    let error = top
        .get("error")
        .and_then(|v| v.as_object())
        .ok_or("rate-limit response missing error object")?;

    let allowed: HashSet<&str> = [
        "code",
        "message",
        "retry_after_ms",
        "retry_at",
        "limit_key",
        "scope",
        "resource_key",
        "limit_per_min",
        "limit_burst",
        "denied_total",
    ]
    .into_iter()
    .collect();
    for key in error.keys() {
        if !allowed.contains(key.as_str()) {
            return Err(format!("unexpected error field: {key}").into());
        }
    }

    let code = error
        .get("code")
        .and_then(|v| v.as_str())
        .ok_or("rate-limit error.code missing or not a string")?;
    if code != "rate_limited" {
        return Err(format!("rate-limit error.code mismatch: {code}").into());
    }
    let message = error
        .get("message")
        .and_then(|v| v.as_str())
        .ok_or("rate-limit error.message missing or not a string")?;
    if message.len() > MAX_RATE_LIMIT_MESSAGE_BYTES + "…".len() {
        return Err(format!(
            "rate-limit error.message too large: {} bytes",
            message.len()
        )
        .into());
    }
    error
        .get("retry_after_ms")
        .and_then(|v| v.as_u64())
        .ok_or("rate-limit error.retry_after_ms missing or not an integer")?;
    let limit_key = error
        .get("limit_key")
        .and_then(|v| v.as_str())
        .ok_or("rate-limit error.limit_key missing or not a string")?;
    if limit_key != "http_ip" {
        return Err(format!("rate-limit error.limit_key mismatch: {limit_key}").into());
    }
    let scope = error
        .get("scope")
        .and_then(|v| v.as_str())
        .ok_or("rate-limit error.scope missing or not a string")?;
    if scope != "ip" {
        return Err(format!("rate-limit error.scope mismatch: {scope}").into());
    }
    let resource_key = error
        .get("resource_key")
        .and_then(|v| v.as_str())
        .ok_or("rate-limit error.resource_key missing or not a string")?;
    if resource_key.parse::<std::net::IpAddr>().is_err() {
        return Err(
            format!("rate-limit error.resource_key is not an IP address: {resource_key}").into(),
        );
    }
    let limit_per_min = error
        .get("limit_per_min")
        .and_then(|v| v.as_u64())
        .ok_or("rate-limit error.limit_per_min missing or not an integer")?;
    if limit_per_min != 60 {
        return Err(format!("rate-limit error.limit_per_min mismatch: {limit_per_min}").into());
    }
    let limit_burst = error
        .get("limit_burst")
        .and_then(|v| v.as_u64())
        .ok_or("rate-limit error.limit_burst missing or not an integer")?;
    if limit_burst != 2 {
        return Err(format!("rate-limit error.limit_burst mismatch: {limit_burst}").into());
    }
    error
        .get("denied_total")
        .and_then(|v| v.as_u64())
        .ok_or("rate-limit error.denied_total missing or not an integer")?;
    if let Some(retry_at) = error.get("retry_at") {
        retry_at
            .as_str()
            .ok_or("rate-limit error.retry_at must be a string when present")?;
    }

    Ok(error.keys().cloned().collect())
}

#[test]
fn http_rate_limit_signaling_is_stable_under_concurrency() -> Result<(), BoxError> {
    let repo = setup_repo()?;
    let state_root = TempDir::new()?;
    let repo_str = repo.path().to_string_lossy().to_string();
    run_docdex(state_root.path(), ["index", "--repo", repo_str.as_str()])?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let mut child = spawn_server_with_args(
        state_root.path(),
        repo.path(),
        host,
        port,
        &[
            "--secure-mode=false",
            // Use a low burst so concurrent calls reliably hit the limiter without waiting.
            "--rate-limit-per-min",
            "60",
            "--rate-limit-burst",
            "2",
        ],
    )?;
    wait_for_health(host, port)?;

    let client = Client::builder().timeout(Duration::from_secs(2)).build()?;
    let search_url = format!("http://{host}:{port}/search");
    let snippet_url = format!("http://{host}:{port}/snippet/docs%2Foverview.md");

    // Preflight endpoints to avoid mixing in handler-level errors; then wait for a refill.
    assert!(
        client
            .get(&search_url)
            .query(&[("q", "roadmap"), ("limit", "1")])
            .send()?
            .status()
            .is_success(),
        "preflight /search should succeed"
    );
    assert!(
        client
            .get(&snippet_url)
            .query(&[("window", "8"), ("q", "roadmap"), ("text_only", "true")])
            .send()?
            .status()
            .is_success(),
        "preflight /snippet should succeed"
    );
    thread::sleep(Duration::from_millis(1100));

    let threads = 32usize;
    let barrier = Arc::new(Barrier::new(threads));
    let mut handles = Vec::with_capacity(threads);
    for i in 0..threads {
        let barrier = barrier.clone();
        let search_url = search_url.clone();
        let snippet_url = snippet_url.clone();
        handles.push(thread::spawn(
            move || -> Result<(u16, Option<String>, Vec<u8>), BoxError> {
                let client = Client::builder().timeout(Duration::from_secs(2)).build()?;
                barrier.wait();
                let resp = if i % 2 == 0 {
                    client
                        .get(&search_url)
                        .query(&[("q", "roadmap"), ("limit", "1")])
                        .send()?
                } else {
                    client
                        .get(&snippet_url)
                        .query(&[("window", "8"), ("q", "roadmap"), ("text_only", "true")])
                        .send()?
                };
                let status = resp.status().as_u16();
                let retry_after = resp
                    .headers()
                    .get(RETRY_AFTER)
                    .and_then(|v| v.to_str().ok())
                    .map(|v| v.to_string());
                let bytes = resp.bytes()?.to_vec();
                Ok((status, retry_after, bytes))
            },
        ));
    }

    let mut rate_limited = 0usize;
    let mut keysets: HashSet<Vec<String>> = HashSet::new();
    for handle in handles {
        let (status, retry_after, bytes) = handle.join().expect("thread panicked")?;
        if status == 429 {
            rate_limited += 1;
            assert!(
                retry_after
                    .as_deref()
                    .and_then(|value| value.parse::<u64>().ok())
                    .is_some(),
                "429 responses must include numeric Retry-After header"
            );
            assert!(
                bytes.len() <= 1024,
                "rate-limit payload should remain small (got {} bytes)",
                bytes.len()
            );
            let json: Value = serde_json::from_slice(&bytes)?;
            let keyset = assert_http_rate_limit_payload(&json)?;
            let mut keys: Vec<String> = keyset.into_iter().collect();
            keys.sort();
            keysets.insert(keys);
        }
    }

    assert!(
        rate_limited >= 8,
        "expected rate limiting under concurrency (got {rate_limited} 429s out of {threads})"
    );
    assert_eq!(
        keysets.len(),
        1,
        "rate-limit payload schema should not vary under concurrency"
    );

    child.kill().ok();
    child.wait().ok();
    Ok(())
}
