use reqwest::blocking::Client;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fs;
use std::net::TcpListener;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

fn docdex_bin() -> PathBuf {
    assert_cmd::cargo::cargo_bin!("docdexd").to_path_buf()
}

fn write_fixture_repo(repo_root: &Path) -> Result<(), Box<dyn Error>> {
    let docs_dir = repo_root.join("docs");
    fs::create_dir_all(&docs_dir)?;
    fs::write(
        docs_dir.join("overview.md"),
        r#"
# Platform Overview

Our roadmap includes authentication, billing, and observability upgrades.

## Authentication

Detailed description about the auth roadmap.
        "#,
    )?;
    fs::write(
        repo_root.join("readme.md"),
        r#"
# Internal README

This repository hosts design docs for the Control Plane roadmap.
        "#,
    )?;
    Ok(())
}

fn setup_repo() -> Result<TempDir, Box<dyn Error>> {
    let temp = TempDir::new()?;
    write_fixture_repo(temp.path())?;
    Ok(temp)
}

fn symbols_record_path(repo_state_root: &Path, rel_path: &str) -> PathBuf {
    let key = hex::encode(Sha256::digest(rel_path.as_bytes()));
    repo_state_root
        .join("symbols.db")
        .join("files")
        .join(format!("{key}.json"))
}

fn run_docdex<I, S>(state_root: &Path, args: I) -> Result<Vec<u8>, Box<dyn Error>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let output = Command::new(docdex_bin())
        .env_remove("DOCDEX_ENABLE_SYMBOL_EXTRACTION")
        .env("DOCDEX_STATE_DIR", state_root)
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

fn inspect_repo_state(state_root: &Path, repo_root: &Path) -> Result<Value, Box<dyn Error>> {
    let repo_str = repo_root.to_string_lossy().to_string();
    let state_root_str = state_root.to_string_lossy().to_string();
    let output = Command::new(docdex_bin())
        .args([
            "repo",
            "inspect",
            "--repo",
            repo_str.as_str(),
            "--state-dir",
            state_root_str.as_str(),
        ])
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "docdexd repo inspect exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(serde_json::from_slice(&output.stdout)?)
}

fn resolve_index_dir(state_root: &Path, repo_root: &Path) -> Result<PathBuf, Box<dyn Error>> {
    let payload = inspect_repo_state(state_root, repo_root)?;
    let resolved = payload
        .get("resolvedIndexStateDir")
        .and_then(|value| value.as_str())
        .ok_or("missing resolvedIndexStateDir")?;
    Ok(PathBuf::from(resolved))
}

fn resolve_repo_state_root(state_root: &Path, repo_root: &Path) -> Result<PathBuf, Box<dyn Error>> {
    let payload = inspect_repo_state(state_root, repo_root)?;
    let root = payload
        .get("statePaths")
        .and_then(|value| value.get("repoStateRoot"))
        .and_then(|value| value.as_str())
        .ok_or("missing statePaths.repoStateRoot")?;
    Ok(PathBuf::from(root))
}

fn pick_free_port() -> Option<u16> {
    match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => Some(listener.local_addr().ok()?.port()),
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping HTTP smoke tests: TCP bind not permitted in this environment");
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

#[test]
fn cli_index_and_query_smoke() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let state_root = TempDir::new()?;
    let repo_str = repo.path().to_string_lossy().to_string();

    run_docdex(state_root.path(), ["index", "--repo", repo_str.as_str()])?;

    let stdout = run_docdex(state_root.path(), [
        "query",
        "--repo",
        repo_str.as_str(),
        "--query",
        "roadmap",
        "--limit",
        "4",
    ])?;
    let payload: Value = serde_json::from_slice(&stdout)?;
    let hits = payload
        .get("hits")
        .and_then(|value| value.as_array())
        .expect("hits array missing");
    assert!(
        !hits.is_empty(),
        "expected at least one search hit for 'roadmap'"
    );
    let first = hits.first().expect("hit missing");
    let path = first
        .get("path")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    assert!(!path.is_empty(), "hit.path should be present in CLI query response");
    assert!(
        first.get("snippet").and_then(|v| v.as_str()).is_some(),
        "hit.snippet should be present in CLI query response"
    );
    assert!(
        first.get("score").and_then(|v| v.as_f64()).is_some(),
        "hit.score should be present in CLI query response"
    );
    let summary = first
        .get("summary")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    assert!(
        !summary.is_empty(),
        "summary should not be empty in CLI query response"
    );
    Ok(())
}

#[test]
fn index_writes_default_state_dir() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let state_root = TempDir::new()?;
    let repo_root = repo.path();
    let repo_str = repo_root.to_string_lossy().to_string();

    run_docdex(state_root.path(), ["index", "--repo", repo_str.as_str()])?;

    let resolved_index = resolve_index_dir(state_root.path(), repo_root)?;
    assert!(
        resolved_index.exists(),
        "default state index dir should exist after indexing"
    );
    assert!(
        !repo_root.join(".docdex").exists(),
        "repo-local .docdex should not be created when using global state root"
    );
    Ok(())
}

#[test]
fn index_honors_custom_state_dir() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let state_root = TempDir::new()?;
    let repo_root = repo.path();
    let repo_str = repo_root.to_string_lossy().to_string();
    let custom_state = ".alt-docdex";

    run_docdex(state_root.path(), [
        "index",
        "--repo",
        repo_str.as_str(),
        "--state-dir",
        custom_state,
    ])?;

    let custom_base = repo_root.join(custom_state);
    let resolved_index = resolve_index_dir(&custom_base, repo_root)?;
    assert!(
        resolved_index.exists(),
        "custom state dir should be created when provided"
    );
    assert!(
        !repo_root.join(".docdex").exists(),
        "default .docdex should not be created when custom state dir is used"
    );
    Ok(())
}

#[test]
fn symbols_disabled_does_not_create_symbols_store() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let state_root = TempDir::new()?;
    let repo_root = repo.path();
    let repo_str = repo_root.to_string_lossy().to_string();

    run_docdex(state_root.path(), ["index", "--repo", repo_str.as_str()])?;

    let repo_state_root = resolve_repo_state_root(state_root.path(), repo_root)?;
    assert!(
        !repo_state_root.join("symbols.db").exists(),
        "symbols.db should not be created when symbol extraction is disabled"
    );
    Ok(())
}

#[test]
fn symbols_enabled_creates_symbols_store_records() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let state_root = TempDir::new()?;
    let repo_root = repo.path();
    let repo_str = repo_root.to_string_lossy().to_string();
    let rel_path = "docs/overview.md";

    run_docdex(state_root.path(), [
        "index",
        "--repo",
        repo_str.as_str(),
        "--enable-symbol-extraction=true",
    ])?;

    let repo_state_root = resolve_repo_state_root(state_root.path(), repo_root)?;
    let record_path = symbols_record_path(&repo_state_root, rel_path);
    assert!(
        record_path.exists(),
        "expected symbols record to exist for {rel_path}"
    );
    let raw = fs::read_to_string(record_path)?;
    let parsed: Value = serde_json::from_str(&raw)?;
    assert_eq!(
        parsed
            .get("schema")
            .and_then(|v| v.get("name"))
            .and_then(|v| v.as_str()),
        Some("docdex.symbols"),
        "symbols record should use docdex.symbols schema"
    );
    assert_eq!(
        parsed.get("file").and_then(|v| v.as_str()),
        Some(rel_path),
        "symbols record should include the file rel path"
    );
    assert_eq!(
        parsed
            .get("outcome")
            .and_then(|v| v.get("status"))
            .and_then(|v| v.as_str()),
        Some("ok"),
        "markdown symbol extraction should succeed"
    );
    Ok(())
}

#[test]
fn exclude_dir_flag_skips_vendor_docs() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let state_root = TempDir::new()?;
    let repo_root = repo.path();
    let repo_str = repo_root.to_string_lossy().to_string();
    let vendor_dir = repo_root.join("vendor");
    fs::create_dir_all(&vendor_dir)?;
    fs::write(
        vendor_dir.join("private.md"),
        "# Vendor Doc\nSHOULD_BE_SKIPPED_VENDOR_TEST\n",
    )?;

    run_docdex(state_root.path(), [
        "index",
        "--repo",
        repo_str.as_str(),
        "--exclude-dir",
        "vendor",
    ])?;

    let stdout = run_docdex(state_root.path(), [
        "query",
        "--repo",
        repo_str.as_str(),
        "--query",
        "SHOULD_BE_SKIPPED_VENDOR_TEST",
        "--limit",
        "4",
    ])?;
    let payload: Value = serde_json::from_slice(&stdout)?;
    let empty: Vec<Value> = Vec::new();
    let hits = payload
        .get("hits")
        .and_then(|value| value.as_array())
        .unwrap_or(&empty);
    assert!(
        hits.is_empty(),
        "files in excluded vendor dir should not be indexed"
    );
    Ok(())
}

#[test]
fn exclude_prefix_on_ingest_skips_secret_file() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let state_root = TempDir::new()?;
    let repo_root = repo.path();
    let repo_str = repo_root.to_string_lossy().to_string();
    run_docdex(state_root.path(), ["index", "--repo", repo_str.as_str()])?;

    let secret_dir = repo_root.join("secret");
    fs::create_dir_all(&secret_dir)?;
    let secret_file = secret_dir.join("note.md");
    let needle = "SHOULD_NOT_BE_INDEXED_SECRET_123";
    fs::write(&secret_file, format!("# Secret\n{needle}\n"))?;

    run_docdex(state_root.path(), [
        "ingest",
        "--repo",
        repo_str.as_str(),
        "--exclude-prefix",
        "secret/",
        "--file",
        secret_file.to_string_lossy().as_ref(),
    ])?;

    let stdout = run_docdex(state_root.path(), [
        "query",
        "--repo",
        repo_str.as_str(),
        "--query",
        needle,
        "--limit",
        "4",
    ])?;
    let payload: Value = serde_json::from_slice(&stdout)?;
    let empty: Vec<Value> = Vec::new();
    let hits = payload
        .get("hits")
        .and_then(|value| value.as_array())
        .unwrap_or(&empty);
    assert!(
        hits.is_empty(),
        "ingest with exclude-prefix should not index files under that prefix"
    );
    Ok(())
}

fn spawn_server(
    state_root: &Path,
    repo_root: &Path,
    host: &str,
    port: u16,
) -> Result<Child, Box<dyn Error>> {
    spawn_server_with_args(state_root, repo_root, host, port, &["--secure-mode=false"])
}

fn spawn_server_with_args(
    state_root: &Path,
    repo_root: &Path,
    host: &str,
    port: u16,
    extra_args: &[&str],
) -> Result<Child, Box<dyn Error>> {
    let repo_arg = repo_root.to_string_lossy().to_string();
    let port_string = port.to_string();
    let mut args = vec![
        "serve",
        "--repo",
        repo_arg.as_str(),
        "--host",
        host,
        "--port",
        &port_string,
        "--log",
        "warn",
    ];
    args.extend_from_slice(extra_args);
    let child = Command::new(docdex_bin())
        .env("DOCDEX_STATE_DIR", state_root)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    wait_for_health(host, port)?;
    Ok(child)
}

fn spawn_server_with_auth(
    state_root: &Path,
    repo_root: &Path,
    host: &str,
    port: u16,
    token: &str,
) -> Result<Child, Box<dyn Error>> {
    spawn_server_with_args(state_root, repo_root, host, port, &["--auth-token", token])
}

#[test]
fn http_server_smoke() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let state_root = TempDir::new()?;
    let repo_str = repo.path().to_string_lossy().to_string();
    run_docdex(state_root.path(), ["index", "--repo", repo_str.as_str()])?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let mut child = spawn_server(state_root.path(), repo.path(), host, port)?;
    let client = Client::builder().timeout(Duration::from_secs(2)).build()?;
    let url = format!("http://{host}:{port}/search");
    let payload: Value = client
        .get(&url)
        .query(&[("q", "roadmap"), ("limit", "2")])
        .send()?
        .json()?;
    let hit_count = payload
        .get("hits")
        .and_then(|value| value.as_array())
        .map(|arr| arr.len())
        .unwrap_or(0);
    assert!(hit_count > 0, "HTTP /search should return at least one hit");
    let top_score = payload.get("top_score").and_then(|v| v.as_f64());
    let top_score_camel = payload.get("topScore").and_then(|v| v.as_f64());
    assert!(
        top_score.is_some(),
        "HTTP /search should include top_score when hits are returned"
    );
    assert!(
        top_score_camel.is_some(),
        "HTTP /search should include topScore when hits are returned"
    );
    let first_score = payload
        .get("hits")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|hit| hit.get("score"))
        .and_then(|v| v.as_f64())
        .unwrap_or(-1.0);
    let first = payload
        .get("hits")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .ok_or("hits missing from response")?;
    assert!(
        first.get("path").and_then(|v| v.as_str()).is_some(),
        "HTTP /search hits should include path"
    );
    assert!(
        first.get("snippet").and_then(|v| v.as_str()).is_some(),
        "HTTP /search hits should include snippet"
    );
    assert!(
        (top_score.unwrap_or(-1.0) - first_score).abs() < 1e-6,
        "top_score should match the first hit score"
    );
    assert!(
        (top_score.unwrap_or(-1.0) - top_score_camel.unwrap_or(-1.0)).abs() < 1e-6,
        "topScore should match top_score"
    );
    child.kill().ok();
    child.wait().ok();
    Ok(())
}

#[test]
fn http_search_missing_index_returns_error_code() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let mut child = spawn_server(repo.path(), host, port)?;
    let client = Client::builder().timeout(Duration::from_secs(2)).build()?;
    let url = format!("http://{host}:{port}/search");
    let payload: Value = client
        .get(&url)
        .query(&[("q", "roadmap"), ("limit", "1")])
        .send()?
        .json()?;
    let code = payload
        .get("error")
        .and_then(|value| value.get("code"))
        .and_then(|value| value.as_str());
    assert_eq!(code, Some("missing_index"));
    let message = payload
        .get("error")
        .and_then(|value| value.get("message"))
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    assert!(
        message.contains("docdexd index"),
        "expected missing_index message to include index hint; got: {message}"
    );
    child.kill().ok();
    child.wait().ok();
    Ok(())
}

#[test]
fn http_search_missing_index_returns_error_code() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let mut child = spawn_server(repo.path(), host, port)?;
    let client = Client::builder().timeout(Duration::from_secs(2)).build()?;
    let url = format!("http://{host}:{port}/search");
    let payload: Value = client
        .get(&url)
        .query(&[("q", "roadmap"), ("limit", "1")])
        .send()?
        .json()?;
    let code = payload
        .get("error")
        .and_then(|value| value.get("code"))
        .and_then(|value| value.as_str());
    assert_eq!(code, Some("missing_index"));
    let message = payload
        .get("error")
        .and_then(|value| value.get("message"))
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    assert!(
        message.contains("docdexd index"),
        "expected missing_index message to include index hint; got: {message}"
    );
    child.kill().ok();
    child.wait().ok();
    Ok(())
}

#[test]
fn http_search_validation_error_on_empty_or_invalid_query() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let state_root = TempDir::new()?;
    let repo_root = repo.path();
    let repo_str = repo_root.to_string_lossy().to_string();
    run_docdex(state_root.path(), ["index", "--repo", repo_str.as_str()])?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let mut child = spawn_server(state_root.path(), repo_root, host, port)?;
    let client = Client::builder().timeout(Duration::from_secs(2)).build()?;
    let url = format!("http://{host}:{port}/search");

    let empty_resp = client.get(&url).query(&[("q", "")]).send()?;
    assert_eq!(
        empty_resp.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "empty query should be rejected"
    );
    let empty_payload: Value = empty_resp.json()?;
    assert_eq!(
        empty_payload
            .get("error")
            .and_then(|v| v.get("code"))
            .and_then(|v| v.as_str()),
        Some("invalid_query"),
        "empty query should return machine-readable invalid_query code"
    );

    let invalid_resp = client.get(&url).query(&[("q", "!!!")]).send()?;
    assert_eq!(
        invalid_resp.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "invalid query should be rejected"
    );
    let invalid_payload: Value = invalid_resp.json()?;
    assert_eq!(
        invalid_payload
            .get("error")
            .and_then(|v| v.get("code"))
            .and_then(|v| v.as_str()),
        Some("invalid_query"),
        "invalid query should return machine-readable invalid_query code"
    );

    child.kill().ok();
    child.wait().ok();
    Ok(())
}

#[test]
fn http_search_no_matches_returns_empty_hits_and_null_top_score() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let state_root = TempDir::new()?;
    let repo_root = repo.path();
    let repo_str = repo_root.to_string_lossy().to_string();
    run_docdex(state_root.path(), ["index", "--repo", repo_str.as_str()])?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let mut child = spawn_server(state_root.path(), repo_root, host, port)?;
    let client = Client::builder().timeout(Duration::from_secs(2)).build()?;
    let url = format!("http://{host}:{port}/search");

    let payload: Value = client
        .get(&url)
        .query(&[("q", "NO_MATCH_TERM_123456"), ("limit", "3")])
        .send()?
        .json()?;
    let hits = payload
        .get("hits")
        .and_then(|v| v.as_array())
        .map(|arr| arr.len())
        .unwrap_or(999);
    assert_eq!(hits, 0, "no-match query should return empty hits");
    assert!(
        payload.get("top_score").map(|v| v.is_null()).unwrap_or(false),
        "no-match query should return top_score: null"
    );
    assert!(
        payload.get("topScore").map(|v| v.is_null()).unwrap_or(false),
        "no-match query should return topScore: null"
    );

    child.kill().ok();
    child.wait().ok();
    Ok(())
}

#[test]
fn http_server_requires_auth_when_configured() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let state_root = TempDir::new()?;
    let repo_str = repo.path().to_string_lossy().to_string();
    run_docdex(state_root.path(), ["index", "--repo", repo_str.as_str()])?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let token = "secret-token";
    let mut child = spawn_server_with_auth(state_root.path(), repo.path(), host, port, token)?;
    let client = Client::builder().timeout(Duration::from_secs(2)).build()?;
    let url = format!("http://{host}:{port}/search");

    // Without auth should 401
    let unauthorized = client
        .get(&url)
        .query(&[("q", "roadmap"), ("limit", "1")])
        .send()?;
    assert_eq!(
        unauthorized.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "server should reject requests without auth token"
    );

    // With auth should succeed
    let payload: Value = client
        .get(&url)
        .query(&[("q", "roadmap"), ("limit", "1")])
        .header("Authorization", format!("Bearer {token}"))
        .send()?
        .json()?;
    let hit_count = payload
        .get("hits")
        .and_then(|value| value.as_array())
        .map(|arr| arr.len())
        .unwrap_or(0);
    assert!(
        hit_count > 0,
        "authorized search should return at least one hit"
    );
    child.kill().ok();
    child.wait().ok();
    Ok(())
}

#[test]
fn non_loopback_plain_http_requires_tls_or_opt_out() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let state_root = TempDir::new()?;
    let repo_str = repo.path().to_string_lossy().to_string();
    run_docdex(state_root.path(), ["index", "--repo", repo_str.as_str()])?;

    // Default behavior: fail fast when binding publicly without TLS/insecure.
    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let failure = Command::new(docdex_bin())
        .env("DOCDEX_STATE_DIR", state_root.path())
        .args([
            "serve",
            "--repo",
            repo_str.as_str(),
            "--host",
            "0.0.0.0",
            "--port",
            &port.to_string(),
            "--log",
            "warn",
            "--secure-mode=false",
        ])
        .output()?;
    assert!(
        !failure.status.success(),
        "non-loopback binds without TLS should fail unless explicitly allowed"
    );
    let stderr = String::from_utf8_lossy(&failure.stderr);
    let trimmed = stderr.trim();
    assert!(
        stderr.contains("refusing to bind on non-loopback without TLS"),
        "stderr should mention TLS requirement, got: {stderr}"
    );
    assert_eq!(
        trimmed.lines().filter(|line| !line.trim().is_empty()).count(),
        1,
        "startup failures should emit a single primary error line, got: {stderr}"
    );
    let payload: Value = serde_json::from_str(trimmed)
        .map_err(|err| format!("startup error should be JSON (got {trimmed:?}): {err}"))?;
    assert_eq!(
        payload
            .get("error")
            .and_then(|v| v.get("code"))
            .and_then(|v| v.as_str()),
        Some("startup_tls_required"),
        "startup error code should be stable"
    );
    assert_eq!(
        payload
            .get("error")
            .and_then(|v| v.get("message"))
            .and_then(|v| v.as_str()),
        Some("refusing to bind on non-loopback without TLS; provide --tls-cert/--tls-key or --insecure to allow plain HTTP"),
        "startup error message should be stable"
    );

    // Optional override: allow plain HTTP when explicitly opting out.
    let Some(opt_out_port) = pick_free_port() else {
        return Ok(());
    };
    let mut child = Command::new(docdex_bin())
        .env("DOCDEX_STATE_DIR", state_root.path())
        .args([
            "serve",
            "--repo",
            repo_str.as_str(),
            "--host",
            "0.0.0.0",
            "--port",
            &opt_out_port.to_string(),
            "--log",
            "warn",
            "--require-tls=false",
            "--secure-mode=false",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    wait_for_health("127.0.0.1", opt_out_port)?;
    child.kill().ok();
    child.wait().ok();
    Ok(())
}

#[test]
fn rate_limit_and_request_size_limits_apply() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let state_root = TempDir::new()?;
    let repo_str = repo.path().to_string_lossy().to_string();
    run_docdex(state_root.path(), ["index", "--repo", repo_str.as_str()])?;

    let host = "127.0.0.1";

    // Clamp limit and reject oversized query strings.
    let Some(clamp_port) = pick_free_port() else {
        return Ok(());
    };
    let mut clamp_child = spawn_server_with_args(
        state_root.path(),
        repo.path(),
        host,
        clamp_port,
        &[
            "--max-limit",
            "1",
            "--max-query-bytes",
            "32",
            "--secure-mode=false",
        ],
    )?;
    let client = Client::builder().timeout(Duration::from_secs(2)).build()?;
    let clamp_url = format!("http://{host}:{clamp_port}/search");

    // Limit should be clamped to 1 when request passes a higher limit.
    let payload: Value = client
        .get(&clamp_url)
        .query(&[("q", "roadmap"), ("limit", "10")])
        .send()?
        .json()?;
    let hit_count = payload
        .get("hits")
        .and_then(|value| value.as_array())
        .map(|arr| arr.len())
        .unwrap_or(0);
    assert_eq!(
        hit_count, 1,
        "limit should be clamped to max-limit when exceeded"
    );

    // Oversized query string should be rejected.
    let long_query = "x".repeat(200);
    let oversized = client
        .get(&clamp_url)
        .query(&[("q", long_query.as_str()), ("limit", "1")])
        .send()?;
    assert_eq!(
        oversized.status(),
        reqwest::StatusCode::PAYLOAD_TOO_LARGE,
        "oversized query string should be rejected"
    );

    clamp_child.kill().ok();
    clamp_child.wait().ok();

    // Rate limit: allow two requests, reject the third within the window.
    let Some(rate_port) = pick_free_port() else {
        return Ok(());
    };
    let mut rate_child = spawn_server_with_args(
        state_root.path(),
        repo.path(),
        host,
        rate_port,
        &[
            "--rate-limit-per-min",
            "2",
            "--rate-limit-burst",
            "2",
            "--secure-mode=false",
        ],
    )?;
    let rate_url = format!("http://{host}:{rate_port}/search");

    // Rate limit: allow two requests, reject the third within the window.
    let first = client
        .get(&rate_url)
        .query(&[("q", "roadmap"), ("limit", "1")])
        .send()?;
    assert!(
        first.status().is_success(),
        "first request should pass rate limit"
    );
    let second = client
        .get(&rate_url)
        .query(&[("q", "roadmap"), ("limit", "1")])
        .send()?;
    assert!(
        second.status().is_success(),
        "second request should pass rate limit"
    );
    let third = client
        .get(&rate_url)
        .query(&[("q", "roadmap"), ("limit", "1")])
        .send()?;
    let third_status = third.status();
    assert_eq!(
        third_status,
        reqwest::StatusCode::TOO_MANY_REQUESTS,
        "third request within window should be rate limited"
    );
    let limited: Value = third.json()?;
    assert_eq!(
        limited
            .get("error")
            .and_then(|v| v.get("code"))
            .and_then(|v| v.as_str()),
        Some("rate_limited"),
        "rate-limited responses should include stable code"
    );
    assert!(
        limited
            .get("error")
            .and_then(|v| v.get("retry_after_ms"))
            .and_then(|v| v.as_u64())
            .is_some(),
        "rate-limited responses should include machine-readable retry_after_ms"
    );

    rate_child.kill().ok();
    rate_child.wait().ok();
    Ok(())
}

#[test]
fn search_and_snippet_flags_reduce_payloads() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let state_root = TempDir::new()?;
    let repo_str = repo.path().to_string_lossy().to_string();
    run_docdex(state_root.path(), ["index", "--repo", repo_str.as_str()])?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let mut child = spawn_server(state_root.path(), repo.path(), host, port)?;
    let client = Client::builder().timeout(Duration::from_secs(2)).build()?;
    let search_url = format!("http://{host}:{port}/search");

    // Baseline search to grab a doc_id.
    let baseline: Value = client
        .get(&search_url)
        .query(&[("q", "roadmap"), ("limit", "1")])
        .send()?
        .json()?;
    let doc_id = baseline
        .get("hits")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|hit| hit.get("doc_id"))
        .and_then(|v| v.as_str())
        .ok_or("doc_id missing from baseline search")?
        .to_string();

    // Summary-only search should zero out snippets.
    let summary_only: Value = client
        .get(&search_url)
        .query(&[("q", "roadmap"), ("limit", "2"), ("snippets", "false")])
        .send()?
        .json()?;
    let snippets_empty = summary_only
        .get("hits")
        .and_then(|v| v.as_array())
        .unwrap_or(&Vec::new())
        .iter()
        .all(|hit| {
            hit.get("snippet")
                .and_then(|s| s.as_str())
                .unwrap_or_default()
                .is_empty()
        });
    assert!(
        snippets_empty,
        "snippets should be empty when snippets=false"
    );

    // Max tokens should allow pruning hits above the budget (set tiny to drop all).
    let pruned: Value = client
        .get(&search_url)
        .query(&[
            ("q", "roadmap"),
            ("limit", "5"),
            ("snippets", "false"),
            ("max_tokens", "0"),
        ])
        .send()?
        .json()?;
    let empty_hits: Vec<Value> = Vec::new();
    let pruned_hits = pruned
        .get("hits")
        .and_then(|v| v.as_array())
        .unwrap_or(&empty_hits);
    assert!(
        pruned_hits.is_empty(),
        "max_tokens=0 should prune all hits, got {}",
        pruned_hits.len()
    );

    // text_only should omit HTML in snippets.
    let snippet_url = format!("http://{host}:{port}/snippet/{doc_id}");
    let snippet_resp = client
        .get(&snippet_url)
        .query(&[("window", "20"), ("text_only", "true")])
        .send()?
        .error_for_status()?;
    let snippet_text = snippet_resp.text()?;
    let snippet: Value = serde_json::from_str(&snippet_text)
        .map_err(|err| format!("failed to parse snippet json: {err}; body={snippet_text}"))?;
    let html = snippet
        .get("snippet")
        .and_then(|v| v.get("html"))
        .and_then(|v| v.as_str());
    assert!(html.is_none(), "text_only should drop HTML field");

    child.kill().ok();
    child.wait().ok();
    Ok(())
}

#[test]
fn watcher_removes_deleted_docs() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let state_root = TempDir::new()?;
    let repo_root = repo.path();
    let repo_str = repo_root.to_string_lossy().to_string();
    let unique = "SHOULD_BE_REMOVED_UNIQUE_123";
    let doomed = repo_root.join("docs").join("temp.md");
    fs::write(&doomed, format!("# Temp\n{unique}\n"))?;

    run_docdex(state_root.path(), ["index", "--repo", repo_str.as_str()])?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let mut child = spawn_server(state_root.path(), repo_root, host, port)?;
    let client = Client::builder().timeout(Duration::from_secs(2)).build()?;
    let search_url = format!("http://{host}:{port}/search");

    // Confirm the doc is indexed.
    let initial: Value = client
        .get(&search_url)
        .query(&[("q", unique), ("limit", "2")])
        .send()?
        .json()?;
    let initial_hits = initial
        .get("hits")
        .and_then(|v| v.as_array())
        .map(|arr| arr.len())
        .unwrap_or(0);
    assert!(initial_hits > 0, "expected doc to be indexed before delete");

    // Delete the file and wait for watcher to remove it from the index.
    fs::remove_file(&doomed)?;
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        let resp = client
            .get(&search_url)
            .query(&[("q", unique), ("limit", "2")])
            .send()?;
        let payload: Value = resp.json()?;
        let hits = payload
            .get("hits")
            .and_then(|v| v.as_array())
            .map(|arr| arr.len())
            .unwrap_or(0);
        if hits == 0 {
            break;
        }
        if Instant::now() > deadline {
            panic!("deleted doc still present after watcher grace period");
        }
        thread::sleep(Duration::from_millis(300));
    }

    child.kill().ok();
    child.wait().ok();
    Ok(())
}

#[test]
fn snippet_html_is_sanitized_or_stripped() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let state_root = TempDir::new()?;
    let repo_root = repo.path();
    let repo_str = repo_root.to_string_lossy().to_string();

    // Add a file with potentially unsafe HTML content.
    let doc_path = repo_root.join("unsafe.md");
    fs::write(
        &doc_path,
        r#"
# Unsafe Doc

This line contains malicious content: <script>alert("pwned")</script> plus a keyword MALICIOUS.
        "#,
    )?;

    run_docdex(state_root.path(), ["index", "--repo", repo_str.as_str()])?;

    // Start server with default sanitized HTML.
    let host = "127.0.0.1";
    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let mut child = spawn_server(state_root.path(), repo_root, host, port)?;
    let client = Client::builder().timeout(Duration::from_secs(2)).build()?;
    let search_url = format!("http://{host}:{port}/search");
    let snippet_url_base = format!("http://{host}:{port}/snippet");

    // Fetch doc id via search.
    let search_payload: Value = client
        .get(&search_url)
        .query(&[("q", "MALICIOUS"), ("limit", "1")])
        .send()?
        .json()?;
    let doc_id = search_payload
        .get("hits")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|hit| hit.get("doc_id"))
        .and_then(|v| v.as_str())
        .ok_or("doc_id missing from search response")?;

    let snippet_url = format!("{snippet_url_base}/{doc_id}");
    let snippet_payload: Value = client
        .get(&snippet_url)
        .query(&[("q", "MALICIOUS"), ("window", "40")])
        .send()?
        .json()?;
    let html = snippet_payload
        .get("snippet")
        .and_then(|v| v.get("html"))
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert!(
        !html.contains("<script"),
        "sanitized HTML should not include script tags"
    );
    child.kill().ok();
    child.wait().ok();

    // Start server with HTML stripped.
    let Some(strip_port) = pick_free_port() else {
        return Ok(());
    };
    let mut strip_child = spawn_server_with_args(
        state_root.path(),
        repo_root,
        host,
        strip_port,
        &["--strip-snippet-html", "--secure-mode=false"],
    )?;
    let strip_snippet_url_base = format!("http://{host}:{strip_port}/snippet");
    let strip_snippet_url = format!("{strip_snippet_url_base}/{doc_id}");
    let snippet_payload: Value = client
        .get(&strip_snippet_url)
        .query(&[
            ("q", "MALICIOUS"),
            ("window", "40"),
            ("text_only", "true"),
            ("strip_html", "true"),
        ])
        .send()?
        .json()?;
    assert!(
        snippet_payload
            .get("snippet")
            .and_then(|v| v.get("html"))
            .and_then(|v| v.as_str())
            .is_none(),
        "HTML should be omitted when strip-snippet-html is set"
    );
    strip_child.kill().ok();
    strip_child.wait().ok();
    Ok(())
}

#[test]
fn ai_help_requires_auth_when_configured() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let state_root = TempDir::new()?;
    run_docdex(
        state_root.path(),
        ["index", "--repo", repo.path().to_string_lossy().as_ref()],
    )?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let token = "secret-token";
    let mut child = spawn_server_with_auth(state_root.path(), repo.path(), host, port, token)?;
    let client = Client::builder().timeout(Duration::from_secs(2)).build()?;
    let url = format!("http://{host}:{port}/ai-help");

    let unauth = client.get(&url).send()?;
    assert_eq!(
        unauth.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "ai-help should require auth when configured"
    );

    let authed: Value = client
        .get(&url)
        .header("Authorization", format!("Bearer {token}"))
        .send()?
        .json()?;
    assert_eq!(
        authed.get("product").and_then(|v| v.as_str()),
        Some("Docdex"),
        "ai-help payload should include product"
    );

    child.kill().ok();
    child.wait().ok();
    Ok(())
}

#[test]
fn help_all_command_outputs_subcommands() -> Result<(), Box<dyn Error>> {
    let output = Command::new(docdex_bin()).arg("help-all").output()?;
    assert!(output.status.success(), "help-all should exit successfully");
    let stdout = String::from_utf8_lossy(&output.stdout);
    for needle in ["serve", "index", "ingest", "query", "self-check"] {
        assert!(
            stdout.contains(needle),
            "help-all output should include {needle}"
        );
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn state_dir_has_strict_permissions() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let state_root = TempDir::new()?;
    let repo_root = repo.path();
    let repo_str = repo_root.to_string_lossy().to_string();

    run_docdex(state_root.path(), ["index", "--repo", repo_str.as_str()])?;

    let state_dir = resolve_index_dir(state_root.path(), repo_root)?;
    let metadata = fs::metadata(&state_dir)?;
    let mode = metadata.permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o700,
        "state dir should be created with 0700 perms, got {:o}",
        mode
    );
    Ok(())
}

#[test]
fn self_check_reports_sensitive_terms() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let state_root = TempDir::new()?;
    let repo_root = repo.path();
    let repo_str = repo_root.to_string_lossy().to_string();

    // Insert a sensitive term.
    fs::write(repo_root.join("leak.md"), "company SECRET_TOKEN leak")?;
    run_docdex(state_root.path(), ["index", "--repo", repo_str.as_str()])?;

    // Self-check should fail when sensitive term is present.
    let failure = Command::new(docdex_bin())
        .env("DOCDEX_STATE_DIR", state_root.path())
        .args([
            "self-check",
            "--repo",
            repo_str.as_str(),
            "--terms",
            "SECRET_TOKEN",
        ])
        .output()?;
    assert!(
        !failure.status.success(),
        "self-check should return non-zero when sensitive terms are found"
    );
    let stderr = String::from_utf8_lossy(&failure.stderr);
    assert!(
        stderr.contains("sensitive terms found"),
        "stderr should mention sensitive findings"
    );

    // Self-check passes when term is absent.
    let success = Command::new(docdex_bin())
        .env("DOCDEX_STATE_DIR", state_root.path())
        .args([
            "self-check",
            "--repo",
            repo_str.as_str(),
            "--terms",
            "NOT_PRESENT",
            "--include-default-patterns=false",
        ])
        .output()?;
    assert!(
        success.status.success(),
        "self-check should succeed when no sensitive terms are found"
    );
    Ok(())
}
