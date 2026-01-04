use reqwest::blocking::Client;
use serde_json::Value;
use std::error::Error;
use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

fn docdex_bin() -> PathBuf {
    std::env::set_var("DOCDEX_CLI_LOCAL", "1");
    std::env::set_var("DOCDEX_WEB_ENABLED", "0");
    assert_cmd::cargo::cargo_bin!("docdexd").to_path_buf()
}

struct Daemon {
    child: Child,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
    }
}

fn run_docdex<I, S>(state_root: &Path, args: I) -> Result<std::process::Output, Box<dyn Error>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    Ok(Command::new(docdex_bin())
        .env("DOCDEX_WEB_ENABLED", "0")
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env_remove("DOCDEX_ENABLE_SYMBOL_EXTRACTION")
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("DOCDEX_STATE_DIR", state_root)
        .args(args)
        .output()?)
}

fn run_docdex_ok<I, S>(state_root: &Path, args: I) -> Result<Vec<u8>, Box<dyn Error>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let output = run_docdex(state_root, args)?;
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

fn write_fixture_repo(repo_root: &Path) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(repo_root.join(".git"))?;
    let docs_dir = repo_root.join("docs");
    fs::create_dir_all(&docs_dir)?;
    fs::write(
        docs_dir.join("overview.md"),
        r#"# Overview

This repository contains INTERACTIVE_NEEDLE used for contract tests.
"#,
    )?;
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
            eprintln!("skipping HTTP contract tests: TCP bind not permitted in this environment");
            None
        }
        Err(err) => panic!("bind ephemeral port: {err}"),
    }
}

fn wait_for_health(port: u16) -> Result<(), Box<dyn Error>> {
    let client = Client::builder().timeout(Duration::from_secs(1)).build()?;
    let url = format!("http://127.0.0.1:{port}/healthz");
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        match client.get(&url).send() {
            Ok(resp) if resp.status().is_success() => return Ok(()),
            _ => thread::sleep(Duration::from_millis(200)),
        }
    }
    Err("docdexd healthz endpoint did not respond in time".into())
}

fn repo_id_from_payload(payload: &Value) -> Result<&str, Box<dyn Error>> {
    if let Some(repo_id) = payload.get("repo_id").and_then(|v| v.as_str()) {
        return Ok(repo_id);
    }
    let meta = payload
        .get("meta")
        .and_then(|v| v.as_object())
        .ok_or("payload missing repo_id and meta is missing/not an object")?;
    let repo_id = meta
        .get("repo_id")
        .and_then(|v| v.as_str())
        .ok_or("payload missing repo_id and meta.repo_id is missing/not a string")?;
    Ok(repo_id)
}

fn assert_sha256_hex(value: &str, context: &str) {
    assert_eq!(value.len(), 64, "{context} should be a sha256 hex string");
    assert!(
        value.chars().all(|c| c.is_ascii_hexdigit()),
        "{context} should be hex"
    );
}

#[test]
fn repo_inspect_fingerprint_is_stable_for_canonical_path() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let repo_str = repo.path().to_string_lossy().to_string();
    let state_root = TempDir::new()?;

    let first = run_docdex_ok(
        state_root.path(),
        ["repo", "inspect", "--repo", repo_str.as_str()],
    )?;
    let second = run_docdex_ok(
        state_root.path(),
        ["repo", "inspect", "--repo", repo_str.as_str()],
    )?;

    let v1: Value = serde_json::from_slice(&first)?;
    let v2: Value = serde_json::from_slice(&second)?;

    let fp1 = v1
        .get("computedFingerprint")
        .or_else(|| v1.get("fingerprint_sha256"))
        .or_else(|| v1.get("fingerprint"))
        .and_then(|v| v.as_str())
        .ok_or("repo inspect payload missing fingerprint")?;
    let fp2 = v2
        .get("computedFingerprint")
        .or_else(|| v2.get("fingerprint_sha256"))
        .or_else(|| v2.get("fingerprint"))
        .and_then(|v| v.as_str())
        .ok_or("repo inspect payload missing fingerprint (second run)")?;

    assert_sha256_hex(fp1, "repo inspect fingerprint");
    assert_eq!(fp1, fp2, "fingerprint should be stable across runs");
    Ok(())
}

#[test]
fn cli_query_includes_repo_id_in_meta() -> Result<(), Box<dyn Error>> {
    let repo = setup_repo()?;
    let repo_str = repo.path().to_string_lossy().to_string();
    let state_root = TempDir::new()?;

    run_docdex_ok(state_root.path(), ["index", "--repo", repo_str.as_str()])?;
    let stdout = run_docdex_ok(
        state_root.path(),
        [
            "query",
            "--repo",
            repo_str.as_str(),
            "--query",
            "INTERACTIVE_NEEDLE",
            "--limit",
            "2",
        ],
    )?;

    let payload: Value = serde_json::from_slice(&stdout)?;
    let repo_id = repo_id_from_payload(&payload)?;
    assert_sha256_hex(repo_id, "CLI query repo_id");

    Ok(())
}

#[test]
fn http_search_includes_repo_id_and_is_reasonably_fast() -> Result<(), Box<dyn Error>> {
    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let repo = setup_repo()?;
    let repo_str = repo.path().to_string_lossy().to_string();
    let state_root = TempDir::new()?;

    run_docdex_ok(state_root.path(), ["index", "--repo", repo_str.as_str()])?;

    let port_str = port.to_string();
    let mut cmd = Command::new(docdex_bin());
    cmd.env("DOCDEX_WEB_ENABLED", "0");
    cmd.env("DOCDEX_ENABLE_MEMORY", "0");
    cmd.env("DOCDEX_ENABLE_MCP", "0");
    cmd.env("DOCDEX_STATE_DIR", state_root.path());
    cmd.args([
        "serve",
        "--repo",
        repo_str.as_str(),
        "--host",
        "127.0.0.1",
        "--port",
        port_str.as_str(),
        "--log",
        "warn",
        "--secure-mode=false",
    ]);
    let child = cmd.stdout(Stdio::null()).stderr(Stdio::null()).spawn()?;
    let _daemon = Daemon { child };

    wait_for_health(port)?;

    let client = Client::builder().timeout(Duration::from_secs(2)).build()?;
    let url = format!("http://127.0.0.1:{port}/search?q=INTERACTIVE_NEEDLE&limit=2&snippets=false");

    let warm = client.get(&url).send()?;
    assert!(
        warm.status().is_success(),
        "HTTP /search warmup returned {}",
        warm.status()
    );

    let start = Instant::now();
    let resp = client.get(&url).send()?;
    let elapsed = start.elapsed();
    assert!(
        resp.status().is_success(),
        "HTTP /search returned {}",
        resp.status()
    );
    let payload: Value = resp.json()?;

    let hits = payload
        .get("hits")
        .and_then(|v| v.as_array())
        .ok_or("HTTP /search payload missing hits array")?;
    assert!(
        !hits.is_empty(),
        "expected at least one hit from HTTP /search"
    );

    let repo_id = repo_id_from_payload(&payload)?;
    assert_sha256_hex(repo_id, "HTTP /search repo_id");

    let max = if cfg!(debug_assertions) {
        Duration::from_secs(2)
    } else {
        Duration::from_millis(750)
    };
    assert!(
        elapsed <= max,
        "HTTP /search latency regression: {:?} > {:?}",
        elapsed,
        max
    );

    Ok(())
}
