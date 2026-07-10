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
use url::Url;

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

fn run_docdex_ok<I, S>(state_root: &Path, args: I) -> Result<(), Box<dyn Error>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let output = Command::new(docdex_bin())
        .env("DOCDEX_WEB_ENABLED", "0")
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("DOCDEX_STATE_DIR", state_root)
        .env("DOCDEX_ENABLE_MCP", "0")
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("DOCDEX_CLI_LOCAL", "1")
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
    Ok(())
}

fn pick_free_port() -> Option<u16> {
    match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => Some(listener.local_addr().ok()?.port()),
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping multi-repo test: TCP bind not permitted in this environment");
            None
        }
        Err(err) => panic!("bind ephemeral port: {err}"),
    }
}

fn wait_for_health(port: u16) -> Result<(), Box<dyn Error>> {
    let client = Client::builder().timeout(Duration::from_secs(1)).build()?;
    let url = format!("http://127.0.0.1:{port}/healthz");
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        match client.get(&url).send() {
            Ok(resp) if resp.status().is_success() => return Ok(()),
            _ => thread::sleep(Duration::from_millis(200)),
        }
    }
    Err("docdexd healthz endpoint did not respond in time".into())
}

fn write_repo(repo_root: &Path, marker: &str) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(repo_root.join(".git"))?;
    let docs_dir = repo_root.join("docs");
    fs::create_dir_all(&docs_dir)?;
    fs::write(docs_dir.join("readme.md"), format!("# Repo\n\n{marker}\n"))?;
    Ok(())
}

fn file_uri(path: &Path) -> String {
    Url::from_directory_path(path)
        .expect("file uri")
        .to_string()
}

fn start_daemon(
    state_root: &Path,
    repo_root: &Path,
    port: u16,
    lock_path: &Path,
) -> Result<Daemon, Box<dyn Error>> {
    let child = Command::new(docdex_bin())
        .env("DOCDEX_WEB_ENABLED", "0")
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("DOCDEX_STATE_DIR", state_root)
        .env("DOCDEX_ENABLE_MCP", "0")
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("DOCDEX_DAEMON_LOCK_PATH", lock_path)
        .args([
            "daemon",
            "--repo",
            repo_root.to_str().unwrap(),
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--log",
            "warn",
            "--secure-mode=false",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    Ok(Daemon { child })
}

#[test]
fn daemon_routes_requests_by_repo_id() -> Result<(), Box<dyn Error>> {
    let repo_one = TempDir::new()?;
    let repo_two = TempDir::new()?;
    write_repo(repo_one.path(), "alpha")?;
    write_repo(repo_two.path(), "bravo")?;

    let state_dir = TempDir::new()?;
    run_docdex_ok(
        state_dir.path(),
        ["index", "--repo", repo_one.path().to_str().unwrap()],
    )?;
    run_docdex_ok(
        state_dir.path(),
        ["index", "--repo", repo_two.path().to_str().unwrap()],
    )?;

    let port = match pick_free_port() {
        Some(port) => port,
        None => return Ok(()),
    };
    let lock_path = state_dir.path().join("daemon.lock");
    let _daemon = start_daemon(state_dir.path(), repo_one.path(), port, &lock_path)?;
    wait_for_health(port)?;

    let client = Client::builder().timeout(Duration::from_secs(2)).build()?;
    let init_resp = client
        .post(format!("http://127.0.0.1:{port}/v1/initialize"))
        .json(&serde_json::json!({ "rootUri": file_uri(repo_two.path()) }))
        .send()?;
    assert!(init_resp.status().is_success());
    let init_payload: Value = init_resp.json()?;
    let repo_two_id = init_payload
        .get("repo_id")
        .and_then(|value| value.as_str())
        .ok_or("missing repo_id")?;

    let init_resp = client
        .post(format!("http://127.0.0.1:{port}/v1/initialize"))
        .json(&serde_json::json!({ "rootUri": file_uri(repo_one.path()) }))
        .send()?;
    assert!(init_resp.status().is_success());
    let init_payload: Value = init_resp.json()?;
    let repo_one_id = init_payload
        .get("repo_id")
        .and_then(|value| value.as_str())
        .ok_or("missing repo_id")?;

    let search_resp = client
        .get(format!("http://127.0.0.1:{port}/search"))
        .query(&[("q", "bravo")])
        .header("x-docdex-repo-id", repo_two_id)
        .send()?;
    if !search_resp.status().is_success() {
        let status = search_resp.status();
        let body = search_resp.text().unwrap_or_default();
        return Err(format!("search failed: {status} {body}").into());
    }
    let payload: Value = search_resp.json()?;
    let hits = payload
        .get("hits")
        .and_then(|value| value.as_array())
        .ok_or("missing hits")?;
    assert!(!hits.is_empty(), "expected hits for repo two");

    let search_default = client
        .get(format!("http://127.0.0.1:{port}/search"))
        .query(&[("q", "alpha")])
        .header("x-docdex-repo-id", repo_one_id)
        .send()?;
    if !search_default.status().is_success() {
        let status = search_default.status();
        let body = search_default.text().unwrap_or_default();
        return Err(format!("default search failed: {status} {body}").into());
    }
    let payload: Value = search_default.json()?;
    let hits = payload
        .get("hits")
        .and_then(|value| value.as_array())
        .ok_or("missing hits")?;
    assert!(!hits.is_empty(), "expected hits for default repo");

    let missing_repo = client
        .get(format!("http://127.0.0.1:{port}/search"))
        .query(&[("q", "alpha")])
        .send()?;
    assert_eq!(missing_repo.status(), reqwest::StatusCode::BAD_REQUEST);
    let missing_payload: Value = missing_repo.json()?;
    let error = missing_payload
        .get("error")
        .and_then(|value| value.as_object())
        .ok_or("missing error payload")?;
    assert_eq!(
        error.get("code").and_then(|value| value.as_str()),
        Some("missing_repo")
    );
    assert!(error.get("details").is_some(), "expected error details");

    Ok(())
}
