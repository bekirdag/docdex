use reqwest::blocking::Client;
use serde_json::json;
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

fn run_docdex<I, S>(state_root: &Path, args: I) -> Result<Vec<u8>, Box<dyn Error>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let output = Command::new(docdex_bin())
        .env("DOCDEX_STATE_DIR", state_root)
        .env("DOCDEX_ENABLE_MCP", "0")
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
    Ok(output.stdout)
}

fn pick_free_port() -> Option<u16> {
    match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => Some(listener.local_addr().ok()?.port()),
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping initialize test: TCP bind not permitted in this environment");
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

fn write_repo(repo_root: &Path) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(repo_root.join(".git"))?;
    let docs_dir = repo_root.join("docs");
    fs::create_dir_all(&docs_dir)?;
    fs::write(docs_dir.join("readme.md"), "# Docdex\n\nHello\n")?;
    Ok(())
}

fn start_daemon(state_root: &Path, repo_root: &Path, port: u16) -> Result<Daemon, Box<dyn Error>> {
    let child = Command::new(docdex_bin())
        .env("DOCDEX_STATE_DIR", state_root)
        .env("DOCDEX_ENABLE_MCP", "0")
        .args([
            "serve",
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

fn file_uri(path: &Path) -> String {
    Url::from_directory_path(path)
        .expect("file uri")
        .to_string()
}

#[test]
fn initialize_returns_repo_id_and_status() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    write_repo(repo.path())?;
    let state_dir = TempDir::new()?;
    run_docdex(
        state_dir.path(),
        ["index", "--repo", repo.path().to_str().unwrap()],
    )?;

    let port = match pick_free_port() {
        Some(port) => port,
        None => return Ok(()),
    };
    let _daemon = start_daemon(state_dir.path(), repo.path(), port)?;
    wait_for_health(port)?;

    let client = Client::builder().timeout(Duration::from_secs(2)).build()?;
    let resp = client
        .post(format!("http://127.0.0.1:{port}/v1/initialize"))
        .json(&json!({ "rootUri": file_uri(repo.path()) }))
        .send()?;
    assert!(
        resp.status().is_success(),
        "initialize failed: {}",
        resp.status()
    );
    let payload: serde_json::Value = resp.json()?;
    let repo_id = payload
        .get("repo_id")
        .and_then(|v| v.as_str())
        .ok_or("missing repo_id")?;
    assert_eq!(repo_id.len(), 64);
    assert!(repo_id.chars().all(|c| c.is_ascii_hexdigit()));
    let status = payload.get("status").and_then(|v| v.as_str()).unwrap_or("");
    assert_eq!(status, "ready");

    Ok(())
}

#[test]
fn initialize_rejects_unknown_repo() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    write_repo(repo.path())?;
    let state_dir = TempDir::new()?;
    run_docdex(
        state_dir.path(),
        ["index", "--repo", repo.path().to_str().unwrap()],
    )?;

    let port = match pick_free_port() {
        Some(port) => port,
        None => return Ok(()),
    };
    let _daemon = start_daemon(state_dir.path(), repo.path(), port)?;
    wait_for_health(port)?;

    let other = TempDir::new()?;
    write_repo(other.path())?;

    let client = Client::builder().timeout(Duration::from_secs(2)).build()?;
    let resp = client
        .post(format!("http://127.0.0.1:{port}/v1/initialize"))
        .json(&json!({ "rootUri": file_uri(other.path()) }))
        .send()?;
    assert_eq!(resp.status(), reqwest::StatusCode::NOT_FOUND);
    let payload: serde_json::Value = resp.json()?;
    let code = payload
        .get("error")
        .and_then(|e| e.get("code"))
        .and_then(|c| c.as_str())
        .unwrap_or("");
    assert_eq!(code, "unknown_repo");
    Ok(())
}
