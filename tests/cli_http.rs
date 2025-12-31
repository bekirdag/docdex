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
    assert_cmd::cargo::cargo_bin!("docdexd").to_path_buf()
}

fn pick_free_port() -> Option<u16> {
    match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => Some(listener.local_addr().ok()?.port()),
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping cli http tests: TCP bind not permitted");
            None
        }
        Err(err) => panic!("bind ephemeral port: {err}"),
    }
}

fn spawn_server(
    state_root: &Path,
    repo_root: &Path,
    host: &str,
    port: u16,
) -> Result<Child, Box<dyn Error>> {
    let repo_str = repo_root.to_string_lossy().to_string();
    let state_root_str = state_root.to_string_lossy().to_string();
    Ok(Command::new(docdex_bin())
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("DOCDEX_ENABLE_MCP", "0")
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .args([
            "serve",
            "--repo",
            repo_str.as_str(),
            "--state-dir",
            state_root_str.as_str(),
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
        .spawn()?)
}

fn wait_for_health(host: &str, port: u16) -> Result<(), Box<dyn Error>> {
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(1))
        .build()?;
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
    fs::create_dir_all(repo_root)?;
    fs::write(repo_root.join("doc.md"), "# Fixture\n\nHTTP_SEARCH_TOKEN\n")?;
    Ok(())
}

fn resolve_index_dir(state_root: &Path, repo_root: &Path) -> Result<PathBuf, Box<dyn Error>> {
    let output = Command::new(docdex_bin())
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("DOCDEX_STATE_DIR", state_root)
        .args([
            "repo",
            "inspect",
            "--repo",
            repo_root.to_string_lossy().as_ref(),
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
    let payload: Value = serde_json::from_slice(&output.stdout)?;
    let resolved = payload
        .get("resolvedIndexStateDir")
        .and_then(|value| value.as_str())
        .ok_or("missing resolvedIndexStateDir")?;
    Ok(PathBuf::from(resolved))
}

#[test]
fn cli_index_and_query_use_http() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    write_repo(repo.path())?;
    let state_root = TempDir::new()?;
    let local_state = TempDir::new()?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let mut server = spawn_server(state_root.path(), repo.path(), host, port)?;
    wait_for_health(host, port)?;

    let base_url = format!("http://{host}:{port}");

    let index_out = Command::new(docdex_bin())
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("DOCDEX_HTTP_BASE_URL", &base_url)
        .env("DOCDEX_CLI_LOCAL", "0")
        .env("DOCDEX_STATE_DIR", local_state.path())
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .args(["index", "--repo", repo.path().to_string_lossy().as_ref()])
        .output()?;
    assert!(
        index_out.status.success(),
        "docdexd index failed: {}",
        String::from_utf8_lossy(&index_out.stderr)
    );

    let resolved_index = resolve_index_dir(state_root.path(), repo.path())?;
    assert!(
        resolved_index.join("meta.json").exists(),
        "expected server index metadata after HTTP index"
    );

    let query_out = Command::new(docdex_bin())
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("DOCDEX_HTTP_BASE_URL", &base_url)
        .env("DOCDEX_CLI_LOCAL", "0")
        .env("DOCDEX_STATE_DIR", local_state.path())
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .args([
            "query",
            "--repo",
            repo.path().to_string_lossy().as_ref(),
            "--query",
            "HTTP_SEARCH_TOKEN",
            "--limit",
            "1",
        ])
        .output()?;
    assert!(
        query_out.status.success(),
        "docdexd query failed: {}",
        String::from_utf8_lossy(&query_out.stderr)
    );
    let payload: Value = serde_json::from_slice(&query_out.stdout)?;
    let hits = payload
        .get("hits")
        .and_then(|v| v.as_array())
        .map(|v| v.as_slice())
        .unwrap_or(&[]);
    assert!(!hits.is_empty(), "expected query hits via HTTP");

    server.kill().ok();
    server.wait().ok();
    Ok(())
}

#[test]
fn cli_query_errors_when_http_unavailable() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    write_repo(repo.path())?;
    let local_state = TempDir::new()?;
    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let base_url = format!("http://127.0.0.1:{port}");

    let query_out = Command::new(docdex_bin())
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("DOCDEX_HTTP_BASE_URL", &base_url)
        .env("DOCDEX_CLI_LOCAL", "0")
        .env("DOCDEX_STATE_DIR", local_state.path())
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .args([
            "query",
            "--repo",
            repo.path().to_string_lossy().as_ref(),
            "--query",
            "HTTP_SEARCH_TOKEN",
            "--limit",
            "1",
        ])
        .output()?;
    assert!(
        !query_out.status.success(),
        "expected CLI query to fail without daemon"
    );
    let stderr = String::from_utf8_lossy(&query_out.stderr);
    assert!(
        stderr.contains("docdexd search failed"),
        "expected HTTP failure message, got: {stderr}"
    );
    Ok(())
}
