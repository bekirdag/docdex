use reqwest::blocking::Client;
use serde_json::Value;
use std::error::Error;
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

fn write_repo(repo_root: &Path) -> Result<(), Box<dyn Error>> {
    let docs_dir = repo_root.join("docs");
    let mcoda_dir = repo_root.join(".mcoda");
    let node_dir = repo_root.join("node_modules").join("pkg");
    let build_dir = repo_root.join("build");
    std::fs::create_dir_all(&docs_dir)?;
    std::fs::create_dir_all(&mcoda_dir)?;
    std::fs::create_dir_all(&node_dir)?;
    std::fs::create_dir_all(&build_dir)?;

    std::fs::write(docs_dir.join("visible.md"), "VISIBLE_TOKEN\n")?;
    std::fs::write(mcoda_dir.join("notes.md"), "MCODA_TOKEN\n")?;
    std::fs::write(node_dir.join("readme.md"), "NODE_TOKEN\n")?;
    std::fs::write(build_dir.join("output.md"), "BUILD_TOKEN\n")?;
    Ok(())
}

fn run_index(state_root: &Path, repo_root: &Path) -> Result<(), Box<dyn Error>> {
    let output = Command::new(docdex_bin())
        .env("DOCDEX_WEB_ENABLED", "0")
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .args([
            "index",
            "--repo",
            repo_root.to_string_lossy().as_ref(),
            "--state-dir",
            state_root.to_string_lossy().as_ref(),
        ])
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "docdexd index failed: {}\nstdout: {}\nstderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
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
            eprintln!("skipping ignore-pattern test: TCP bind not permitted");
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

fn spawn_server(state_root: &Path, repo_root: &Path, port: u16) -> Result<Child, Box<dyn Error>> {
    let repo_arg = repo_root.to_string_lossy().to_string();
    Ok(Command::new(docdex_bin())
        .env("DOCDEX_WEB_ENABLED", "0")
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("DOCDEX_ENABLE_MCP", "0")
        .env("DOCDEX_STATE_DIR", state_root)
        .args([
            "serve",
            "--repo",
            repo_arg.as_str(),
            "--host",
            "127.0.0.1",
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

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn search_hits(client: &Client, port: u16, query: &str) -> Result<usize, Box<dyn Error>> {
    let url = format!("http://127.0.0.1:{port}/search?q={query}&limit=5");
    let resp = client.get(&url).send()?;
    if !resp.status().is_success() {
        return Err(format!("search failed with {}", resp.status()).into());
    }
    let payload: Value = resp.json()?;
    let hits = payload
        .get("hits")
        .and_then(|value| value.as_array())
        .ok_or("missing hits")?;
    Ok(hits.len())
}

#[test]
fn http_search_ignores_default_patterns() -> Result<(), Box<dyn Error>> {
    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let repo = TempDir::new()?;
    let state_root = TempDir::new()?;
    write_repo(repo.path())?;
    run_index(state_root.path(), repo.path())?;

    let child = spawn_server(state_root.path(), repo.path(), port)?;
    let _guard = ChildGuard(child);
    wait_for_health("127.0.0.1", port)?;

    let client = Client::builder().timeout(Duration::from_secs(2)).build()?;
    assert!(search_hits(&client, port, "VISIBLE_TOKEN")? > 0);
    assert_eq!(search_hits(&client, port, "MCODA_TOKEN")?, 0);
    assert_eq!(search_hits(&client, port, "NODE_TOKEN")?, 0);
    assert_eq!(search_hits(&client, port, "BUILD_TOKEN")?, 0);
    Ok(())
}
