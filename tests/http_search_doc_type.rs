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
    let pdr_dir = repo_root.join("docs").join("pdr");
    let sds_dir = repo_root.join("docs").join("sds");
    let openapi_dir = repo_root.join("openapi");
    let src_dir = repo_root.join("src");
    std::fs::create_dir_all(&pdr_dir)?;
    std::fs::create_dir_all(&sds_dir)?;
    std::fs::create_dir_all(&openapi_dir)?;
    std::fs::create_dir_all(&src_dir)?;
    std::fs::write(pdr_dir.join("overview.md"), "PDR_TOKEN\n")?;
    std::fs::write(sds_dir.join("sds.md"), "SDS_TOKEN\n")?;
    std::fs::write(openapi_dir.join("spec.yaml"), "OPENAPI_TOKEN\n")?;
    std::fs::write(
        src_dir.join("main.rs"),
        "fn main() { let _ = \"CODE_TOKEN\"; }\n",
    )?;
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
            eprintln!("skipping doc_type test: TCP bind not permitted");
            None
        }
        Err(err) => panic!("bind ephemeral port: {err}"),
    }
}

fn wait_for_health(host: &str, port: u16) -> Result<(), Box<dyn Error>> {
    let client = Client::builder().timeout(Duration::from_secs(1)).build()?;
    let url = format!("http://{host}:{port}/healthz");
    let deadline = Instant::now() + Duration::from_secs(30);
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
    let lock_path = state_root.join("daemon.lock");
    Ok(Command::new(docdex_bin())
        .env("DOCDEX_WEB_ENABLED", "0")
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("DOCDEX_ENABLE_MCP", "0")
        .env("DOCDEX_STATE_DIR", state_root)
        .env("DOCDEX_DAEMON_LOCK_PATH", &lock_path)
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

fn fetch_doc_type(client: &Client, port: u16, query: &str) -> Result<String, Box<dyn Error>> {
    let url = format!("http://127.0.0.1:{port}/search?q={query}&limit=1");
    let resp = client.get(&url).send()?;
    if !resp.status().is_success() {
        return Err(format!("search failed with {}", resp.status()).into());
    }
    let payload: Value = resp.json()?;
    let hit = payload
        .get("hits")
        .and_then(|value| value.as_array())
        .and_then(|hits| hits.first())
        .ok_or("missing search hit")?;
    let doc_type = hit
        .get("doc_type")
        .and_then(|value| value.as_str())
        .ok_or("missing doc_type")?;
    Ok(doc_type.to_string())
}

#[test]
fn http_search_returns_doc_type() -> Result<(), Box<dyn Error>> {
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
    assert_eq!(fetch_doc_type(&client, port, "PDR_TOKEN")?, "pdr");
    assert_eq!(fetch_doc_type(&client, port, "SDS_TOKEN")?, "sds");
    assert_eq!(fetch_doc_type(&client, port, "OPENAPI_TOKEN")?, "openapi");
    assert_eq!(fetch_doc_type(&client, port, "CODE_TOKEN")?, "code");
    Ok(())
}
