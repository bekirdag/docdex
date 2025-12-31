use reqwest::blocking::Client;
use serde_json::{json, Value};
use std::error::Error;
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
            eprintln!("skipping AST query tests: TCP bind not permitted");
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
    Ok(Command::new(docdex_bin()).env("DOCDEX_ENABLE_MEMORY", "0")
        .env("DOCDEX_ENABLE_MCP", "0")
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

fn run_index(state_root: &Path, repo_root: &Path) -> Result<(), Box<dyn Error>> {
    let output = Command::new(docdex_bin()).env("DOCDEX_ENABLE_MEMORY", "0")
        .args([
            "index",
            "--repo",
            repo_root.to_string_lossy().as_ref(),
            "--state-dir",
            state_root.to_string_lossy().as_ref(),
            "--enable-symbol-extraction=true",
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

#[test]
fn ast_query_filters_name_and_path_prefix() -> Result<(), Box<dyn Error>> {
    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let repo = TempDir::new()?;
    let state_root = TempDir::new()?;
    let src_dir = repo.path().join("src");
    let other_dir = repo.path().join("other");
    std::fs::create_dir_all(&src_dir)?;
    std::fs::create_dir_all(&other_dir)?;
    std::fs::write(src_dir.join("lib.rs"), "fn greet() { println!(\"hi\"); }\n")?;
    std::fs::write(other_dir.join("lib.rs"), "fn greet() {}\n")?;

    run_index(state_root.path(), repo.path())?;

    let mut server = spawn_server(state_root.path(), repo.path(), "127.0.0.1", port)?;
    let result = (|| -> Result<(), Box<dyn Error>> {
        wait_for_health("127.0.0.1", port)?;
        let client = Client::builder().timeout(Duration::from_secs(2)).build()?;
        let url = format!("http://127.0.0.1:{port}/v1/ast/query");
        let body = json!({
            "kinds": ["function_item"],
            "name": "greet",
            "pathPrefix": "src",
            "mode": "any",
            "limit": 10,
            "sampleLimit": 3
        });
        let resp = client.post(&url).json(&body).send()?;
        if !resp.status().is_success() {
            return Err(format!("ast query failed: {}", resp.status()).into());
        }
        let payload: Value = resp.json()?;
        let matches = payload
            .get("matches")
            .and_then(|v| v.as_array())
            .ok_or("missing matches array")?;
        let files = matches
            .iter()
            .filter_map(|item| item.get("file").and_then(|v| v.as_str()))
            .collect::<Vec<_>>();
        if files != vec!["src/lib.rs"] {
            return Err(format!("expected only src/lib.rs, got {files:?}").into());
        }
        let sample_count = matches
            .get(0)
            .and_then(|item| item.get("samples"))
            .and_then(|v| v.as_array())
            .map(|v| v.len())
            .unwrap_or(0);
        if sample_count == 0 {
            return Err("expected at least one sample node".into());
        }
        Ok(())
    })();
    let _ = server.kill();
    let _ = server.wait();
    result
}
