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
    assert_cmd::cargo::cargo_bin!("docdexd").to_path_buf()
}

fn write_repo(repo_root: &Path) -> Result<(), Box<dyn Error>> {
    let docs_dir = repo_root.join("docs");
    fs::create_dir_all(&docs_dir)?;
    fs::write(docs_dir.join("readme.md"), "# Docs\n\nTesting.\n")?;
    Ok(())
}

fn write_config(home: &Path, enable_mcp: bool) -> Result<(), Box<dyn Error>> {
    let config_dir = home.join(".docdex");
    fs::create_dir_all(&config_dir)?;
    let payload = format!("[server]\nenable_mcp = {}\n", enable_mcp);
    fs::write(config_dir.join("config.toml"), payload)?;
    Ok(())
}

fn pick_free_port() -> Option<u16> {
    match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => Some(listener.local_addr().ok()?.port()),
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("skipping MCP autostart tests: TCP bind not permitted");
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

fn spawn_server(
    state_root: &Path,
    home_dir: &Path,
    repo_root: &Path,
    port: u16,
    missing_mcp_bin: &Path,
) -> Result<Child, Box<dyn Error>> {
    let repo_str = repo_root.to_string_lossy().to_string();
    Ok(Command::new(docdex_bin())
        .env("HOME", home_dir)
        .env("DOCDEX_STATE_DIR", state_root)
        .env("DOCDEX_MCP_SERVER_BIN", missing_mcp_bin)
        .env_remove("DOCDEX_ENABLE_MCP")
        .args([
            "serve",
            "--repo",
            repo_str.as_str(),
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

fn parse_single_error(stderr: &[u8]) -> Result<Value, Box<dyn Error>> {
    let raw = String::from_utf8_lossy(stderr);
    let trimmed = raw.trim();
    assert!(
        !trimmed.contains('\n'),
        "expected single-line JSON error payload, got:\n{trimmed}"
    );
    Ok(serde_json::from_str(trimmed)?)
}

#[test]
fn mcp_disabled_in_config_skips_missing_binary() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    write_repo(repo.path())?;
    let home = TempDir::new()?;
    let state_root = TempDir::new()?;
    write_config(home.path(), false)?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let missing_bin = home.path().join("missing-mcp-server");

    let mut child = spawn_server(
        state_root.path(),
        home.path(),
        repo.path(),
        port,
        &missing_bin,
    )?;
    wait_for_health("127.0.0.1", port)?;
    let _ = child.kill();
    let _ = child.wait();
    Ok(())
}

#[test]
fn mcp_cli_enable_requires_binary() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    write_repo(repo.path())?;
    let home = TempDir::new()?;
    let state_root = TempDir::new()?;
    write_config(home.path(), false)?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let missing_bin = home.path().join("missing-mcp-server");
    let repo_str = repo.path().to_string_lossy().to_string();
    let output = Command::new(docdex_bin())
        .env("HOME", home.path())
        .env("DOCDEX_STATE_DIR", state_root.path())
        .env("DOCDEX_MCP_SERVER_BIN", &missing_bin)
        .env_remove("DOCDEX_ENABLE_MCP")
        .args([
            "serve",
            "--repo",
            repo_str.as_str(),
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--log",
            "warn",
            "--secure-mode=false",
            "--enable-mcp",
        ])
        .output()?;
    assert!(
        !output.status.success(),
        "expected non-zero exit when MCP is enabled but binary is missing"
    );
    let payload = parse_single_error(&output.stderr)?;
    let code = payload
        .get("error")
        .and_then(|err| err.get("code"))
        .and_then(|code| code.as_str());
    assert_eq!(code, Some("startup_mcp_failed"));
    Ok(())
}
