mod common;

use common::{docdex_bin, pick_free_port, wait_for_health};
use docdexd::error::ERR_INVALID_ARGUMENT;
use reqwest::blocking::Client;
use serde_json::Value;
use std::error::Error;
use std::fs;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tempfile::TempDir;

fn write_repo(repo_root: &Path) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(repo_root.join("docs"))?;
    fs::write(repo_root.join("docs").join("guide.md"), "# Guide\n")?;
    Ok(())
}

fn write_config(home_dir: &Path, global_state_dir: &Path) -> Result<(), Box<dyn Error>> {
    let config_dir = home_dir.join(".docdex");
    fs::create_dir_all(&config_dir)?;
    let config_path = config_dir.join("config.toml");
    let payload = format!("[core]\nglobal_state_dir = \"{}\"\n", global_state_dir.display());
    fs::write(config_path, payload)?;
    Ok(())
}

struct ServerHarness {
    child: Child,
}

impl ServerHarness {
    fn spawn(
        state_root: &Path,
        home_dir: &Path,
        repo_root: &Path,
        host: &str,
        port: u16,
    ) -> Result<Self, Box<dyn Error>> {
        let repo_str = repo_root.to_string_lossy().to_string();
        let child = Command::new(docdex_bin())
            .env("DOCDEX_STATE_DIR", state_root)
            .env("DOCDEX_ENABLE_MCP", "0")
            .env("HOME", home_dir)
            .args([
                "serve",
                "--repo",
                repo_str.as_str(),
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
            .spawn()?;
        wait_for_health(host, port)?;
        Ok(Self { child })
    }

    fn shutdown(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
    }
}

#[test]
fn profile_add_validates_required_fields() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    write_repo(repo.path())?;

    let state_root = TempDir::new()?;
    let home_dir = TempDir::new()?;
    let global_state_dir = home_dir.path().join(".docdex").join("state");
    write_config(home_dir.path(), &global_state_dir)?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let mut server = ServerHarness::spawn(state_root.path(), home_dir.path(), repo.path(), host, port)?;

    let client = Client::builder().timeout(Duration::from_secs(3)).build()?;
    let url = format!("http://{host}:{port}/v1/profile/add");
    let resp = client
        .post(url)
        .json(&serde_json::json!({
            "agent_id": "",
            "category": "style",
            "content": ""
        }))
        .send()?;
    assert_eq!(resp.status().as_u16(), 400);
    let payload: Value = resp.json()?;
    let code = payload
        .get("error")
        .and_then(|v| v.get("code"))
        .and_then(|v| v.as_str());
    assert_eq!(code, Some(ERR_INVALID_ARGUMENT));

    server.shutdown();
    Ok(())
}

#[test]
fn profile_search_validates_query() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    write_repo(repo.path())?;

    let state_root = TempDir::new()?;
    let home_dir = TempDir::new()?;
    let global_state_dir = home_dir.path().join(".docdex").join("state");
    write_config(home_dir.path(), &global_state_dir)?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let mut server = ServerHarness::spawn(state_root.path(), home_dir.path(), repo.path(), host, port)?;

    let client = Client::builder().timeout(Duration::from_secs(3)).build()?;
    let url = format!("http://{host}:{port}/v1/profile/search");
    let resp = client
        .post(url)
        .json(&serde_json::json!({
            "agent_id": "agent",
            "query": ""
        }))
        .send()?;
    assert_eq!(resp.status().as_u16(), 400);
    let payload: Value = resp.json()?;
    let code = payload
        .get("error")
        .and_then(|v| v.get("code"))
        .and_then(|v| v.as_str());
    assert_eq!(code, Some(ERR_INVALID_ARGUMENT));

    server.shutdown();
    Ok(())
}
