mod common;

use common::{docdex_bin, pick_free_port, wait_for_health};
use reqwest::blocking::Client;
use serde_json::Value;
use std::error::Error;
use std::fs;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use tempfile::TempDir;

fn write_repo(repo_root: &Path) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(repo_root)?;
    fs::write(repo_root.join("README.md"), "# Repo\n")?;
    Ok(())
}

struct ServerHarness {
    child: Child,
}

impl ServerHarness {
    fn spawn(
        state_root: &Path,
        repo_root: &Path,
        host: &str,
        port: u16,
    ) -> Result<Self, Box<dyn Error>> {
        let repo_str = repo_root.to_string_lossy().to_string();
        let lock_path = state_root.join("daemon.lock");
        let child = Command::new(docdex_bin())
            .env("DOCDEX_ENABLE_MEMORY", "0")
            .env("DOCDEX_WEB_ENABLED", "0")
            .env("DOCDEX_STATE_DIR", state_root)
            .env("DOCDEX_ENABLE_MCP", "0")
            .env(
                "DOCDEX_DAEMON_LOCK_PATH",
                lock_path.to_string_lossy().as_ref(),
            )
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
fn telemetry_delegation_endpoint_returns_payload() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    write_repo(repo.path())?;
    let state_root = TempDir::new()?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let base_url = format!("http://{host}:{port}");
    let mut server = ServerHarness::spawn(state_root.path(), repo.path(), host, port)?;

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()?;
    let payload = client
        .get(format!("{base_url}/v1/telemetry/delegation"))
        .send()?
        .text()?;
    let value: Value = serde_json::from_str(&payload)?;

    assert!(value.get("generated_at_epoch_ms").is_some());
    assert!(value.get("delegate_requests_total").is_some());
    assert!(value.get("delegate_offloaded_total").is_some());
    assert!(value.get("delegate_token_savings_total").is_some());
    assert!(value.get("delegate_local_tokens_total").is_some());
    assert!(value.get("delegate_primary_tokens_total").is_some());
    assert!(value.get("delegate_tokens_total").is_some());
    assert!(value.get("delegate_local_cost_micros_total").is_some());
    assert!(value.get("delegate_primary_cost_micros_total").is_some());
    assert!(value.get("delegate_cost_savings_micros_total").is_some());
    assert!(value.get("pricing").is_some());

    server.shutdown();
    Ok(())
}
