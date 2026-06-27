mod common;

use common::{pick_free_port, write_basic_repo, TestServerHarness};
use reqwest::blocking::Client;
use serde_json::Value;
use std::error::Error;
use tempfile::TempDir;

#[test]
fn llm_diagnostics_endpoint_returns_payload() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    write_basic_repo(repo.path())?;
    let state_root = TempDir::new()?;
    let home_dir = TempDir::new()?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let base_url = format!("http://{host}:{port}");
    let mut server = TestServerHarness::spawn_basic(
        state_root.path(),
        home_dir.path(),
        repo.path(),
        host,
        port,
        false,
    )?;

    let client = Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()?;
    let payload = client
        .get(format!("{base_url}/v1/llm/diagnostics?refresh=false"))
        .send()?
        .text()?;
    let value: Value = serde_json::from_str(&payload)?;
    let diagnostics = value
        .get("diagnostics")
        .and_then(|value| value.as_object())
        .ok_or("diagnostics missing")?;

    assert!(diagnostics.get("services_detected").is_some());
    assert!(diagnostics.get("models_detected").is_some());
    assert!(diagnostics.get("agents_detected").is_some());
    assert!(diagnostics.get("defaults").is_some());
    assert!(diagnostics.get("status_messages").is_some());

    let payload = client
        .post(format!("{base_url}/v1/llm/diagnostics"))
        .json(&serde_json::json!({ "refresh": false }))
        .send()?
        .text()?;
    let value: Value = serde_json::from_str(&payload)?;
    assert!(value.get("diagnostics").is_some());

    server.shutdown();
    Ok(())
}
