mod common;

use common::{docdex_bin, pick_free_port, wait_for_health, MockOllama};
use reqwest::blocking::Client;
use serde_json::{json, Value};
use std::error::Error;
use std::fs;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tempfile::TempDir;

fn write_repo(repo_root: &Path) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(repo_root.join(".git"))?;
    fs::write(repo_root.join("README.md"), "# Repo\n")?;
    Ok(())
}

fn write_config(
    home_dir: &Path,
    global_state_dir: &Path,
    llm_base_url: &str,
) -> Result<(), Box<dyn Error>> {
    let config_dir = home_dir.join(".docdex");
    fs::create_dir_all(&config_dir)?;
    fs::write(
        config_dir.join("config.toml"),
        format!(
            "[core]\nglobal_state_dir = \"{}\"\n\n[llm]\nbase_url = \"{}\"\ndefault_model = \"fake-model\"\n\n[memory.profile]\nembedding_dim = 4\nembedding_model = \"fake-embed\"\n",
            common::toml_path(global_state_dir),
            llm_base_url
        ),
    )?;
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
        embedding_base_url: &str,
    ) -> Result<Self, Box<dyn Error>> {
        let repo_arg = repo_root.to_string_lossy().to_string();
        let child = Command::new(docdex_bin())
            .env("DOCDEX_WEB_ENABLED", "0")
            .env("DOCDEX_ENABLE_MEMORY", "1")
            .env("DOCDEX_ENABLE_MCP", "0")
            .env("DOCDEX_STATE_DIR", state_root)
            .env("HOME", home_dir)
            .args([
                "serve",
                "--repo",
                repo_arg.as_str(),
                "--host",
                host,
                "--port",
                &port.to_string(),
                "--log",
                "warn",
                "--secure-mode=false",
                "--embedding-base-url",
                embedding_base_url,
                "--embedding-model",
                "fake-embed",
                "--embedding-timeout-ms",
                "200",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        wait_for_health(host, port)?;
        Ok(Self { child })
    }

    fn shutdown(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn conversation_import_routes_durable_memories_into_repo_and_profile_http(
) -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    let state_root = TempDir::new()?;
    let home_dir = TempDir::new()?;
    let Some(mock) = MockOllama::spawn()? else {
        return Ok(());
    };
    write_repo(repo.path())?;
    let global_state_dir = home_dir.path().join(".docdex").join("state");
    write_config(home_dir.path(), &global_state_dir, &mock.base_url)?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let mut server = ServerHarness::spawn(
        state_root.path(),
        home_dir.path(),
        repo.path(),
        host,
        port,
        &mock.base_url,
    )?;

    let client = Client::builder().timeout(Duration::from_secs(5)).build()?;
    let import_url = format!("http://{host}:{port}/v1/conversations/import");
    let imported: Value = client
        .post(import_url)
        .json(&json!({
            "source": "manual",
            "agent_id": "codex",
            "transcript_text": "\
        developer: repo fact: The wake-up endpoint lives in src/api/v1/wakeup.rs\n\
        user: Use Zod for validation\n\
        user: Do not use Moment.js here\n\
        user: When a production fix is done, commit and deploy it"
        }))
        .send()?
        .json()?;
    let durable = imported
        .get("durable_memories")
        .and_then(|value| value.as_array())
        .ok_or("missing durable_memories")?;
    assert_eq!(durable.len(), 4);
    assert!(durable.iter().all(|item| {
        item.get("status")
            .and_then(|value| value.as_str())
            .map(|value| value == "stored")
            .unwrap_or(false)
    }));

    let profile_url = format!("http://{host}:{port}/v1/profile/list?agent_id=codex");
    let profile: Value = client.get(profile_url).send()?.json()?;
    let preferences = profile
        .get("preferences")
        .and_then(|value| value.as_array())
        .ok_or("missing preferences")?;
    assert!(preferences.iter().any(|item| {
        item.get("content")
            .and_then(|value| value.as_str())
            .map(|value| value.contains("Use Zod for validation"))
            .unwrap_or(false)
    }));
    assert!(preferences.iter().any(|item| {
        item.get("content")
            .and_then(|value| value.as_str())
            .map(|value| value.contains("Do not use Moment.js here"))
            .unwrap_or(false)
    }));

    let memory_url = format!("http://{host}:{port}/v1/memory/recall");
    let memory: Value = client
        .post(memory_url)
        .json(&json!({
            "query": "wake-up endpoint",
            "top_k": 5
        }))
        .send()?
        .json()?;
    let results = memory
        .get("results")
        .and_then(|value| value.as_array())
        .ok_or("missing memory results")?;
    assert!(!results.is_empty());
    assert!(results.iter().any(|item| {
        item.get("metadata")
            .and_then(|value| value.get("kind"))
            .and_then(|value| value.as_str())
            .map(|value| value == "conversation_durable_memory")
            .unwrap_or(false)
    }));

    server.shutdown();
    Ok(())
}
