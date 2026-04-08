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
            .env("DOCDEX_ENABLE_MCP", "1")
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

fn parse_tool_result(body: &Value) -> Result<Value, Box<dyn Error>> {
    let text = body
        .get("result")
        .and_then(|value| value.get("content"))
        .and_then(|value| value.as_array())
        .and_then(|value| value.first())
        .and_then(|value| value.get("text"))
        .and_then(|value| value.as_str())
        .ok_or("missing MCP tool response")?;
    Ok(serde_json::from_str(text)?)
}

#[test]
fn mcp_conversation_import_routes_durable_memories_into_repo_and_profile(
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
    let import_response: Value = client
        .post(format!("http://{host}:{port}/v1/mcp"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "docdex_conversation_import",
                "arguments": {
                    "agent_id": "codex",
                    "transcript_text": "\
        developer: repo fact: The wake-up endpoint lives in src/api/v1/wakeup.rs\n\
        user: Use Zod for validation\n\
        user: When a production fix is done, commit and deploy it"
                }
            }
        }))
        .send()?
        .json()?;
    let imported = parse_tool_result(&import_response)?;
    let durable = imported
        .get("durable_memories")
        .and_then(|value| value.as_array())
        .ok_or("missing durable_memories")?;
    assert_eq!(durable.len(), 3);

    let memory_response: Value = client
        .post(format!("http://{host}:{port}/v1/mcp"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "docdex_memory_recall",
                "arguments": {
                    "query": "wake-up endpoint",
                    "top_k": 5
                }
            }
        }))
        .send()?
        .json()?;
    let memory = parse_tool_result(&memory_response)?;
    assert!(memory
        .get("results")
        .and_then(|value| value.as_array())
        .map(|items| !items.is_empty())
        .unwrap_or(false));

    let profile_response: Value = client
        .post(format!("http://{host}:{port}/v1/mcp"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "docdex_get_profile",
                "arguments": {
                    "agent_id": "codex"
                }
            }
        }))
        .send()?
        .json()?;
    let profile = parse_tool_result(&profile_response)?;
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

    server.shutdown();
    Ok(())
}
