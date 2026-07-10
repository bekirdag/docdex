mod common;

use common::{pick_free_port, wait_for_health, TestServerHarness};
use reqwest::blocking::Client;
use serde_json::{json, Value};
use std::error::Error;
use std::fs;
use std::path::Path;
use std::time::Duration;
use tempfile::TempDir;

fn write_repo(repo_root: &Path) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(repo_root.join(".git"))?;
    fs::write(repo_root.join("README.md"), "# Repo\n")?;
    Ok(())
}

fn write_config(home_dir: &Path, global_state_dir: &Path) -> Result<(), Box<dyn Error>> {
    let config_dir = home_dir.join(".docdex");
    fs::create_dir_all(&config_dir)?;
    fs::write(
        config_dir.join("config.toml"),
        format!(
            "[core]\nglobal_state_dir = \"{}\"\n\n[memory]\nenabled = true\n\n[memory.conversations]\nenabled = true\nwakeup_include_recent_diary_episodes = true\n\n[memory.personal_preferences]\nenabled = true\ncontext_injection_enabled = true\n",
            common::toml_path(global_state_dir),
        ),
    )?;
    Ok(())
}

fn parse_tool_result(body: &Value) -> Result<Value, Box<dyn Error>> {
    let text = body
        .get("result")
        .and_then(|value| value.get("content"))
        .and_then(Value::as_array)
        .and_then(|value| value.first())
        .and_then(|value| value.get("text"))
        .and_then(Value::as_str)
        .ok_or("missing MCP tool response")?;
    Ok(serde_json::from_str(text)?)
}

#[test]
fn mcp_memory_layers_reports_agent_usage_map() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    let state_root = TempDir::new()?;
    let home_dir = TempDir::new()?;
    write_repo(repo.path())?;
    let global_state_dir = home_dir.path().join(".docdex").join("state");
    write_config(home_dir.path(), &global_state_dir)?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let mut server = TestServerHarness::spawn_with_env(
        state_root.path(),
        home_dir.path(),
        repo.path(),
        host,
        port,
        true,
        &[
            ("DOCDEX_ENABLE_MEMORY", "1"),
            ("DOCDEX_PERSONAL_PREFERENCES_ENABLED", "1"),
        ],
    )?;
    wait_for_health(host, port)?;

    let client = Client::builder().timeout(Duration::from_secs(5)).build()?;
    let response: Value = client
        .post(format!("http://{host}:{port}/v1/mcp"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "docdex_memory_layers",
                "arguments": {
                    "project_root": repo.path().display().to_string()
                }
            }
        }))
        .send()?
        .error_for_status()?
        .json()?;
    let value = parse_tool_result(&response)?;

    assert_eq!(
        value
            .get("scope")
            .and_then(|scope| scope.get("kind"))
            .and_then(Value::as_str),
        Some("repo")
    );
    let layers = value
        .get("layers")
        .and_then(Value::as_array)
        .ok_or("missing layers")?;
    assert!(layers.iter().any(|layer| {
        layer.get("id").and_then(Value::as_str) == Some("conversation_memory")
            && layer
                .get("agent_awareness")
                .and_then(|value| value.get("status"))
                .and_then(Value::as_str)
                == Some("strong")
    }));
    assert!(layers.iter().any(|layer| {
        layer.get("id").and_then(Value::as_str) == Some("repo_memory")
            && layer
                .get("manual_tools")
                .and_then(Value::as_array)
                .map(|tools| {
                    tools
                        .iter()
                        .any(|tool| tool.as_str() == Some("docdex_memory_recall"))
                })
                == Some(true)
    }));

    server.shutdown();
    Ok(())
}

#[test]
fn mcp_memory_route_returns_ranked_lane_guidance() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    let state_root = TempDir::new()?;
    let home_dir = TempDir::new()?;
    write_repo(repo.path())?;
    let global_state_dir = home_dir.path().join(".docdex").join("state");
    write_config(home_dir.path(), &global_state_dir)?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let mut server = TestServerHarness::spawn_with_env(
        state_root.path(),
        home_dir.path(),
        repo.path(),
        host,
        port,
        true,
        &[
            ("DOCDEX_ENABLE_MEMORY", "1"),
            ("DOCDEX_PERSONAL_PREFERENCES_ENABLED", "1"),
        ],
    )?;
    wait_for_health(host, port)?;

    let client = Client::builder().timeout(Duration::from_secs(5)).build()?;
    let response: Value = client
        .post(format!("http://{host}:{port}/v1/mcp"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "docdex_memory_route",
                "arguments": {
                    "project_root": repo.path().display().to_string(),
                    "query": "Store that we prefer date-fns and keep handoff notes for the renderer work.",
                    "intent": "write"
                }
            }
        }))
        .send()?
        .error_for_status()?
        .json()?;
    let value = parse_tool_result(&response)?;

    assert_eq!(value.get("intent").and_then(Value::as_str), Some("write"));
    let core = value
        .get("core_memory")
        .and_then(Value::as_array)
        .ok_or("missing core memory")?;
    assert!(core
        .iter()
        .any(|item| { item.get("layer_id").and_then(Value::as_str) == Some("profile_memory") }));
    let retrievable = value
        .get("retrievable_memory")
        .and_then(Value::as_array)
        .ok_or("missing retrievable memory")?;
    assert!(retrievable
        .iter()
        .any(|item| { item.get("layer_id").and_then(Value::as_str) == Some("diary_memory") }));

    server.shutdown();
    Ok(())
}
