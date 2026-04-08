mod common;

use common::{docdex_bin, pick_free_port, wait_for_health};
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

fn write_config(home_dir: &Path, global_state_dir: &Path) -> Result<(), Box<dyn Error>> {
    let config_dir = home_dir.join(".docdex");
    fs::create_dir_all(&config_dir)?;
    fs::write(
        config_dir.join("config.toml"),
        format!(
            "[core]\nglobal_state_dir = \"{}\"\n\n[memory.conversations]\nauto_capture = true\n",
            common::toml_path(global_state_dir)
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
    ) -> Result<Self, Box<dyn Error>> {
        let repo_arg = repo_root.to_string_lossy().to_string();
        let child = Command::new(docdex_bin())
            .env("DOCDEX_WEB_ENABLED", "0")
            .env("DOCDEX_ENABLE_MEMORY", "0")
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
fn mcp_diary_and_hook_tools_work_over_http_transport() -> Result<(), Box<dyn Error>> {
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
    let mut server =
        ServerHarness::spawn(state_root.path(), home_dir.path(), repo.path(), host, port)?;

    let client = Client::builder().timeout(Duration::from_secs(5)).build()?;

    let write_payload = json!({
        "jsonrpc": "2.0",
        "id": 21,
        "method": "tools/call",
        "params": {
            "name": "docdex_diary_write",
            "arguments": {
                "agent_id": "codex",
                "content": "Store a periodic summary note.",
                "entry_type": "note"
            }
        }
    });
    let write_response: Value = client
        .post(format!("http://{host}:{port}/v1/mcp"))
        .json(&write_payload)
        .send()?
        .json()?;
    let write = parse_tool_result(&write_response)?;
    assert_eq!(
        write.get("entry_type").and_then(|value| value.as_str()),
        Some("note")
    );

    let read_payload = json!({
        "jsonrpc": "2.0",
        "id": 22,
        "method": "tools/call",
        "params": {
            "name": "docdex_diary_read",
            "arguments": {
                "agent_id": "codex",
                "limit": 10
            }
        }
    });
    let read_response: Value = client
        .post(format!("http://{host}:{port}/v1/mcp"))
        .json(&read_payload)
        .send()?
        .json()?;
    let read = parse_tool_result(&read_response)?;
    assert_eq!(read.get("total").and_then(|value| value.as_u64()), Some(1));

    let hook_payload = json!({
        "jsonrpc": "2.0",
        "id": 23,
        "method": "tools/call",
        "params": {
            "name": "docdex_conversation_hook",
            "arguments": {
                "action": "periodic_memory_save",
                "agent_id": "codex",
                "format": "plain_text",
                "transcript_text": "user: Keep the last checkpoint\nassistant: Next step: queue the save",
                "summary_text": "Periodic save checkpoint written.",
                "wait_for_processing": true
            }
        }
    });
    let hook_response: Value = client
        .post(format!("http://{host}:{port}/v1/mcp"))
        .json(&hook_payload)
        .send()?
        .json()?;
    let hook = parse_tool_result(&hook_response)?;
    assert_eq!(
        hook.get("status").and_then(|value| value.as_str()),
        Some("processed")
    );
    assert!(hook
        .get("session_id")
        .and_then(|value| value.as_str())
        .is_some());
    assert!(hook
        .get("diary_entry")
        .and_then(|value| value.get("entry_id"))
        .and_then(|value| value.as_str())
        .is_some());

    server.shutdown();
    Ok(())
}
