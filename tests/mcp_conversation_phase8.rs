mod common;

use common::{docdex_bin, pick_free_port, wait_for_health};
use reqwest::blocking::Client;
use rusqlite::Connection;
use serde_json::{json, Value};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
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
            "[core]\nglobal_state_dir = \"{}\"\n\n[memory.conversations]\nauto_capture = true\narchive_raw_transcripts = false\nsource_denylist = [\"blocked-source\"]\nmanual_retention_days = 30\nauto_capture_retention_days = 30\ndiary_retention_days = 30\nhook_event_retention_days = 30\n",
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

fn find_conversation_db(root: &Path) -> Result<PathBuf, Box<dyn Error>> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            if path.file_name().and_then(|value| value.to_str()) == Some("conversation.db") {
                return Ok(path);
            }
        }
    }
    Err("conversation.db not found".into())
}

#[test]
fn mcp_conversation_phase8_supports_export_redact_prune_and_hook_policy(
) -> Result<(), Box<dyn Error>> {
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
    let import_response: Value = client
        .post(format!("http://{host}:{port}/v1/mcp"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "docdex_conversation_import",
                "arguments": {
                    "title": "mcp-phase8",
                    "agent_id": "codex",
                    "transcript_text": "user: Add export and redaction\nassistant: Next step: add prune"
                }
            }
        }))
        .send()?
        .json()?;
    let imported = parse_tool_result(&import_response)?;
    let session_id = imported
        .get("session_id")
        .and_then(|value| value.as_str())
        .ok_or("missing session_id")?
        .to_string();
    assert_eq!(
        imported
            .get("raw_messages_stored")
            .and_then(|value| value.as_bool()),
        Some(false)
    );

    let export_response: Value = client
        .post(format!("http://{host}:{port}/v1/mcp"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "docdex_conversation_export",
                "arguments": { "session_id": session_id }
            }
        }))
        .send()?
        .json()?;
    let export = parse_tool_result(&export_response)?;
    assert_eq!(
        export
            .get("export")
            .and_then(|value| value.get("session"))
            .and_then(|value| value.get("message_count"))
            .and_then(|value| value.as_u64()),
        Some(2)
    );

    let redact_response: Value = client
        .post(format!("http://{host}:{port}/v1/mcp"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "docdex_conversation_redact",
                "arguments": { "session_id": session_id }
            }
        }))
        .send()?
        .json()?;
    let redacted = parse_tool_result(&redact_response)?;
    assert_eq!(
        redacted
            .get("result")
            .and_then(|value| value.get("redacted"))
            .and_then(|value| value.as_bool()),
        Some(true)
    );

    let blocked_hook: Value = client
        .post(format!("http://{host}:{port}/v1/mcp"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "docdex_conversation_hook",
                "arguments": {
                    "action": "session_close_summarization",
                    "source": "blocked-source",
                    "transcript_text": "user: hi",
                    "wait_for_processing": true
                }
            }
        }))
        .send()?
        .json()?;
    assert!(
        blocked_hook
            .get("error")
            .and_then(|value| value.get("data"))
            .and_then(|value| value.get("code"))
            .and_then(|value| value.as_str())
            == Some("invalid_argument")
    );

    let db_path = find_conversation_db(state_root.path())?;
    let conn = Connection::open(db_path)?;
    conn.execute(
        "UPDATE conversation_sessions SET imported_at_ms = 1 WHERE id = ?1",
        rusqlite::params![session_id],
    )?;

    let prune_response: Value = client
        .post(format!("http://{host}:{port}/v1/mcp"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "docdex_conversation_prune",
                "arguments": {
                    "apply": true,
                    "manual_retention_days": 1
                }
            }
        }))
        .send()?
        .json()?;
    let pruned = parse_tool_result(&prune_response)?;
    assert_eq!(
        pruned
            .get("result")
            .and_then(|value| value.get("deleted_manual_sessions"))
            .and_then(|value| value.as_u64()),
        Some(1)
    );

    server.shutdown();
    Ok(())
}
