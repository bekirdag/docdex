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
            "[core]\nglobal_state_dir = \"{}\"\n",
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
fn conversation_list_read_delete_http_contracts() -> Result<(), Box<dyn Error>> {
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
    let import_url = format!("http://{host}:{port}/v1/conversations/import");
    let first_import: Value = client
        .post(&import_url)
        .json(&json!({
            "source": "manual",
            "title": "Wake-up rollout",
            "agent_id": "codex",
            "started_at_ms": 10,
            "ended_at_ms": 20,
            "messages": [
                {
                    "role": "user",
                    "content": "Add session inspection endpoints.",
                    "created_at_ms": 10
                },
                {
                    "role": "assistant",
                    "content": "Next step: list, read, and delete handlers.",
                    "created_at_ms": 20
                }
            ]
        }))
        .send()?
        .json()?;
    let first_session_id = first_import
        .get("session_id")
        .and_then(|value| value.as_str())
        .ok_or("missing first session id")?
        .to_string();

    let second_import: Value = client
        .post(&import_url)
        .json(&json!({
            "source": "manual",
            "source_session_id": "session-2",
            "title": "Follow-up",
            "agent_id": "reviewer",
            "started_at_ms": 30,
            "ended_at_ms": 40,
            "messages": [
                {
                    "role": "user",
                    "content": "Review the new handlers.",
                    "created_at_ms": 30
                },
                {
                    "role": "assistant",
                    "content": "Looks good.",
                    "created_at_ms": 40
                }
            ]
        }))
        .send()?
        .json()?;
    let second_session_id = second_import
        .get("session_id")
        .and_then(|value| value.as_str())
        .ok_or("missing second session id")?
        .to_string();

    let list_url = format!("http://{host}:{port}/v1/conversations?limit=10");
    let list: Value = client.get(&list_url).send()?.json()?;
    assert_eq!(list.get("total").and_then(|value| value.as_u64()), Some(2));
    let sessions = list
        .get("sessions")
        .and_then(|value| value.as_array())
        .ok_or("missing sessions array")?;
    assert_eq!(sessions.len(), 2);
    assert_eq!(
        sessions[0]
            .get("session_id")
            .and_then(|value| value.as_str()),
        Some(second_session_id.as_str())
    );

    let filtered: Value = client
        .get(format!(
            "http://{host}:{port}/v1/conversations?agent_id=codex&limit=10"
        ))
        .send()?
        .json()?;
    assert_eq!(
        filtered.get("total").and_then(|value| value.as_u64()),
        Some(1)
    );
    assert_eq!(
        filtered
            .get("sessions")
            .and_then(|value| value.as_array())
            .and_then(|value| value.first())
            .and_then(|value| value.get("session_id"))
            .and_then(|value| value.as_str()),
        Some(first_session_id.as_str())
    );

    let read_response = client
        .get(format!(
            "http://{host}:{port}/v1/conversations/{}",
            first_session_id
        ))
        .send()?;
    assert!(read_response.status().is_success());
    let read: Value = read_response.json()?;
    assert_eq!(
        read.get("session")
            .and_then(|value| value.get("message_count"))
            .and_then(|value| value.as_u64()),
        Some(2)
    );
    assert_eq!(
        read.get("session")
            .and_then(|value| value.get("messages"))
            .and_then(|value| value.as_array())
            .map(|value| value.len()),
        Some(2)
    );

    let delete_response = client
        .delete(format!(
            "http://{host}:{port}/v1/conversations/{}",
            first_session_id
        ))
        .send()?;
    assert!(delete_response.status().is_success());
    let deleted: Value = delete_response.json()?;
    assert_eq!(
        deleted.get("deleted").and_then(|value| value.as_bool()),
        Some(true)
    );

    let missing = client
        .get(format!(
            "http://{host}:{port}/v1/conversations/{}",
            first_session_id
        ))
        .send()?;
    assert_eq!(missing.status(), reqwest::StatusCode::NOT_FOUND);
    let missing_body: Value = missing.json()?;
    assert_eq!(
        missing_body
            .get("error")
            .and_then(|value| value.get("code"))
            .and_then(|value| value.as_str()),
        Some("conversation_not_found")
    );

    let list_after_delete: Value = client
        .get(format!("http://{host}:{port}/v1/conversations?limit=10"))
        .send()?
        .json()?;
    assert_eq!(
        list_after_delete
            .get("total")
            .and_then(|value| value.as_u64()),
        Some(1)
    );
    assert_eq!(
        list_after_delete
            .get("sessions")
            .and_then(|value| value.as_array())
            .and_then(|value| value.first())
            .and_then(|value| value.get("session_id"))
            .and_then(|value| value.as_str()),
        Some(second_session_id.as_str())
    );

    server.shutdown();
    Ok(())
}
