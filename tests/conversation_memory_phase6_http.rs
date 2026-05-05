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
fn diary_write_and_read_http_contracts() -> Result<(), Box<dyn Error>> {
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
    let write_url = format!("http://{host}:{port}/v1/diary/write");
    let first: Value = client
        .post(&write_url)
        .json(&json!({
            "agent_id": "codex",
            "entry_type": "note",
            "content": "Remember to persist hook summaries.",
            "metadata": {"source":"test"}
        }))
        .send()?
        .json()?;
    assert_eq!(
        first.get("entry_type").and_then(|value| value.as_str()),
        Some("note")
    );

    let read_url = format!("http://{host}:{port}/v1/diary/read");
    let read: Value = client
        .get(&read_url)
        .query(&[("agent_id", "codex"), ("limit", "10")])
        .send()?
        .json()?;
    assert_eq!(read.get("total").and_then(|value| value.as_u64()), Some(1));
    assert!(read
        .get("entries")
        .and_then(|value| value.as_array())
        .and_then(|value| value.first())
        .and_then(|value| value.get("content"))
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .contains("hook summaries"));

    let entry_id = first
        .get("entry_id")
        .and_then(|value| value.as_str())
        .ok_or("missing diary entry id")?;
    let delete_url = format!("http://{host}:{port}/v1/diary/delete");
    let deleted: Value = client
        .post(&delete_url)
        .json(&json!({ "entry_id": entry_id }))
        .send()?
        .json()?;
    assert_eq!(
        deleted.get("entry_id").and_then(|value| value.as_str()),
        Some(entry_id)
    );
    assert_eq!(
        deleted.get("deleted").and_then(|value| value.as_bool()),
        Some(true)
    );
    let deleted_again: Value = client
        .post(&delete_url)
        .json(&json!({ "entry_id": entry_id }))
        .send()?
        .json()?;
    assert_eq!(
        deleted_again
            .get("deleted")
            .and_then(|value| value.as_bool()),
        Some(false)
    );

    server.shutdown();
    Ok(())
}

#[test]
fn conversation_hook_processes_import_and_diary_http_contracts() -> Result<(), Box<dyn Error>> {
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
    let hook_url = format!("http://{host}:{port}/v1/hooks/conversation");
    let hook: Value = client
        .post(&hook_url)
        .json(&json!({
            "action": "session_close_summarization",
            "agent_id": "codex",
            "format": "plain_text",
            "transcript_text": "user: Add a hook worker\nassistant: Next step: queue session close processing",
            "summary_text": "Closed the session after wiring the async hook path.",
            "wait_for_processing": true
        }))
        .send()?
        .json()?;
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

    let list: Value = client
        .get(format!("http://{host}:{port}/v1/conversations"))
        .query(&[("agent_id", "codex")])
        .send()?
        .json()?;
    assert_eq!(list.get("total").and_then(|value| value.as_u64()), Some(1));

    let diary: Value = client
        .get(format!("http://{host}:{port}/v1/diary/read"))
        .query(&[("agent_id", "codex")])
        .send()?
        .json()?;
    assert_eq!(diary.get("total").and_then(|value| value.as_u64()), Some(1));
    assert!(diary
        .get("entries")
        .and_then(|value| value.as_array())
        .and_then(|value| value.first())
        .and_then(|value| value.get("content"))
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .contains("Closed the session"));

    server.shutdown();
    Ok(())
}
