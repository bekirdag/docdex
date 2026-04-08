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

fn write_config(
    home_dir: &Path,
    global_state_dir: &Path,
    auto_capture: bool,
    archive_raw_transcripts: bool,
) -> Result<(), Box<dyn Error>> {
    let config_dir = home_dir.join(".docdex");
    fs::create_dir_all(&config_dir)?;
    fs::write(
        config_dir.join("config.toml"),
        format!(
            "[core]\nglobal_state_dir = \"{}\"\n\n[memory.conversations]\nauto_capture = {}\narchive_raw_transcripts = {}\nsource_denylist = [\"blocked-source\"]\nmanual_retention_days = 30\nauto_capture_retention_days = 30\ndiary_retention_days = 30\nhook_event_retention_days = 30\n",
            common::toml_path(global_state_dir),
            auto_capture,
            archive_raw_transcripts
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
fn conversation_phase8_http_supports_export_redact_and_prune() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    let state_root = TempDir::new()?;
    let home_dir = TempDir::new()?;
    write_repo(repo.path())?;
    let global_state_dir = home_dir.path().join(".docdex").join("state");
    write_config(home_dir.path(), &global_state_dir, true, false)?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let base_url = format!("http://{host}:{port}");
    let mut server =
        ServerHarness::spawn(state_root.path(), home_dir.path(), repo.path(), host, port)?;

    let client = Client::builder().timeout(Duration::from_secs(5)).build()?;
    let imported: Value = client
        .post(format!("{base_url}/v1/conversations/import"))
        .json(&json!({
            "source": "manual",
            "title": "alpha-phase8",
            "agent_id": "codex",
            "transcript_text": "user: Keep this in summary only\nassistant: Next step: add retention controls"
        }))
        .send()?
        .json()?;
    let session_id = imported
        .get("session_id")
        .and_then(|value| value.as_str())
        .ok_or("missing session id")?
        .to_string();
    assert_eq!(
        imported
            .get("raw_messages_stored")
            .and_then(|value| value.as_bool()),
        Some(false)
    );

    let read: Value = client
        .get(format!("{base_url}/v1/conversations/{session_id}"))
        .send()?
        .json()?;
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
        Some(0)
    );

    let export: Value = client
        .get(format!("{base_url}/v1/conversations/{session_id}/export"))
        .send()?
        .json()?;
    assert_eq!(
        export
            .get("export")
            .and_then(|value| value.get("session"))
            .and_then(|value| value.get("raw_messages_stored"))
            .and_then(|value| value.as_bool()),
        Some(false)
    );

    let search_before: Value = client
        .get(format!("{base_url}/v1/conversations/search?q=alpha-phase8"))
        .send()?
        .json()?;
    assert_eq!(
        search_before.get("total").and_then(|value| value.as_u64()),
        Some(1)
    );

    let redacted: Value = client
        .post(format!("{base_url}/v1/conversations/{session_id}/redact"))
        .send()?
        .json()?;
    assert_eq!(
        redacted
            .get("result")
            .and_then(|value| value.get("redacted"))
            .and_then(|value| value.as_bool()),
        Some(true)
    );

    let search_after: Value = client
        .get(format!("{base_url}/v1/conversations/search?q=alpha-phase8"))
        .send()?
        .json()?;
    assert_eq!(
        search_after.get("total").and_then(|value| value.as_u64()),
        Some(0)
    );

    let db_path = find_conversation_db(state_root.path())?;
    let conn = Connection::open(db_path)?;
    conn.execute(
        "UPDATE conversation_sessions SET imported_at_ms = 1 WHERE id = ?1",
        rusqlite::params![session_id],
    )?;

    let prune_preview: Value = client
        .post(format!("{base_url}/v1/conversations/prune"))
        .json(&json!({
            "apply": false,
            "manual_retention_days": 1
        }))
        .send()?
        .json()?;
    assert_eq!(
        prune_preview
            .get("result")
            .and_then(|value| value.get("deleted_manual_sessions"))
            .and_then(|value| value.as_u64()),
        Some(1)
    );
    assert_eq!(
        prune_preview
            .get("result")
            .and_then(|value| value.get("applied"))
            .and_then(|value| value.as_bool()),
        Some(false)
    );

    let prune_apply: Value = client
        .post(format!("{base_url}/v1/conversations/prune"))
        .json(&json!({
            "apply": true,
            "manual_retention_days": 1
        }))
        .send()?
        .json()?;
    assert_eq!(
        prune_apply
            .get("result")
            .and_then(|value| value.get("deleted_manual_sessions"))
            .and_then(|value| value.as_u64()),
        Some(1)
    );

    let missing = client
        .get(format!("{base_url}/v1/conversations/{session_id}"))
        .send()?;
    assert_eq!(missing.status(), reqwest::StatusCode::NOT_FOUND);

    server.shutdown();
    Ok(())
}

#[test]
fn conversation_phase8_http_enforces_hook_source_policy_and_allows_explicit_hooks_when_auto_capture_is_disabled(
) -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    let state_root = TempDir::new()?;
    let home_dir = TempDir::new()?;
    write_repo(repo.path())?;
    let global_state_dir = home_dir.path().join(".docdex").join("state");
    write_config(home_dir.path(), &global_state_dir, true, false)?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let base_url = format!("http://{host}:{port}");
    let mut server =
        ServerHarness::spawn(state_root.path(), home_dir.path(), repo.path(), host, port)?;

    let client = Client::builder().timeout(Duration::from_secs(5)).build()?;
    let blocked = client
        .post(format!("{base_url}/v1/hooks/conversation"))
        .json(&json!({
            "action": "session_close_summarization",
            "source": "blocked-source",
            "transcript_text": "user: hi",
            "wait_for_processing": true
        }))
        .send()?;
    assert_eq!(blocked.status(), reqwest::StatusCode::FORBIDDEN);

    server.shutdown();

    let state_root = TempDir::new()?;
    let home_dir = TempDir::new()?;
    let global_state_dir = home_dir.path().join(".docdex").join("state");
    write_config(home_dir.path(), &global_state_dir, false, false)?;
    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let base_url = format!("http://{host}:{port}");
    let mut server =
        ServerHarness::spawn(state_root.path(), home_dir.path(), repo.path(), host, port)?;

    let manual = client
        .post(format!("{base_url}/v1/hooks/conversation"))
        .json(&json!({
            "action": "session_close_summarization",
            "source": "manual",
            "transcript_text": "user: hi",
            "wait_for_processing": true
        }))
        .send()?;
    assert_eq!(manual.status(), reqwest::StatusCode::OK);
    let manual_body: Value = manual.json()?;
    assert_eq!(
        manual_body.get("status").and_then(|value| value.as_str()),
        Some("processed")
    );

    server.shutdown();
    Ok(())
}

#[test]
fn conversation_phase8_http_redaction_preserves_message_slots_with_placeholders(
) -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    let state_root = TempDir::new()?;
    let home_dir = TempDir::new()?;
    write_repo(repo.path())?;
    let global_state_dir = home_dir.path().join(".docdex").join("state");
    write_config(home_dir.path(), &global_state_dir, true, true)?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let base_url = format!("http://{host}:{port}");
    let mut server =
        ServerHarness::spawn(state_root.path(), home_dir.path(), repo.path(), host, port)?;

    let client = Client::builder().timeout(Duration::from_secs(5)).build()?;
    let imported: Value = client
        .post(format!("{base_url}/v1/conversations/import"))
        .json(&json!({
            "source": "manual",
            "title": "placeholder-phase8",
            "agent_id": "codex",
            "transcript_text": "user: secret-placeholder-token\nassistant: Next step: preserve slot count"
        }))
        .send()?
        .json()?;
    let session_id = imported
        .get("session_id")
        .and_then(|value| value.as_str())
        .ok_or("missing session id")?
        .to_string();
    assert_eq!(
        imported
            .get("raw_messages_stored")
            .and_then(|value| value.as_bool()),
        Some(true)
    );

    let read_before: Value = client
        .get(format!("{base_url}/v1/conversations/{session_id}"))
        .send()?
        .json()?;
    assert_eq!(
        read_before
            .get("session")
            .and_then(|value| value.get("messages"))
            .and_then(|value| value.as_array())
            .map(|value| value.len()),
        Some(2)
    );

    let redacted: Value = client
        .post(format!("{base_url}/v1/conversations/{session_id}/redact"))
        .send()?
        .json()?;
    assert_eq!(
        redacted
            .get("result")
            .and_then(|value| value.get("redacted"))
            .and_then(|value| value.as_bool()),
        Some(true)
    );

    let read_after: Value = client
        .get(format!("{base_url}/v1/conversations/{session_id}"))
        .send()?
        .json()?;
    assert_eq!(
        read_after
            .get("session")
            .and_then(|value| value.get("raw_messages_stored"))
            .and_then(|value| value.as_bool()),
        Some(false)
    );
    assert_eq!(
        read_after
            .get("session")
            .and_then(|value| value.get("title"))
            .and_then(|value| value.as_str()),
        Some("[redacted]")
    );
    let read_messages = read_after
        .get("session")
        .and_then(|value| value.get("messages"))
        .and_then(|value| value.as_array())
        .ok_or("missing redacted messages")?;
    assert_eq!(read_messages.len(), 2);
    assert!(read_messages.iter().all(|message| {
        message.get("content").and_then(|value| value.as_str()) == Some("[redacted]")
    }));

    let export_after: Value = client
        .get(format!("{base_url}/v1/conversations/{session_id}/export"))
        .send()?
        .json()?;
    let export_messages = export_after
        .get("export")
        .and_then(|value| value.get("session"))
        .and_then(|value| value.get("messages"))
        .and_then(|value| value.as_array())
        .ok_or("missing export messages")?;
    assert_eq!(export_messages.len(), 2);
    assert!(export_messages.iter().all(|message| {
        message.get("content").and_then(|value| value.as_str()) == Some("[redacted]")
    }));

    let search_after: Value = client
        .get(format!(
            "{base_url}/v1/conversations/search?q=secret-placeholder-token"
        ))
        .send()?
        .json()?;
    assert_eq!(
        search_after.get("total").and_then(|value| value.as_u64()),
        Some(0)
    );

    server.shutdown();
    Ok(())
}
