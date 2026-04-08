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
            "[core]\nglobal_state_dir = \"{}\"\n\n[memory.conversations]\narchive_raw_transcripts = false\nmanual_retention_days = 30\nauto_capture_retention_days = 30\ndiary_retention_days = 30\nhook_event_retention_days = 30\n",
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

fn run_docdex<I, S>(home_dir: &Path, base_url: &str, args: I) -> Result<Value, Box<dyn Error>>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    let output = Command::new(docdex_bin())
        .env("DOCDEX_WEB_ENABLED", "0")
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("DOCDEX_HTTP_BASE_URL", base_url)
        .env("HOME", home_dir)
        .args(args)
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "docdexd exited with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
    Ok(serde_json::from_slice(&output.stdout)?)
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
fn cli_conversation_phase8_commands_work_against_http_daemon() -> Result<(), Box<dyn Error>> {
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
    let base_url = format!("http://{host}:{port}");
    let mut server =
        ServerHarness::spawn(state_root.path(), home_dir.path(), repo.path(), host, port)?;

    let client = Client::builder().timeout(Duration::from_secs(5)).build()?;
    let imported: Value = client
        .post(format!("{base_url}/v1/conversations/import"))
        .json(&json!({
            "source": "manual",
            "title": "cli-phase8",
            "agent_id": "codex",
            "transcript_text": "user: Export me\nassistant: Next step: redact and prune"
        }))
        .send()?
        .json()?;
    let session_id = imported
        .get("session_id")
        .and_then(|value| value.as_str())
        .ok_or("missing session id")?
        .to_string();
    let repo_arg = repo.path().to_string_lossy().to_string();

    let exported = run_docdex(
        home_dir.path(),
        &base_url,
        [
            "conversations",
            "export",
            "--repo",
            repo_arg.as_str(),
            session_id.as_str(),
        ],
    )?;
    assert_eq!(
        exported
            .get("export")
            .and_then(|value| value.get("session"))
            .and_then(|value| value.get("raw_messages_stored"))
            .and_then(|value| value.as_bool()),
        Some(false)
    );

    let redacted = run_docdex(
        home_dir.path(),
        &base_url,
        [
            "conversations",
            "redact",
            "--repo",
            repo_arg.as_str(),
            session_id.as_str(),
        ],
    )?;
    assert_eq!(
        redacted
            .get("result")
            .and_then(|value| value.get("redacted"))
            .and_then(|value| value.as_bool()),
        Some(true)
    );

    let db_path = find_conversation_db(state_root.path())?;
    let conn = Connection::open(db_path)?;
    conn.execute(
        "UPDATE conversation_sessions SET imported_at_ms = 1 WHERE id = ?1",
        rusqlite::params![session_id],
    )?;

    let preview = run_docdex(
        home_dir.path(),
        &base_url,
        [
            "conversations",
            "prune",
            "--repo",
            repo_arg.as_str(),
            "--manual-retention-days",
            "1",
        ],
    )?;
    assert_eq!(
        preview
            .get("result")
            .and_then(|value| value.get("applied"))
            .and_then(|value| value.as_bool()),
        Some(false)
    );

    let applied = run_docdex(
        home_dir.path(),
        &base_url,
        [
            "conversations",
            "prune",
            "--repo",
            repo_arg.as_str(),
            "--apply",
            "--manual-retention-days",
            "1",
        ],
    )?;
    assert_eq!(
        applied
            .get("result")
            .and_then(|value| value.get("deleted_manual_sessions"))
            .and_then(|value| value.as_u64()),
        Some(1)
    );

    server.shutdown();
    Ok(())
}
