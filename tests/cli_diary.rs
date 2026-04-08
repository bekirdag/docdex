mod common;

use common::{docdex_bin, pick_free_port, wait_for_health};
use serde_json::Value;
use std::error::Error;
use std::fs;
use std::path::Path;
use std::process::{Child, Command, Stdio};
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

#[test]
fn cli_diary_and_hook_commands_work_against_http_daemon() -> Result<(), Box<dyn Error>> {
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

    let repo_arg = repo.path().to_string_lossy().to_string();
    let note = run_docdex(
        home_dir.path(),
        &base_url,
        [
            "diary",
            "write",
            "--repo",
            repo_arg.as_str(),
            "--agent-id",
            "codex",
            "Initial diary note",
        ],
    )?;
    assert_eq!(
        note.get("entry_type").and_then(|value| value.as_str()),
        Some("note")
    );

    let transcript_path = home_dir.path().join("hook.txt");
    fs::write(
        &transcript_path,
        "user: Save the latest context\nassistant: Next step: enqueue the hook",
    )?;
    let hook = run_docdex(
        home_dir.path(),
        &base_url,
        [
            "hook",
            "conversation",
            "--repo",
            repo_arg.as_str(),
            "--action",
            "session_close_summarization",
            "--agent-id",
            "codex",
            "--transcript",
            transcript_path.to_string_lossy().as_ref(),
            "--summary-text",
            "CLI hook summary persisted.",
            "--wait-for-processing",
        ],
    )?;
    assert_eq!(
        hook.get("status").and_then(|value| value.as_str()),
        Some("processed")
    );

    let read = run_docdex(
        home_dir.path(),
        &base_url,
        [
            "diary",
            "read",
            "--repo",
            repo_arg.as_str(),
            "--agent-id",
            "codex",
        ],
    )?;
    assert_eq!(read.get("total").and_then(|value| value.as_u64()), Some(2));

    server.shutdown();
    Ok(())
}
