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
            "[core]\nglobal_state_dir = \"{}\"\n\n[llm]\nbase_url = \"{}\"\ndefault_model = \"fake-model\"\n",
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
fn chat_prompt_includes_wakeup_context() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    let state_root = TempDir::new()?;
    let home_dir = TempDir::new()?;
    write_repo(repo.path())?;
    let Some(mock) = MockOllama::spawn()? else {
        return Ok(());
    };
    let global_state_dir = home_dir.path().join(".docdex").join("state");
    write_config(home_dir.path(), &global_state_dir, &mock.base_url)?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let mut server =
        ServerHarness::spawn(state_root.path(), home_dir.path(), repo.path(), host, port)?;

    let client = Client::builder().timeout(Duration::from_secs(5)).build()?;
    let import_url = format!("http://{host}:{port}/v1/conversations/import");
    client
        .post(import_url)
        .json(&json!({
            "source": "manual",
            "title": "Wake-up rollout",
            "agent_id": "codex",
            "transcript_text": "user: Add wake-up context to chat\nassistant: Next step: add the endpoint\nuser: Please add tests too"
        }))
        .send()?
        .error_for_status()?;

    let chat_url = format!("http://{host}:{port}/v1/chat/completions");
    let response: Value = client
        .post(chat_url)
        .json(&json!({
            "model": "fake-model",
            "messages": [{ "role": "user", "content": "What is the next step for the wake-up work?" }],
            "docdex": {
                "agent_id": "codex",
                "compress_results": false,
                "skip_local_search": true,
                "limit": 1
            }
        }))
        .send()?
        .json()?;

    let content = response
        .get("choices")
        .and_then(|value| value.as_array())
        .and_then(|value| value.first())
        .and_then(|value| value.get("message"))
        .and_then(|value| value.get("content"))
        .and_then(|value| value.as_str())
        .ok_or("missing chat completion content")?;
    assert!(content.contains("Wake-up context:"));
    assert!(content.contains("Next step:"));
    assert!(content.contains("add the endpoint"));

    server.shutdown();
    Ok(())
}
