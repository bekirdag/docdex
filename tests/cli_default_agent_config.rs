mod common;

use common::{docdex_bin, pick_free_port, wait_for_health, MockOllama};
use docdexd::profiles::{PreferenceCategory, ProfileManager};
use reqwest::blocking::Client;
use serde_json::Value;
use std::error::Error;
use std::fs;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;
use tempfile::TempDir;

fn write_repo(repo_root: &Path) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(repo_root.join("docs"))?;
    fs::write(repo_root.join("docs").join("readme.md"), "# Repo\n")?;
    Ok(())
}

fn write_config(
    home_dir: &Path,
    global_state_dir: &Path,
    llm_base_url: &str,
) -> Result<(), Box<dyn Error>> {
    let config_dir = home_dir.join(".docdex");
    fs::create_dir_all(&config_dir)?;
    let config_path = config_dir.join("config.toml");
    let payload = format!(
        "[core]\nglobal_state_dir = \"{}\"\n\n[llm]\nbase_url = \"{}\"\ndefault_model = \"fake-model\"\n\n[memory.profile]\nembedding_dim = 4\nembedding_model = \"fake-embed\"\n",
        crate::common::toml_path(global_state_dir),
        llm_base_url,
    );
    fs::write(config_path, payload)?;
    Ok(())
}

fn seed_profile(global_state_dir: &Path, agent_id: &str) -> Result<(), Box<dyn Error>> {
    let manager = ProfileManager::new(global_state_dir, 4)?;
    let now_ms = 1_700_000_000_000i64;
    manager.create_agent(agent_id, "cli-default", now_ms)?;
    let embedding = vec![0.1; 4];
    manager.add_preference(
        agent_id,
        "Use tabs for indentation",
        &embedding,
        PreferenceCategory::Style,
        now_ms,
    )?;
    Ok(())
}

fn run_index(state_root: &Path, home_dir: &Path, repo_root: &Path) -> Result<(), Box<dyn Error>> {
    let repo_str = repo_root.to_string_lossy().to_string();
    let output = Command::new(docdex_bin())
        .env("DOCDEX_ENABLE_MEMORY", "0")
        .env("DOCDEX_STATE_DIR", state_root)
        .env("HOME", home_dir)
        .args(["index", "--repo", repo_str.as_str()])
        .output()?;
    if !output.status.success() {
        return Err(format!(
            "docdexd index failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )
        .into());
    }
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
        agent_id: &str,
    ) -> Result<Self, Box<dyn Error>> {
        let repo_str = repo_root.to_string_lossy().to_string();
        let child = Command::new(docdex_bin())
            .env("DOCDEX_ENABLE_MEMORY", "0")
            .env("DOCDEX_WEB_ENABLED", "0")
            .env("DOCDEX_STATE_DIR", state_root)
            .env("DOCDEX_ENABLE_MCP", "0")
            .env("HOME", home_dir)
            .args([
                "serve",
                "--repo",
                repo_str.as_str(),
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
                "--agent-id",
                agent_id,
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        wait_for_health(host, port)?;
        Ok(Self { child })
    }

    fn shutdown(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
    }
}

#[test]
fn serve_agent_id_flag_sets_default_profile() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    write_repo(repo.path())?;
    let state_root = TempDir::new()?;
    let home_dir = TempDir::new()?;
    let Some(mock) = MockOllama::spawn()? else {
        return Ok(());
    };

    let global_state_dir = home_dir.path().join(".docdex").join("state");
    write_config(home_dir.path(), &global_state_dir, &mock.base_url)?;
    seed_profile(&global_state_dir, "agent-flag")?;
    run_index(state_root.path(), home_dir.path(), repo.path())?;

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
        "agent-flag",
    )?;

    let client = Client::builder().timeout(Duration::from_secs(5)).build()?;
    let url = format!("http://{host}:{port}/v1/chat/completions");
    let resp: Value = client
        .post(url)
        .json(&serde_json::json!({
            "model": "fake-model",
            "messages": [{ "role": "user", "content": "profile" }],
            "docdex": { "compress_results": true }
        }))
        .send()?
        .json()?;

    let content = resp
        .get("choices")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|choice| choice.get("message"))
        .and_then(|message| message.get("content"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let compressed: Value = serde_json::from_str(content)?;
    let profile_items = compressed
        .get("results")
        .and_then(|v| v.get("profile"))
        .and_then(|v| v.as_array())
        .map(|v| v.as_slice())
        .unwrap_or(&[]);
    assert!(profile_items.iter().any(|item| {
        item.get("content")
            .and_then(|v| v.as_str())
            .map(|text| text.contains("Use tabs for indentation"))
            .unwrap_or(false)
    }));

    server.shutdown();
    Ok(())
}
