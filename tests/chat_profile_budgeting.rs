mod common;

use common::{docdex_bin, pick_free_port, wait_for_health, MockOllama};
use docdexd::profiles::{PreferenceCategory, ProfileManager};
use reqwest::blocking::Client;
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
    manager.create_agent(agent_id, "budget-test", now_ms)?;
    let embedding = vec![0.1, 0.2, 0.3, 0.4];
    for idx in 0..20 {
        manager.add_preference(
            agent_id,
            &format!("Use rule number {} for style consistency.", idx),
            &embedding,
            PreferenceCategory::Style,
            now_ms + idx as i64,
        )?;
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
fn profile_budget_drops_increment_metrics() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    write_repo(repo.path())?;
    let state_root = TempDir::new()?;
    let home_dir = TempDir::new()?;
    let Some(mock) = MockOllama::spawn()? else {
        return Ok(());
    };

    let global_state_dir = home_dir.path().join(".docdex").join("state");
    write_config(home_dir.path(), &global_state_dir, &mock.base_url)?;
    seed_profile(&global_state_dir, "agent-budget")?;

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
    )?;

    let client = Client::builder().timeout(Duration::from_secs(5)).build()?;
    let chat_url = format!("http://{host}:{port}/v1/chat/completions");
    let _resp: serde_json::Value = client
        .post(chat_url)
        .json(&serde_json::json!({
            "model": "fake-model",
            "messages": [{ "role": "user", "content": "budget check" }],
            "docdex": {
                "agent_id": "agent-budget",
                "compress_results": false,
                "skip_local_search": true,
                "limit": 3
            }
        }))
        .send()?
        .json()?;

    let metrics_url = format!("http://{host}:{port}/metrics");
    let metrics = client.get(metrics_url).send()?.text()?;
    let line = metrics
        .lines()
        .find(|line| line.starts_with("docdex_profile_budget_drops_total"))
        .unwrap_or("");
    let value = line
        .split_whitespace()
        .last()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    assert!(value > 0, "expected profile budget drops to increment");

    server.shutdown();
    Ok(())
}
