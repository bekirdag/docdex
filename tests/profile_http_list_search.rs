mod common;

use common::{docdex_bin, pick_free_port, wait_for_health, MockOllama};
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
    fs::write(repo_root.join("docs").join("guide.md"), "# Guide\n")?;
    Ok(())
}

fn write_config(
    home_dir: &Path,
    global_state_dir: &Path,
    llm_base_url: &str,
    embedding_dim: usize,
) -> Result<(), Box<dyn Error>> {
    let config_dir = home_dir.join(".docdex");
    fs::create_dir_all(&config_dir)?;
    let config_path = config_dir.join("config.toml");
    let payload = format!(
        "[core]\nglobal_state_dir = \"{}\"\n\n[llm]\nbase_url = \"{}\"\ndefault_model = \"fake-model\"\n\n[memory.profile]\nembedding_dim = {}\nembedding_model = \"fake-embed\"\n",
        global_state_dir.display(),
        llm_base_url,
        embedding_dim
    );
    fs::write(config_path, payload)?;
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
fn profile_list_and_search_round_trip() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    write_repo(repo.path())?;

    let state_root = TempDir::new()?;
    let home_dir = TempDir::new()?;
    let Some(mock) = MockOllama::spawn()? else {
        return Ok(());
    };

    let embedding_dim = 4;
    let global_state_dir = home_dir.path().join(".docdex").join("state");
    write_config(
        home_dir.path(),
        &global_state_dir,
        &mock.base_url,
        embedding_dim,
    )?;

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

    let client = Client::builder().timeout(Duration::from_secs(3)).build()?;
    let add_url = format!("http://{host}:{port}/v1/profile/add");
    let add_resp: Value = client
        .post(add_url)
        .json(&serde_json::json!({
            "agent_id": "agent-list",
            "category": "style",
            "content": "Prefer concise answers"
        }))
        .send()?
        .json()?;
    let pref_id = add_resp
        .get("preference")
        .and_then(|v| v.get("id"))
        .and_then(|v| v.as_str())
        .unwrap_or("");
    assert!(!pref_id.is_empty());

    let list_url = format!("http://{host}:{port}/v1/profile/list?agent_id=agent-list");
    let list_resp: Value = client.get(list_url).send()?.json()?;
    let prefs = list_resp
        .get("preferences")
        .and_then(|v| v.as_array())
        .ok_or("missing preferences")?;
    assert!(prefs.iter().any(|pref| {
        pref.get("content")
            .and_then(|v| v.as_str())
            .map(|text| text.contains("concise"))
            .unwrap_or(false)
    }));

    let search_url = format!("http://{host}:{port}/v1/profile/search");
    let search_resp: Value = client
        .post(search_url)
        .json(&serde_json::json!({
            "agent_id": "agent-list",
            "query": "concise",
            "top_k": 5
        }))
        .send()?
        .json()?;
    let results = search_resp
        .get("results")
        .and_then(|v| v.as_array())
        .ok_or("missing results")?;
    assert!(!results.is_empty());

    server.shutdown();
    Ok(())
}
