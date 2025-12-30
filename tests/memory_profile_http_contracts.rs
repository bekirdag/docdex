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
        global_state_dir.display(),
        llm_base_url,
    );
    fs::write(config_path, payload)?;
    Ok(())
}

fn seed_profile(global_state_dir: &Path, agent_id: &str) -> Result<(), Box<dyn Error>> {
    let manager = ProfileManager::new(global_state_dir, 4)?;
    let now_ms = 1_700_000_000_000i64;
    manager.create_agent(agent_id, "export-test", now_ms)?;
    let embedding = vec![0.1; 4];
    manager.add_preference(
        agent_id,
        "Use markdown docs",
        &embedding,
        PreferenceCategory::Tooling,
        now_ms,
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
fn profile_export_and_import_contracts() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    write_repo(repo.path())?;
    let state_root = TempDir::new()?;
    let home_dir = TempDir::new()?;
    let Some(mock) = MockOllama::spawn()? else {
        return Ok(());
    };

    let global_state_dir = home_dir.path().join(".docdex").join("state");
    write_config(home_dir.path(), &global_state_dir, &mock.base_url)?;
    seed_profile(&global_state_dir, "agent-export")?;

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
    let export_url = format!("http://{host}:{port}/v1/profile/export");
    let export_resp: Value = client.get(export_url).send()?.json()?;
    assert!(export_resp.get("schema_version").is_some());
    assert!(export_resp.get("embedding_dim").is_some());
    let agents = export_resp
        .get("agents")
        .and_then(|v| v.as_array())
        .map(|v| v.as_slice())
        .unwrap_or(&[]);
    assert!(!agents.is_empty());

    let import_url = format!("http://{host}:{port}/v1/profile/import");
    let mut manifest = export_resp.clone();
    if let Some(prefs) = manifest.get_mut("preferences").and_then(|v| v.as_array_mut()) {
        for (idx, pref) in prefs.iter_mut().enumerate() {
            if let Some(obj) = pref.as_object_mut() {
                obj.insert("id".to_string(), Value::String(format!("import-{}", idx)));
            }
        }
    }
    let import_resp: Value = client.post(import_url).json(&manifest).send()?.json()?;
    let inserted = import_resp
        .get("inserted")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    assert!(inserted >= 1);

    server.shutdown();
    Ok(())
}
