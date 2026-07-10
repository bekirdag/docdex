mod common;

use common::{pick_free_port, wait_for_health, TestServerHarness};
use reqwest::blocking::Client;
use serde_json::Value;
use std::error::Error;
use std::fs;
use std::path::Path;
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
            "[core]\nglobal_state_dir = \"{}\"\n\n[memory]\nenabled = true\n\n[memory.conversations]\nenabled = true\nwakeup_include_recent_diary_episodes = true\n\n[memory.personal_preferences]\nenabled = true\ncontext_injection_enabled = true\ncapture_enabled = true\n",
            common::toml_path(global_state_dir),
        ),
    )?;
    Ok(())
}

#[test]
fn memory_layers_http_reports_all_six_layers() -> Result<(), Box<dyn Error>> {
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
    let mut server = TestServerHarness::spawn_with_env(
        state_root.path(),
        home_dir.path(),
        repo.path(),
        host,
        port,
        false,
        &[
            ("DOCDEX_ENABLE_MEMORY", "1"),
            ("DOCDEX_PERSONAL_PREFERENCES_ENABLED", "1"),
        ],
    )?;
    wait_for_health(host, port)?;

    let client = Client::builder().timeout(Duration::from_secs(5)).build()?;
    let body: Value = client
        .get(format!("http://{host}:{port}/v1/memory/layers"))
        .send()?
        .error_for_status()?
        .json()?;

    assert_eq!(
        body.get("scope")
            .and_then(|value| value.get("kind"))
            .and_then(Value::as_str),
        Some("repo")
    );
    assert_eq!(
        body.get("layers").and_then(Value::as_array).map(Vec::len),
        Some(6)
    );
    let layers = body
        .get("layers")
        .and_then(Value::as_array)
        .ok_or("missing layers array")?;
    assert!(layers.iter().any(|layer| {
        layer.get("id").and_then(Value::as_str) == Some("repo_memory")
            && layer.get("enabled").and_then(Value::as_bool) == Some(true)
    }));
    assert!(layers.iter().any(|layer| {
        layer.get("id").and_then(Value::as_str) == Some("temporal_knowledge_graph")
            && layer
                .get("storage")
                .and_then(|value| value.get("paths"))
                .and_then(Value::as_array)
                .and_then(|paths| paths.first())
                .and_then(Value::as_str)
                .map(|path| path.ends_with("knowledge.db"))
                == Some(true)
    }));
    assert!(
        layers.iter().any(|layer| {
            layer.get("id").and_then(Value::as_str) == Some("personal_preferences")
                && layer
                    .get("agent_awareness")
                    .and_then(|value| value.get("status"))
                    .and_then(Value::as_str)
                    == Some("strong")
        }),
        "personal preferences layer was not strongly enabled: {body}"
    );

    server.shutdown();
    Ok(())
}

#[test]
fn memory_route_http_ranks_core_and_retrievable_lanes() -> Result<(), Box<dyn Error>> {
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
    let mut server = TestServerHarness::spawn_with_env(
        state_root.path(),
        home_dir.path(),
        repo.path(),
        host,
        port,
        false,
        &[
            ("DOCDEX_ENABLE_MEMORY", "1"),
            ("DOCDEX_PERSONAL_PREFERENCES_ENABLED", "1"),
        ],
    )?;
    wait_for_health(host, port)?;

    let client = Client::builder().timeout(Duration::from_secs(5)).build()?;
    let body: Value = client
        .post(format!("http://{host}:{port}/v1/memory/route"))
        .json(&serde_json::json!({
            "query": "What did we decide last session, what is the handoff note, and when did that decision happen?"
        }))
        .send()?
        .error_for_status()?
        .json()?;

    assert_eq!(body.get("intent").and_then(Value::as_str), Some("read"));
    assert!(
        body.get("core_memory")
            .and_then(Value::as_array)
            .map(|items| !items.is_empty())
            == Some(true)
    );
    let retrievable = body
        .get("retrievable_memory")
        .and_then(Value::as_array)
        .ok_or("missing retrievable_memory")?;
    assert!(retrievable.iter().any(|item| {
        item.get("layer_id").and_then(Value::as_str) == Some("conversation_memory")
    }));
    assert!(retrievable
        .iter()
        .any(|item| { item.get("layer_id").and_then(Value::as_str) == Some("diary_memory") }));
    assert!(retrievable.iter().any(|item| {
        item.get("layer_id").and_then(Value::as_str) == Some("temporal_knowledge_graph")
    }));

    server.shutdown();
    Ok(())
}
