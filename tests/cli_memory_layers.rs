mod common;

use common::{pick_free_port, run_docdex_json, wait_for_health, TestServerHarness};
use serde_json::Value;
use std::error::Error;
use std::fs;
use std::path::Path;
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
            "[core]\nglobal_state_dir = \"{}\"\n\n[memory]\nenabled = true\n\n[memory.conversations]\nenabled = true\nwakeup_include_recent_diary_episodes = true\n\n[memory.personal_preferences]\nenabled = true\ncontext_injection_enabled = true\n",
            common::toml_path(global_state_dir),
        ),
    )?;
    Ok(())
}

#[test]
fn cli_memory_layers_supports_conversation_namespace_scope() -> Result<(), Box<dyn Error>> {
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
    let mut server = TestServerHarness::spawn_with_env(
        state_root.path(),
        home_dir.path(),
        repo.path(),
        host,
        port,
        false,
        &[("DOCDEX_ENABLE_MEMORY", "1")],
    )?;
    wait_for_health(host, port)?;

    let value = run_docdex_json(
        home_dir.path(),
        &base_url,
        ["memory-layers", "--conversation-namespace", "scratchpad"],
    )?;

    assert_eq!(
        value
            .get("scope")
            .and_then(|scope| scope.get("kind"))
            .and_then(Value::as_str),
        Some("conversation_namespace")
    );
    let layers = value
        .get("layers")
        .and_then(Value::as_array)
        .ok_or("missing layers")?;
    assert!(layers.iter().any(|layer| {
        layer.get("id").and_then(Value::as_str) == Some("repo_memory")
            && layer.get("enabled").and_then(Value::as_bool) == Some(false)
    }));
    assert!(layers.iter().any(|layer| {
        layer.get("id").and_then(Value::as_str) == Some("conversation_memory")
            && layer
                .get("effective_use")
                .and_then(|value| value.get("status"))
                .and_then(Value::as_str)
                == Some("strong")
    }));

    server.shutdown();
    Ok(())
}

#[test]
fn cli_memory_route_returns_ranked_lane_guidance() -> Result<(), Box<dyn Error>> {
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
    let mut server = TestServerHarness::spawn_with_env(
        state_root.path(),
        home_dir.path(),
        repo.path(),
        host,
        port,
        false,
        &[("DOCDEX_ENABLE_MEMORY", "1")],
    )?;
    wait_for_health(host, port)?;

    let args = vec![
        "memory-route".to_string(),
        "--repo".to_string(),
        repo.path().display().to_string(),
        "What did we decide last session, what is the handoff note, and when did that happen?"
            .to_string(),
    ];
    let value = run_docdex_json(home_dir.path(), &base_url, args)?;

    assert_eq!(value.get("intent").and_then(Value::as_str), Some("read"));
    let retrievable = value
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
