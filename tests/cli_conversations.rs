mod common;

use common::{
    pick_free_port, run_docdex_json, write_basic_config, write_basic_repo, TestServerHarness,
};
use reqwest::blocking::Client;
use serde_json::{json, Value};
use std::error::Error;
use std::fs;
use std::time::Duration;
use tempfile::TempDir;

#[test]
fn cli_conversation_commands_work_against_http_daemon() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    let state_root = TempDir::new()?;
    let home_dir = TempDir::new()?;
    write_basic_repo(repo.path())?;
    let global_state_dir = home_dir.path().join(".docdex").join("state");
    write_basic_config(home_dir.path(), &global_state_dir)?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let base_url = format!("http://{host}:{port}");
    let mut server = TestServerHarness::spawn_basic(
        state_root.path(),
        home_dir.path(),
        repo.path(),
        host,
        port,
        false,
    )?;

    let client = Client::builder().timeout(Duration::from_secs(5)).build()?;
    let imported: Value = client
        .post(format!("{base_url}/v1/conversations/import"))
        .json(&json!({
            "source": "manual",
            "title": "CLI controls",
            "agent_id": "codex",
            "transcript_text": "user: Add CLI commands\nassistant: Next step: list, read, and delete"
        }))
        .send()?
        .json()?;
    let session_id = imported
        .get("session_id")
        .and_then(|value| value.as_str())
        .ok_or("missing session id")?
        .to_string();
    let repo_arg = repo.path().to_string_lossy().to_string();

    let list = run_docdex_json(
        home_dir.path(),
        &base_url,
        [
            "conversations",
            "list",
            "--repo",
            repo_arg.as_str(),
            "--agent-id",
            "codex",
        ],
    )?;
    assert_eq!(list.get("total").and_then(|value| value.as_u64()), Some(1));

    let read = run_docdex_json(
        home_dir.path(),
        &base_url,
        [
            "conversations",
            "read",
            "--repo",
            repo_arg.as_str(),
            session_id.as_str(),
        ],
    )?;
    assert_eq!(
        read.get("session")
            .and_then(|value| value.get("message_count"))
            .and_then(|value| value.as_u64()),
        Some(2)
    );

    let deleted = run_docdex_json(
        home_dir.path(),
        &base_url,
        [
            "conversations",
            "delete",
            "--repo",
            repo_arg.as_str(),
            session_id.as_str(),
        ],
    )?;
    assert_eq!(
        deleted.get("deleted").and_then(|value| value.as_bool()),
        Some(true)
    );

    let list_after_delete = run_docdex_json(
        home_dir.path(),
        &base_url,
        ["conversations", "list", "--repo", repo_arg.as_str()],
    )?;
    assert_eq!(
        list_after_delete
            .get("total")
            .and_then(|value| value.as_u64()),
        Some(0)
    );

    server.shutdown();
    Ok(())
}

#[test]
fn cli_conversation_import_and_search_work_against_http_daemon() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    let state_root = TempDir::new()?;
    let home_dir = TempDir::new()?;
    write_basic_repo(repo.path())?;
    let global_state_dir = home_dir.path().join(".docdex").join("state");
    write_basic_config(home_dir.path(), &global_state_dir)?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let base_url = format!("http://{host}:{port}");
    let mut server = TestServerHarness::spawn_basic(
        state_root.path(),
        home_dir.path(),
        repo.path(),
        host,
        port,
        false,
    )?;

    let transcript_path = home_dir.path().join("codex-session.jsonl");
    fs::write(
        &transcript_path,
        concat!(
            "{\"timestamp\":\"2026-04-07T10:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"codex-cli-1\",\"source\":\"vscode\"}}\n",
            "{\"timestamp\":\"2026-04-07T10:00:01Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"user_message\",\"message\":\"Please add archive search.\",\"kind\":\"plain\"}}\n",
            "{\"timestamp\":\"2026-04-07T10:00:02Z\",\"type\":\"response_item\",\"payload\":{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"Search anchor alpha-token-42.\"}]}}\n",
            "{\"timestamp\":\"2026-04-07T10:00:03Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"user_message\",\"message\":\"Also add the CLI surface.\",\"kind\":\"plain\"}}\n",
            "{\"timestamp\":\"2026-04-07T10:00:04Z\",\"type\":\"response_item\",\"payload\":{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"Next step: add conversation search CLI output.\"}]}}"
        ),
    )?;
    let repo_arg = repo.path().to_string_lossy().to_string();
    let import = run_docdex_json(
        home_dir.path(),
        &base_url,
        [
            "conversations",
            "import",
            "--repo",
            repo_arg.as_str(),
            "--format",
            "codex_jsonl",
            "--agent-id",
            "codex",
            transcript_path.to_string_lossy().as_ref(),
        ],
    )?;
    assert_eq!(
        import.get("message_count").and_then(|value| value.as_u64()),
        Some(4)
    );

    let search = run_docdex_json(
        home_dir.path(),
        &base_url,
        [
            "conversations",
            "search",
            "--repo",
            repo_arg.as_str(),
            "--agent-id",
            "codex",
            "alpha-token-42",
        ],
    )?;
    assert_eq!(
        search.get("total").and_then(|value| value.as_u64()),
        Some(1)
    );
    assert_eq!(
        search
            .get("hits")
            .and_then(|value| value.as_array())
            .and_then(|value| value.first())
            .and_then(|value| value.get("matched_field"))
            .and_then(|value| value.as_str()),
        Some("message")
    );

    server.shutdown();
    Ok(())
}

#[test]
fn cli_conversation_graph_commands_work_against_http_daemon() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    let state_root = TempDir::new()?;
    let home_dir = TempDir::new()?;
    write_basic_repo(repo.path())?;
    let global_state_dir = home_dir.path().join(".docdex").join("state");
    write_basic_config(home_dir.path(), &global_state_dir)?;

    let Some(port) = pick_free_port() else {
        return Ok(());
    };
    let host = "127.0.0.1";
    let base_url = format!("http://{host}:{port}");
    let mut server = TestServerHarness::spawn_basic(
        state_root.path(),
        home_dir.path(),
        repo.path(),
        host,
        port,
        false,
    )?;

    let client = Client::builder().timeout(Duration::from_secs(5)).build()?;
    client
        .post(format!("{base_url}/v1/conversations/import"))
        .json(&json!({
            "source": "manual",
            "title": "graph maintenance",
            "agent_id": "codex",
            "transcript_text": "user: Repo fact: wake-up endpoint lives in src/api/v1/wakeup.rs\nassistant: Repo fact: timeline_index lives in src/knowledge/db.rs\nassistant: Decision: keep graph maintenance local only"
        }))
        .send()?
        .error_for_status()?;

    let repo_arg = repo.path().to_string_lossy().to_string();

    let node_search = run_docdex_json(
        home_dir.path(),
        &base_url,
        [
            "conversations",
            "kg-search-nodes",
            "--repo",
            repo_arg.as_str(),
            "wake-up endpoint",
        ],
    )?;
    assert_eq!(
        node_search.get("total").and_then(|value| value.as_u64()),
        Some(1)
    );

    let edge_search = run_docdex_json(
        home_dir.path(),
        &base_url,
        [
            "conversations",
            "kg-search-edges",
            "--repo",
            repo_arg.as_str(),
            "wake-up endpoint",
        ],
    )?;
    let edge = edge_search
        .get("edges")
        .and_then(|value| value.as_array())
        .and_then(|items| items.first())
        .ok_or("missing wake-up edge")?;
    let edge_id = edge
        .get("edge_id")
        .and_then(|value| value.as_str())
        .map(str::to_string)
        .ok_or("missing wake-up edge id")?;
    let episode_id = edge
        .get("episode_id")
        .and_then(|value| value.as_str())
        .map(str::to_string)
        .ok_or("missing wake-up episode id")?;

    let neighborhood = run_docdex_json(
        home_dir.path(),
        &base_url,
        [
            "conversations",
            "kg-neighborhood",
            "--repo",
            repo_arg.as_str(),
            "wake-up endpoint",
        ],
    )?;
    assert!(neighborhood
        .get("edges")
        .and_then(|value| value.as_array())
        .map(|items| !items.is_empty())
        .unwrap_or(false));

    let wake_links = run_docdex_json(
        home_dir.path(),
        &base_url,
        [
            "conversations",
            "kg-entity-links",
            "--repo",
            repo_arg.as_str(),
            "--link-type",
            "file",
            "wake-up endpoint",
        ],
    )?;
    assert_eq!(
        wake_links.get("total").and_then(|value| value.as_u64()),
        Some(1)
    );

    let episode = run_docdex_json(
        home_dir.path(),
        &base_url,
        [
            "conversations",
            "kg-episode",
            "--repo",
            repo_arg.as_str(),
            episode_id.as_str(),
        ],
    )?;
    assert!(episode
        .get("edges")
        .and_then(|value| value.as_array())
        .map(|items| !items.is_empty())
        .unwrap_or(false));

    let deleted_edge = run_docdex_json(
        home_dir.path(),
        &base_url,
        [
            "conversations",
            "kg-delete-edge",
            "--repo",
            repo_arg.as_str(),
            edge_id.as_str(),
        ],
    )?;
    assert_eq!(
        deleted_edge
            .get("deleted")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        deleted_edge
            .get("deleted_entity_links")
            .and_then(|value| value.as_u64()),
        Some(1)
    );

    let sibling_links = run_docdex_json(
        home_dir.path(),
        &base_url,
        [
            "conversations",
            "kg-entity-links",
            "--repo",
            repo_arg.as_str(),
            "--link-type",
            "file",
            "timeline_index",
        ],
    )?;
    assert_eq!(
        sibling_links.get("total").and_then(|value| value.as_u64()),
        Some(1)
    );

    let rebuilt = run_docdex_json(
        home_dir.path(),
        &base_url,
        ["conversations", "kg-rebuild", "--repo", repo_arg.as_str()],
    )?;
    assert_eq!(
        rebuilt.get("rebuilt").and_then(|value| value.as_bool()),
        Some(true)
    );

    let deleted_episode = run_docdex_json(
        home_dir.path(),
        &base_url,
        [
            "conversations",
            "kg-delete-episode",
            "--repo",
            repo_arg.as_str(),
            episode_id.as_str(),
        ],
    )?;
    assert_eq!(
        deleted_episode
            .get("deleted")
            .and_then(|value| value.as_bool()),
        Some(true)
    );

    client
        .post(format!("{base_url}/v1/conversations/import"))
        .json(&json!({
            "source": "manual",
            "title": "clear maintenance",
            "agent_id": "codex",
            "transcript_text": "user: Repo fact: clear-marker lives in src/api/v1/kg.rs"
        }))
        .send()?
        .error_for_status()?;

    let cleared = run_docdex_json(
        home_dir.path(),
        &base_url,
        ["conversations", "kg-clear", "--repo", repo_arg.as_str()],
    )?;
    assert_eq!(
        cleared.get("cleared").and_then(|value| value.as_bool()),
        Some(true)
    );

    let nodes_after_clear = run_docdex_json(
        home_dir.path(),
        &base_url,
        [
            "conversations",
            "kg-search-nodes",
            "--repo",
            repo_arg.as_str(),
            "clear-marker",
        ],
    )?;
    assert_eq!(
        nodes_after_clear
            .get("total")
            .and_then(|value| value.as_u64()),
        Some(0)
    );

    server.shutdown();
    Ok(())
}
