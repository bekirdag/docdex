mod common;

use common::{pick_free_port, write_basic_config, write_basic_repo, TestServerHarness};
use reqwest::blocking::Client;
use serde_json::{json, Value};
use std::error::Error;
use std::time::Duration;
use tempfile::TempDir;

const CONVERSATION_NAMESPACE_HEADER: &str = "x-docdex-conversation-namespace";

#[test]
fn conversation_import_and_wakeup_http_contracts() -> Result<(), Box<dyn Error>> {
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
    let mut server = TestServerHarness::spawn_basic(
        state_root.path(),
        home_dir.path(),
        repo.path(),
        host,
        port,
        false,
    )?;

    let client = Client::builder().timeout(Duration::from_secs(5)).build()?;
    let import_url = format!("http://{host}:{port}/v1/conversations/import");
    let import_payload = json!({
        "source": "manual",
        "title": "Wake-up rollout",
        "agent_id": "codex",
        "transcript_text": "user: Add wake-up context to chat\nassistant: Next step: add the endpoint\nuser: Please add tests too"
    });
    let first_import: Value = client
        .post(&import_url)
        .json(&import_payload)
        .send()?
        .json()?;
    assert_eq!(
        first_import
            .get("deduplicated")
            .and_then(|value| value.as_bool()),
        Some(false)
    );
    assert_eq!(
        first_import
            .get("message_count")
            .and_then(|value| value.as_u64()),
        Some(3)
    );
    let session_id = first_import
        .get("session_id")
        .and_then(|value| value.as_str())
        .ok_or("missing session_id")?
        .to_string();
    assert!(first_import
        .get("summary")
        .and_then(|value| value.get("summary"))
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .contains("Recent goal:"));

    let second_import: Value = client
        .post(&import_url)
        .json(&import_payload)
        .send()?
        .json()?;
    assert_eq!(
        second_import
            .get("deduplicated")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        second_import
            .get("session_id")
            .and_then(|value| value.as_str()),
        Some(session_id.as_str())
    );

    let wakeup_url = format!("http://{host}:{port}/v1/wakeup");
    let wakeup: Value = client
        .post(wakeup_url)
        .json(&json!({
            "agent_id": "codex",
            "query": "endpoint",
            "max_tokens": 64
        }))
        .send()?
        .json()?;
    let text = wakeup
        .get("text")
        .and_then(|value| value.as_str())
        .ok_or("missing wakeup text")?;
    assert!(text.contains("Wake-up context:"));
    assert!(text.contains("Recent conversation summaries:"));
    assert!(
        wakeup
            .get("trace")
            .and_then(|value| value.get("selected_items"))
            .and_then(|value| value.as_u64())
            .unwrap_or(0)
            > 0
    );
    assert!(!wakeup
        .get("transcript_snippets")
        .and_then(|value| value.as_array())
        .unwrap_or(&Vec::new())
        .is_empty());

    server.shutdown();
    Ok(())
}

#[test]
fn conversation_native_import_and_search_http_contracts() -> Result<(), Box<dyn Error>> {
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
    let mut server = TestServerHarness::spawn_basic(
        state_root.path(),
        home_dir.path(),
        repo.path(),
        host,
        port,
        false,
    )?;

    let client = Client::builder().timeout(Duration::from_secs(5)).build()?;
    let import_url = format!("http://{host}:{port}/v1/conversations/import");
    let codex_jsonl = concat!(
        "{\"timestamp\":\"2026-04-07T10:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"codex-http-1\",\"source\":\"vscode\"}}\n",
        "{\"timestamp\":\"2026-04-07T10:00:01Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"user_message\",\"message\":\"Add archive search support.\",\"kind\":\"plain\"}}\n",
        "{\"timestamp\":\"2026-04-07T10:00:02Z\",\"type\":\"response_item\",\"payload\":{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"Search anchor alpha-token-42.\"}]}}\n",
        "{\"timestamp\":\"2026-04-07T10:00:03Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"user_message\",\"message\":\"Also add the HTTP route.\",\"kind\":\"plain\"}}\n",
        "{\"timestamp\":\"2026-04-07T10:00:04Z\",\"type\":\"response_item\",\"payload\":{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"Next step: add /v1/conversations/search.\"}]}}"
    );
    let imported: Value = client
        .post(&import_url)
        .json(&json!({
            "format": "codex_jsonl",
            "agent_id": "codex",
            "transcript_text": codex_jsonl
        }))
        .send()?
        .json()?;
    assert_eq!(
        imported
            .get("message_count")
            .and_then(|value| value.as_u64()),
        Some(4)
    );
    assert_eq!(
        imported
            .get("summary")
            .and_then(|value| value.get("session_id"))
            .and_then(|value| value.as_str())
            .is_some(),
        true
    );

    let search_url = format!("http://{host}:{port}/v1/conversations/search");
    let search: Value = client
        .get(&search_url)
        .query(&[("q", "alpha-token-42"), ("agent_id", "codex")])
        .send()?
        .json()?;
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
    assert!(search
        .get("hits")
        .and_then(|value| value.as_array())
        .and_then(|value| value.first())
        .and_then(|value| value.get("snippet"))
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .contains("alpha-token-42"));

    server.shutdown();
    Ok(())
}

#[test]
fn conversation_kg_query_and_timeline_http_contracts() -> Result<(), Box<dyn Error>> {
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
    let mut server = TestServerHarness::spawn_basic(
        state_root.path(),
        home_dir.path(),
        repo.path(),
        host,
        port,
        false,
    )?;

    let client = Client::builder().timeout(Duration::from_secs(5)).build()?;
    let import_url = format!("http://{host}:{port}/v1/conversations/import");
    let imported: Value = client
        .post(&import_url)
        .json(&json!({
            "source": "manual",
            "title": "knowledge rollout",
            "agent_id": "codex",
            "transcript_text": "user: Repo fact: knowledge.db uses timeline_index\nassistant: Repo fact: timeline_index lives in src/knowledge/db.rs\nassistant: Decision: We decided to keep timeline_index repo-scoped"
        }))
        .send()?
        .json()?;
    assert_eq!(
        imported
            .get("knowledge_facts")
            .and_then(|value| value.as_array())
            .map(|items| items.len())
            .unwrap_or(0),
        3
    );

    let kg_query: Value = client
        .get(format!("http://{host}:{port}/v1/kg/query"))
        .query(&[("q", "knowledge.db"), ("limit", "10")])
        .send()?
        .json()?;
    assert!(kg_query
        .get("facts")
        .and_then(|value| value.as_array())
        .map(|items| !items.is_empty())
        .unwrap_or(false));
    assert!(kg_query
        .get("matched_entities")
        .and_then(|value| value.as_array())
        .map(|items| !items.is_empty())
        .unwrap_or(false));

    let timeline: Value = client
        .get(format!("http://{host}:{port}/v1/kg/timeline"))
        .query(&[("entity", "knowledge.db"), ("limit", "10")])
        .send()?
        .json()?;
    assert!(timeline
        .get("events")
        .and_then(|value| value.as_array())
        .map(|items| !items.is_empty())
        .unwrap_or(false));
    assert_eq!(
        timeline.get("entity").and_then(|value| value.as_str()),
        Some("knowledge.db")
    );

    let node_search: Value = client
        .get(format!("http://{host}:{port}/v1/kg/search/nodes"))
        .query(&[("q", "knowledge.db"), ("limit", "10")])
        .send()?
        .json()?;
    assert!(node_search
        .get("nodes")
        .and_then(|value| value.as_array())
        .map(|items| !items.is_empty())
        .unwrap_or(false));

    let neighborhood: Value = client
        .get(format!("http://{host}:{port}/v1/kg/neighborhood"))
        .query(&[("entity", "knowledge.db"), ("limit", "10")])
        .send()?
        .json()?;
    assert!(neighborhood
        .get("edges")
        .and_then(|value| value.as_array())
        .map(|items| !items.is_empty())
        .unwrap_or(false));
    assert_eq!(
        neighborhood.get("entity").and_then(|value| value.as_str()),
        Some("knowledge.db")
    );

    let entity_links: Value = client
        .get(format!("http://{host}:{port}/v1/kg/entity-links"))
        .query(&[
            ("entity", "timeline_index"),
            ("link_type", "file"),
            ("limit", "10"),
        ])
        .send()?
        .json()?;
    assert_eq!(
        entity_links.get("entity").and_then(|value| value.as_str()),
        Some("timeline_index")
    );
    assert!(entity_links
        .get("links")
        .and_then(|value| value.as_array())
        .map(|items| {
            items.iter().any(|item| {
                item.get("target").and_then(|value| value.as_str()) == Some("src/knowledge/db.rs")
            })
        })
        .unwrap_or(false));
    let episode_id = neighborhood
        .get("edges")
        .and_then(|value| value.as_array())
        .and_then(|items| items.first())
        .and_then(|value| value.get("episode_id"))
        .and_then(|value| value.as_str())
        .map(str::to_string)
        .expect("neighborhood edge should include episode_id");

    let edge_search: Value = client
        .get(format!("http://{host}:{port}/v1/kg/search/edges"))
        .query(&[("q", "timeline_index"), ("limit", "10")])
        .send()?
        .json()?;
    assert!(edge_search
        .get("edges")
        .and_then(|value| value.as_array())
        .map(|items| !items.is_empty())
        .unwrap_or(false));

    let episode_search: Value = client
        .get(format!("http://{host}:{port}/v1/kg/search/episodes"))
        .query(&[("q", "timeline_index"), ("limit", "10")])
        .send()?
        .json()?;
    assert!(episode_search
        .get("episodes")
        .and_then(|value| value.as_array())
        .map(|items| !items.is_empty())
        .unwrap_or(false));

    let episode: Value = client
        .get(format!("http://{host}:{port}/v1/kg/episode"))
        .query(&[("episode_id", episode_id.as_str()), ("limit", "10")])
        .send()?
        .json()?;
    assert_eq!(
        episode
            .get("episode")
            .and_then(|value| value.get("episode_id"))
            .and_then(|value| value.as_str()),
        Some(episode_id.as_str())
    );
    assert!(episode
        .get("edges")
        .and_then(|value| value.as_array())
        .map(|items| !items.is_empty())
        .unwrap_or(false));
    assert!(episode
        .get("evidence")
        .and_then(|value| value.as_array())
        .map(|items| !items.is_empty())
        .unwrap_or(false));

    server.shutdown();
    Ok(())
}

#[test]
fn conversation_kg_maintenance_and_graph_wakeup_http_contracts() -> Result<(), Box<dyn Error>> {
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
    let mut server = TestServerHarness::spawn_basic(
        state_root.path(),
        home_dir.path(),
        repo.path(),
        host,
        port,
        false,
    )?;

    let client = Client::builder().timeout(Duration::from_secs(5)).build()?;
    let import_url = format!("http://{host}:{port}/v1/conversations/import");
    client
        .post(&import_url)
        .json(&json!({
            "source": "manual",
            "title": "graph maintenance",
            "agent_id": "codex",
            "transcript_text": "user: Repo fact: wake-up endpoint lives in src/api/v1/wakeup.rs\nassistant: Repo fact: timeline_index lives in src/knowledge/db.rs\nassistant: Decision: keep graph maintenance local only"
        }))
        .send()?
        .error_for_status()?;

    let wakeup: Value = client
        .post(format!("http://{host}:{port}/v1/wakeup"))
        .json(&json!({
            "agent_id": "codex",
            "query": "wake-up endpoint",
            "max_tokens": 128
        }))
        .send()?
        .json()?;
    assert!(wakeup
        .get("knowledge_edges")
        .and_then(|value| value.as_array())
        .map(|items| !items.is_empty())
        .unwrap_or(false));
    assert!(wakeup
        .get("knowledge_episodes")
        .and_then(|value| value.as_array())
        .map(|items| !items.is_empty())
        .unwrap_or(false));
    assert!(wakeup
        .get("knowledge_entity_links")
        .and_then(|value| value.as_array())
        .map(|items| !items.is_empty())
        .unwrap_or(false));
    assert!(
        wakeup
            .get("trace")
            .and_then(|value| value.get("graph_edge_candidates"))
            .and_then(|value| value.as_u64())
            .unwrap_or(0)
            > 0
    );

    let wake_edge: Value = client
        .get(format!("http://{host}:{port}/v1/kg/search/edges"))
        .query(&[("q", "wake-up endpoint"), ("limit", "10")])
        .send()?
        .json()?;
    let wake_edge_id = wake_edge
        .get("edges")
        .and_then(|value| value.as_array())
        .and_then(|items| items.first())
        .and_then(|value| value.get("edge_id"))
        .and_then(|value| value.as_str())
        .map(str::to_string)
        .ok_or("missing wake-up edge id")?;
    let episode_id = wake_edge
        .get("edges")
        .and_then(|value| value.as_array())
        .and_then(|items| items.first())
        .and_then(|value| value.get("episode_id"))
        .and_then(|value| value.as_str())
        .map(str::to_string)
        .ok_or("missing wake-up episode id")?;

    let deleted_edge: Value = client
        .post(format!("http://{host}:{port}/v1/kg/edge/delete"))
        .json(&json!({ "edge_id": wake_edge_id }))
        .send()?
        .json()?;
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

    let wake_links_after_delete: Value = client
        .get(format!("http://{host}:{port}/v1/kg/entity-links"))
        .query(&[
            ("entity", "wake-up endpoint"),
            ("link_type", "file"),
            ("limit", "10"),
        ])
        .send()?
        .json()?;
    assert_eq!(
        wake_links_after_delete
            .get("total")
            .and_then(|value| value.as_u64()),
        Some(0)
    );

    let sibling_links: Value = client
        .get(format!("http://{host}:{port}/v1/kg/entity-links"))
        .query(&[
            ("entity", "timeline_index"),
            ("link_type", "file"),
            ("limit", "10"),
        ])
        .send()?
        .json()?;
    assert_eq!(
        sibling_links.get("total").and_then(|value| value.as_u64()),
        Some(1)
    );
    assert!(sibling_links
        .get("links")
        .and_then(|value| value.as_array())
        .map(|items| items.iter().any(|item| {
            item.get("target").and_then(|value| value.as_str()) == Some("src/knowledge/db.rs")
        }))
        .unwrap_or(false));

    let rebuilt: Value = client
        .post(format!("http://{host}:{port}/v1/kg/rebuild"))
        .json(&json!({}))
        .send()?
        .json()?;
    assert_eq!(
        rebuilt.get("rebuilt").and_then(|value| value.as_bool()),
        Some(true)
    );
    assert!(
        rebuilt
            .get("relation_links_projected")
            .and_then(|value| value.as_u64())
            .unwrap_or(0)
            >= 1
    );

    let deleted_episode: Value = client
        .post(format!("http://{host}:{port}/v1/kg/episode/delete"))
        .json(&json!({ "episode_id": episode_id }))
        .send()?
        .json()?;
    assert_eq!(
        deleted_episode
            .get("deleted")
            .and_then(|value| value.as_bool()),
        Some(true)
    );
    assert!(
        deleted_episode
            .get("deleted_edges")
            .and_then(|value| value.as_u64())
            .unwrap_or(0)
            >= 1
    );

    let episodes_after_delete: Value = client
        .get(format!("http://{host}:{port}/v1/kg/search/episodes"))
        .query(&[("q", "graph maintenance"), ("limit", "10")])
        .send()?
        .json()?;
    assert_eq!(
        episodes_after_delete
            .get("total")
            .and_then(|value| value.as_u64()),
        Some(0)
    );

    client
        .post(&import_url)
        .json(&json!({
            "source": "manual",
            "title": "clear maintenance",
            "agent_id": "codex",
            "transcript_text": "user: Repo fact: clear-marker lives in src/api/v1/kg.rs"
        }))
        .send()?
        .error_for_status()?;
    let cleared: Value = client
        .post(format!("http://{host}:{port}/v1/kg/clear"))
        .json(&json!({}))
        .send()?
        .json()?;
    assert_eq!(
        cleared.get("cleared").and_then(|value| value.as_bool()),
        Some(true)
    );
    assert!(
        cleared
            .get("deleted_edges")
            .and_then(|value| value.as_u64())
            .unwrap_or(0)
            >= 1
    );

    let nodes_after_clear: Value = client
        .get(format!("http://{host}:{port}/v1/kg/search/nodes"))
        .query(&[("q", "clear-marker"), ("limit", "10")])
        .send()?
        .json()?;
    assert_eq!(
        nodes_after_clear
            .get("total")
            .and_then(|value| value.as_u64()),
        Some(0)
    );

    server.shutdown();
    Ok(())
}

#[test]
fn conversation_namespace_scope_isolated_from_repo_state_http_contracts(
) -> Result<(), Box<dyn Error>> {
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
    let mut server = TestServerHarness::spawn_basic(
        state_root.path(),
        home_dir.path(),
        repo.path(),
        host,
        port,
        false,
    )?;

    let client = Client::builder().timeout(Duration::from_secs(5)).build()?;
    let namespace = "shared-team";
    let import_url = format!("http://{host}:{port}/v1/conversations/import");
    let imported: Value = client
        .post(&import_url)
        .json(&json!({
            "conversation_namespace": namespace,
            "source": "manual",
            "title": "Shared namespace wake-up",
            "agent_id": "codex",
            "transcript_text": "user: Preserve namespace-token-42 in the shared archive\nassistant: Next step: check namespace isolation"
        }))
        .send()?
        .json()?;
    assert_eq!(
        imported
            .get("deduplicated")
            .and_then(|value| value.as_bool()),
        Some(false)
    );

    let repo_search: Value = client
        .get(format!("http://{host}:{port}/v1/conversations/search"))
        .query(&[("q", "namespace-token-42")])
        .send()?
        .json()?;
    assert_eq!(
        repo_search.get("total").and_then(|value| value.as_u64()),
        Some(0)
    );

    let namespace_search: Value = client
        .get(format!("http://{host}:{port}/v1/conversations/search"))
        .query(&[
            ("q", "namespace-token-42"),
            ("conversation_namespace", namespace),
        ])
        .send()?
        .json()?;
    assert_eq!(
        namespace_search
            .get("total")
            .and_then(|value| value.as_u64()),
        Some(1)
    );

    let namespace_wakeup: Value = client
        .post(format!("http://{host}:{port}/v1/wakeup"))
        .header(CONVERSATION_NAMESPACE_HEADER, namespace)
        .json(&json!({
            "agent_id": "codex",
            "query": "namespace-token-42",
            "max_tokens": 96
        }))
        .send()?
        .json()?;
    assert!(namespace_wakeup
        .get("text")
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .contains("Wake-up context:"));
    assert!(
        namespace_wakeup
            .get("trace")
            .and_then(|value| value.get("selected_items"))
            .and_then(|value| value.as_u64())
            .unwrap_or(0)
            > 0
    );

    let repo_wakeup: Value = client
        .post(format!("http://{host}:{port}/v1/wakeup"))
        .json(&json!({
            "agent_id": "codex",
            "query": "namespace-token-42",
            "max_tokens": 96
        }))
        .send()?
        .json()?;
    assert_eq!(
        repo_wakeup
            .get("trace")
            .and_then(|value| value.get("selected_items"))
            .and_then(|value| value.as_u64()),
        Some(0)
    );

    server.shutdown();
    Ok(())
}
