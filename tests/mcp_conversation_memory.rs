mod common;

use common::{pick_free_port, write_basic_config, write_basic_repo, TestServerHarness};
use reqwest::blocking::Client;
use serde_json::{json, Value};
use std::error::Error;
use std::fs;
use std::path::Path;
use std::time::Duration;
use tempfile::TempDir;

fn parse_tool_result(body: &Value) -> Result<Value, Box<dyn Error>> {
    let text = body
        .get("result")
        .and_then(|value| value.get("content"))
        .and_then(|value| value.as_array())
        .and_then(|value| value.first())
        .and_then(|value| value.get("text"))
        .and_then(|value| value.as_str())
        .ok_or("missing MCP tool response")?;
    Ok(serde_json::from_str(text)?)
}

fn write_startup_diary_config(
    home_dir: &Path,
    global_state_dir: &Path,
) -> Result<(), Box<dyn Error>> {
    let config_dir = home_dir.join(".docdex");
    fs::create_dir_all(&config_dir)?;
    fs::write(
        config_dir.join("config.toml"),
        format!(
            "[core]\nglobal_state_dir = \"{}\"\n\n[memory.conversations]\nwakeup_include_recent_diary_episodes = true\nmax_wakeup_diary_episodes = 1\n",
            common::toml_path(global_state_dir)
        ),
    )?;
    Ok(())
}

#[test]
fn mcp_conversation_import_and_wakeup_work_over_http_transport() -> Result<(), Box<dyn Error>> {
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
        true,
    )?;

    let client = Client::builder().timeout(Duration::from_secs(5)).build()?;
    let import_payload = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "docdex_conversation_import",
            "arguments": {
                "agent_id": "codex",
                "title": "Wake-up rollout",
                "transcript_text": "user: Add wake-up context to chat\nassistant: Next step: add the endpoint\nuser: Please add tests too"
            }
        }
    });
    let import_response: Value = client
        .post(format!("http://{host}:{port}/v1/mcp"))
        .json(&import_payload)
        .send()?
        .json()?;
    let imported = parse_tool_result(&import_response)?;
    assert_eq!(
        imported
            .get("deduplicated")
            .and_then(|value| value.as_bool()),
        Some(false)
    );

    let wakeup_payload = json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "docdex_wakeup",
            "arguments": {
                "agent_id": "codex",
                "query": "endpoint",
                "max_tokens": 64
            }
        }
    });
    let wakeup_response: Value = client
        .post(format!("http://{host}:{port}/v1/mcp"))
        .json(&wakeup_payload)
        .send()?
        .json()?;
    let wakeup = parse_tool_result(&wakeup_response)?;
    assert!(wakeup
        .get("text")
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .contains("Wake-up context:"));
    assert!(
        wakeup
            .get("trace")
            .and_then(|value| value.get("selected_items"))
            .and_then(|value| value.as_u64())
            .unwrap_or(0)
            > 0
    );

    server.shutdown();
    Ok(())
}

#[test]
fn mcp_wakeup_includes_startup_diary_episodes_when_enabled() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    let state_root = TempDir::new()?;
    let home_dir = TempDir::new()?;
    write_basic_repo(repo.path())?;
    let global_state_dir = home_dir.path().join(".docdex").join("state");
    write_startup_diary_config(home_dir.path(), &global_state_dir)?;

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
        true,
    )?;

    let client = Client::builder().timeout(Duration::from_secs(5)).build()?;
    for (id, entry_type, content, metadata) in [
        (31, "note", "Plain note about the ongoing work.", json!({})),
        (
            32,
            "handoff",
            "Handoff: unblock the wake-up rollout before changing the renderer.",
            json!({ "important": true }),
        ),
    ] {
        let payload = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {
                "name": "docdex_diary_write",
                "arguments": {
                    "agent_id": "codex",
                    "entry_type": entry_type,
                    "content": content,
                    "metadata": metadata
                }
            }
        });
        let response: Value = client
            .post(format!("http://{host}:{port}/v1/mcp"))
            .json(&payload)
            .send()?
            .json()?;
        let written = parse_tool_result(&response)?;
        assert_eq!(
            written.get("entry_type").and_then(|value| value.as_str()),
            Some(entry_type)
        );
    }

    let wakeup_payload = json!({
        "jsonrpc": "2.0",
        "id": 33,
        "method": "tools/call",
        "params": {
            "name": "docdex_wakeup",
            "arguments": {
                "agent_id": "codex",
                "max_tokens": 128
            }
        }
    });
    let wakeup_response: Value = client
        .post(format!("http://{host}:{port}/v1/mcp"))
        .json(&wakeup_payload)
        .send()?
        .json()?;
    let wakeup = parse_tool_result(&wakeup_response)?;
    assert_eq!(
        wakeup
            .get("trace")
            .and_then(|value| value.get("startup_diary_candidates"))
            .and_then(|value| value.as_u64()),
        Some(2)
    );
    assert_eq!(
        wakeup
            .get("trace")
            .and_then(|value| value.get("startup_diary_selected"))
            .and_then(|value| value.as_u64()),
        Some(1)
    );
    let episodes = wakeup
        .get("knowledge_episodes")
        .and_then(|value| value.as_array())
        .ok_or("missing knowledge_episodes")?;
    assert_eq!(episodes.len(), 1);
    assert_eq!(
        episodes[0]
            .get("source_type")
            .and_then(|value| value.as_str()),
        Some("diary_entry")
    );
    assert!(episodes[0]
        .get("summary")
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .contains("Handoff: unblock the wake-up rollout"));

    server.shutdown();
    Ok(())
}

#[test]
fn mcp_conversation_list_read_delete_work_over_http_transport() -> Result<(), Box<dyn Error>> {
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
        true,
    )?;

    let client = Client::builder().timeout(Duration::from_secs(5)).build()?;
    let import_payload = json!({
        "jsonrpc": "2.0",
        "id": 11,
        "method": "tools/call",
        "params": {
            "name": "docdex_conversation_import",
            "arguments": {
                "agent_id": "codex",
                "title": "Conversation controls",
                "transcript_text": "user: Add list/read/delete tools\nassistant: Next step: wire the handlers"
            }
        }
    });
    let import_response: Value = client
        .post(format!("http://{host}:{port}/v1/mcp"))
        .json(&import_payload)
        .send()?
        .json()?;
    let imported = parse_tool_result(&import_response)?;
    let session_id = imported
        .get("session_id")
        .and_then(|value| value.as_str())
        .ok_or("missing session_id")?
        .to_string();

    let list_payload = json!({
        "jsonrpc": "2.0",
        "id": 12,
        "method": "tools/call",
        "params": {
            "name": "docdex_conversation_list",
            "arguments": {
                "agent_id": "codex",
                "limit": 10
            }
        }
    });
    let list_response: Value = client
        .post(format!("http://{host}:{port}/v1/mcp"))
        .json(&list_payload)
        .send()?
        .json()?;
    let list = parse_tool_result(&list_response)?;
    assert_eq!(list.get("total").and_then(|value| value.as_u64()), Some(1));
    assert_eq!(
        list.get("sessions")
            .and_then(|value| value.as_array())
            .and_then(|value| value.first())
            .and_then(|value| value.get("session_id"))
            .and_then(|value| value.as_str()),
        Some(session_id.as_str())
    );

    let read_payload = json!({
        "jsonrpc": "2.0",
        "id": 13,
        "method": "tools/call",
        "params": {
            "name": "docdex_conversation_read",
            "arguments": {
                "session_id": session_id
            }
        }
    });
    let read_response: Value = client
        .post(format!("http://{host}:{port}/v1/mcp"))
        .json(&read_payload)
        .send()?
        .json()?;
    let read = parse_tool_result(&read_response)?;
    assert_eq!(
        read.get("session")
            .and_then(|value| value.get("message_count"))
            .and_then(|value| value.as_u64()),
        Some(2)
    );

    let delete_payload = json!({
        "jsonrpc": "2.0",
        "id": 14,
        "method": "tools/call",
        "params": {
            "name": "docdex_conversation_delete",
            "arguments": {
                "session_id": session_id
            }
        }
    });
    let delete_response: Value = client
        .post(format!("http://{host}:{port}/v1/mcp"))
        .json(&delete_payload)
        .send()?
        .json()?;
    let deleted = parse_tool_result(&delete_response)?;
    assert_eq!(
        deleted.get("deleted").and_then(|value| value.as_bool()),
        Some(true)
    );

    let list_after_delete_response: Value = client
        .post(format!("http://{host}:{port}/v1/mcp"))
        .json(&list_payload)
        .send()?
        .json()?;
    let list_after_delete = parse_tool_result(&list_after_delete_response)?;
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
fn mcp_conversation_kg_query_and_timeline_work_over_http_transport() -> Result<(), Box<dyn Error>> {
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
        true,
    )?;

    let client = Client::builder().timeout(Duration::from_secs(5)).build()?;
    let import_response: Value = client
        .post(format!("http://{host}:{port}/v1/mcp"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 21,
            "method": "tools/call",
            "params": {
                "name": "docdex_conversation_import",
                "arguments": {
                    "agent_id": "codex",
                    "title": "KG rollout",
                    "transcript_text": "user: Repo fact: knowledge.db uses timeline_index\nassistant: Repo fact: timeline_index lives in src/knowledge/db.rs\nassistant: Decision: We decided to keep timeline_index repo-scoped"
                }
            }
        }))
        .send()?
        .json()?;
    let imported = parse_tool_result(&import_response)?;
    assert!(imported
        .get("knowledge_facts")
        .and_then(|value| value.as_array())
        .map(|items| !items.is_empty())
        .unwrap_or(false));

    let kg_query_response: Value = client
        .post(format!("http://{host}:{port}/v1/mcp"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 22,
            "method": "tools/call",
            "params": {
                "name": "docdex_kg_query",
                "arguments": {
                    "query": "knowledge.db",
                    "limit": 10
                }
            }
        }))
        .send()?
        .json()?;
    let kg_query = parse_tool_result(&kg_query_response)?;
    assert!(kg_query
        .get("facts")
        .and_then(|value| value.as_array())
        .map(|items| !items.is_empty())
        .unwrap_or(false));

    let timeline_response: Value = client
        .post(format!("http://{host}:{port}/v1/mcp"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 23,
            "method": "tools/call",
            "params": {
                "name": "docdex_kg_timeline",
                "arguments": {
                    "entity": "knowledge.db",
                    "limit": 10
                }
            }
        }))
        .send()?
        .json()?;
    let timeline = parse_tool_result(&timeline_response)?;
    assert!(timeline
        .get("events")
        .and_then(|value| value.as_array())
        .map(|items| !items.is_empty())
        .unwrap_or(false));
    assert_eq!(
        timeline.get("entity").and_then(|value| value.as_str()),
        Some("knowledge.db")
    );

    let node_search_response: Value = client
        .post(format!("http://{host}:{port}/v1/mcp"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 24,
            "method": "tools/call",
            "params": {
                "name": "docdex_kg_search_nodes",
                "arguments": {
                    "query": "knowledge.db",
                    "limit": 10
                }
            }
        }))
        .send()?
        .json()?;
    let node_search = parse_tool_result(&node_search_response)?;
    assert!(node_search
        .get("nodes")
        .and_then(|value| value.as_array())
        .map(|items| !items.is_empty())
        .unwrap_or(false));

    let neighborhood_response: Value = client
        .post(format!("http://{host}:{port}/v1/mcp"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 25,
            "method": "tools/call",
            "params": {
                "name": "docdex_kg_neighborhood",
                "arguments": {
                    "entity": "knowledge.db",
                    "limit": 10
                }
            }
        }))
        .send()?
        .json()?;
    let neighborhood = parse_tool_result(&neighborhood_response)?;
    assert!(neighborhood
        .get("edges")
        .and_then(|value| value.as_array())
        .map(|items| !items.is_empty())
        .unwrap_or(false));
    assert_eq!(
        neighborhood.get("entity").and_then(|value| value.as_str()),
        Some("knowledge.db")
    );

    let entity_links_response: Value = client
        .post(format!("http://{host}:{port}/v1/mcp"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 26,
            "method": "tools/call",
            "params": {
                "name": "docdex_kg_entity_links",
                "arguments": {
                    "entity": "timeline_index",
                    "link_type": "file",
                    "limit": 10
                }
            }
        }))
        .send()?
        .json()?;
    let entity_links = parse_tool_result(&entity_links_response)?;
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

    let edge_search_response: Value = client
        .post(format!("http://{host}:{port}/v1/mcp"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 27,
            "method": "tools/call",
            "params": {
                "name": "docdex_kg_search_edges",
                "arguments": {
                    "query": "timeline_index",
                    "limit": 10
                }
            }
        }))
        .send()?
        .json()?;
    let edge_search = parse_tool_result(&edge_search_response)?;
    assert!(edge_search
        .get("edges")
        .and_then(|value| value.as_array())
        .map(|items| !items.is_empty())
        .unwrap_or(false));

    let episode_search_response: Value = client
        .post(format!("http://{host}:{port}/v1/mcp"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 28,
            "method": "tools/call",
            "params": {
                "name": "docdex_kg_search_episodes",
                "arguments": {
                    "query": "timeline_index",
                    "limit": 10
                }
            }
        }))
        .send()?
        .json()?;
    let episode_search = parse_tool_result(&episode_search_response)?;
    assert!(episode_search
        .get("episodes")
        .and_then(|value| value.as_array())
        .map(|items| !items.is_empty())
        .unwrap_or(false));

    let episode_response: Value = client
        .post(format!("http://{host}:{port}/v1/mcp"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 29,
            "method": "tools/call",
            "params": {
                "name": "docdex_kg_episode",
                "arguments": {
                    "episode_id": episode_id,
                    "limit": 10
                }
            }
        }))
        .send()?
        .json()?;
    let episode = parse_tool_result(&episode_response)?;
    assert!(episode
        .get("episode")
        .and_then(|value| value.get("episode_id"))
        .and_then(|value| value.as_str())
        .is_some());
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
fn mcp_conversation_kg_maintenance_and_graph_wakeup_work_over_http_transport(
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
        true,
    )?;

    let client = Client::builder().timeout(Duration::from_secs(5)).build()?;
    let import_response: Value = client
        .post(format!("http://{host}:{port}/v1/mcp"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 41,
            "method": "tools/call",
            "params": {
                "name": "docdex_conversation_import",
                "arguments": {
                    "agent_id": "codex",
                    "title": "graph maintenance",
                    "transcript_text": "user: Repo fact: wake-up endpoint lives in src/api/v1/wakeup.rs\nassistant: Repo fact: timeline_index lives in src/knowledge/db.rs\nassistant: Decision: keep graph maintenance local only"
                }
            }
        }))
        .send()?
        .json()?;
    let imported = parse_tool_result(&import_response)?;
    assert_eq!(
        imported
            .get("deduplicated")
            .and_then(|value| value.as_bool()),
        Some(false)
    );

    let wakeup_response: Value = client
        .post(format!("http://{host}:{port}/v1/mcp"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 42,
            "method": "tools/call",
            "params": {
                "name": "docdex_wakeup",
                "arguments": {
                    "agent_id": "codex",
                    "query": "wake-up endpoint",
                    "max_tokens": 128
                }
            }
        }))
        .send()?
        .json()?;
    let wakeup = parse_tool_result(&wakeup_response)?;
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

    let edge_search_response: Value = client
        .post(format!("http://{host}:{port}/v1/mcp"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 43,
            "method": "tools/call",
            "params": {
                "name": "docdex_kg_search_edges",
                "arguments": {
                    "query": "wake-up endpoint",
                    "limit": 10
                }
            }
        }))
        .send()?
        .json()?;
    let edge_search = parse_tool_result(&edge_search_response)?;
    let wake_edge = edge_search
        .get("edges")
        .and_then(|value| value.as_array())
        .and_then(|items| items.first())
        .ok_or("missing wake-up edge")?;
    let wake_edge_id = wake_edge
        .get("edge_id")
        .and_then(|value| value.as_str())
        .map(str::to_string)
        .ok_or("missing wake-up edge id")?;
    let episode_id = wake_edge
        .get("episode_id")
        .and_then(|value| value.as_str())
        .map(str::to_string)
        .ok_or("missing wake-up episode id")?;

    let deleted_edge_response: Value = client
        .post(format!("http://{host}:{port}/v1/mcp"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 44,
            "method": "tools/call",
            "params": {
                "name": "docdex_kg_delete_edge",
                "arguments": {
                    "edge_id": wake_edge_id
                }
            }
        }))
        .send()?
        .json()?;
    let deleted_edge = parse_tool_result(&deleted_edge_response)?;
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

    let wake_links_response: Value = client
        .post(format!("http://{host}:{port}/v1/mcp"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 45,
            "method": "tools/call",
            "params": {
                "name": "docdex_kg_entity_links",
                "arguments": {
                    "entity": "wake-up endpoint",
                    "link_type": "file",
                    "limit": 10
                }
            }
        }))
        .send()?
        .json()?;
    let wake_links = parse_tool_result(&wake_links_response)?;
    assert_eq!(
        wake_links.get("total").and_then(|value| value.as_u64()),
        Some(0)
    );

    let sibling_links_response: Value = client
        .post(format!("http://{host}:{port}/v1/mcp"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 46,
            "method": "tools/call",
            "params": {
                "name": "docdex_kg_entity_links",
                "arguments": {
                    "entity": "timeline_index",
                    "link_type": "file",
                    "limit": 10
                }
            }
        }))
        .send()?
        .json()?;
    let sibling_links = parse_tool_result(&sibling_links_response)?;
    assert_eq!(
        sibling_links.get("total").and_then(|value| value.as_u64()),
        Some(1)
    );

    let rebuild_response: Value = client
        .post(format!("http://{host}:{port}/v1/mcp"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 47,
            "method": "tools/call",
            "params": {
                "name": "docdex_kg_rebuild",
                "arguments": {}
            }
        }))
        .send()?
        .json()?;
    let rebuild = parse_tool_result(&rebuild_response)?;
    assert_eq!(
        rebuild.get("rebuilt").and_then(|value| value.as_bool()),
        Some(true)
    );

    let delete_episode_response: Value = client
        .post(format!("http://{host}:{port}/v1/mcp"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 48,
            "method": "tools/call",
            "params": {
                "name": "docdex_kg_delete_episode",
                "arguments": {
                    "episode_id": episode_id
                }
            }
        }))
        .send()?
        .json()?;
    let deleted_episode = parse_tool_result(&delete_episode_response)?;
    assert_eq!(
        deleted_episode
            .get("deleted")
            .and_then(|value| value.as_bool()),
        Some(true)
    );

    let clear_import_response: Value = client
        .post(format!("http://{host}:{port}/v1/mcp"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 49,
            "method": "tools/call",
            "params": {
                "name": "docdex_conversation_import",
                "arguments": {
                    "agent_id": "codex",
                    "title": "clear maintenance",
                    "transcript_text": "user: Repo fact: clear-marker lives in src/api/v1/kg.rs"
                }
            }
        }))
        .send()?
        .json()?;
    let _ = parse_tool_result(&clear_import_response)?;

    let clear_response: Value = client
        .post(format!("http://{host}:{port}/v1/mcp"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 50,
            "method": "tools/call",
            "params": {
                "name": "docdex_kg_clear",
                "arguments": {}
            }
        }))
        .send()?
        .json()?;
    let cleared = parse_tool_result(&clear_response)?;
    assert_eq!(
        cleared.get("cleared").and_then(|value| value.as_bool()),
        Some(true)
    );

    let nodes_after_clear_response: Value = client
        .post(format!("http://{host}:{port}/v1/mcp"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 51,
            "method": "tools/call",
            "params": {
                "name": "docdex_kg_search_nodes",
                "arguments": {
                    "query": "clear-marker",
                    "limit": 10
                }
            }
        }))
        .send()?
        .json()?;
    let nodes_after_clear = parse_tool_result(&nodes_after_clear_response)?;
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
fn mcp_conversation_native_import_and_search_work_over_http_transport() -> Result<(), Box<dyn Error>>
{
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
        true,
    )?;

    let client = Client::builder().timeout(Duration::from_secs(5)).build()?;
    let codex_jsonl = concat!(
        "{\"timestamp\":\"2026-04-07T10:00:00Z\",\"type\":\"session_meta\",\"payload\":{\"id\":\"codex-mcp-1\",\"source\":\"vscode\"}}\n",
        "{\"timestamp\":\"2026-04-07T10:00:01Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"user_message\",\"message\":\"Please add archive search.\",\"kind\":\"plain\"}}\n",
        "{\"timestamp\":\"2026-04-07T10:00:02Z\",\"type\":\"response_item\",\"payload\":{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"Search anchor alpha-token-42.\"}]}}\n",
        "{\"timestamp\":\"2026-04-07T10:00:03Z\",\"type\":\"event_msg\",\"payload\":{\"type\":\"user_message\",\"message\":\"Also wire the HTTP route.\",\"kind\":\"plain\"}}\n",
        "{\"timestamp\":\"2026-04-07T10:00:04Z\",\"type\":\"response_item\",\"payload\":{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"Next step: add archive search endpoints.\"}]}}"
    );
    let import_payload = json!({
        "jsonrpc": "2.0",
        "id": 21,
        "method": "tools/call",
        "params": {
            "name": "docdex_conversation_import",
            "arguments": {
                "agent_id": "codex",
                "format": "codex_jsonl",
                "transcript_text": codex_jsonl
            }
        }
    });
    let import_response: Value = client
        .post(format!("http://{host}:{port}/v1/mcp"))
        .json(&import_payload)
        .send()?
        .json()?;
    let imported = parse_tool_result(&import_response)?;
    assert_eq!(
        imported
            .get("message_count")
            .and_then(|value| value.as_u64()),
        Some(4)
    );

    let search_payload = json!({
        "jsonrpc": "2.0",
        "id": 22,
        "method": "tools/call",
        "params": {
            "name": "docdex_conversation_search",
            "arguments": {
                "query": "alpha-token-42",
                "agent_id": "codex"
            }
        }
    });
    let search_response: Value = client
        .post(format!("http://{host}:{port}/v1/mcp"))
        .json(&search_payload)
        .send()?
        .json()?;
    let search = parse_tool_result(&search_response)?;
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
fn mcp_conversation_namespace_scope_works_over_http_transport() -> Result<(), Box<dyn Error>> {
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
        true,
    )?;

    let client = Client::builder().timeout(Duration::from_secs(5)).build()?;
    let namespace = "shared-team";
    let import_response: Value = client
        .post(format!("http://{host}:{port}/v1/mcp"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 31,
            "method": "tools/call",
            "params": {
                "name": "docdex_conversation_import",
                "arguments": {
                    "conversation_namespace": namespace,
                    "agent_id": "codex",
                    "title": "Shared namespace import",
                    "transcript_text": "user: Preserve namespace-token-42 in the shared archive\nassistant: Next step: keep namespace scope isolated"
                }
            }
        }))
        .send()?
        .json()?;
    let imported = parse_tool_result(&import_response)?;
    assert_eq!(
        imported
            .get("deduplicated")
            .and_then(|value| value.as_bool()),
        Some(false)
    );

    let repo_list_response: Value = client
        .post(format!("http://{host}:{port}/v1/mcp"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 32,
            "method": "tools/call",
            "params": {
                "name": "docdex_conversation_list",
                "arguments": {
                    "agent_id": "codex",
                    "limit": 10
                }
            }
        }))
        .send()?
        .json()?;
    let repo_list = parse_tool_result(&repo_list_response)?;
    assert_eq!(
        repo_list.get("total").and_then(|value| value.as_u64()),
        Some(0)
    );

    let namespace_list_response: Value = client
        .post(format!("http://{host}:{port}/v1/mcp"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 33,
            "method": "tools/call",
            "params": {
                "name": "docdex_conversation_list",
                "arguments": {
                    "conversation_namespace": namespace,
                    "agent_id": "codex",
                    "limit": 10
                }
            }
        }))
        .send()?
        .json()?;
    let namespace_list = parse_tool_result(&namespace_list_response)?;
    assert_eq!(
        namespace_list.get("total").and_then(|value| value.as_u64()),
        Some(1)
    );

    let wakeup_response: Value = client
        .post(format!("http://{host}:{port}/v1/mcp"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 34,
            "method": "tools/call",
            "params": {
                "name": "docdex_wakeup",
                "arguments": {
                    "conversation_namespace": namespace,
                    "agent_id": "codex",
                    "query": "namespace-token-42",
                    "max_tokens": 96
                }
            }
        }))
        .send()?
        .json()?;
    let wakeup = parse_tool_result(&wakeup_response)?;
    assert!(wakeup
        .get("text")
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .contains("Wake-up context:"));
    assert!(
        wakeup
            .get("trace")
            .and_then(|value| value.get("selected_items"))
            .and_then(|value| value.as_u64())
            .unwrap_or(0)
            > 0
    );

    server.shutdown();
    Ok(())
}
