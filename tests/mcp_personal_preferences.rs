mod common;

use common::{pick_free_port, wait_for_health, TestServerHarness};
use docdexd::personal_preferences::{
    PersonalPreferenceDigestOutput, PersonalPreferenceDigestRecord,
    PersonalPreferencesCaptureRequest, PersonalPreferencesMessage, PersonalPreferencesStore,
};
use reqwest::blocking::Client;
use serde_json::{json, Value};
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
            "[core]\nglobal_state_dir = \"{}\"\n\n[personal_preferences]\nenabled = true\nprocess_in_background = false\ncapture_supported_client_transcripts = true\narchive_raw_conversations = true\n",
            common::toml_path(global_state_dir),
        ),
    )?;
    Ok(())
}

fn create_codex_scan_transcript(home_dir: &Path) -> Result<(), Box<dyn Error>> {
    let transcript_dir = home_dir.join(".codex").join("sessions");
    fs::create_dir_all(&transcript_dir)?;
    fs::write(
        transcript_dir.join("mcp-scan.jsonl"),
        r#"{"type":"session_meta","timestamp":"2026-04-09T00:00:00Z","payload":{"id":"mcp-scan","title":"MCP Scanned"}}
{"type":"event_msg","timestamp":"2026-04-09T00:00:01Z","payload":{"type":"user_message","text":"I prefer local-first tooling and reviewable automation."}}
"#,
    )?;
    Ok(())
}

fn seed_processed_personal_preferences(home_dir: &Path) -> Result<(), Box<dyn Error>> {
    let store_root = home_dir.join(".docdex").join("personal_preferences");
    let store = PersonalPreferencesStore::new(&store_root)?;
    store.capture_conversation(
        PersonalPreferencesCaptureRequest {
            source: "claude".to_string(),
            source_session_id: Some("seed-session".to_string()),
            capture_kind: Some("conversation_import".to_string()),
            title: Some("seeded".to_string()),
            agent_id: Some("codex".to_string()),
            transport: Some("http".to_string()),
            repo_id: Some("repo-1".to_string()),
            repo_root: Some("/tmp/repo-one".to_string()),
            scope_id: Some("repo-1".to_string()),
            scope_label: Some("/tmp/repo-one".to_string()),
            started_at_ms: Some(10),
            ended_at_ms: Some(20),
            messages: vec![PersonalPreferencesMessage {
                role: "user".to_string(),
                content: "I prefer Rust and local-first tooling.".to_string(),
                created_at_ms: Some(10),
                metadata: Value::Null,
            }],
            transcript_text: Some("user: I prefer Rust and local-first tooling.".to_string()),
            summary_text: None,
            metadata: json!({ "source": "seed" }),
        },
        true,
        true,
    )?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        store
            .process_pending_with_runner(4, |_input| async {
                Ok(Some(PersonalPreferenceDigestOutput {
                    records: vec![
                        PersonalPreferenceDigestRecord {
                            record_type: "preference".to_string(),
                            category: "tech stack".to_string(),
                            subcategory: None,
                            subject: "user".to_string(),
                            attribute: Some("prefers".to_string()),
                            value: "Rust".to_string(),
                            confidence: Some(0.94),
                            sensitivity: Some("low".to_string()),
                            evidence: Some("I prefer Rust".to_string()),
                            metadata: Value::Null,
                        },
                        PersonalPreferenceDigestRecord {
                            record_type: "context".to_string(),
                            category: "health_context".to_string(),
                            subcategory: None,
                            subject: "user".to_string(),
                            attribute: Some("shared".to_string()),
                            value: "private detail".to_string(),
                            confidence: Some(0.89),
                            sensitivity: Some("sensitive".to_string()),
                            evidence: Some("private detail".to_string()),
                            metadata: Value::Null,
                        },
                    ],
                }))
            })
            .await
    })?;
    Ok(())
}

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

fn call_tool(
    client: &Client,
    host: &str,
    port: u16,
    id: u64,
    name: &str,
    arguments: Value,
) -> Result<Value, Box<dyn Error>> {
    let response: Value = client
        .post(format!("http://{host}:{port}/v1/mcp"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": arguments
            }
        }))
        .send()?
        .json()?;
    parse_tool_result(&response)
}

#[test]
fn mcp_personal_preferences_tools_work_over_http_transport() -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    let state_root = TempDir::new()?;
    let home_dir = TempDir::new()?;
    write_repo(repo.path())?;
    let global_state_dir = home_dir.path().join(".docdex").join("state");
    write_config(home_dir.path(), &global_state_dir)?;
    seed_processed_personal_preferences(home_dir.path())?;
    create_codex_scan_transcript(home_dir.path())?;

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
    wait_for_health(host, port)?;

    let client = Client::builder().timeout(Duration::from_secs(5)).build()?;

    let status_response: Value = client
        .post(format!("http://{host}:{port}/v1/mcp"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "docdex_personal_preferences_status",
                "arguments": {}
            }
        }))
        .send()?
        .json()?;
    let status = parse_tool_result(&status_response)?;
    assert_eq!(
        status.get("captures_total").and_then(Value::as_u64),
        Some(1)
    );

    let categories_response: Value = client
        .post(format!("http://{host}:{port}/v1/mcp"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "docdex_personal_preferences_categories",
                "arguments": {}
            }
        }))
        .send()?
        .json()?;
    let categories = parse_tool_result(&categories_response)?;
    assert!(categories
        .as_array()
        .unwrap_or(&Vec::new())
        .iter()
        .any(|item| item.get("category").and_then(Value::as_str) == Some("tech_stack")));

    let reviews_response: Value = client
        .post(format!("http://{host}:{port}/v1/mcp"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "docdex_personal_preferences_reviews",
                "arguments": {
                    "status": "pending_review",
                    "limit": 10
                }
            }
        }))
        .send()?
        .json()?;
    let reviews = parse_tool_result(&reviews_response)?;
    assert_eq!(reviews.get("total").and_then(Value::as_u64), Some(1));
    let record_id = reviews
        .get("items")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(|item| item.get("id"))
        .and_then(Value::as_str)
        .ok_or("missing review record id")?
        .to_string();

    let review_response: Value = client
        .post(format!("http://{host}:{port}/v1/mcp"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "docdex_personal_preferences_review",
                "arguments": {
                    "record_id": record_id,
                    "verdict": "approved"
                }
            }
        }))
        .send()?
        .json()?;
    let reviewed = parse_tool_result(&review_response)?;
    assert_eq!(
        reviewed.get("review_status").and_then(Value::as_str),
        Some("approved")
    );

    let search_response: Value = client
        .post(format!("http://{host}:{port}/v1/mcp"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "docdex_personal_preferences_search",
                "arguments": {
                    "query": "Rust",
                    "include_sensitive": true
                }
            }
        }))
        .send()?
        .json()?;
    let search = parse_tool_result(&search_response)?;
    assert!(search
        .as_array()
        .map(|items| !items.is_empty())
        .unwrap_or(false));

    let scan_response: Value = client
        .post(format!("http://{host}:{port}/v1/mcp"))
        .json(&json!({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {
                "name": "docdex_personal_preferences_scan",
                "arguments": {
                    "limit": 10
                }
            }
        }))
        .send()?
        .json()?;
    let scan = parse_tool_result(&scan_response)?;
    assert_eq!(
        scan.get("captures_created").and_then(Value::as_u64),
        Some(1)
    );

    server.shutdown();
    Ok(())
}

#[test]
fn mcp_personal_preferences_mind_clone_tools_work_over_http_transport() -> Result<(), Box<dyn Error>>
{
    let repo = TempDir::new()?;
    let state_root = TempDir::new()?;
    let home_dir = TempDir::new()?;
    write_repo(repo.path())?;
    let global_state_dir = home_dir.path().join(".docdex").join("state");
    write_config(home_dir.path(), &global_state_dir)?;
    seed_processed_personal_preferences(home_dir.path())?;

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
    wait_for_health(host, port)?;

    let client = Client::builder().timeout(Duration::from_secs(5)).build()?;

    let claims = call_tool(
        &client,
        host,
        port,
        10,
        "docdex_personal_preferences_claims",
        json!({ "limit": 10, "include_sensitive": true }),
    )?;
    assert!(claims.get("total").and_then(Value::as_u64).unwrap_or(0) >= 2);
    let claim_id = claims
        .get("items")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(|item| item.get("id"))
        .and_then(Value::as_str)
        .ok_or("missing claim id")?
        .to_string();

    let claim = call_tool(
        &client,
        host,
        port,
        11,
        "docdex_personal_preferences_claim_read",
        json!({ "claim_id": claim_id }),
    )?;
    let claim_id = claim
        .get("id")
        .and_then(Value::as_str)
        .ok_or("missing claim id in read response")?
        .to_string();

    let reviewed = call_tool(
        &client,
        host,
        port,
        12,
        "docdex_personal_preferences_claim_review",
        json!({ "claim_id": claim_id, "verdict": "approved" }),
    )?;
    assert_eq!(
        reviewed.get("review_status").and_then(Value::as_str),
        Some("approved")
    );

    let overridden = call_tool(
        &client,
        host,
        port,
        13,
        "docdex_personal_preferences_claim_override",
        json!({ "claim_id": claim_id, "value": "Rust and Go" }),
    )?;
    assert_eq!(
        overridden.get("event_type").and_then(Value::as_str),
        Some("override_preference")
    );

    let forgotten = call_tool(
        &client,
        host,
        port,
        14,
        "docdex_personal_preferences_claim_forget",
        json!({
            "claim_id": claim_id,
            "notes": "forget the superseded claim in mcp test"
        }),
    )?;
    assert_eq!(
        forgotten.get("forgotten").and_then(Value::as_bool),
        Some(true)
    );

    let feedback = call_tool(
        &client,
        host,
        port,
        15,
        "docdex_personal_preferences_feedback",
        json!({
            "event_type": "override",
            "category": "workflow",
            "attribute": "prefers",
            "value": "Always verify tests"
        }),
    )?;
    assert!(feedback
        .get("created_claim_id")
        .and_then(Value::as_str)
        .is_some());

    let snapshots = call_tool(
        &client,
        host,
        port,
        16,
        "docdex_personal_preferences_snapshots",
        json!({ "limit": 10 }),
    )?;
    assert!(snapshots.get("total").and_then(Value::as_u64).unwrap_or(0) >= 1);
    let snapshot_id = snapshots
        .get("items")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(|item| item.get("id"))
        .and_then(Value::as_str)
        .ok_or("missing snapshot id")?
        .to_string();

    let snapshot = call_tool(
        &client,
        host,
        port,
        17,
        "docdex_personal_preferences_snapshot_read",
        json!({ "snapshot_id": snapshot_id }),
    )?;
    assert!(snapshot.get("summary").and_then(Value::as_str).is_some());

    let rebuilt = call_tool(
        &client,
        host,
        port,
        18,
        "docdex_personal_preferences_snapshots_rebuild",
        json!({}),
    )?;
    assert_eq!(rebuilt.get("created").and_then(Value::as_u64), Some(1));

    let clone_context = call_tool(
        &client,
        host,
        port,
        19,
        "docdex_clone_context",
        json!({
            "query": "local-first Rust tests",
            "mode": "project_build",
            "current_repo_root": "/tmp/repo-one"
        }),
    )?;
    assert!(clone_context
        .get("items")
        .and_then(Value::as_array)
        .map(|items| !items.is_empty())
        .unwrap_or(false));

    let clone_explain = call_tool(
        &client,
        host,
        port,
        20,
        "docdex_clone_explain",
        json!({
            "query": "local-first Rust tests",
            "mode": "project_build",
            "current_repo_root": "/tmp/repo-one"
        }),
    )?;
    assert!(clone_explain.get("pack").is_some());
    assert!(clone_explain
        .get("included_claims")
        .and_then(Value::as_array)
        .map(|items| !items.is_empty())
        .unwrap_or(false));
    assert!(clone_explain
        .get("pack")
        .and_then(|pack| pack.get("trace"))
        .and_then(Value::as_array)
        .map(|items| !items.is_empty())
        .unwrap_or(false));

    let clone_evaluate = call_tool(
        &client,
        host,
        port,
        21,
        "docdex_clone_evaluate",
        json!({
            "query": "local-first Rust tests",
            "mode": "project_build",
            "current_repo_root": "/tmp/repo-one"
        }),
    )?;
    assert!(
        clone_evaluate
            .get("overall_score")
            .and_then(Value::as_f64)
            .unwrap_or(-1.0)
            >= 0.0
    );

    server.shutdown();
    Ok(())
}
