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
    fs::create_dir_all(repo_root.join("docs/planning"))?;
    fs::write(
        repo_root.join("docs/planning/operator_progress.md"),
        "# Progress\n\nOperator event capture MCP coverage.\n",
    )?;
    Ok(())
}

fn assert_generated_skill_quality_report(payload: &Value, skill_id: &str) {
    let quality = payload
        .get("quality")
        .expect("missing generated skill quality report");
    assert!(quality.get("total").and_then(Value::as_u64).unwrap_or(0) >= 1);
    assert!(quality
        .get("notes")
        .and_then(Value::as_array)
        .map(|items| !items.is_empty())
        .unwrap_or(false));
    let quality_item = quality
        .get("items")
        .and_then(Value::as_array)
        .and_then(|items| {
            items
                .iter()
                .find(|item| item.get("skill_id").and_then(Value::as_str) == Some(skill_id))
        })
        .expect("missing generated skill quality item");
    assert!(matches!(
        quality_item.get("recommendation").and_then(Value::as_str),
        Some("promote" | "keep" | "review" | "demote" | "quarantine")
    ));
    assert!(quality_item
        .get("reasons")
        .and_then(Value::as_array)
        .map(|items| !items.is_empty())
        .unwrap_or(false));
    assert!(
        quality_item
            .get("confidence")
            .and_then(Value::as_f64)
            .unwrap_or(0.0)
            > 0.0
    );
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
                        PersonalPreferenceDigestRecord {
                            record_type: "method".to_string(),
                            category: "workflow_method".to_string(),
                            subcategory: None,
                            subject: "user".to_string(),
                            attribute: Some("plan and progress".to_string()),
                            value: "Create a docs/planning implementation plan and keep a separate progress markdown file.".to_string(),
                            confidence: Some(0.95),
                            sensitivity: Some("low".to_string()),
                            evidence: Some("make an implementation plan and keep your progress on another md file".to_string()),
                            metadata: Value::Null,
                        },
                        PersonalPreferenceDigestRecord {
                            record_type: "method".to_string(),
                            category: "workflow_method".to_string(),
                            subcategory: None,
                            subject: "user".to_string(),
                            attribute: Some("repo inspection and DAG".to_string()),
                            value: "Inspect the repo with Docdex search, symbols, impact graph, and DAG before code changes.".to_string(),
                            confidence: Some(0.92),
                            sensitivity: Some("low".to_string()),
                            evidence: Some("use Docdex search, symbols, impact graph, and DAG before code changes".to_string()),
                            metadata: Value::Null,
                        },
                        PersonalPreferenceDigestRecord {
                            record_type: "method".to_string(),
                            category: "quality_bar".to_string(),
                            subcategory: None,
                            subject: "user".to_string(),
                            attribute: Some("tests and validation".to_string()),
                            value: "Run targeted tests and record validation evidence before release work.".to_string(),
                            confidence: Some(0.93),
                            sensitivity: Some("low".to_string()),
                            evidence: Some("run tests and record validation evidence".to_string()),
                            metadata: Value::Null,
                        },
                        PersonalPreferenceDigestRecord {
                            record_type: "method".to_string(),
                            category: "delivery_preference".to_string(),
                            subcategory: None,
                            subject: "user".to_string(),
                            attribute: Some("git deploy backup".to_string()),
                            value: "After validation, use the git commit, tag, push, deploy, and backup routine when requested.".to_string(),
                            confidence: Some(0.91),
                            sensitivity: Some("low".to_string()),
                            evidence: Some("commit, tag, push, deploy, and backup after validation".to_string()),
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
    let clone_readiness = status
        .get("clone_readiness")
        .and_then(Value::as_object)
        .ok_or("missing clone readiness")?;
    assert!(clone_readiness
        .get("metrics")
        .and_then(Value::as_array)
        .is_some_and(|items| !items.is_empty()));

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

    let operator_event = call_tool(
        &client,
        host,
        port,
        30,
        "docdex_personal_preferences_operator_event_record",
        json!({
            "action": "cargo test personal_preferences::",
            "summary": "Run targeted personal-preferences tests",
            "command_text": "API_TOKEN=supersecret cargo test personal_preferences::"
        }),
    )?;
    assert_eq!(
        operator_event.get("event_kind").and_then(Value::as_str),
        Some("test_action")
    );
    assert!(!operator_event
        .get("command_text")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .contains("supersecret"));

    let artifact_scan = call_tool(
        &client,
        host,
        port,
        31,
        "docdex_personal_preferences_operator_events_scan_artifacts",
        json!({ "limit": 10 }),
    )?;
    assert!(
        artifact_scan
            .get("created_events")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            >= 1
    );

    let operator_events = call_tool(
        &client,
        host,
        port,
        32,
        "docdex_personal_preferences_operator_events",
        json!({ "limit": 10 }),
    )?;
    assert!(
        operator_events
            .get("total")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            >= 2
    );

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

    let retention_policies = call_tool(
        &client,
        host,
        port,
        111,
        "docdex_personal_preferences_retention_policies",
        json!({}),
    )?;
    assert!(retention_policies
        .as_array()
        .unwrap_or(&Vec::new())
        .iter()
        .any(|policy| policy.get("lane").and_then(Value::as_str) == Some("raw_archive")));

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

    let routines = call_tool(
        &client,
        host,
        port,
        19,
        "docdex_personal_preferences_routines",
        json!({ "limit": 10 }),
    )?;
    assert!(routines.get("total").and_then(Value::as_u64).unwrap_or(0) >= 1);
    let routine_id = routines
        .get("items")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(|item| item.get("id"))
        .and_then(Value::as_str)
        .ok_or("missing routine id")?
        .to_string();

    let routine = call_tool(
        &client,
        host,
        port,
        20,
        "docdex_personal_preferences_routine_read",
        json!({ "routine_id": routine_id }),
    )?;
    let routine_id = routine
        .get("id")
        .and_then(Value::as_str)
        .ok_or("missing routine id in read response")?
        .to_string();
    assert!(routine
        .get("steps")
        .and_then(Value::as_array)
        .map(|items| !items.is_empty())
        .unwrap_or(false));
    assert!(routine.get("purpose").and_then(Value::as_str).is_some());
    assert!(routine.get("version").and_then(Value::as_u64).unwrap_or(0) >= 1);
    assert!(routine.get("risk_level").and_then(Value::as_str).is_some());
    assert!(routine
        .get("applies_when")
        .and_then(Value::as_array)
        .map(|items| !items.is_empty())
        .unwrap_or(false));
    let first_step = routine
        .get("steps")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .ok_or("missing routine step")?;
    assert_eq!(
        first_step.get("required").and_then(Value::as_bool),
        Some(true)
    );
    assert!(first_step
        .get("success_check")
        .and_then(Value::as_str)
        .map(|value| !value.is_empty())
        .unwrap_or(false));

    let routine_explain = call_tool(
        &client,
        host,
        port,
        21,
        "docdex_personal_preferences_routine_explain",
        json!({ "routine_id": routine_id }),
    )?;
    assert_eq!(
        routine_explain
            .get("routine")
            .and_then(|routine| routine.get("id"))
            .and_then(Value::as_str),
        Some(routine_id.as_str())
    );
    assert!(routine_explain
        .get("step_evidence")
        .and_then(Value::as_array)
        .map(|items| !items.is_empty())
        .unwrap_or(false));

    let routines_rebuilt = call_tool(
        &client,
        host,
        port,
        22,
        "docdex_personal_preferences_routines_rebuild",
        json!({}),
    )?;
    assert!(
        routines_rebuilt
            .get("total")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            >= 1
    );
    assert!(
        routines_rebuilt
            .get("executable_total")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            >= 1
    );

    let mind_map = call_tool(
        &client,
        host,
        port,
        23,
        "docdex_personal_preferences_mind_map",
        json!({
            "query": "how does the user ship a product fix",
            "limit": 40
        }),
    )?;
    assert!(mind_map
        .get("nodes")
        .and_then(Value::as_array)
        .map(|items| !items.is_empty())
        .unwrap_or(false));
    assert!(mind_map
        .get("edges")
        .and_then(Value::as_array)
        .map(|items| !items.is_empty())
        .unwrap_or(false));

    let playbooks = call_tool(
        &client,
        host,
        port,
        24,
        "docdex_personal_preferences_playbooks",
        json!({
            "min_confidence": 0.7,
            "min_support_count": 2
        }),
    )?;
    assert!(playbooks
        .get("items")
        .and_then(Value::as_array)
        .map(|items| !items.is_empty())
        .unwrap_or(false));

    let detected_integrations = call_tool(
        &client,
        host,
        port,
        240,
        "docdex_ai_terminal_detect",
        json!({
            "terminals": ["codex"]
        }),
    )?;
    assert!(detected_integrations
        .get("integrations")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .any(|item| item.get("terminal").and_then(Value::as_str) == Some("codex"))
        })
        .unwrap_or(false));
    assert!(detected_integrations
        .get("notes")
        .and_then(Value::as_array)
        .map(|notes| {
            notes.iter().any(|note| {
                note.as_str()
                    .is_some_and(|text| text.contains("non-mutating"))
            })
        })
        .unwrap_or(false));

    let terminal_integrations = call_tool(
        &client,
        host,
        port,
        241,
        "docdex_ai_terminal_integrations_bootstrap",
        json!({
            "terminals": ["codex"]
        }),
    )?;
    assert!(terminal_integrations
        .get("integrations")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .any(|item| item.get("terminal").and_then(Value::as_str) == Some("codex"))
        })
        .unwrap_or(false));

    let terminal_capture = call_tool(
        &client,
        host,
        port,
        242,
        "docdex_ai_terminal_capture",
        json!({
            "terminal": "codex",
            "source_session_id": "mcp-ai-terminal-session",
            "event_kind": "session_close",
            "repo_scope": "/tmp/repo-one",
            "agent_id": "codex",
            "summary": "User asked for plan, progress markdown, and tests before completion.",
            "metadata": { "test": "mcp" }
        }),
    )?;
    assert_eq!(
        terminal_capture.get("terminal").and_then(Value::as_str),
        Some("codex")
    );
    assert!(terminal_capture
        .get("capture_id")
        .and_then(Value::as_str)
        .is_some());

    let generated_sync = call_tool(
        &client,
        host,
        port,
        243,
        "docdex_personal_preferences_generated_skills_sync",
        json!({
            "min_confidence": 0.7,
            "min_support_count": 2,
            "include_sensitive": false,
            "install": false,
            "terminals": ["codex"]
        }),
    )?;
    assert!(
        generated_sync
            .get("rendered")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            >= 1
    );
    assert_eq!(
        generated_sync.get("installed").and_then(Value::as_u64),
        Some(0)
    );
    let generated_skill_id = generated_sync
        .get("items")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(|item| item.get("skill_id"))
        .and_then(Value::as_str)
        .ok_or("missing generated skill id")?
        .to_string();
    assert_generated_skill_quality_report(&generated_sync, &generated_skill_id);

    let generated_list = call_tool(
        &client,
        host,
        port,
        244,
        "docdex_personal_preferences_generated_skills",
        json!({}),
    )?;
    assert!(generated_list
        .get("items")
        .and_then(Value::as_array)
        .map(|items| !items.is_empty())
        .unwrap_or(false));
    assert_generated_skill_quality_report(&generated_list, &generated_skill_id);

    let generated_skill = call_tool(
        &client,
        host,
        port,
        245,
        "docdex_personal_preferences_generated_skill",
        json!({
            "skill_id": generated_skill_id.as_str()
        }),
    )?;
    assert_eq!(
        generated_skill.get("skill_id").and_then(Value::as_str),
        Some(generated_skill_id.as_str())
    );

    let terminal_status = call_tool(
        &client,
        host,
        port,
        246,
        "docdex_ai_terminal_status",
        json!({}),
    )?;
    assert!(
        terminal_status
            .get("capture_events_total")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            >= 1
    );
    assert!(
        terminal_status
            .get("generated_skills_total")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            >= 1
    );

    let terminal_events = call_tool(
        &client,
        host,
        port,
        247,
        "docdex_ai_terminal_events",
        json!({ "limit": 10 }),
    )?;
    assert!(terminal_events
        .get("items")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .any(|item| item.get("terminal").and_then(Value::as_str) == Some("codex"))
        })
        .unwrap_or(false));

    let generated_preview = call_tool(
        &client,
        host,
        port,
        248,
        "docdex_personal_preferences_generated_skills_preview",
        json!({
            "min_confidence": 0.7,
            "min_support_count": 2,
            "include_sensitive": false,
            "terminals": ["codex"]
        }),
    )?;
    assert!(
        generated_preview
            .get("rendered")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            >= 1
    );
    assert_eq!(
        generated_preview.get("installed").and_then(Value::as_u64),
        Some(0)
    );

    let generated_render = call_tool(
        &client,
        host,
        port,
        249,
        "docdex_personal_preferences_generated_skills_render",
        json!({
            "min_confidence": 0.7,
            "min_support_count": 2,
            "include_sensitive": false,
            "terminals": ["codex"]
        }),
    )?;
    assert!(generated_render
        .get("notes")
        .and_then(Value::as_array)
        .map(|notes| !notes.is_empty())
        .unwrap_or(false));

    let generated_autopilot = call_tool(
        &client,
        host,
        port,
        250,
        "docdex_personal_preferences_generated_skills_autopilot",
        json!({
            "min_confidence": 0.7,
            "min_support_count": 2,
            "include_sensitive": false,
            "install": false,
            "terminals": ["codex"]
        }),
    )?;
    assert_eq!(
        generated_autopilot.get("installed").and_then(Value::as_u64),
        Some(0)
    );
    assert!(generated_autopilot
        .get("notes")
        .and_then(Value::as_array)
        .map(|notes| {
            notes.iter().any(|note| {
                note.as_str()
                    .is_some_and(|text| text.contains("Autopilot one-shot processed"))
            })
        })
        .unwrap_or(false));
    assert_generated_skill_quality_report(&generated_autopilot, &generated_skill_id);

    let generated_validation = call_tool(
        &client,
        host,
        port,
        251,
        "docdex_personal_preferences_generated_skill_validate",
        json!({ "skill_id": generated_skill_id.as_str() }),
    )?;
    assert_eq!(
        generated_validation.get("action").and_then(Value::as_str),
        Some("validate")
    );
    assert_eq!(
        generated_validation
            .pointer("/validation/status")
            .and_then(Value::as_str),
        Some("passed")
    );

    let generated_events = call_tool(
        &client,
        host,
        port,
        252,
        "docdex_personal_preferences_generated_skill_events",
        json!({ "limit": 20 }),
    )?;
    assert!(generated_events
        .get("items")
        .and_then(Value::as_array)
        .map(|items| {
            items.iter().any(|item| {
                item.get("skill_id").and_then(Value::as_str) == Some(generated_skill_id.as_str())
                    && matches!(
                        item.get("event_kind").and_then(Value::as_str),
                        Some("rendered" | "validated")
                    )
            })
        })
        .unwrap_or(false));

    let disabled_skill = call_tool(
        &client,
        host,
        port,
        253,
        "docdex_personal_preferences_generated_skill_disable",
        json!({
            "skill_id": generated_skill_id.as_str(),
            "reason": "mcp integration test"
        }),
    )?;
    assert_eq!(
        disabled_skill.get("action").and_then(Value::as_str),
        Some("disable")
    );
    assert_eq!(
        disabled_skill
            .pointer("/skill/status")
            .and_then(Value::as_str),
        Some("disabled")
    );

    let rollback_skill = call_tool(
        &client,
        host,
        port,
        254,
        "docdex_personal_preferences_generated_skill_rollback",
        json!({
            "skill_id": generated_skill_id.as_str(),
            "terminals": ["codex"]
        }),
    )?;
    assert_eq!(
        rollback_skill.get("action").and_then(Value::as_str),
        Some("rollback")
    );
    assert_eq!(
        rollback_skill.get("rolled_back").and_then(Value::as_bool),
        Some(false)
    );

    let clone_context = call_tool(
        &client,
        host,
        port,
        25,
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

    let clone_directive = call_tool(
        &client,
        host,
        port,
        260,
        "docdex_clone_directive",
        json!({
            "query": "compare plan to codebase and complete missing gaps",
            "agent_id": "codex",
            "mode": "project_build",
            "current_repo_root": "/tmp/repo-one",
            "current_files": ["src/personal_preferences/mod.rs"],
            "current_plan_path": "docs/planning/operator_progress.md",
            "task_type": "implementation"
        }),
    )?;
    assert!(clone_directive
        .get("selected_routines")
        .and_then(Value::as_array)
        .map(|items| !items.is_empty())
        .unwrap_or(false));
    assert!(clone_directive
        .get("required_steps")
        .and_then(Value::as_array)
        .map(|items| !items.is_empty())
        .unwrap_or(false));

    let clone_explain = call_tool(
        &client,
        host,
        port,
        26,
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
        27,
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

    let replay_evaluate = call_tool(
        &client,
        host,
        port,
        28,
        "docdex_clone_replay_evaluate",
        json!({
            "query": "how does the user ship a product fix",
            "mode": "project_build",
            "current_repo_root": "/tmp/repo-one",
            "expected_categories": ["plan", "tests"]
        }),
    )?;
    assert!(
        replay_evaluate
            .get("overall_score")
            .and_then(Value::as_f64)
            .unwrap_or(-1.0)
            >= 0.0
    );

    let replay_dataset = call_tool(
        &client,
        host,
        port,
        29,
        "docdex_clone_replay_dataset",
        json!({
            "ci_subset": true,
            "limit": 3,
            "current_repo_root": "/tmp/repo-one"
        }),
    )?;
    assert!(
        replay_dataset
            .get("total")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            >= 1
    );
    assert!(replay_dataset
        .get("cases")
        .and_then(Value::as_array)
        .map(|items| !items.is_empty())
        .unwrap_or(false));

    let replay_suite = call_tool(
        &client,
        host,
        port,
        30,
        "docdex_clone_replay_suite",
        json!({
            "ci_subset": true,
            "limit": 3,
            "threshold": 0.0,
            "current_repo_root": "/tmp/repo-one"
        }),
    )?;
    assert!(
        replay_suite
            .pointer("/metrics/case_count")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            >= 1
    );
    assert!(replay_suite
        .get("results")
        .and_then(Value::as_array)
        .map(|items| !items.is_empty())
        .unwrap_or(false));

    server.shutdown();
    Ok(())
}
