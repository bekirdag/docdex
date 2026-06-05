mod common;

use common::{pick_free_port, wait_for_health, TestServerHarness};
use docdexd::personal_preferences::{
    PersonalPreferenceDigestOutput, PersonalPreferenceDigestRecord,
    PersonalPreferencesCaptureRequest, PersonalPreferencesMessage, PersonalPreferencesStore,
};
use reqwest::blocking::Client;
use rusqlite::{params, Connection};
use serde_json::{json, Value};
use std::error::Error;
use std::fs;
use std::path::Path;
use std::time::Duration;
use tempfile::TempDir;

fn write_repo(repo_root: &Path) -> Result<(), Box<dyn Error>> {
    fs::create_dir_all(repo_root.join(".git"))?;
    fs::write(
        repo_root.join("README.md"),
        "# Repo\n\nThis repo uses Rust and local-first tooling.\n",
    )?;
    fs::create_dir_all(repo_root.join("docs/planning"))?;
    fs::write(
        repo_root.join("docs/planning/operator_progress.md"),
        "# Progress\n\nOperator event capture is being implemented.\n",
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

fn seed_processed_personal_preferences(home_dir: &Path) -> Result<(), Box<dyn Error>> {
    let store_root = home_dir.join(".docdex").join("personal_preferences");
    let store = PersonalPreferencesStore::new(&store_root)?;
    let capture = store.capture_conversation(
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
                content: "I prefer Rust and shared local-first patterns.".to_string(),
                created_at_ms: Some(10),
                metadata: Value::Null,
            }],
            transcript_text: Some(
                "user: I prefer Rust and shared local-first patterns.".to_string(),
            ),
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
    let conn = Connection::open(store.db_path())?;
    let old_ms = 1;
    conn.execute(
        "UPDATE captured_conversations SET created_at_ms = ?2 WHERE id = ?1",
        params![capture.id, old_ms],
    )?;
    conn.execute(
        "UPDATE derived_records SET updated_at_ms = ?1",
        params![old_ms],
    )?;
    Ok(())
}

fn write_config(home_dir: &Path, global_state_dir: &Path) -> Result<(), Box<dyn Error>> {
    let config_dir = home_dir.join(".docdex");
    fs::create_dir_all(&config_dir)?;
    fs::write(
        config_dir.join("config.toml"),
        format!(
            "[core]\nglobal_state_dir = \"{}\"\n\n[personal_preferences]\nenabled = true\nprocess_in_background = false\ncapture_docdex_conversations = true\ncapture_conversation_hooks = true\ncapture_imported_conversations = true\narchive_raw_conversations = true\n",
            common::toml_path(global_state_dir),
        ),
    )?;
    Ok(())
}

fn create_codex_scan_transcript(home_dir: &Path) -> Result<(), Box<dyn Error>> {
    let transcript_dir = home_dir
        .join(".codex")
        .join("sessions")
        .join("2026")
        .join("04")
        .join("09");
    fs::create_dir_all(&transcript_dir)?;
    fs::write(
        transcript_dir.join("rollout-2026-04-09T00-00-00-scan-session.jsonl"),
        r#"{"type":"session_meta","timestamp":"2026-04-09T00:00:00Z","payload":{"id":"scan-session","title":"Scanned session"}}
{"type":"event_msg","timestamp":"2026-04-09T00:00:01Z","payload":{"type":"user_message","text":"I prefer local-first Rust tooling and deterministic tests."}}
"#,
    )?;
    Ok(())
}

#[test]
fn personal_preferences_http_controls_cover_capture_lifecycle() -> Result<(), Box<dyn Error>> {
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
    let mut server = TestServerHarness::spawn_basic(
        state_root.path(),
        home_dir.path(),
        repo.path(),
        host,
        port,
        false,
    )?;
    wait_for_health(host, port)?;

    let client = Client::builder().timeout(Duration::from_secs(5)).build()?;
    let base_url = format!("http://{host}:{port}");

    client
        .post(format!("{base_url}/v1/hooks/conversation"))
        .json(&json!({
            "action": "session_close_summarization",
            "source": "codex",
            "agent_id": "codex",
            "transcript_text": "user: I prefer Rust and local-first tooling.\nassistant: Noted."
        }))
        .send()?
        .error_for_status()?;

    client
        .post(format!("{base_url}/v1/chat/completions"))
        .json(&json!({
            "messages": [
                { "role": "user", "content": "Keep this project local-first and test-heavy." }
            ],
            "docdex": {
                "compress_results": true,
                "limit": 1
            }
        }))
        .send()?
        .error_for_status()?;

    client
        .post(format!("{base_url}/v1/conversations/import"))
        .json(&json!({
            "source": "manual",
            "title": "imported transcript",
            "agent_id": "codex",
            "transcript_text": "user: I reuse local-first patterns across tools.\nassistant: captured."
        }))
        .send()?
        .error_for_status()?;

    let status: Value = client
        .get(format!("{base_url}/v1/personal-preferences/status"))
        .send()?
        .json()?;
    assert_eq!(
        status.get("captures_total").and_then(Value::as_u64),
        Some(3)
    );
    assert!(status
        .get("storage_root")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .ends_with(".docdex/personal_preferences"));
    let clone_readiness = status
        .get("clone_readiness")
        .and_then(Value::as_object)
        .ok_or("missing clone readiness")?;
    assert!(clone_readiness
        .get("stage")
        .and_then(Value::as_str)
        .is_some());
    assert!(clone_readiness
        .get("metrics")
        .and_then(Value::as_array)
        .is_some_and(|items| !items.is_empty()));

    let operator_event: Value = client
        .post(format!(
            "{base_url}/v1/personal-preferences/operator-events"
        ))
        .json(&json!({
            "action": "cargo test personal_preferences::",
            "summary": "Run targeted personal-preferences tests",
            "command_text": "API_TOKEN=supersecret cargo test personal_preferences::",
            "repo_root": repo.path().display().to_string()
        }))
        .send()?
        .json()?;
    assert_eq!(
        operator_event.get("event_kind").and_then(Value::as_str),
        Some("test_action")
    );
    assert!(!operator_event
        .get("command_text")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .contains("supersecret"));

    let artifact_scan: Value = client
        .post(format!(
            "{base_url}/v1/personal-preferences/operator-events/scan-artifacts"
        ))
        .json(&json!({}))
        .send()?
        .json()?;
    assert!(
        artifact_scan
            .get("created_events")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            >= 1
    );

    let operator_events: Value = client
        .get(format!(
            "{base_url}/v1/personal-preferences/operator-events?limit=10"
        ))
        .send()?
        .json()?;
    assert!(
        operator_events
            .get("total")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            >= 2
    );

    let captures: Value = client
        .get(format!(
            "{base_url}/v1/personal-preferences/captures?limit=10&offset=0"
        ))
        .send()?
        .json()?;
    assert_eq!(captures.get("total").and_then(Value::as_u64), Some(3));
    let first_capture_id = captures
        .get("items")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(|item| item.get("id"))
        .and_then(Value::as_str)
        .ok_or("missing capture id")?
        .to_string();

    let read: Value = client
        .get(format!(
            "{base_url}/v1/personal-preferences/captures/{first_capture_id}"
        ))
        .send()?
        .json()?;
    assert!(read
        .get("archive_path")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .ends_with(".json"));
    assert!(
        read.get("raw_message_count")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            >= 1
    );

    let exported: Value = client
        .post(format!("{base_url}/v1/personal-preferences/export"))
        .json(&json!({ "capture_id": first_capture_id }))
        .send()?
        .json()?;
    assert_eq!(exported.get("captures").and_then(Value::as_u64), Some(1));

    let redacted: Value = client
        .post(format!(
            "{base_url}/v1/personal-preferences/captures/{first_capture_id}/redact"
        ))
        .send()?
        .json()?;
    assert_eq!(
        redacted.get("redacted").and_then(Value::as_bool),
        Some(true)
    );

    let read_after_redact: Value = client
        .get(format!(
            "{base_url}/v1/personal-preferences/captures/{first_capture_id}"
        ))
        .send()?
        .json()?;
    assert_eq!(
        read_after_redact
            .get("transcript_text")
            .and_then(Value::as_str),
        Some("[redacted]")
    );

    let deleted: Value = client
        .delete(format!(
            "{base_url}/v1/personal-preferences/captures/{first_capture_id}"
        ))
        .send()?
        .json()?;
    assert_eq!(deleted.get("deleted").and_then(Value::as_bool), Some(true));

    let purge: Value = client
        .post(format!("{base_url}/v1/personal-preferences/purge"))
        .json(&json!({ "include_exports": true }))
        .send()?
        .json()?;
    assert_eq!(
        purge.get("captures_deleted").and_then(Value::as_u64),
        Some(2)
    );

    let status_after_purge: Value = client
        .get(format!("{base_url}/v1/personal-preferences/status"))
        .send()?
        .json()?;
    assert_eq!(
        status_after_purge
            .get("captures_total")
            .and_then(Value::as_u64),
        Some(0)
    );
    assert_eq!(
        status_after_purge
            .get("operator_events_total")
            .and_then(Value::as_u64),
        Some(0)
    );

    server.shutdown();
    Ok(())
}

#[test]
fn personal_preferences_http_categories_reviews_and_prune_work() -> Result<(), Box<dyn Error>> {
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
        false,
    )?;
    wait_for_health(host, port)?;

    let client = Client::builder().timeout(Duration::from_secs(5)).build()?;
    let base_url = format!("http://{host}:{port}");

    let categories: Value = client
        .get(format!("{base_url}/v1/personal-preferences/categories"))
        .send()?
        .json()?;
    assert!(categories
        .as_array()
        .unwrap_or(&Vec::new())
        .iter()
        .any(|item| item.get("category").and_then(Value::as_str) == Some("tech_stack")));

    let reviews: Value = client
        .get(format!(
            "{base_url}/v1/personal-preferences/reviews?status=pending_review"
        ))
        .send()?
        .json()?;
    assert_eq!(reviews.get("total").and_then(Value::as_u64), Some(1));
    let record_id = reviews
        .get("items")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(|item| item.get("id"))
        .and_then(Value::as_str)
        .ok_or("missing review record id")?
        .to_string();

    let reviewed: Value = client
        .post(format!(
            "{base_url}/v1/personal-preferences/reviews/{record_id}"
        ))
        .json(&json!({
            "verdict": "approved",
            "notes": "explicitly approved in test"
        }))
        .send()?
        .json()?;
    assert_eq!(
        reviewed.get("review_status").and_then(Value::as_str),
        Some("approved")
    );

    let search: Value = client
        .get(format!(
            "{base_url}/v1/personal-preferences/search?q=Rust&include_sensitive=true"
        ))
        .send()?
        .json()?;
    assert_eq!(search.get("query").and_then(Value::as_str), Some("Rust"));
    assert!(search
        .get("items")
        .and_then(Value::as_array)
        .map(|items| !items.is_empty())
        .unwrap_or(false));

    let preview: Value = client
        .post(format!("{base_url}/v1/personal-preferences/prune"))
        .json(&json!({
            "raw_retention_days": 1,
            "derived_retention_days": 1,
            "apply": false
        }))
        .send()?
        .json()?;
    assert_eq!(
        preview.get("raw_candidates").and_then(Value::as_u64),
        Some(1)
    );

    let applied: Value = client
        .post(format!("{base_url}/v1/personal-preferences/prune"))
        .json(&json!({
            "raw_retention_days": 1,
            "derived_retention_days": 1,
            "apply": true
        }))
        .send()?
        .json()?;
    assert_eq!(applied.get("raw_redacted").and_then(Value::as_u64), Some(1));
    assert!(
        applied
            .get("derived_deleted")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            >= 1
    );

    server.shutdown();
    Ok(())
}

#[test]
fn personal_preferences_supported_client_transcripts_capture_even_when_import_capture_is_off(
) -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    let state_root = TempDir::new()?;
    let home_dir = TempDir::new()?;
    write_repo(repo.path())?;
    let global_state_dir = home_dir.path().join(".docdex").join("state");
    let config_dir = home_dir.path().join(".docdex");
    fs::create_dir_all(&config_dir)?;
    fs::write(
        config_dir.join("config.toml"),
        format!(
            "[core]\nglobal_state_dir = \"{}\"\n\n[personal_preferences]\nenabled = true\nprocess_in_background = false\ncapture_imported_conversations = false\ncapture_supported_client_transcripts = true\narchive_raw_conversations = true\n",
            common::toml_path(&global_state_dir),
        ),
    )?;

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
    wait_for_health(host, port)?;

    let client = Client::builder().timeout(Duration::from_secs(5)).build()?;
    let base_url = format!("http://{host}:{port}");
    client
        .post(format!("{base_url}/v1/conversations/import"))
        .json(&json!({
            "source": "claude",
            "title": "supported transcript",
            "agent_id": "codex",
            "transcript_text": "user: keep it local-first\nassistant: ok"
        }))
        .send()?
        .error_for_status()?;
    let status: Value = client
        .get(format!("{base_url}/v1/personal-preferences/status"))
        .send()?
        .json()?;
    assert_eq!(
        status.get("captures_total").and_then(Value::as_u64),
        Some(1)
    );

    server.shutdown();
    Ok(())
}

#[test]
fn personal_preferences_scan_handler_imports_supported_client_transcripts(
) -> Result<(), Box<dyn Error>> {
    let repo = TempDir::new()?;
    let state_root = TempDir::new()?;
    let home_dir = TempDir::new()?;
    write_repo(repo.path())?;
    let global_state_dir = home_dir.path().join(".docdex").join("state");
    let config_dir = home_dir.path().join(".docdex");
    fs::create_dir_all(&config_dir)?;
    fs::write(
        config_dir.join("config.toml"),
        format!(
            "[core]\nglobal_state_dir = \"{}\"\n\n[personal_preferences]\nenabled = true\nprocess_in_background = false\ncapture_supported_client_transcripts = true\narchive_raw_conversations = true\n",
            common::toml_path(&global_state_dir),
        ),
    )?;
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
        false,
    )?;
    wait_for_health(host, port)?;

    let client = Client::builder().timeout(Duration::from_secs(5)).build()?;
    let base_url = format!("http://{host}:{port}");
    let first_scan: Value = client
        .post(format!("{base_url}/v1/personal-preferences/scan"))
        .json(&json!({ "limit": 10 }))
        .send()?
        .json()?;
    assert_eq!(
        first_scan.get("captures_created").and_then(Value::as_u64),
        Some(1)
    );
    assert_eq!(
        first_scan.get("sessions_detected").and_then(Value::as_u64),
        Some(1)
    );

    let second_scan: Value = client
        .post(format!("{base_url}/v1/personal-preferences/scan"))
        .json(&json!({ "limit": 10 }))
        .send()?
        .json()?;
    assert_eq!(
        second_scan.get("captures_created").and_then(Value::as_u64),
        Some(0)
    );
    assert_eq!(
        second_scan.get("skipped_existing").and_then(Value::as_u64),
        Some(1)
    );
    assert!(second_scan
        .get("last_scan_at_ms")
        .and_then(Value::as_i64)
        .is_some());

    let status: Value = client
        .get(format!("{base_url}/v1/personal-preferences/status"))
        .send()?
        .json()?;
    assert_eq!(
        status.get("captures_total").and_then(Value::as_u64),
        Some(1)
    );
    assert!(status
        .get("last_scan_at_ms")
        .and_then(Value::as_i64)
        .is_some());
    assert_eq!(
        status
            .get("automation")
            .and_then(|value| value.get("process_in_background"))
            .and_then(Value::as_bool),
        Some(false)
    );
    assert_eq!(
        status
            .get("automation")
            .and_then(|value| value.get("freshness_risk"))
            .and_then(Value::as_bool),
        Some(true)
    );

    let captures: Value = client
        .get(format!(
            "{base_url}/v1/personal-preferences/captures?limit=10"
        ))
        .send()?
        .json()?;
    let capture = captures
        .get("items")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .ok_or("missing scanned capture")?;
    assert_eq!(capture.get("source").and_then(Value::as_str), Some("codex"));
    assert_eq!(
        capture.get("capture_kind").and_then(Value::as_str),
        Some("client_transcript_scan")
    );

    server.shutdown();
    Ok(())
}

#[test]
fn personal_preferences_http_mind_clone_surfaces_work() -> Result<(), Box<dyn Error>> {
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
        false,
    )?;
    wait_for_health(host, port)?;

    let client = Client::builder().timeout(Duration::from_secs(5)).build()?;
    let base_url = format!("http://{host}:{port}");

    let claims: Value = client
        .get(format!(
            "{base_url}/v1/personal-preferences/claims?limit=10&include_sensitive=true"
        ))
        .send()?
        .json()?;
    assert!(claims.get("total").and_then(Value::as_u64).unwrap_or(0) >= 2);
    let claim_id = claims
        .get("items")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(|item| item.get("id"))
        .and_then(Value::as_str)
        .ok_or("missing claim id")?
        .to_string();

    let claim: Value = client
        .get(format!(
            "{base_url}/v1/personal-preferences/claims/{claim_id}"
        ))
        .send()?
        .json()?;
    assert_eq!(
        claim.get("id").and_then(Value::as_str),
        Some(claim_id.as_str())
    );

    let retention_policies: Value = client
        .get(format!(
            "{base_url}/v1/personal-preferences/retention-policies"
        ))
        .send()?
        .json()?;
    let retention_policy_items = retention_policies
        .as_array()
        .ok_or("retention policies response must be an array")?;
    assert!(retention_policy_items.len() >= 3);
    assert!(retention_policy_items
        .iter()
        .any(|policy| policy.get("lane").and_then(Value::as_str) == Some("raw_archive")));

    let reviewed: Value = client
        .post(format!(
            "{base_url}/v1/personal-preferences/claims/{claim_id}/review"
        ))
        .json(&json!({
            "verdict": "approved",
            "notes": "approved in http test"
        }))
        .send()?
        .json()?;
    assert_eq!(
        reviewed.get("review_status").and_then(Value::as_str),
        Some("approved")
    );

    let overridden: Value = client
        .post(format!(
            "{base_url}/v1/personal-preferences/claims/{claim_id}/override"
        ))
        .json(&json!({
            "value": "Rust and Go",
            "notes": "explicit override in http test"
        }))
        .send()?
        .json()?;
    assert_eq!(
        overridden.get("event_type").and_then(Value::as_str),
        Some("override_preference")
    );
    assert!(overridden
        .get("created_claim_id")
        .and_then(Value::as_str)
        .is_some());

    let forgotten: Value = client
        .post(format!(
            "{base_url}/v1/personal-preferences/claims/{claim_id}/forget"
        ))
        .json(&json!({
            "notes": "forget the superseded claim in http test"
        }))
        .send()?
        .json()?;
    assert_eq!(
        forgotten.get("forgotten").and_then(Value::as_bool),
        Some(true)
    );

    let feedback: Value = client
        .post(format!("{base_url}/v1/personal-preferences/feedback"))
        .json(&json!({
            "event_type": "override",
            "category": "workflow",
            "attribute": "prefers",
            "value": "Always verify tests before commit",
            "notes": "manual workflow correction"
        }))
        .send()?
        .json()?;
    assert_eq!(
        feedback.get("event_type").and_then(Value::as_str),
        Some("override_preference")
    );
    assert!(feedback
        .get("created_claim_id")
        .and_then(Value::as_str)
        .is_some());

    let snapshots: Value = client
        .get(format!(
            "{base_url}/v1/personal-preferences/snapshots?limit=10&offset=0"
        ))
        .send()?
        .json()?;
    assert!(snapshots.get("total").and_then(Value::as_u64).unwrap_or(0) >= 1);
    let snapshot_id = snapshots
        .get("items")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(|item| item.get("id"))
        .and_then(Value::as_str)
        .ok_or("missing snapshot id")?
        .to_string();

    let snapshot: Value = client
        .get(format!(
            "{base_url}/v1/personal-preferences/snapshots/{snapshot_id}"
        ))
        .send()?
        .json()?;
    assert_eq!(
        snapshot.get("id").and_then(Value::as_str),
        Some(snapshot_id.as_str())
    );

    let rebuilt: Value = client
        .post(format!(
            "{base_url}/v1/personal-preferences/snapshots/rebuild"
        ))
        .send()?
        .json()?;
    assert_eq!(rebuilt.get("created").and_then(Value::as_u64), Some(1));

    let routines: Value = client
        .get(format!(
            "{base_url}/v1/personal-preferences/routines?limit=10&offset=0"
        ))
        .send()?
        .json()?;
    assert!(routines.get("total").and_then(Value::as_u64).unwrap_or(0) >= 1);
    let routine_id = routines
        .get("items")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(|item| item.get("id"))
        .and_then(Value::as_str)
        .ok_or("missing routine id")?
        .to_string();

    let routine: Value = client
        .get(format!(
            "{base_url}/v1/personal-preferences/routines/{routine_id}"
        ))
        .send()?
        .json()?;
    assert_eq!(
        routine.get("id").and_then(Value::as_str),
        Some(routine_id.as_str())
    );
    assert!(routine
        .get("steps")
        .and_then(Value::as_array)
        .map(|steps| !steps.is_empty())
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

    let routine_explain: Value = client
        .get(format!(
            "{base_url}/v1/personal-preferences/routines/{routine_id}/explain"
        ))
        .send()?
        .json()?;
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

    let routines_rebuilt: Value = client
        .post(format!(
            "{base_url}/v1/personal-preferences/routines/rebuild"
        ))
        .send()?
        .json()?;
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

    let mind_map: Value = client
        .get(format!(
            "{base_url}/v1/personal-preferences/mind-map?query=how%20does%20the%20user%20ship%20a%20product%20fix&limit=40"
        ))
        .send()?
        .json()?;
    assert!(mind_map
        .get("nodes")
        .and_then(Value::as_array)
        .map(|nodes| !nodes.is_empty())
        .unwrap_or(false));
    assert!(mind_map
        .get("edges")
        .and_then(Value::as_array)
        .map(|edges| {
            edges.iter().any(|edge| {
                matches!(
                    edge.get("relation").and_then(Value::as_str),
                    Some("runs_routine" | "validates_with" | "commits_after")
                )
            })
        })
        .unwrap_or(false));

    let playbooks: Value = client
        .get(format!(
            "{base_url}/v1/personal-preferences/playbooks?min_confidence=0.7&min_support_count=2"
        ))
        .send()?
        .json()?;
    assert!(playbooks
        .get("items")
        .and_then(Value::as_array)
        .map(|items| {
            items.iter().any(|item| {
                item.get("skill_markdown")
                    .and_then(Value::as_str)
                    .map(|value| value.contains("SKILL.md") || value.contains("## Steps"))
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false));

    let detected_integrations: Value = client
        .post(format!("{base_url}/v1/ai-terminals/detect"))
        .json(&json!({ "terminals": ["codex"] }))
        .send()?
        .json()?;
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

    let terminal_integrations: Value = client
        .post(format!("{base_url}/v1/ai-terminals/integrations/bootstrap"))
        .json(&json!({ "terminals": ["codex"] }))
        .send()?
        .json()?;
    assert!(terminal_integrations
        .get("integrations")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .any(|item| item.get("terminal").and_then(Value::as_str) == Some("codex"))
        })
        .unwrap_or(false));

    let terminal_capture: Value = client
        .post(format!("{base_url}/v1/ai-terminals/capture"))
        .json(&json!({
            "terminal": "codex",
            "source_session_id": "http-ai-terminal-session",
            "event_kind": "session_close",
            "repo_scope": "/tmp/repo-one",
            "agent_id": "codex",
            "summary": "User asked for plan, progress markdown, and tests before completion.",
            "metadata": { "test": "http" }
        }))
        .send()?
        .json()?;
    assert_eq!(
        terminal_capture.get("terminal").and_then(Value::as_str),
        Some("codex")
    );
    assert!(terminal_capture
        .get("capture_id")
        .and_then(Value::as_str)
        .is_some());

    let generated_sync: Value = client
        .post(format!(
            "{base_url}/v1/personal-preferences/generated-skills/sync"
        ))
        .json(&json!({
            "min_confidence": 0.7,
            "min_support_count": 2,
            "include_sensitive": false,
            "install": false,
            "terminals": ["codex"]
        }))
        .send()?
        .json()?;
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
    assert!(generated_sync
        .get("items")
        .and_then(Value::as_array)
        .map(|items| {
            items.iter().any(|item| {
                item.pointer("/current_version/skill_markdown")
                    .and_then(Value::as_str)
                    .map(|value| value.contains("name:") && value.contains("description:"))
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false));

    let generated_list: Value = client
        .get(format!(
            "{base_url}/v1/personal-preferences/generated-skills"
        ))
        .send()?
        .json()?;
    assert!(generated_list
        .get("items")
        .and_then(Value::as_array)
        .map(|items| !items.is_empty())
        .unwrap_or(false));
    assert_generated_skill_quality_report(&generated_list, &generated_skill_id);

    let generated_skill: Value = client
        .get(format!(
            "{base_url}/v1/personal-preferences/generated-skills/{generated_skill_id}"
        ))
        .send()?
        .json()?;
    assert_eq!(
        generated_skill.get("skill_id").and_then(Value::as_str),
        Some(generated_skill_id.as_str())
    );

    let terminal_status: Value = client
        .get(format!("{base_url}/v1/ai-terminals/status"))
        .send()?
        .json()?;
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

    let terminal_events: Value = client
        .get(format!("{base_url}/v1/ai-terminals/events?limit=10"))
        .send()?
        .json()?;
    assert!(terminal_events
        .get("items")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .any(|item| item.get("terminal").and_then(Value::as_str) == Some("codex"))
        })
        .unwrap_or(false));

    let generated_preview: Value = client
        .post(format!(
            "{base_url}/v1/personal-preferences/generated-skills/preview"
        ))
        .json(&json!({
            "min_confidence": 0.7,
            "min_support_count": 2,
            "include_sensitive": false,
            "install": false,
            "terminals": ["codex"]
        }))
        .send()?
        .json()?;
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

    let generated_render: Value = client
        .post(format!(
            "{base_url}/v1/personal-preferences/generated-skills/render"
        ))
        .json(&json!({
            "min_confidence": 0.7,
            "min_support_count": 2,
            "include_sensitive": false,
            "install": false,
            "terminals": ["codex"]
        }))
        .send()?
        .json()?;
    assert!(generated_render
        .get("notes")
        .and_then(Value::as_array)
        .map(|notes| !notes.is_empty())
        .unwrap_or(false));

    let generated_autopilot: Value = client
        .post(format!(
            "{base_url}/v1/personal-preferences/generated-skills/autopilot"
        ))
        .json(&json!({
            "min_confidence": 0.7,
            "min_support_count": 2,
            "include_sensitive": false,
            "install": false,
            "terminals": ["codex"]
        }))
        .send()?
        .json()?;
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

    let generated_validation: Value = client
        .post(format!(
            "{base_url}/v1/personal-preferences/generated-skills/{generated_skill_id}/validate"
        ))
        .send()?
        .json()?;
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

    let generated_events: Value = client
        .get(format!(
            "{base_url}/v1/personal-preferences/generated-skills/events?limit=20"
        ))
        .send()?
        .json()?;
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

    let disabled_skill: Value = client
        .post(format!(
            "{base_url}/v1/personal-preferences/generated-skills/{generated_skill_id}/disable"
        ))
        .json(&json!({ "reason": "http integration test" }))
        .send()?
        .json()?;
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

    let rollback_skill: Value = client
        .post(format!(
            "{base_url}/v1/personal-preferences/generated-skills/{generated_skill_id}/rollback"
        ))
        .json(&json!({ "terminals": ["codex"] }))
        .send()?
        .json()?;
    assert_eq!(
        rollback_skill.get("action").and_then(Value::as_str),
        Some("rollback")
    );
    assert_eq!(
        rollback_skill.get("rolled_back").and_then(Value::as_bool),
        Some(false)
    );

    let clone_context: Value = client
        .post(format!("{base_url}/v1/personal-preferences/clone/context"))
        .json(&json!({
            "query": "local-first Rust tests",
            "mode": "project_build",
            "current_repo_root": "/tmp/repo-one",
            "max_records": 8,
            "budget_tokens": 256
        }))
        .send()?
        .json()?;
    assert_eq!(
        clone_context.get("mode").and_then(Value::as_str),
        Some("project_build")
    );
    assert!(clone_context
        .get("items")
        .and_then(Value::as_array)
        .map(|items| !items.is_empty())
        .unwrap_or(false));

    let clone_directive: Value = client
        .post(format!(
            "{base_url}/v1/personal-preferences/clone/directive"
        ))
        .json(&json!({
            "query": "compare plan to codebase and complete missing gaps",
            "agent_id": "codex",
            "mode": "project_build",
            "current_repo_root": "/tmp/repo-one",
            "current_files": ["src/personal_preferences/mod.rs"],
            "current_plan_path": "docs/planning/operator_progress.md",
            "task_type": "implementation"
        }))
        .send()?
        .json()?;
    assert_eq!(
        clone_directive.get("mode").and_then(Value::as_str),
        Some("project_build")
    );
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
    assert!(clone_directive
        .get("memory_to_load")
        .and_then(Value::as_array)
        .map(|items| items.iter().any(|item| item == "profile_memory:codex"))
        .unwrap_or(false));

    let clone_explain: Value = client
        .post(format!("{base_url}/v1/personal-preferences/clone/explain"))
        .json(&json!({
            "query": "local-first Rust tests",
            "mode": "project_build",
            "current_repo_root": "/tmp/repo-one"
        }))
        .send()?
        .json()?;
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

    let clone_eval: Value = client
        .post(format!("{base_url}/v1/personal-preferences/clone/evaluate"))
        .json(&json!({
            "query": "local-first Rust tests",
            "mode": "project_build",
            "current_repo_root": "/tmp/repo-one"
        }))
        .send()?
        .json()?;
    assert!(
        clone_eval
            .get("overall_score")
            .and_then(Value::as_f64)
            .unwrap_or(-1.0)
            >= 0.0
    );

    let replay_eval: Value = client
        .post(format!(
            "{base_url}/v1/personal-preferences/clone/replay-evaluate"
        ))
        .json(&json!({
            "query": "how does the user ship a product fix",
            "mode": "project_build",
            "current_repo_root": "/tmp/repo-one",
            "expected_categories": ["plan", "progress_update", "repo_inspection", "tests", "commit"]
        }))
        .send()?
        .json()?;
    assert!(replay_eval
        .get("expected_categories")
        .and_then(Value::as_array)
        .map(|items| items.len() >= 5)
        .unwrap_or(false));
    assert!(
        replay_eval
            .get("overall_score")
            .and_then(Value::as_f64)
            .unwrap_or(-1.0)
            >= 0.0
    );

    let replay_dataset: Value = client
        .post(format!(
            "{base_url}/v1/personal-preferences/clone/replay-dataset"
        ))
        .json(&json!({
            "ci_subset": true,
            "limit": 3,
            "current_repo_root": "/tmp/repo-one"
        }))
        .send()?
        .json()?;
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

    let replay_suite: Value = client
        .post(format!(
            "{base_url}/v1/personal-preferences/clone/replay-suite"
        ))
        .json(&json!({
            "ci_subset": true,
            "limit": 3,
            "threshold": 0.0,
            "current_repo_root": "/tmp/repo-one"
        }))
        .send()?
        .json()?;
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
