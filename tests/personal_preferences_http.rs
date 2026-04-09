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
    Ok(())
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
    let transcript_dir = home_dir.join(".codex").join("sessions");
    fs::create_dir_all(&transcript_dir)?;
    fs::write(
        transcript_dir.join("scan-session.jsonl"),
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
    assert_eq!(
        applied.get("derived_deleted").and_then(Value::as_u64),
        Some(1)
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
