mod common;

use common::{pick_free_port, run_docdex_json, wait_for_health, TestServerHarness};
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

fn write_config(home_dir: &Path, global_state_dir: &Path) -> Result<(), Box<dyn Error>> {
    let config_dir = home_dir.join(".docdex");
    fs::create_dir_all(&config_dir)?;
    fs::write(
        config_dir.join("config.toml"),
        format!(
            "[core]\nglobal_state_dir = \"{}\"\n\n[personal_preferences]\nenabled = true\nprocess_in_background = false\ncapture_docdex_conversations = true\ncapture_conversation_hooks = true\ncapture_supported_client_transcripts = true\narchive_raw_conversations = true\n",
            common::toml_path(global_state_dir),
        ),
    )?;
    Ok(())
}

fn create_codex_scan_transcript(home_dir: &Path) -> Result<(), Box<dyn Error>> {
    let transcript_dir = home_dir.join(".codex").join("sessions");
    fs::create_dir_all(&transcript_dir)?;
    fs::write(
        transcript_dir.join("cli-scan.jsonl"),
        r#"{"type":"session_meta","timestamp":"2026-04-09T00:00:00Z","payload":{"id":"cli-scan","title":"CLI Scanned"}}
{"type":"event_msg","timestamp":"2026-04-09T00:00:01Z","payload":{"type":"user_message","text":"I prefer local-first automation and deterministic tests."}}
"#,
    )?;
    Ok(())
}

#[test]
fn cli_personal_preferences_commands_work_against_http_daemon() -> Result<(), Box<dyn Error>> {
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
    let base_url = format!("http://{host}:{port}");
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
    client
        .post(format!("{base_url}/v1/hooks/conversation"))
        .json(&json!({
            "action": "session_close_summarization",
            "source": "codex",
            "agent_id": "codex",
            "transcript_text": "user: Prefer local-first tooling.\nassistant: stored."
        }))
        .send()?
        .error_for_status()?;

    let status = run_docdex_json(
        home_dir.path(),
        &base_url,
        ["personal-preferences", "status"],
    )?;
    assert_eq!(
        status.get("captures_total").and_then(Value::as_u64),
        Some(2)
    );

    let categories = run_docdex_json(
        home_dir.path(),
        &base_url,
        ["personal-preferences", "categories"],
    )?;
    assert!(categories
        .as_array()
        .unwrap_or(&Vec::new())
        .iter()
        .any(|item| item.get("category").and_then(Value::as_str) == Some("tech_stack")));

    let list = run_docdex_json(
        home_dir.path(),
        &base_url,
        ["personal-preferences", "list", "--limit", "10"],
    )?;
    assert_eq!(list.get("total").and_then(Value::as_u64), Some(2));
    let capture_id = list
        .get("items")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(|item| item.get("id"))
        .and_then(Value::as_str)
        .ok_or("missing capture id")?
        .to_string();

    let read = run_docdex_json(
        home_dir.path(),
        &base_url,
        ["personal-preferences", "read", capture_id.as_str()],
    )?;
    assert!(read.get("archive_path").and_then(Value::as_str).is_some());

    let reviews = run_docdex_json(
        home_dir.path(),
        &base_url,
        [
            "personal-preferences",
            "reviews",
            "--status",
            "pending_review",
            "--limit",
            "10",
        ],
    )?;
    assert_eq!(reviews.get("total").and_then(Value::as_u64), Some(1));
    let record_id = reviews
        .get("items")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(|item| item.get("id"))
        .and_then(Value::as_str)
        .ok_or("missing review record id")?
        .to_string();

    let reviewed = run_docdex_json(
        home_dir.path(),
        &base_url,
        [
            "personal-preferences",
            "review",
            record_id.as_str(),
            "--verdict",
            "approved",
        ],
    )?;
    assert_eq!(
        reviewed.get("review_status").and_then(Value::as_str),
        Some("approved")
    );

    let exported = run_docdex_json(
        home_dir.path(),
        &base_url,
        [
            "personal-preferences",
            "export",
            "--capture-id",
            capture_id.as_str(),
        ],
    )?;
    assert_eq!(exported.get("captures").and_then(Value::as_u64), Some(1));

    let scanned = run_docdex_json(
        home_dir.path(),
        &base_url,
        ["personal-preferences", "scan", "--limit", "10"],
    )?;
    assert_eq!(
        scanned.get("captures_created").and_then(Value::as_u64),
        Some(1)
    );

    let deleted = run_docdex_json(
        home_dir.path(),
        &base_url,
        ["personal-preferences", "delete", capture_id.as_str()],
    )?;
    assert_eq!(deleted.get("deleted").and_then(Value::as_bool), Some(true));

    let prune = run_docdex_json(
        home_dir.path(),
        &base_url,
        [
            "personal-preferences",
            "prune",
            "--raw-retention-days",
            "1",
            "--derived-retention-days",
            "1",
        ],
    )?;
    assert!(prune.get("applied").and_then(Value::as_bool) == Some(false));

    let status_after_delete = run_docdex_json(
        home_dir.path(),
        &base_url,
        ["personal-preferences", "status"],
    )?;
    assert_eq!(
        status_after_delete
            .get("captures_total")
            .and_then(Value::as_u64),
        Some(2)
    );

    server.shutdown();
    Ok(())
}
