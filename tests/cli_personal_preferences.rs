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
    fs::create_dir_all(repo_root.join("docs/planning"))?;
    fs::write(
        repo_root.join("docs/planning/operator_progress.md"),
        "# Progress\n\nOperator event capture CLI coverage.\n",
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
    let clone_readiness = status
        .get("clone_readiness")
        .and_then(Value::as_object)
        .ok_or("missing clone readiness")?;
    assert_eq!(
        clone_readiness
            .get("autonomy_ready")
            .and_then(Value::as_bool),
        Some(false)
    );
    assert!(clone_readiness
        .get("warnings")
        .and_then(Value::as_array)
        .is_some_and(|items| !items.is_empty()));

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
    let retention_policies = run_docdex_json(
        home_dir.path(),
        &base_url,
        ["personal-preferences", "retention-policies"],
    )?;
    assert!(retention_policies
        .as_array()
        .unwrap_or(&Vec::new())
        .iter()
        .any(|item| item.get("lane").and_then(Value::as_str) == Some("raw_archive")));

    let operator_event = run_docdex_json(
        home_dir.path(),
        &base_url,
        [
            "personal-preferences",
            "operator-events",
            "record",
            "--action",
            "cargo test personal_preferences::",
            "--summary",
            "Run targeted personal-preferences tests",
            "--command-text",
            "API_TOKEN=supersecret cargo test personal_preferences::",
        ],
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

    let artifact_scan = run_docdex_json(
        home_dir.path(),
        &base_url,
        [
            "personal-preferences",
            "operator-events",
            "scan-artifacts",
            "--limit",
            "10",
        ],
    )?;
    assert!(
        artifact_scan
            .get("created_events")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            >= 1
    );

    let operator_events = run_docdex_json(
        home_dir.path(),
        &base_url,
        [
            "personal-preferences",
            "operator-events",
            "list",
            "--limit",
            "10",
        ],
    )?;
    assert!(
        operator_events
            .get("total")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            >= 2
    );

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
    assert!(
        status_after_delete
            .get("operator_events_total")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            >= 2
    );

    server.shutdown();
    Ok(())
}

#[test]
fn cli_personal_preferences_mind_clone_commands_work() -> Result<(), Box<dyn Error>> {
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

    let claims = run_docdex_json(
        home_dir.path(),
        &base_url,
        [
            "personal-preferences",
            "claims",
            "list",
            "--limit",
            "10",
            "--include-sensitive",
        ],
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

    let claim = run_docdex_json(
        home_dir.path(),
        &base_url,
        ["personal-preferences", "claims", "read", claim_id.as_str()],
    )?;
    assert_eq!(
        claim.get("id").and_then(Value::as_str),
        Some(claim_id.as_str())
    );

    let reviewed = run_docdex_json(
        home_dir.path(),
        &base_url,
        [
            "personal-preferences",
            "claims",
            "review",
            claim_id.as_str(),
            "--verdict",
            "approved",
        ],
    )?;
    assert_eq!(
        reviewed.get("review_status").and_then(Value::as_str),
        Some("approved")
    );

    let overridden = run_docdex_json(
        home_dir.path(),
        &base_url,
        [
            "personal-preferences",
            "claims",
            "override",
            claim_id.as_str(),
            "--value",
            "Rust and Go",
        ],
    )?;
    assert_eq!(
        overridden.get("event_type").and_then(Value::as_str),
        Some("override_preference")
    );

    let forgotten = run_docdex_json(
        home_dir.path(),
        &base_url,
        [
            "personal-preferences",
            "claims",
            "forget",
            claim_id.as_str(),
            "--notes",
            "forget the superseded claim in cli test",
        ],
    )?;
    assert_eq!(
        forgotten.get("forgotten").and_then(Value::as_bool),
        Some(true)
    );

    let feedback = run_docdex_json(
        home_dir.path(),
        &base_url,
        [
            "personal-preferences",
            "feedback",
            "add",
            "--event-type",
            "override",
            "--category",
            "workflow",
            "--attribute",
            "prefers",
            "--value",
            "Always verify tests",
        ],
    )?;
    assert!(feedback
        .get("created_claim_id")
        .and_then(Value::as_str)
        .is_some());

    let snapshots = run_docdex_json(
        home_dir.path(),
        &base_url,
        ["personal-preferences", "snapshots", "list", "--limit", "10"],
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

    let snapshot = run_docdex_json(
        home_dir.path(),
        &base_url,
        [
            "personal-preferences",
            "snapshots",
            "read",
            snapshot_id.as_str(),
        ],
    )?;
    assert_eq!(
        snapshot.get("id").and_then(Value::as_str),
        Some(snapshot_id.as_str())
    );

    let rebuilt = run_docdex_json(
        home_dir.path(),
        &base_url,
        ["personal-preferences", "snapshots", "rebuild"],
    )?;
    assert_eq!(rebuilt.get("created").and_then(Value::as_u64), Some(1));

    let routines = run_docdex_json(
        home_dir.path(),
        &base_url,
        ["personal-preferences", "routines", "list", "--limit", "10"],
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

    let routine = run_docdex_json(
        home_dir.path(),
        &base_url,
        [
            "personal-preferences",
            "routines",
            "read",
            routine_id.as_str(),
        ],
    )?;
    assert_eq!(
        routine.get("id").and_then(Value::as_str),
        Some(routine_id.as_str())
    );
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

    let routine_explain = run_docdex_json(
        home_dir.path(),
        &base_url,
        [
            "personal-preferences",
            "routines",
            "explain",
            routine_id.as_str(),
        ],
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

    let routines_rebuilt = run_docdex_json(
        home_dir.path(),
        &base_url,
        ["personal-preferences", "routines", "rebuild"],
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

    let mind_map = run_docdex_json(
        home_dir.path(),
        &base_url,
        [
            "personal-preferences",
            "mind-map",
            "how does the user ship a product fix",
            "--limit",
            "40",
        ],
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

    let playbooks = run_docdex_json(
        home_dir.path(),
        &base_url,
        [
            "personal-preferences",
            "playbooks",
            "--min-confidence",
            "0.7",
            "--min-support-count",
            "2",
        ],
    )?;
    assert!(playbooks
        .get("items")
        .and_then(Value::as_array)
        .map(|items| !items.is_empty())
        .unwrap_or(false));

    let detected_integrations = run_docdex_json(
        home_dir.path(),
        &base_url,
        ["ai-terminals", "detect", "--all"],
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

    let terminal_integrations = run_docdex_json(
        home_dir.path(),
        &base_url,
        ["ai-terminals", "integrate", "--all"],
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

    let terminal_capture = run_docdex_json(
        home_dir.path(),
        &base_url,
        [
            "ai-terminals",
            "capture",
            "--terminal",
            "codex",
            "--source-session-id",
            "cli-ai-terminal-session",
            "--event-kind",
            "session-close",
            "--repo-scope",
            "/tmp/repo-one",
            "--agent-id",
            "codex",
            "--summary",
            "User asked for plan, progress markdown, and tests before completion.",
        ],
    )?;
    assert_eq!(
        terminal_capture.get("terminal").and_then(Value::as_str),
        Some("codex")
    );
    assert!(terminal_capture
        .get("capture_id")
        .and_then(Value::as_str)
        .is_some());

    let generated_sync = run_docdex_json(
        home_dir.path(),
        &base_url,
        [
            "personal-preferences",
            "skills",
            "sync",
            "--min-confidence",
            "0.7",
            "--min-support-count",
            "2",
            "--no-install",
            "--terminal",
            "codex",
        ],
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

    let generated_list = run_docdex_json(
        home_dir.path(),
        &base_url,
        ["personal-preferences", "skills", "list"],
    )?;
    assert!(generated_list
        .get("items")
        .and_then(Value::as_array)
        .map(|items| !items.is_empty())
        .unwrap_or(false));
    assert_generated_skill_quality_report(&generated_list, &generated_skill_id);

    let generated_skill = run_docdex_json(
        home_dir.path(),
        &base_url,
        [
            "personal-preferences",
            "skills",
            "read",
            generated_skill_id.as_str(),
        ],
    )?;
    assert_eq!(
        generated_skill.get("skill_id").and_then(Value::as_str),
        Some(generated_skill_id.as_str())
    );

    let terminal_status = run_docdex_json(home_dir.path(), &base_url, ["ai-terminals", "status"])?;
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

    let terminal_events = run_docdex_json(
        home_dir.path(),
        &base_url,
        ["ai-terminals", "events", "--limit", "10"],
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

    let generated_preview = run_docdex_json(
        home_dir.path(),
        &base_url,
        [
            "personal-preferences",
            "skills",
            "preview",
            "--min-confidence",
            "0.7",
            "--min-support-count",
            "2",
            "--terminal",
            "codex",
        ],
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

    let generated_render = run_docdex_json(
        home_dir.path(),
        &base_url,
        [
            "personal-preferences",
            "skills",
            "render",
            "--min-confidence",
            "0.7",
            "--min-support-count",
            "2",
            "--terminal",
            "codex",
        ],
    )?;
    assert_eq!(
        generated_render.get("installed").and_then(Value::as_u64),
        Some(0)
    );
    assert!(generated_render
        .get("notes")
        .and_then(Value::as_array)
        .map(|notes| !notes.is_empty())
        .unwrap_or(false));

    let generated_autopilot = run_docdex_json(
        home_dir.path(),
        &base_url,
        [
            "personal-preferences",
            "skills",
            "autopilot",
            "--once",
            "--no-install",
            "--terminal",
            "codex",
        ],
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

    let generated_validation = run_docdex_json(
        home_dir.path(),
        &base_url,
        [
            "personal-preferences",
            "skills",
            "validate",
            generated_skill_id.as_str(),
        ],
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

    let generated_events = run_docdex_json(
        home_dir.path(),
        &base_url,
        ["personal-preferences", "skills", "events", "--limit", "20"],
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

    let disabled_skill = run_docdex_json(
        home_dir.path(),
        &base_url,
        [
            "personal-preferences",
            "skills",
            "disable",
            generated_skill_id.as_str(),
            "--reason",
            "cli integration test",
        ],
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

    let rollback_skill = run_docdex_json(
        home_dir.path(),
        &base_url,
        [
            "personal-preferences",
            "skills",
            "rollback",
            generated_skill_id.as_str(),
            "--terminal",
            "codex",
        ],
    )?;
    assert_eq!(
        rollback_skill.get("action").and_then(Value::as_str),
        Some("rollback")
    );
    assert_eq!(
        rollback_skill.get("rolled_back").and_then(Value::as_bool),
        Some(false)
    );

    let clone_context = run_docdex_json(
        home_dir.path(),
        &base_url,
        [
            "personal-preferences",
            "clone",
            "context",
            "local-first Rust tests",
            "--mode",
            "project_build",
            "--current-repo-root",
            "/tmp/repo-one",
        ],
    )?;
    assert!(clone_context
        .get("items")
        .and_then(Value::as_array)
        .map(|items| !items.is_empty())
        .unwrap_or(false));

    let clone_directive = run_docdex_json(
        home_dir.path(),
        &base_url,
        [
            "personal-preferences",
            "clone",
            "directive",
            "compare plan to codebase and complete missing gaps",
            "--agent-id",
            "codex",
            "--mode",
            "project_build",
            "--current-repo-root",
            "/tmp/repo-one",
            "--current-file",
            "src/personal_preferences/mod.rs",
            "--current-plan-path",
            "docs/planning/operator_progress.md",
            "--task-type",
            "implementation",
        ],
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

    let clone_explain = run_docdex_json(
        home_dir.path(),
        &base_url,
        [
            "personal-preferences",
            "clone",
            "explain",
            "local-first Rust tests",
            "--mode",
            "project_build",
            "--current-repo-root",
            "/tmp/repo-one",
        ],
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

    let clone_evaluate = run_docdex_json(
        home_dir.path(),
        &base_url,
        [
            "personal-preferences",
            "clone",
            "evaluate",
            "local-first Rust tests",
            "--mode",
            "project_build",
            "--current-repo-root",
            "/tmp/repo-one",
        ],
    )?;
    assert!(
        clone_evaluate
            .get("overall_score")
            .and_then(Value::as_f64)
            .unwrap_or(-1.0)
            >= 0.0
    );

    let replay_evaluate = run_docdex_json(
        home_dir.path(),
        &base_url,
        [
            "personal-preferences",
            "clone",
            "replay-evaluate",
            "how does the user ship a product fix",
            "--mode",
            "project_build",
            "--current-repo-root",
            "/tmp/repo-one",
            "--expected-category",
            "plan",
            "--expected-category",
            "tests",
        ],
    )?;
    assert!(
        replay_evaluate
            .get("overall_score")
            .and_then(Value::as_f64)
            .unwrap_or(-1.0)
            >= 0.0
    );

    let replay_dataset = run_docdex_json(
        home_dir.path(),
        &base_url,
        [
            "personal-preferences",
            "clone",
            "replay-dataset",
            "--ci-subset",
            "--limit",
            "3",
            "--current-repo-root",
            "/tmp/repo-one",
        ],
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

    let replay_suite = run_docdex_json(
        home_dir.path(),
        &base_url,
        [
            "personal-preferences",
            "clone",
            "replay-suite",
            "--ci-subset",
            "--limit",
            "3",
            "--threshold",
            "0",
            "--current-repo-root",
            "/tmp/repo-one",
        ],
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
