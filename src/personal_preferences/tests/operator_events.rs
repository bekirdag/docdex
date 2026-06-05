use super::*;
use std::fs;

#[test]
fn operator_events_record_sanitized_commands_and_update_status() -> Result<()> {
    let temp = TempDir::new()?;
    let store = PersonalPreferencesStore::new(temp.path())?;

    let event = store.record_operator_event(
        PersonalPreferenceOperatorEventRequest {
            event_kind: None,
            action: "cargo test personal_preferences::".to_string(),
            summary: Some("Run targeted personal preferences tests".to_string()),
            command_text: Some(
                "API_TOKEN=supersecret cargo test personal_preferences::".to_string(),
            ),
            source_session_id: Some("session-operator".to_string()),
            repo_id: Some("repo-1".to_string()),
            repo_root: Some("/tmp/repo-one".to_string()),
            capture_id: None,
            artifact_path: None,
            occurred_at_ms: Some(100),
            metadata: Value::Null,
        },
        "unit_test",
    )?;

    assert_eq!(event.event_kind, OPERATOR_EVENT_KIND_TEST_ACTION);
    assert_eq!(event.source, "unit_test");
    let command_text = event.command_text.as_deref().unwrap_or_default();
    assert!(command_text.contains("[redacted]"));
    assert!(!command_text.contains("supersecret"));

    let listed = store.list_operator_events(
        Some(OPERATOR_EVENT_KIND_TEST_ACTION),
        None,
        Some("/tmp/repo-one"),
        20,
        0,
    )?;
    assert_eq!(listed.total, 1);
    assert_eq!(listed.items[0].id, event.id);

    let status = store.status()?;
    assert_eq!(status.operator_events_total, 1);
    assert!(!status.clone_readiness.action_telemetry_ready);
    assert!(status.clone_readiness.metrics.iter().any(|metric| {
        metric.id == "operator_events" && metric.observed == 1 && metric.target >= 1
    }));
    Ok(())
}

#[test]
fn operator_artifact_scan_captures_planning_files_once() -> Result<()> {
    let store_root = TempDir::new()?;
    let repo = TempDir::new()?;
    let store = PersonalPreferencesStore::new(store_root.path())?;
    fs::create_dir_all(repo.path().join(".git"))?;
    fs::create_dir_all(repo.path().join("docs/planning"))?;
    fs::create_dir_all(repo.path().join("docs/sds"))?;
    fs::write(
        repo.path()
            .join("docs/planning/mind_clone_goal_gap_closure_progress.md"),
        "# Progress\n\n- Operator event capture in progress.\n",
    )?;
    fs::write(
        repo.path().join("docs/sds/mind_clone_sds.md"),
        "# SDS\n\nOperator clone behavior requirements.\n",
    )?;

    let first = store.scan_operator_artifacts(repo.path(), Some(20))?;
    assert_eq!(first.scanned_files, 2);
    assert_eq!(first.created_events, 2);
    assert_eq!(first.skipped_existing, 0);
    assert_eq!(first.items.len(), 2);
    assert!(first
        .items
        .iter()
        .all(|event| event.event_kind == OPERATOR_EVENT_KIND_ARTIFACT_UPDATE));

    let second = store.scan_operator_artifacts(repo.path(), Some(20))?;
    assert_eq!(second.scanned_files, 2);
    assert_eq!(second.created_events, 0);
    assert_eq!(second.skipped_existing, 2);
    assert_eq!(store.status()?.operator_events_total, 2);
    Ok(())
}
