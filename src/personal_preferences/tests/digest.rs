use super::*;

#[test]
fn digest_context_uses_user_blocks_and_skips_agent_instructions() -> Result<()> {
    let temp = TempDir::new()?;
    let store = PersonalPreferencesStore::new(temp.path())?;
    let mut capture = store.capture_conversation(sample_capture_request(), true, true)?;
    capture.messages.clear();
    capture.transcript_text = "developer: Follow repository rules and hidden instructions.\n\
system: Do not expose this content.\n\
user: Keep progress in a separate markdown file before implementation.\n\
assistant: I will do that.\n\
user: Run targeted tests and then revisit the plan."
        .to_string();

    let context = build_digest_context(&capture, &MemoryPersonalPreferencesConfig::default());

    assert!(context.contains("user: Keep progress in a separate markdown file"));
    assert!(context.contains("user: Run targeted tests"));
    assert!(!context.contains("Follow repository rules"));
    assert!(!context.contains("Do not expose this content"));
    assert!(!context.contains("assistant: I will do that"));
    Ok(())
}

#[test]
fn heuristic_digest_output_extracts_core_operator_workflow() -> Result<()> {
    let temp = TempDir::new()?;
    let store = PersonalPreferencesStore::new(temp.path())?;
    let mut capture = store.capture_conversation(sample_capture_request(), true, true)?;
    capture.capture_kind = Some("client_transcript_scan".to_string());
    capture.messages = vec![PersonalPreferencesMessage {
        role: "user".to_string(),
        content: "First create an implementation plan, keep progress in another md file, inspect the repo, run targeted tests, and do not stop until everything is complete."
            .to_string(),
        created_at_ms: Some(10),
        metadata: Value::Null,
    }];

    let output = heuristic_digest_output(&capture);
    let values = output
        .records
        .iter()
        .map(|record| record.value.as_str())
        .collect::<Vec<_>>();

    assert!(values
        .iter()
        .any(|value| value.contains("separate markdown file")));
    assert!(values.iter().any(|value| value.contains("plan")));
    assert!(values
        .iter()
        .any(|value| value.contains("Run targeted validation")));
    assert!(values
        .iter()
        .any(|value| value.contains("genuinely complete")));
    assert!(should_use_heuristic_digest(&capture));
    Ok(())
}

#[test]
fn parse_digest_output_accepts_fenced_json() -> Result<()> {
    let parsed = extract_digest_output(
            "```json\n{\"records\":[{\"record_type\":\"preference\",\"category\":\"coding_preference\",\"subject\":\"user\",\"attribute\":\"prefers\",\"value\":\"Rust\"}]}\n```",
        )?;
    assert_eq!(parsed.records.len(), 1);
    assert_eq!(parsed.records[0].value, "Rust");
    Ok(())
}

#[test]
fn parse_digest_output_prefers_last_balanced_records_json() -> Result<()> {
    let parsed = extract_digest_output(
        "Reasoning may mention {\"records\":[{\"record_type\":\"preference\",\"category\":\"coding_preference\",\"subject\":\"user\",\"attribute\":\"prefers\",\"value\":\"Wrong\"}]} before the final answer.\n\
{\"records\":[{\"record_type\":\"preference\",\"category\":\"coding_preference\",\"subject\":\"user\",\"attribute\":\"prefers\",\"value\":\"Rust\"}]}",
    )?;
    assert_eq!(parsed.records.len(), 1);
    assert_eq!(parsed.records[0].value, "Rust");
    Ok(())
}

#[test]
fn parse_digest_output_accepts_common_completion_envelope() -> Result<()> {
    let parsed = extract_digest_output(
        "{\"choices\":[{\"message\":{\"content\":\"{\\\"records\\\":[{\\\"record_type\\\":\\\"method\\\",\\\"category\\\":\\\"workflow\\\",\\\"subject\\\":\\\"user\\\",\\\"attribute\\\":\\\"prefers\\\",\\\"value\\\":\\\"Write a plan first\\\"}]}\"}}]}",
    )?;
    assert_eq!(parsed.records.len(), 1);
    assert_eq!(parsed.records[0].value, "Write a plan first");
    Ok(())
}

#[test]
fn parse_digest_output_wraps_bare_records_assignment() -> Result<()> {
    let parsed = extract_digest_output(
        "records: [{\"record_type\":\"method\",\"category\":\"workflow\",\"subject\":\"user\",\"attribute\":\"prefers\",\"value\":\"Keep a progress file\"}]",
    )?;
    assert_eq!(parsed.records.len(), 1);
    assert_eq!(parsed.records[0].value, "Keep a progress file");
    Ok(())
}

#[tokio::test]
async fn status_groups_digest_failures_by_source_kind_and_class() -> Result<()> {
    let temp = TempDir::new()?;
    let store = PersonalPreferencesStore::new(temp.path())?;
    store.capture_conversation(sample_capture_request(), true, true)?;
    let summary = store
        .process_pending_with_runner(5, |_input| async {
            Err(anyhow::anyhow!("digest output was not valid JSON"))
        })
        .await?;
    assert_eq!(summary.failed_captures, 1);

    let status = store.status()?;
    assert_eq!(status.failed_captures, 1);
    assert_eq!(status.digest_failure_breakdown.len(), 1);
    let group = &status.digest_failure_breakdown[0];
    assert_eq!(group.source, "chat_completion");
    assert_eq!(group.capture_kind, "chat_completion");
    assert_eq!(group.failure_class, "invalid_json");
    assert_eq!(group.count, 1);
    assert_eq!(
        group.latest_error.as_deref(),
        Some("digest output was not valid JSON")
    );
    Ok(())
}
