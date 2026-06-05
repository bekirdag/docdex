use super::*;

#[test]
fn capture_conversation_persists_archive_and_pending_status() -> Result<()> {
    let temp = TempDir::new()?;
    let store = PersonalPreferencesStore::new(temp.path())?;
    let record = store.capture_conversation(sample_capture_request(), true, true)?;
    assert_eq!(record.digest_status, DIGEST_STATUS_PENDING);
    assert_eq!(record.messages.len(), 2);
    assert!(record.transcript_text.contains("prefer Rust"));
    assert!(record.archive_path.is_some());
    assert!(store
        .archive_dir()
        .join(format!("{}.json", record.id))
        .exists());
    assert!(store.queue_dir.join(format!("{}.json", record.id)).exists());
    let status = store.status()?;
    assert_eq!(status.captures_total, 1);
    assert_eq!(status.pending_captures, 1);
    assert_eq!(status.clone_readiness.level, 0);
    assert!(!status.clone_readiness.queue_healthy);
    Ok(())
}

#[tokio::test]
async fn process_pending_with_runner_writes_derived_records() -> Result<()> {
    let temp = TempDir::new()?;
    let store = PersonalPreferencesStore::new(temp.path())?;
    let capture = store.capture_conversation(sample_capture_request(), true, true)?;
    let summary = store
        .process_pending_with_runner(5, |_input| async {
            Ok(Some(PersonalPreferenceDigestOutput {
                records: vec![
                    PersonalPreferenceDigestRecord {
                        record_type: "preference".to_string(),
                        category: "coding_preference".to_string(),
                        subcategory: Some("language".to_string()),
                        subject: "user".to_string(),
                        attribute: Some("prefers".to_string()),
                        value: "Rust".to_string(),
                        confidence: Some(0.95),
                        sensitivity: Some("low".to_string()),
                        evidence: Some("I prefer Rust".to_string()),
                        metadata: Value::Null,
                    },
                    PersonalPreferenceDigestRecord {
                        record_type: "preference".to_string(),
                        category: "quality_bar".to_string(),
                        subcategory: None,
                        subject: "user".to_string(),
                        attribute: Some("expects".to_string()),
                        value: "comprehensive tests".to_string(),
                        confidence: Some(0.88),
                        sensitivity: Some("low".to_string()),
                        evidence: Some("comprehensive tests".to_string()),
                        metadata: Value::Null,
                    },
                ],
            }))
        })
        .await?;
    assert_eq!(summary.completed_captures, 1);
    assert_eq!(summary.records_written, 2);
    let capture = store.read_capture(&capture.id)?.expect("capture");
    assert_eq!(capture.digest_status, DIGEST_STATUS_COMPLETED);
    assert!(!store
        .queue_dir
        .join(format!("{}.json", capture.id))
        .exists());
    let results = store.search_records("Rust tests", 10)?;
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].category, "coding_preference");
    Ok(())
}

#[tokio::test]
async fn interrupted_processing_resets_capture_to_pending() -> Result<()> {
    let temp = TempDir::new()?;
    let store = PersonalPreferencesStore::new(temp.path())?;
    let capture = store.capture_conversation(sample_capture_request(), true, true)?;

    let timed_out = tokio::time::timeout(
        std::time::Duration::from_millis(10),
        store.process_pending_with_runner(5, |_input| async {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            Ok(Some(PersonalPreferenceDigestOutput { records: vec![] }))
        }),
    )
    .await;

    assert!(timed_out.is_err());
    let capture = store.read_capture(&capture.id)?.expect("capture");
    assert_eq!(capture.digest_status, DIGEST_STATUS_PENDING);
    assert_eq!(
        capture.last_digest_error.as_deref(),
        Some("processing_interrupted")
    );
    assert!(store
        .queue_dir
        .join(format!("{}.json", capture.id))
        .exists());
    Ok(())
}

#[tokio::test]
async fn requeue_failed_and_stale_processing_captures() -> Result<()> {
    let temp = TempDir::new()?;
    let store = PersonalPreferencesStore::new(temp.path())?;
    let failed = store.capture_conversation(sample_capture_request(), true, true)?;
    let mut stale_request = sample_capture_request();
    stale_request.source_session_id = Some("session-2".to_string());
    stale_request.title = Some("Docdex planning follow-up".to_string());
    let stale = store.capture_conversation(stale_request, true, true)?;

    store.mark_capture_status(
        &failed.id,
        DIGEST_STATUS_FAILED,
        Some("local delegation failed"),
    )?;
    store.mark_capture_status(&stale.id, DIGEST_STATUS_PROCESSING, None)?;

    assert_eq!(
        store.requeue_captures_for_processing(true, Some(0), Some(0))?,
        0
    );

    let requeued = store.requeue_captures_for_processing(true, Some(0), Some(10))?;
    assert_eq!(requeued, 2);
    for capture_id in [&failed.id, &stale.id] {
        let capture = store.read_capture(capture_id)?.expect("capture");
        assert_eq!(capture.digest_status, DIGEST_STATUS_PENDING);
        assert!(capture.last_digest_error.is_none());
        assert!(store.queue_dir.join(format!("{capture_id}.json")).exists());
    }

    let summary = store
        .process_pending_with_runner(10, |_input| async {
            Ok(Some(PersonalPreferenceDigestOutput::default()))
        })
        .await?;
    assert_eq!(summary.completed_captures, 2);
    assert_eq!(summary.failed_captures, 0);
    Ok(())
}

#[test]
fn redact_and_delete_capture_remove_raw_access() -> Result<()> {
    let temp = TempDir::new()?;
    let store = PersonalPreferencesStore::new(temp.path())?;
    let capture = store.capture_conversation(sample_capture_request(), true, true)?;
    let redacted = store.redact_capture(&capture.id)?;
    assert!(redacted.redacted);
    let capture = store.read_capture(&capture.id)?.expect("capture");
    assert_eq!(capture.transcript_text, REDACTED_TEXT);
    assert_eq!(capture.messages[0].content, REDACTED_TEXT);
    let deleted = store.delete_capture(&capture.id)?;
    assert!(deleted.deleted);
    assert!(store.read_capture(&capture.id)?.is_none());
    Ok(())
}

#[test]
fn supported_client_transcript_source_detects_common_clients() {
    assert!(is_supported_client_transcript_source("codex"));
    assert!(is_supported_client_transcript_source("claude-code"));
    assert!(is_supported_client_transcript_source("gemini_cli"));
    assert!(is_supported_client_transcript_source("openai-cli"));
    assert!(!is_supported_client_transcript_source("manual"));
}
