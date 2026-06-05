use super::*;

#[test]
fn dynamic_categories_are_preserved_and_sensitive_records_require_review() -> Result<()> {
    let temp = TempDir::new()?;
    let store = PersonalPreferencesStore::new(temp.path())?;
    let capture = store.capture_conversation(sample_capture_request(), true, true)?;
    store.complete_capture(
        &capture.id,
        None,
        &[
            PersonalPreferenceDigestRecord {
                record_type: "preference".to_string(),
                category: "tech stack".to_string(),
                subcategory: None,
                subject: "user".to_string(),
                attribute: Some("prefers".to_string()),
                value: "Rust".to_string(),
                confidence: Some(0.91),
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
                confidence: Some(0.88),
                sensitivity: Some("sensitive".to_string()),
                evidence: Some("private detail".to_string()),
                metadata: Value::Null,
            },
        ],
    )?;
    let records = store.search_records("", 10)?;
    assert!(records.iter().any(|record| record.category == "tech_stack"));
    assert!(records.iter().any(|record| {
        record.category == "health_context" && record.review_status == REVIEW_STATUS_PENDING
    }));
    let categories = store.list_categories()?;
    assert!(categories
        .iter()
        .any(|category| category.category == "tech_stack"));
    Ok(())
}

#[test]
fn prune_retention_redacts_raw_and_deletes_old_derived_records() -> Result<()> {
    let temp = TempDir::new()?;
    let store = PersonalPreferencesStore::new(temp.path())?;
    let capture = store.capture_conversation(sample_capture_request(), true, true)?;
    store.complete_capture(
        &capture.id,
        None,
        &[PersonalPreferenceDigestRecord {
            record_type: "preference".to_string(),
            category: "coding_preference".to_string(),
            subcategory: None,
            subject: "user".to_string(),
            attribute: Some("prefers".to_string()),
            value: "Rust".to_string(),
            confidence: Some(0.95),
            sensitivity: Some("low".to_string()),
            evidence: Some("Rust".to_string()),
            metadata: Value::Null,
        }],
    )?;
    let cutoff = now_ms() - 3 * 24 * 60 * 60 * 1000;
    let conn = open_db(store.db_path())?;
    conn.execute(
        "UPDATE captured_conversations SET created_at_ms = ?2 WHERE id = ?1",
        params![capture.id, cutoff],
    )?;
    conn.execute(
        "UPDATE derived_records SET updated_at_ms = ?2 WHERE capture_id = ?1",
        params![capture.id, cutoff],
    )?;

    let preview = store.prune_retention(1, 1, false)?;
    assert_eq!(preview.raw_candidates, 1);
    assert_eq!(preview.derived_candidates, 1);
    let applied = store.prune_retention(1, 1, true)?;
    assert_eq!(applied.raw_redacted, 1);
    assert_eq!(applied.derived_deleted, 1);
    let capture = store.read_capture(&capture.id)?.expect("capture");
    assert_eq!(capture.transcript_text, REDACTED_TEXT);
    assert!(store.search_records("", 10)?.is_empty());
    Ok(())
}
