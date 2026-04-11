use super::*;
use tempfile::TempDir;

fn sample_capture_request() -> PersonalPreferencesCaptureRequest {
    PersonalPreferencesCaptureRequest {
        source: "chat_completion".to_string(),
        source_session_id: Some("session-1".to_string()),
        capture_kind: Some("chat_completion".to_string()),
        title: Some("Docdex planning".to_string()),
        agent_id: Some("codex".to_string()),
        transport: Some("http".to_string()),
        repo_id: Some("repo-1".to_string()),
        repo_root: Some("/tmp/repo-one".to_string()),
        scope_id: Some("repo-1".to_string()),
        scope_label: Some("/tmp/repo-one".to_string()),
        started_at_ms: Some(10),
        ended_at_ms: Some(20),
        messages: vec![
            PersonalPreferencesMessage {
                role: "user".to_string(),
                content: "I prefer Rust, local-first tools, and comprehensive tests.".to_string(),
                created_at_ms: Some(10),
                metadata: Value::Null,
            },
            PersonalPreferencesMessage {
                role: "assistant".to_string(),
                content: "Noted.".to_string(),
                created_at_ms: Some(20),
                metadata: Value::Null,
            },
        ],
        transcript_text: None,
        summary_text: None,
        metadata: serde_json::json!({ "source": "test" }),
    }
}

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

#[test]
fn build_context_limits_records_budget_and_sections() -> Result<()> {
    let temp = TempDir::new()?;
    let store = PersonalPreferencesStore::new(temp.path())?;
    let capture = store.capture_conversation(sample_capture_request(), true, true)?;
    store.complete_capture(
        &capture.id,
        None,
        &[
            PersonalPreferenceDigestRecord {
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
            },
            PersonalPreferenceDigestRecord {
                record_type: "context".to_string(),
                category: "health_context".to_string(),
                subcategory: None,
                subject: "user".to_string(),
                attribute: Some("shared".to_string()),
                value: "private health detail".to_string(),
                confidence: Some(0.95),
                sensitivity: Some("sensitive".to_string()),
                evidence: Some("private".to_string()),
                metadata: Value::Null,
            },
        ],
    )?;
    let context = store.build_context(
        "Rust",
        PersonalPreferencesContextOptions {
            max_records: 2,
            budget_tokens: 8,
            allow_sensitive: false,
            current_repo_root: Some("/tmp/repo-one".to_string()),
        },
    )?;
    assert_eq!(context.trace.available, 1);
    assert_eq!(context.trace.selected, 1);
    assert_eq!(context.items[0].category, "coding_preference");
    assert_eq!(context.items[0].section, "stable_preferences");
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
fn parse_digest_output_accepts_fenced_json() -> Result<()> {
    let parsed = extract_digest_output(
            "```json\n{\"records\":[{\"record_type\":\"preference\",\"category\":\"coding_preference\",\"subject\":\"user\",\"attribute\":\"prefers\",\"value\":\"Rust\"}]}\n```",
        )?;
    assert_eq!(parsed.records.len(), 1);
    assert_eq!(parsed.records[0].value, "Rust");
    Ok(())
}

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
fn claims_feedback_snapshots_and_clone_evaluation_work_together() -> Result<()> {
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
                confidence: Some(0.95),
                sensitivity: Some("low".to_string()),
                evidence: Some("I prefer Rust".to_string()),
                metadata: Value::Null,
            },
            PersonalPreferenceDigestRecord {
                record_type: "workflow".to_string(),
                category: "workflow".to_string(),
                subcategory: None,
                subject: "user".to_string(),
                attribute: Some("expects".to_string()),
                value: "comprehensive tests".to_string(),
                confidence: Some(0.92),
                sensitivity: Some("low".to_string()),
                evidence: Some("comprehensive tests".to_string()),
                metadata: Value::Null,
            },
            PersonalPreferenceDigestRecord {
                record_type: "goal".to_string(),
                category: "product_goals".to_string(),
                subcategory: None,
                subject: "user".to_string(),
                attribute: Some("prioritizes".to_string()),
                value: "local-first mind clone fidelity".to_string(),
                confidence: Some(0.9),
                sensitivity: Some("low".to_string()),
                evidence: Some("mind clone fidelity".to_string()),
                metadata: json!({ "goal_status": "active", "project_name": "docdex" }),
            },
        ],
    )?;

    let claims = store.list_claims(PersonalPreferencesClaimsQuery {
        query: Some("Rust".to_string()),
        truth_status: None,
        claim_origin: None,
        include_sensitive: true,
        limit: Some(10),
        offset: Some(0),
    })?;
    assert_eq!(claims.total, 3);
    let claim_id = claims.items[0].id.clone();

    let reviewed = store.review_claim(&claim_id, "approved", Some("approved in unit test"))?;
    assert_eq!(reviewed.review_status, REVIEW_STATUS_APPROVED);

    let feedback = store.add_feedback_event(
        "override",
        Some(&claim_id),
        Some(&capture.id),
        Some("tech_stack"),
        Some("prefers"),
        Some("Rust and Go"),
        Some("explicit correction"),
        Value::Null,
    )?;
    assert_eq!(feedback.event_type, FEEDBACK_EVENT_OVERRIDE_PREFERENCE);
    assert!(feedback.created_claim_id.is_some());
    assert!(feedback.created_snapshot_id.is_some());

    let snapshots = store.list_snapshots(10, 0)?;
    assert!(!snapshots.items.is_empty());

    let pack = store.build_clone_context_pack(
        "Rust local-first tests",
        PersonalPreferencesCloneOptions {
            mode: Some(CLONE_MODE_PROJECT_BUILD.to_string()),
            allow_sensitive: false,
            current_repo_root: Some("/tmp/repo-one".to_string()),
            max_records: Some(8),
            budget_tokens: Some(256),
        },
    )?;
    assert!(!pack.items.is_empty());
    assert!(!pack.trace.is_empty());

    let explanation = store.explain_clone_context(
        "Rust local-first tests",
        PersonalPreferencesCloneOptions {
            mode: Some(CLONE_MODE_PROJECT_BUILD.to_string()),
            allow_sensitive: false,
            current_repo_root: Some("/tmp/repo-one".to_string()),
            max_records: Some(8),
            budget_tokens: Some(256),
        },
    )?;
    assert!(!explanation.included_claims.is_empty());
    assert!(!explanation.pack.trace.is_empty());

    let evaluation = store.evaluate_clone_context(
        "Rust local-first tests",
        PersonalPreferencesCloneOptions {
            mode: Some(CLONE_MODE_PROJECT_BUILD.to_string()),
            allow_sensitive: false,
            current_repo_root: Some("/tmp/repo-one".to_string()),
            max_records: Some(8),
            budget_tokens: Some(256),
        },
    )?;
    assert!(evaluation.overall_score >= 0.0);
    assert!(evaluation.explicit_selected + evaluation.inferred_selected > 0);
    let forgotten = store.forget_claim(&claim_id, Some("forget in unit test"))?;
    assert!(forgotten.forgotten);
    let forgotten_claim = store.read_claim(&claim_id)?.expect("forgotten claim");
    assert!(claim_is_forgotten(&forgotten_claim));
    let status = store.status()?;
    assert!(status.claim_evidence_total >= 1);
    assert!(status.claim_links_total >= 2);
    assert!(status.project_timelines_total >= 1);
    assert!(status.goal_graph_total >= 1);
    assert!(status.override_rules_total >= 1);
    assert!(status.redaction_spans_total >= 1);
    assert!(status.retention_policies_total >= 3);
    let claims_after_forget = store.list_claims(PersonalPreferencesClaimsQuery {
        query: Some("Rust".to_string()),
        truth_status: None,
        claim_origin: None,
        include_sensitive: true,
        limit: Some(20),
        offset: Some(0),
    })?;
    assert!(claims_after_forget
        .items
        .iter()
        .all(|claim| claim.id != claim_id));
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

#[test]
fn supported_client_transcript_source_detects_common_clients() {
    assert!(is_supported_client_transcript_source("codex"));
    assert!(is_supported_client_transcript_source("claude-code"));
    assert!(is_supported_client_transcript_source("gemini_cli"));
    assert!(is_supported_client_transcript_source("openai-cli"));
    assert!(!is_supported_client_transcript_source("manual"));
}
