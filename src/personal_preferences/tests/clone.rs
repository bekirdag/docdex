use super::*;

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
    let policies = store.list_retention_policies()?;
    assert!(policies.iter().any(|policy| policy.lane == "raw_archive"));
    let export = store.export_bundle(None)?;
    assert_eq!(export.captures, 1);
    assert!(export.claims >= 3);
    assert!(export.claim_evidence >= 1);
    assert!(export.feedback_events >= 1);
    assert!(export.identity_snapshots >= 1);
    assert!(export.retention_policies >= 3);
    let exported_payload: Value = serde_json::from_slice(&std::fs::read(&export.path)?)?;
    assert_eq!(
        exported_payload
            .get("schema_version")
            .and_then(Value::as_u64),
        Some(SCHEMA_VERSION as u64)
    );
    assert!(exported_payload
        .get("claims")
        .and_then(Value::as_array)
        .is_some_and(|items| !items.is_empty()));
    assert!(exported_payload
        .get("claim_evidence")
        .and_then(Value::as_array)
        .is_some_and(|items| !items.is_empty()));
    assert!(exported_payload
        .get("retention_policies")
        .and_then(Value::as_array)
        .is_some_and(|items| !items.is_empty()));
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
