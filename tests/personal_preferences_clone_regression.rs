use std::error::Error;

use docdexd::personal_preferences::{
    PersonalPreferenceDigestOutput, PersonalPreferenceDigestRecord,
    PersonalPreferencesCaptureRequest, PersonalPreferencesClaimsQuery,
    PersonalPreferencesCloneOptions, PersonalPreferencesMessage, PersonalPreferencesStore,
};
use serde_json::{json, Value};
use tempfile::TempDir;

fn sample_capture_request() -> PersonalPreferencesCaptureRequest {
    PersonalPreferencesCaptureRequest {
        source: "chat_completion".to_string(),
        source_session_id: Some("session-1".to_string()),
        capture_kind: Some("chat_completion".to_string()),
        title: Some("Mind clone regression".to_string()),
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
                content: "I prefer Rust, direct communication, and comprehensive tests."
                    .to_string(),
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
        metadata: json!({ "source": "regression_test" }),
    }
}

async fn seed_store(
    store: &PersonalPreferencesStore,
    records: Vec<PersonalPreferenceDigestRecord>,
) -> Result<(), Box<dyn Error>> {
    let _capture = store.capture_conversation(sample_capture_request(), true, true)?;
    let summary = store
        .process_pending_with_runner(5, move |_input| {
            let records = records.clone();
            async move { Ok(Some(PersonalPreferenceDigestOutput { records })) }
        })
        .await?;
    assert_eq!(summary.completed_captures, 1);
    Ok(())
}

#[tokio::test]
async fn clone_explain_regression_prioritizes_style_and_workflow_sections(
) -> Result<(), Box<dyn Error>> {
    let temp = TempDir::new()?;
    let store = PersonalPreferencesStore::new(temp.path())?;
    seed_store(
        &store,
        vec![
            PersonalPreferenceDigestRecord {
                record_type: "preference".to_string(),
                category: "coding_preference".to_string(),
                subcategory: None,
                subject: "user".to_string(),
                attribute: Some("prefers".to_string()),
                value: "Rust".to_string(),
                confidence: Some(0.95),
                sensitivity: Some("low".to_string()),
                evidence: Some("Prefer Rust".to_string()),
                metadata: Value::Null,
            },
            PersonalPreferenceDigestRecord {
                record_type: "trait".to_string(),
                category: "communication_style".to_string(),
                subcategory: None,
                subject: "user".to_string(),
                attribute: Some("prefers".to_string()),
                value: "direct and non-fluffy collaboration".to_string(),
                confidence: Some(0.93),
                sensitivity: Some("low".to_string()),
                evidence: Some("be direct".to_string()),
                metadata: Value::Null,
            },
            PersonalPreferenceDigestRecord {
                record_type: "method".to_string(),
                category: "workflow_method".to_string(),
                subcategory: None,
                subject: "user".to_string(),
                attribute: Some("expects".to_string()),
                value: "verify tests before push".to_string(),
                confidence: Some(0.92),
                sensitivity: Some("low".to_string()),
                evidence: Some("run tests before pushing".to_string()),
                metadata: Value::Null,
            },
            PersonalPreferenceDigestRecord {
                record_type: "goal".to_string(),
                category: "product_goals".to_string(),
                subcategory: None,
                subject: "user".to_string(),
                attribute: Some("prioritizes".to_string()),
                value: "local-first tooling".to_string(),
                confidence: Some(0.9),
                sensitivity: Some("low".to_string()),
                evidence: Some("local-first".to_string()),
                metadata: json!({ "goal_status": "active", "project_name": "docdex" }),
            },
        ],
    )
    .await?;

    let explanation = store.explain_clone_context(
        "review Rust changes with direct feedback and tests",
        PersonalPreferencesCloneOptions {
            mode: Some("review".to_string()),
            allow_sensitive: false,
            current_repo_root: Some("/tmp/repo-one".to_string()),
            max_records: Some(8),
            budget_tokens: Some(256),
        },
    )?;

    let sections = explanation
        .included_claims
        .iter()
        .map(|item| item.section.as_str())
        .collect::<Vec<_>>();
    assert_eq!(explanation.pack.mode, "review");
    assert!(sections.contains(&"current_workflow_and_quality_expectations"));
    assert!(sections.contains(&"relevant_communication_style_expectations"));
    assert!(!explanation.ranking_factors.is_empty());
    assert!(!explanation.policy_notes.is_empty());
    Ok(())
}

#[tokio::test]
async fn forgotten_claims_do_not_reappear_in_clone_context_regression() -> Result<(), Box<dyn Error>>
{
    let temp = TempDir::new()?;
    let store = PersonalPreferencesStore::new(temp.path())?;
    seed_store(
        &store,
        vec![
            PersonalPreferenceDigestRecord {
                record_type: "preference".to_string(),
                category: "coding_preference".to_string(),
                subcategory: None,
                subject: "user".to_string(),
                attribute: Some("prefers".to_string()),
                value: "Rust".to_string(),
                confidence: Some(0.95),
                sensitivity: Some("low".to_string()),
                evidence: Some("Prefer Rust".to_string()),
                metadata: Value::Null,
            },
            PersonalPreferenceDigestRecord {
                record_type: "method".to_string(),
                category: "workflow_method".to_string(),
                subcategory: None,
                subject: "user".to_string(),
                attribute: Some("expects".to_string()),
                value: "verify tests before push".to_string(),
                confidence: Some(0.92),
                sensitivity: Some("low".to_string()),
                evidence: Some("run tests before pushing".to_string()),
                metadata: Value::Null,
            },
        ],
    )
    .await?;

    let claims = store.list_claims(PersonalPreferencesClaimsQuery {
        query: Some("Rust".to_string()),
        truth_status: None,
        claim_origin: None,
        include_sensitive: true,
        limit: Some(10),
        offset: Some(0),
    })?;
    let rust_claim_id = claims.items.first().ok_or("missing Rust claim")?.id.clone();
    let _forgotten = store.forget_claim(&rust_claim_id, Some("forget regression claim"))?;

    let claims_after_forget = store.list_claims(PersonalPreferencesClaimsQuery {
        query: Some("Rust".to_string()),
        truth_status: None,
        claim_origin: None,
        include_sensitive: true,
        limit: Some(10),
        offset: Some(0),
    })?;
    assert!(claims_after_forget
        .items
        .iter()
        .all(|claim| claim.id != rust_claim_id));

    let pack = store.build_clone_context_pack(
        "Rust preferences",
        PersonalPreferencesCloneOptions {
            mode: Some("adaptive".to_string()),
            allow_sensitive: false,
            current_repo_root: Some("/tmp/repo-one".to_string()),
            max_records: Some(8),
            budget_tokens: Some(256),
        },
    )?;
    assert!(pack
        .trace
        .iter()
        .all(|trace| trace.claim_id != rust_claim_id));

    let status = store.status()?;
    assert!(status.redaction_spans_total >= 1);
    Ok(())
}
