use super::*;

#[test]
fn operator_routines_are_synthesized_from_repeated_workflow_claims() -> Result<()> {
    let temp = TempDir::new()?;
    let store = PersonalPreferencesStore::new(temp.path())?;
    let capture = store.capture_conversation(sample_capture_request(), true, true)?;
    store.complete_capture(
        &capture.id,
        None,
        &[
            PersonalPreferenceDigestRecord {
                record_type: "method".to_string(),
                category: "workflow_method".to_string(),
                subcategory: Some("documentation".to_string()),
                subject: "user".to_string(),
                attribute: Some("prefers".to_string()),
                value: "create implementation plan and progress markdown files under docs/planning"
                    .to_string(),
                confidence: Some(0.96),
                sensitivity: Some("low".to_string()),
                evidence: Some("plan.md and progress.md files be created".to_string()),
                metadata: Value::Null,
            },
            PersonalPreferenceDigestRecord {
                record_type: "method".to_string(),
                category: "tooling_preference".to_string(),
                subcategory: Some("docdex".to_string()),
                subject: "user".to_string(),
                attribute: Some("uses".to_string()),
                value: "use Docdex impact graph and DAG export before code changes".to_string(),
                confidence: Some(0.95),
                sensitivity: Some("low".to_string()),
                evidence: Some("Use Docdex impact graph and DAG export before code changes".to_string()),
                metadata: Value::Null,
            },
            PersonalPreferenceDigestRecord {
                record_type: "method".to_string(),
                category: "workflow_method".to_string(),
                subcategory: Some("gap_review".to_string()),
                subject: "user".to_string(),
                attribute: Some("expects".to_string()),
                value: "implement directly, compare the plan to the codebase, and complete missing gaps"
                    .to_string(),
                confidence: Some(0.94),
                sensitivity: Some("low".to_string()),
                evidence: Some("revisit the plan and compare to the codebase".to_string()),
                metadata: Value::Null,
            },
            PersonalPreferenceDigestRecord {
                record_type: "method".to_string(),
                category: "quality_bar".to_string(),
                subcategory: Some("validation".to_string()),
                subject: "user".to_string(),
                attribute: Some("requires".to_string()),
                value: "run targeted tests and docdexd run-tests before reporting done".to_string(),
                confidence: Some(0.95),
                sensitivity: Some("low".to_string()),
                evidence: Some("run tests before reporting done".to_string()),
                metadata: Value::Null,
            },
            PersonalPreferenceDigestRecord {
                record_type: "method".to_string(),
                category: "delivery_preference".to_string(),
                subcategory: Some("release".to_string()),
                subject: "user".to_string(),
                attribute: Some("prefers".to_string()),
                value: "commit, tag, push, and deploy to production after validation".to_string(),
                confidence: Some(0.95),
                sensitivity: Some("low".to_string()),
                evidence: Some("bump version, commit, tag and push".to_string()),
                metadata: Value::Null,
            },
        ],
    )?;

    let status = store.status()?;
    assert!(status.operator_routines_total >= 1);
    let conn = open_db(store.db_path())?;
    assert!(count_query(&conn, "SELECT COUNT(*) FROM pp_operator_routine_steps")? >= 3);

    let routine_claims = store.list_claims(PersonalPreferencesClaimsQuery {
        query: Some("operator routine plan progress tests deploy".to_string()),
        truth_status: None,
        claim_origin: None,
        include_sensitive: false,
        limit: Some(20),
        offset: Some(0),
    })?;
    assert!(routine_claims
        .items
        .iter()
        .any(|claim| claim.category == "operator_routine"));

    let pack = store.build_clone_context_pack(
        "operator routine plan progress tests deploy",
        PersonalPreferencesCloneOptions {
            mode: Some(CLONE_MODE_PROJECT_BUILD.to_string()),
            allow_sensitive: false,
            current_repo_root: Some("/tmp/repo-one".to_string()),
            max_records: Some(8),
            budget_tokens: Some(512),
        },
    )?;
    assert!(pack.items.iter().any(|item| {
        item.category == "operator_routine" && item.section == "operator_routines"
    }));

    let events = [
        (
            "sds_intake",
            "Captured SDS requirements for a product implementation plan",
            None,
            None,
            "/tmp/repo-one",
        ),
        (
            "progress_doc_update",
            "Updated implementation plan and progress document",
            None,
            Some("docs/planning/operator_progress.md"),
            "/tmp/repo-one",
        ),
        (
            "impact_analysis",
            "Ran Docdex impact graph before changing code",
            Some("docdexd impact-graph --repo /tmp/repo-one --file src/lib.rs"),
            None,
            "/tmp/repo-one",
        ),
        (
            "implementation_gap_closure",
            "Implemented code and closed missing plan gaps",
            Some("apply_patch"),
            None,
            "/tmp/repo-two",
        ),
        (
            "validation",
            "Validated the implementation with docdexd run-tests",
            Some("docdexd run-tests --repo /tmp/repo-two --target tests/routines.rs"),
            None,
            "/tmp/repo-two",
        ),
        (
            "release_git",
            "Prepared git release flow after validation",
            Some("git status && git diff --check"),
            None,
            "/tmp/repo-two",
        ),
    ];
    for (action, summary, command_text, artifact_path, repo_root) in events {
        store.record_operator_event(
            PersonalPreferenceOperatorEventRequest {
                event_kind: None,
                action: action.to_string(),
                summary: Some(summary.to_string()),
                command_text: command_text.map(ToOwned::to_owned),
                source_session_id: Some("session-routine-events".to_string()),
                repo_id: None,
                repo_root: Some(repo_root.to_string()),
                capture_id: None,
                artifact_path: artifact_path.map(ToOwned::to_owned),
                occurred_at_ms: None,
                metadata: json!({ "test": "event_backed_routine" }),
            },
            "test",
        )?;
    }
    let rebuild = store.rebuild_operator_routines()?;
    assert!(rebuild.executable_total >= 1);
    assert!(rebuild.event_supported_steps >= 3);
    let routine = store
        .read_operator_routine("product_development_loop")?
        .ok_or_else(|| anyhow!("missing product development routine"))?;
    assert_eq!(routine.routine_key, "product_development_loop");
    assert!(!routine.purpose.is_empty());
    assert!(!routine.applies_when.is_empty());
    assert!(routine.cross_project_support_count >= 2);
    assert!(routine.event_support_count >= 5);
    assert_eq!(routine.risk_level, "medium");
    assert_eq!(routine.autonomy_level, "assisted");
    assert!(routine.version >= 2);
    assert_eq!(routine.drift_status, "changed");
    assert!(routine.drift_score > 0.0);
    assert!(routine.steps.iter().any(|step| {
        step.step_key == "plan_and_progress_docs"
            && step.required
            && !step.tool_hints.is_empty()
            && !step.expected_artifacts.is_empty()
            && !step.success_check.is_empty()
            && !step.event_evidence_ids.is_empty()
    }));
    assert!(routine
        .steps
        .iter()
        .any(|step| { step.step_key == "release_deploy_backup" && step.approval_required }));

    let directive = store.build_clone_directive(
        "compare the implementation plan to the codebase and complete phase 4",
        PersonalPreferencesCloneOptions {
            mode: Some(CLONE_MODE_PROJECT_BUILD.to_string()),
            allow_sensitive: false,
            current_repo_root: Some("/tmp/repo-one".to_string()),
            max_records: Some(8),
            budget_tokens: Some(512),
        },
        Some("codex".to_string()),
        Some("implementation".to_string()),
        Some("medium".to_string()),
        vec!["src/personal_preferences/mod.rs".to_string()],
        Some("docs/planning/operator_progress.md".to_string()),
        None,
    )?;
    assert!(directive
        .selected_routines
        .iter()
        .any(|routine| routine.routine_key == "product_development_loop"));
    assert!(directive.required_steps.iter().any(|step| {
        step.step_key == "plan_and_progress_docs" && step.required && !step.tool_hints.is_empty()
    }));
    assert!(directive
        .required_artifacts
        .iter()
        .any(|artifact| artifact == "docs/planning/operator_progress.md"));
    assert!(directive
        .validation_plan
        .iter()
        .any(|item| item.contains("validation")
            || item.contains("Validate")
            || item.contains("tests")));
    assert!(directive
        .memory_to_load
        .iter()
        .any(|item| item == "profile_memory:codex"));
    assert!(directive.confidence > 0.0);

    let dataset =
        store.build_clone_replay_dataset(true, Some(3), Some("/tmp/repo-one".to_string()))?;
    assert!(dataset.total >= 1);
    let case = dataset
        .cases
        .iter()
        .find(|case| {
            case.expected_routine_keys
                .iter()
                .any(|key| key == "product_development_loop")
        })
        .ok_or_else(|| anyhow!("missing product development replay case"))?;
    assert!(case.ci_subset);
    assert!(case
        .expected_categories
        .iter()
        .any(|category| category == "plan"));
    assert!(case
        .expected_step_keys
        .iter()
        .any(|key| key == "plan_and_progress_docs"));

    let suite = store.run_clone_replay_suite(
        true,
        Some(3),
        Some(0.0),
        PersonalPreferencesCloneOptions {
            mode: Some(CLONE_MODE_PROJECT_BUILD.to_string()),
            allow_sensitive: false,
            current_repo_root: Some("/tmp/repo-one".to_string()),
            max_records: Some(12),
            budget_tokens: Some(1024),
        },
    )?;
    assert!(suite.metrics.case_count >= 1);
    assert!(!suite.results.is_empty());
    assert!(suite.metrics.average_score >= 0.0);
    assert!(suite
        .results
        .iter()
        .any(|result| !result.prediction.predicted_routine_keys.is_empty()));

    let status = store.status()?;
    assert!(status.clone_readiness.routine_ready);
    assert!(!status.clone_readiness.collection_ready);
    assert!(status.clone_readiness.metrics.iter().any(|metric| {
        metric.id == "operator_routines" && metric.ready && metric.observed >= 1
    }));
    assert!(status
        .clone_readiness
        .next_actions
        .iter()
        .any(|action| action.contains("event-backed executable routines")));
    Ok(())
}
