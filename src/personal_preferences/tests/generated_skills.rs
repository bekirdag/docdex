use super::*;

fn seed_planning_progress_routine(store: &PersonalPreferencesStore) -> Result<()> {
    let capture = store.capture_conversation(sample_capture_request(), true, true)?;
    store.complete_capture(
        &capture.id,
        None,
        &[
            PersonalPreferenceDigestRecord {
                record_type: "method".to_string(),
                category: "workflow_method".to_string(),
                subcategory: Some("planning".to_string()),
                subject: "user".to_string(),
                attribute: Some("prefers".to_string()),
                value: "Create a detailed implementation plan before broad implementation work."
                    .to_string(),
                confidence: Some(0.95),
                sensitivity: Some("low".to_string()),
                evidence: Some("make an implementation plan first".to_string()),
                metadata: Value::Null,
            },
            PersonalPreferenceDigestRecord {
                record_type: "method".to_string(),
                category: "workflow_method".to_string(),
                subcategory: Some("progress".to_string()),
                subject: "user".to_string(),
                attribute: Some("expects".to_string()),
                value: "Keep progress in a separate markdown progress file while work changes."
                    .to_string(),
                confidence: Some(0.94),
                sensitivity: Some("low".to_string()),
                evidence: Some("keep your progress on another md file".to_string()),
                metadata: Value::Null,
            },
            PersonalPreferenceDigestRecord {
                record_type: "method".to_string(),
                category: "quality_bar".to_string(),
                subcategory: Some("validation".to_string()),
                subject: "user".to_string(),
                attribute: Some("requires".to_string()),
                value: "Record validation evidence and run tests before reporting completion."
                    .to_string(),
                confidence: Some(0.94),
                sensitivity: Some("low".to_string()),
                evidence: Some("always test and record validation evidence".to_string()),
                metadata: Value::Null,
            },
        ],
    )?;
    Ok(())
}

#[test]
fn ai_terminal_capture_bootstraps_integration_and_pending_digest_capture() -> Result<()> {
    let temp = TempDir::new()?;
    let store = PersonalPreferencesStore::new(temp.path())?;

    let event = store.record_ai_terminal_capture(PersonalPreferenceAiTerminalCaptureRequest {
        terminal: "codex".to_string(),
        integration_id: None,
        source_session_id: Some("session-ai-terminal-1".to_string()),
        event_kind: Some("session_close".to_string()),
        repo_scope: Some("/tmp/repo-one".to_string()),
        summary: "User asked to create a plan, keep progress in another md file, and always test."
            .to_string(),
        transcript_text: None,
        agent_id: Some("codex".to_string()),
        metadata: json!({ "test": "ai_terminal_capture" }),
    })?;

    assert_eq!(event.terminal, "codex");
    assert_eq!(event.event_kind, "session_close");
    assert_eq!(event.digest_status, "pending");
    let capture_id = event
        .capture_id
        .as_deref()
        .ok_or_else(|| anyhow!("missing capture id"))?;
    let capture = store
        .read_capture(capture_id)?
        .ok_or_else(|| anyhow!("missing capture"))?;
    assert_eq!(capture.source, "ai_terminal:codex");
    assert_eq!(capture.digest_status, "pending");
    assert_eq!(capture.repo_root.as_deref(), Some("/tmp/repo-one"));

    let integrations = store.list_ai_terminal_integrations()?;
    let codex = integrations
        .integrations
        .iter()
        .find(|integration| integration.terminal == "codex")
        .ok_or_else(|| anyhow!("missing codex integration"))?;
    assert!(codex.capture_enabled);
    assert!(codex.skill_sync_enabled);
    assert!(codex.last_capture_at_ms.is_some());
    Ok(())
}

#[test]
fn generated_skills_sync_promotes_and_installs_low_risk_playbook() -> Result<()> {
    let temp = TempDir::new()?;
    let store = PersonalPreferencesStore::new(temp.path())?;
    seed_planning_progress_routine(&store)?;

    let install_root = temp.path().join("codex-skills").join("docdex-generated");
    store.bootstrap_ai_terminal_integrations(vec!["codex".to_string()])?;
    let conn = open_db(store.db_path())?;
    conn.execute(
        "UPDATE pp_ai_terminal_integrations
         SET skill_roots_json = ?1
         WHERE terminal = 'codex'",
        params![serde_json::to_string(&vec![install_root
            .display()
            .to_string()])?],
    )?;
    drop(conn);

    let summary = store.sync_generated_skills(PersonalPreferenceGeneratedSkillsSyncOptions {
        min_confidence: Some(0.7),
        min_support_count: Some(2),
        include_sensitive: Some(false),
        install: Some(true),
        terminals: vec!["codex".to_string()],
    })?;
    assert!(summary.rendered >= 1);
    assert!(summary.installed >= 1);
    assert_eq!(summary.validation_failures, 0);

    let skill = summary
        .items
        .iter()
        .find(|item| item.slug == "planning-progress-loop")
        .ok_or_else(|| anyhow!("missing generated planning progress skill"))?;
    let quality_item = summary
        .quality
        .items
        .iter()
        .find(|item| item.slug == "planning-progress-loop")
        .ok_or_else(|| anyhow!("missing generated planning progress quality item"))?;
    assert_eq!(skill.status, "installed");
    assert_eq!(skill.risk_level, "low");
    assert_eq!(skill.support_count, 3);
    assert_eq!(quality_item.install_policy, "auto");
    assert_eq!(quality_item.risk_level, "low");
    assert_eq!(quality_item.version_id, skill.current_version_id);
    assert!(summary.quality.total >= 1);
    let version = skill
        .current_version
        .as_ref()
        .ok_or_else(|| anyhow!("missing version"))?;
    assert_eq!(version.validation_status, "passed");
    assert_eq!(version.install_policy, "auto");
    assert!(version.skill_markdown.contains("name:"));
    assert!(version.skill_markdown.contains("description:"));
    assert!(version.skill_markdown.contains("## Steps"));
    assert!(skill
        .validations
        .iter()
        .any(|validation| validation.status == "passed"));
    assert!(skill
        .installations
        .iter()
        .any(|installation| installation.agent_target == "codex"
            && installation.status == "installed"));

    let installed_path = install_root.join("planning-progress-loop").join("SKILL.md");
    assert!(installed_path.exists());
    let installed = std::fs::read_to_string(installed_path)?;
    assert!(installed.contains("Planning And Progress Documentation Loop"));
    Ok(())
}

#[test]
fn disabled_terminal_integration_blocks_capture_and_install() -> Result<()> {
    let temp = TempDir::new()?;
    let store = PersonalPreferencesStore::new(temp.path())?;
    seed_planning_progress_routine(&store)?;

    let install_root = temp.path().join("codex-skills").join("docdex-generated");
    store.bootstrap_ai_terminal_integrations(vec!["codex".to_string()])?;
    let conn = open_db(store.db_path())?;
    conn.execute(
        "UPDATE pp_ai_terminal_integrations
         SET enabled = 0, capture_enabled = 0, skill_sync_enabled = 0, skill_roots_json = ?1
         WHERE terminal = 'codex'",
        params![serde_json::to_string(&vec![install_root
            .display()
            .to_string()])?],
    )?;
    drop(conn);

    let capture = store.record_ai_terminal_capture(PersonalPreferenceAiTerminalCaptureRequest {
        terminal: "codex".to_string(),
        integration_id: None,
        source_session_id: Some("disabled-capture-session".to_string()),
        event_kind: Some("session_close".to_string()),
        repo_scope: Some("/tmp/repo-one".to_string()),
        summary: "User asked to keep progress in another md file and always test.".to_string(),
        transcript_text: None,
        agent_id: Some("codex".to_string()),
        metadata: json!({ "test": "disabled_terminal_capture" }),
    });
    assert!(capture.is_err());

    let summary = store.sync_generated_skills(PersonalPreferenceGeneratedSkillsSyncOptions {
        min_confidence: Some(0.7),
        min_support_count: Some(2),
        include_sensitive: Some(false),
        install: Some(true),
        terminals: vec!["codex".to_string()],
    })?;
    assert!(summary.rendered >= 1);
    assert_eq!(summary.installed, 0);
    assert!(!install_root
        .join("planning-progress-loop")
        .join("SKILL.md")
        .exists());

    let integrations = store.list_ai_terminal_integrations()?;
    let codex = integrations
        .integrations
        .iter()
        .find(|integration| integration.terminal == "codex")
        .ok_or_else(|| anyhow!("missing codex integration"))?;
    assert!(!codex.enabled);
    assert!(!codex.capture_enabled);
    assert!(!codex.skill_sync_enabled);
    Ok(())
}

#[test]
fn generated_skill_status_events_preview_and_actions_are_persisted() -> Result<()> {
    let temp = TempDir::new()?;
    let store = PersonalPreferencesStore::new(temp.path())?;
    seed_planning_progress_routine(&store)?;
    store.bootstrap_ai_terminal_integrations(vec!["codex".to_string()])?;
    let install_root = temp.path().join("codex-skills").join("docdex-generated");
    let conn = open_db(store.db_path())?;
    conn.execute(
        "UPDATE pp_ai_terminal_integrations
         SET skill_roots_json = ?1
         WHERE terminal = 'codex'",
        params![serde_json::to_string(&vec![install_root
            .display()
            .to_string()])?],
    )?;
    drop(conn);
    store.record_ai_terminal_capture(PersonalPreferenceAiTerminalCaptureRequest {
        terminal: "codex".to_string(),
        integration_id: None,
        source_session_id: Some("skill-status-session".to_string()),
        event_kind: Some("session_close".to_string()),
        repo_scope: Some("/tmp/repo-one".to_string()),
        summary: "User asked to keep progress in a markdown file and always test.".to_string(),
        transcript_text: None,
        agent_id: Some("codex".to_string()),
        metadata: json!({ "test": "generated_skill_status" }),
    })?;

    let status_after_capture = store.ai_terminal_status()?;
    assert!(status_after_capture.generated_skills_total >= 1);
    assert!(status_after_capture.installed_skills_total >= 1);
    let preview = store.preview_generated_skills(PersonalPreferenceGeneratedSkillsSyncOptions {
        min_confidence: Some(0.7),
        min_support_count: Some(2),
        include_sensitive: Some(false),
        install: Some(true),
        terminals: vec!["codex".to_string()],
    })?;
    assert!(preview.rendered >= 1);
    assert_eq!(preview.installed, 0);
    let generated_skill_id = preview
        .items
        .iter()
        .find(|item| item.slug == "planning-progress-loop")
        .map(|item| item.skill_id.clone())
        .ok_or_else(|| anyhow!("missing generated skill"))?;
    let installed_path = install_root.join("planning-progress-loop").join("SKILL.md");
    assert!(installed_path.exists());

    let status = store.ai_terminal_status()?;
    assert!(status.capture_events_total >= 1);
    assert!(status.generated_skills_total >= 1);
    let terminal_events = store.list_ai_terminal_capture_events(10, 0)?;
    assert!(terminal_events
        .items
        .iter()
        .any(|event| event.terminal == "codex"));
    let skill_events = store.list_generated_skill_events(20, 0)?;
    assert!(skill_events
        .items
        .iter()
        .any(|event| event.skill_id == generated_skill_id && event.event_kind == "rendered"));

    let validation = store.validate_generated_skill(&generated_skill_id)?;
    assert_eq!(validation.action, "validate");
    assert_eq!(
        validation
            .validation
            .as_ref()
            .map(|item| item.status.as_str()),
        Some("passed")
    );

    let disabled = store.disable_generated_skill(
        &generated_skill_id,
        Some("store regression test".to_string()),
    )?;
    assert_eq!(disabled.action, "disable");
    assert_eq!(
        disabled.skill.as_ref().map(|skill| skill.status.as_str()),
        Some("disabled")
    );

    let rollback =
        store.rollback_generated_skill(&generated_skill_id, vec!["codex".to_string()])?;
    assert_eq!(rollback.action, "rollback");
    assert!(!rollback.rolled_back);
    assert!(rollback
        .notes
        .iter()
        .any(|note| note.contains("No previous generated-skill version")));
    Ok(())
}

#[test]
fn bootstrapped_terminal_scan_records_events_and_context_hints_without_global_scan_flag(
) -> Result<()> {
    let temp = TempDir::new()?;
    let store = PersonalPreferencesStore::new(temp.path())?;
    seed_planning_progress_routine(&store)?;

    let transcript_root = temp.path().join("codex").join("sessions");
    std::fs::create_dir_all(&transcript_root)?;
    std::fs::write(
        transcript_root.join("session-one.txt"),
        "user: make an implementation plan and keep progress on another md file\nassistant: done\nuser: always test before reporting completion",
    )?;

    let install_root = temp.path().join("codex-skills").join("docdex-generated");
    store.bootstrap_ai_terminal_integrations(vec!["codex".to_string()])?;
    let conn = open_db(store.db_path())?;
    conn.execute(
        "UPDATE pp_ai_terminal_integrations
         SET skill_roots_json = ?1
         WHERE terminal = 'codex'",
        params![serde_json::to_string(&vec![install_root
            .display()
            .to_string()])?],
    )?;
    drop(conn);

    let config = MemoryPersonalPreferencesConfig {
        capture_supported_client_transcripts: false,
        client_transcript_roots: vec![transcript_root.display().to_string()],
        archive_raw_conversations: false,
        digest_enabled: true,
        ..MemoryPersonalPreferencesConfig::default()
    };
    let scan = store.scan_supported_client_transcripts(&config, Some(4))?;
    assert_eq!(scan.captures_created, 1);
    assert_eq!(scan.skipped_existing, 0);

    let terminal_events = store.list_ai_terminal_capture_events(10, 0)?;
    assert!(terminal_events.items.iter().any(|event| {
        event.terminal == "codex"
            && event.event_kind == "session_close"
            && event.capture_id.is_some()
    }));

    let context = store.build_context(
        "plan progress tests",
        PersonalPreferencesContextOptions {
            max_records: 16,
            budget_tokens: 1200,
            allow_sensitive: false,
            current_repo_root: None,
        },
    )?;
    assert!(context.items.iter().any(|item| {
        item.section == "generated_skills"
            && item.record_type == "skill_hint"
            && item.content.contains("planning-progress-loop")
    }));
    Ok(())
}

#[test]
fn generated_skill_usage_rejection_records_feedback_and_lowers_confidence() -> Result<()> {
    let temp = TempDir::new()?;
    let store = PersonalPreferencesStore::new(temp.path())?;
    seed_planning_progress_routine(&store)?;
    store.bootstrap_ai_terminal_integrations(vec!["codex".to_string()])?;
    let install_root = temp.path().join("codex-skills").join("docdex-generated");
    let conn = open_db(store.db_path())?;
    conn.execute(
        "UPDATE pp_ai_terminal_integrations
         SET skill_roots_json = ?1
         WHERE terminal = 'codex'",
        params![serde_json::to_string(&vec![install_root
            .display()
            .to_string()])?],
    )?;
    drop(conn);

    let summary = store.sync_generated_skills(PersonalPreferenceGeneratedSkillsSyncOptions {
        min_confidence: Some(0.7),
        min_support_count: Some(2),
        include_sensitive: Some(false),
        install: Some(true),
        terminals: vec!["codex".to_string()],
    })?;
    let skill = summary
        .items
        .iter()
        .find(|item| item.slug == "planning-progress-loop")
        .ok_or_else(|| anyhow!("missing generated skill"))?;
    let before_confidence = skill.confidence;
    let skill_id = skill.skill_id.clone();
    let version_id = skill.current_version_id.clone();

    store.record_ai_terminal_capture(PersonalPreferenceAiTerminalCaptureRequest {
        terminal: "codex".to_string(),
        integration_id: None,
        source_session_id: Some("skill-rejection-session".to_string()),
        event_kind: Some("skill_rejection".to_string()),
        repo_scope: Some("/tmp/repo-one".to_string()),
        summary: "Generated skill missed the expected progress-file workflow.".to_string(),
        transcript_text: None,
        agent_id: Some("codex".to_string()),
        metadata: json!({
            "skill_id": skill_id,
            "version_id": version_id,
            "accepted": false,
            "trigger_query": "compare plan and fill gaps",
            "rejected_reason": "missed progress-file update",
        }),
    })?;

    let updated = store
        .read_generated_skill(&skill_id)?
        .ok_or_else(|| anyhow!("missing updated generated skill"))?;
    assert!(updated.confidence < before_confidence);
    let status = store.ai_terminal_status()?;
    assert!(status.activation_events_total >= 1);
    assert!(status.rejected_activation_events_total >= 1);
    let events = store.list_generated_skill_events(20, 0)?;
    assert!(events
        .items
        .iter()
        .any(|event| event.skill_id == skill_id && event.event_kind == "rejected"));

    let conn = open_db(store.db_path())?;
    conn.execute(
        "UPDATE pp_operator_routines
         SET updated_at_ms = ?1, drift_status = 'changed', drift_score = 0.75
         WHERE routine_key = 'planning_progress_loop'",
        params![now_ms().saturating_add(10_000)],
    )?;
    conn.execute(
        "INSERT INTO pp_generated_skill_validations(
            validation_id, skill_id, version_id, validator, status, details_json, created_at_ms
         ) VALUES (?1, ?2, ?3, 'replay', 'passed', ?4, ?5)",
        params![
            format!("validation_replay_{skill_id}"),
            skill_id,
            version_id.unwrap_or_else(|| "unknown".to_string()),
            json!({ "score": 1.0 }).to_string(),
            now_ms(),
        ],
    )?;
    drop(conn);

    let status = store.ai_terminal_status()?;
    assert!(status.stale_generated_skills_total >= 1);
    assert!(status.generated_skill_replay_validations_total >= 1);
    assert!(status.drifted_operator_routines_total >= 1);
    let list = store.list_generated_skills()?;
    let quality = list
        .quality
        .items
        .iter()
        .find(|item| item.skill_id == skill_id)
        .ok_or_else(|| anyhow!("missing generated skill quality report item"))?;
    assert_eq!(quality.recommendation, "demote");
    assert!(quality.stale);
    assert_eq!(quality.routine_drift_status.as_deref(), Some("changed"));
    assert!(quality.rejected_activation_events >= 1);
    assert_eq!(quality.replay_validation_status.as_deref(), Some("passed"));
    assert_eq!(quality.latest_replay_score, Some(1.0));
    Ok(())
}
