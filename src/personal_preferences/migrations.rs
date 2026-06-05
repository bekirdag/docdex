use super::*;

pub(super) fn init_db(path: &Path) -> Result<()> {
    let conn = open_db(path)?;
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA foreign_keys=ON;
         CREATE TABLE IF NOT EXISTS personal_preferences_meta(
             key TEXT PRIMARY KEY,
             value TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS captured_conversations(
             id TEXT PRIMARY KEY,
             source TEXT NOT NULL,
             source_session_id TEXT,
             capture_kind TEXT,
             title TEXT,
             agent_id TEXT,
             transport TEXT,
             repo_id TEXT,
             repo_root TEXT,
             scope_id TEXT,
             scope_label TEXT,
             started_at_ms INTEGER,
             ended_at_ms INTEGER,
             created_at_ms INTEGER NOT NULL,
             updated_at_ms INTEGER NOT NULL,
             digest_status TEXT NOT NULL,
             transcript_text TEXT NOT NULL,
             metadata_json TEXT NOT NULL,
             archive_path TEXT,
             raw_message_count INTEGER NOT NULL DEFAULT 0,
             archive_redacted_at_ms INTEGER,
             last_digest_error TEXT
         );
         CREATE TABLE IF NOT EXISTS captured_messages(
             id TEXT PRIMARY KEY,
             capture_id TEXT NOT NULL,
             ordinal INTEGER NOT NULL,
             role TEXT NOT NULL,
             content TEXT NOT NULL,
             created_at_ms INTEGER,
             metadata_json TEXT NOT NULL,
             FOREIGN KEY(capture_id) REFERENCES captured_conversations(id) ON DELETE CASCADE
         );
         CREATE TABLE IF NOT EXISTS pp_sources(
             source_id TEXT PRIMARY KEY,
             source_type TEXT NOT NULL,
             client_kind TEXT,
             agent_kind TEXT,
             enabled INTEGER NOT NULL DEFAULT 1,
             last_seen_at_ms INTEGER NOT NULL,
             metadata_json TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS pp_sessions(
             capture_id TEXT PRIMARY KEY,
             source_id TEXT NOT NULL,
             source_session_id TEXT,
             external_ref TEXT,
             external_ref_hash TEXT,
             capture_kind TEXT,
             title TEXT,
             digest_status TEXT NOT NULL,
             sensitivity_summary TEXT,
             started_at_ms INTEGER,
             ended_at_ms INTEGER,
             created_at_ms INTEGER NOT NULL,
             updated_at_ms INTEGER NOT NULL,
             metadata_json TEXT NOT NULL,
             FOREIGN KEY(capture_id) REFERENCES captured_conversations(id) ON DELETE CASCADE,
             FOREIGN KEY(source_id) REFERENCES pp_sources(source_id) ON DELETE CASCADE
         );
         CREATE TABLE IF NOT EXISTS pp_messages(
             id TEXT PRIMARY KEY,
             capture_id TEXT NOT NULL,
             message_id TEXT,
             ordinal INTEGER NOT NULL,
             role TEXT NOT NULL,
             content TEXT NOT NULL,
             created_at_ms INTEGER,
             metadata_json TEXT NOT NULL,
             FOREIGN KEY(capture_id) REFERENCES captured_conversations(id) ON DELETE CASCADE
         );
         CREATE TABLE IF NOT EXISTS pp_attachments(
             id TEXT PRIMARY KEY,
             capture_id TEXT NOT NULL,
             attachment_kind TEXT NOT NULL,
             attachment_ref TEXT,
             metadata_json TEXT NOT NULL,
             created_at_ms INTEGER NOT NULL,
             FOREIGN KEY(capture_id) REFERENCES captured_conversations(id) ON DELETE CASCADE
         );
         CREATE TABLE IF NOT EXISTS derived_records(
             id TEXT PRIMARY KEY,
             capture_id TEXT NOT NULL,
             record_type TEXT NOT NULL,
             category TEXT NOT NULL,
             subcategory TEXT,
             subject TEXT NOT NULL,
             attribute TEXT,
             value TEXT NOT NULL,
             confidence REAL NOT NULL,
             sensitivity TEXT NOT NULL,
             evidence TEXT,
             created_at_ms INTEGER NOT NULL,
             updated_at_ms INTEGER NOT NULL,
             metadata_json TEXT NOT NULL,
             projected_to_profile_at_ms INTEGER,
             review_status TEXT NOT NULL DEFAULT 'approved',
             review_updated_at_ms INTEGER,
             FOREIGN KEY(capture_id) REFERENCES captured_conversations(id) ON DELETE CASCADE
         );
         CREATE TABLE IF NOT EXISTS pp_categories(
             category TEXT PRIMARY KEY,
             description TEXT NOT NULL,
             context_section TEXT,
             context_allowed_default INTEGER NOT NULL DEFAULT 0,
             requires_review_for_sensitive INTEGER NOT NULL DEFAULT 0,
             created_at_ms INTEGER NOT NULL,
             updated_at_ms INTEGER NOT NULL
         );
         CREATE TABLE IF NOT EXISTS pp_subcategories(
             category TEXT NOT NULL,
             subcategory TEXT NOT NULL,
             description TEXT,
             created_at_ms INTEGER NOT NULL,
             updated_at_ms INTEGER NOT NULL,
             PRIMARY KEY(category, subcategory)
         );
         CREATE TABLE IF NOT EXISTS pp_sensitivity_levels(
             level TEXT PRIMARY KEY,
             rank INTEGER NOT NULL,
             description TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS pp_context_policies(
             category TEXT PRIMARY KEY,
             context_section TEXT,
             context_allowed_default INTEGER NOT NULL DEFAULT 0,
             allow_sensitive INTEGER NOT NULL DEFAULT 0,
             requires_review_for_sensitive INTEGER NOT NULL DEFAULT 0,
             updated_at_ms INTEGER NOT NULL
         );
         CREATE TABLE IF NOT EXISTS pp_tombstones(
             id TEXT PRIMARY KEY,
             capture_id TEXT NOT NULL,
             action TEXT NOT NULL,
             details_json TEXT NOT NULL,
             created_at_ms INTEGER NOT NULL
         );
         CREATE TABLE IF NOT EXISTS pp_reviews(
             id TEXT PRIMARY KEY,
             record_id TEXT NOT NULL,
             verdict TEXT NOT NULL,
             notes TEXT,
             created_at_ms INTEGER NOT NULL,
             FOREIGN KEY(record_id) REFERENCES derived_records(id) ON DELETE CASCADE
         );
         CREATE TABLE IF NOT EXISTS pp_digest_jobs(
             id TEXT PRIMARY KEY,
             capture_id TEXT NOT NULL,
             status TEXT NOT NULL,
             error_text TEXT,
             started_at_ms INTEGER NOT NULL,
             finished_at_ms INTEGER,
             created_at_ms INTEGER NOT NULL,
             updated_at_ms INTEGER NOT NULL,
             metadata_json TEXT NOT NULL,
             FOREIGN KEY(capture_id) REFERENCES captured_conversations(id) ON DELETE CASCADE
         );
         CREATE TABLE IF NOT EXISTS pp_digest_runs(
             id TEXT PRIMARY KEY,
             job_id TEXT,
             capture_id TEXT NOT NULL,
             agent_id TEXT,
             model_hint TEXT,
             prompt_version TEXT,
             outcome_status TEXT NOT NULL,
             input_records INTEGER NOT NULL DEFAULT 0,
             output_records INTEGER NOT NULL DEFAULT 0,
             started_at_ms INTEGER NOT NULL,
             finished_at_ms INTEGER,
             error_text TEXT,
             metadata_json TEXT NOT NULL,
             FOREIGN KEY(job_id) REFERENCES pp_digest_jobs(id) ON DELETE SET NULL,
             FOREIGN KEY(capture_id) REFERENCES captured_conversations(id) ON DELETE CASCADE
         );
         CREATE TABLE IF NOT EXISTS pp_entities(
             id TEXT PRIMARY KEY,
             entity_kind TEXT NOT NULL,
             canonical_name TEXT NOT NULL,
             normalized_name TEXT NOT NULL UNIQUE,
             created_at_ms INTEGER NOT NULL,
             updated_at_ms INTEGER NOT NULL,
             metadata_json TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS pp_entity_aliases(
             id TEXT PRIMARY KEY,
             entity_id TEXT NOT NULL,
             alias TEXT NOT NULL,
             normalized_alias TEXT NOT NULL,
             created_at_ms INTEGER NOT NULL,
             UNIQUE(entity_id, normalized_alias),
             FOREIGN KEY(entity_id) REFERENCES pp_entities(id) ON DELETE CASCADE
         );
         CREATE TABLE IF NOT EXISTS pp_relations(
             id TEXT PRIMARY KEY,
             record_id TEXT NOT NULL,
             capture_id TEXT NOT NULL,
             subject_entity_id TEXT NOT NULL,
             relation_type TEXT NOT NULL,
             object_entity_id TEXT,
             literal_object TEXT,
             confidence REAL NOT NULL,
             sensitivity TEXT NOT NULL,
             status TEXT NOT NULL,
             created_at_ms INTEGER NOT NULL,
             updated_at_ms INTEGER NOT NULL,
             metadata_json TEXT NOT NULL,
             FOREIGN KEY(record_id) REFERENCES derived_records(id) ON DELETE CASCADE,
             FOREIGN KEY(capture_id) REFERENCES captured_conversations(id) ON DELETE CASCADE,
             FOREIGN KEY(subject_entity_id) REFERENCES pp_entities(id) ON DELETE CASCADE,
             FOREIGN KEY(object_entity_id) REFERENCES pp_entities(id) ON DELETE SET NULL
         );
         CREATE TABLE IF NOT EXISTS pp_observations(
             id TEXT PRIMARY KEY,
             digest_run_id TEXT,
             record_id TEXT NOT NULL,
             capture_id TEXT NOT NULL,
             observation_type TEXT NOT NULL,
             summary TEXT NOT NULL,
             confidence REAL NOT NULL,
             sensitivity TEXT NOT NULL,
             created_at_ms INTEGER NOT NULL,
             metadata_json TEXT NOT NULL,
             FOREIGN KEY(digest_run_id) REFERENCES pp_digest_runs(id) ON DELETE SET NULL,
             FOREIGN KEY(record_id) REFERENCES derived_records(id) ON DELETE CASCADE,
             FOREIGN KEY(capture_id) REFERENCES captured_conversations(id) ON DELETE CASCADE
         );
         CREATE TABLE IF NOT EXISTS pp_personal_facts(
             id TEXT PRIMARY KEY,
             record_id TEXT NOT NULL UNIQUE,
             category TEXT NOT NULL,
             subcategory TEXT,
             subject TEXT NOT NULL,
             attribute TEXT,
             value TEXT NOT NULL,
             confidence REAL NOT NULL,
             sensitivity TEXT NOT NULL,
             status TEXT NOT NULL,
             created_at_ms INTEGER NOT NULL,
             updated_at_ms INTEGER NOT NULL,
             FOREIGN KEY(record_id) REFERENCES derived_records(id) ON DELETE CASCADE
         );
         CREATE TABLE IF NOT EXISTS pp_preferences(
             id TEXT PRIMARY KEY,
             record_id TEXT NOT NULL UNIQUE,
             preference_type TEXT NOT NULL,
             target_name TEXT NOT NULL,
             normalized_target TEXT NOT NULL,
             confidence REAL NOT NULL,
             sensitivity TEXT NOT NULL,
             status TEXT NOT NULL,
             created_at_ms INTEGER NOT NULL,
             updated_at_ms INTEGER NOT NULL,
             FOREIGN KEY(record_id) REFERENCES derived_records(id) ON DELETE CASCADE
         );
         CREATE TABLE IF NOT EXISTS pp_capabilities(
             id TEXT PRIMARY KEY,
             record_id TEXT NOT NULL UNIQUE,
             capability_name TEXT NOT NULL,
             proficiency_signal TEXT,
             confidence REAL NOT NULL,
             sensitivity TEXT NOT NULL,
             status TEXT NOT NULL,
             created_at_ms INTEGER NOT NULL,
             updated_at_ms INTEGER NOT NULL,
             FOREIGN KEY(record_id) REFERENCES derived_records(id) ON DELETE CASCADE
         );
         CREATE TABLE IF NOT EXISTS pp_projects(
             id TEXT PRIMARY KEY,
             record_id TEXT NOT NULL UNIQUE,
             project_name TEXT NOT NULL,
             repo_root TEXT,
             goal_summary TEXT,
             confidence REAL NOT NULL,
             sensitivity TEXT NOT NULL,
             status TEXT NOT NULL,
             created_at_ms INTEGER NOT NULL,
             updated_at_ms INTEGER NOT NULL,
             FOREIGN KEY(record_id) REFERENCES derived_records(id) ON DELETE CASCADE
         );
         CREATE TABLE IF NOT EXISTS pp_methods(
             id TEXT PRIMARY KEY,
             record_id TEXT NOT NULL UNIQUE,
             method_name TEXT NOT NULL,
             method_kind TEXT,
             confidence REAL NOT NULL,
             sensitivity TEXT NOT NULL,
             status TEXT NOT NULL,
             created_at_ms INTEGER NOT NULL,
             updated_at_ms INTEGER NOT NULL,
             FOREIGN KEY(record_id) REFERENCES derived_records(id) ON DELETE CASCADE
         );
         CREATE TABLE IF NOT EXISTS pp_evidence(
             id TEXT PRIMARY KEY,
             record_id TEXT NOT NULL,
             capture_id TEXT NOT NULL,
             evidence_text TEXT NOT NULL,
             metadata_json TEXT NOT NULL,
             created_at_ms INTEGER NOT NULL,
             FOREIGN KEY(record_id) REFERENCES derived_records(id) ON DELETE CASCADE,
             FOREIGN KEY(capture_id) REFERENCES captured_conversations(id) ON DELETE CASCADE
         );
         CREATE TABLE IF NOT EXISTS pp_cross_project_bridges(
             id TEXT PRIMARY KEY,
             record_id TEXT NOT NULL,
             source_repo_root TEXT NOT NULL,
             target_repo_root TEXT,
             bridge_key TEXT NOT NULL,
             summary TEXT NOT NULL,
             created_at_ms INTEGER NOT NULL,
             FOREIGN KEY(record_id) REFERENCES derived_records(id) ON DELETE CASCADE
         );
         CREATE TABLE IF NOT EXISTS pp_snapshot_summaries(
             id TEXT PRIMARY KEY,
             capture_id TEXT,
             digest_run_id TEXT,
             summary TEXT NOT NULL,
             record_count INTEGER NOT NULL,
             created_at_ms INTEGER NOT NULL,
             metadata_json TEXT NOT NULL,
             FOREIGN KEY(capture_id) REFERENCES captured_conversations(id) ON DELETE CASCADE,
             FOREIGN KEY(digest_run_id) REFERENCES pp_digest_runs(id) ON DELETE SET NULL
         );
         CREATE INDEX IF NOT EXISTS idx_pp_captured_status_created
             ON captured_conversations(digest_status, created_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_sources_kind
             ON pp_sources(source_type, client_kind);
         CREATE INDEX IF NOT EXISTS idx_pp_sessions_source_created
             ON pp_sessions(source_id, created_at_ms);
         CREATE UNIQUE INDEX IF NOT EXISTS idx_pp_sessions_external_ref_hash
             ON pp_sessions(external_ref_hash);
         CREATE INDEX IF NOT EXISTS idx_pp_messages_capture_ordinal
             ON pp_messages(capture_id, ordinal);
         CREATE INDEX IF NOT EXISTS idx_pp_categories_context
             ON pp_categories(context_section, context_allowed_default);
         CREATE INDEX IF NOT EXISTS idx_pp_context_policies_section
             ON pp_context_policies(context_section, context_allowed_default);
         CREATE INDEX IF NOT EXISTS idx_pp_records_category_updated
             ON derived_records(category, updated_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_records_capture
             ON derived_records(capture_id);
         CREATE INDEX IF NOT EXISTS idx_pp_records_projected
             ON derived_records(projected_to_profile_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_records_review_status
             ON derived_records(review_status, updated_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_reviews_record_created
             ON pp_reviews(record_id, created_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_digest_jobs_capture_created
             ON pp_digest_jobs(capture_id, created_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_digest_runs_capture_started
             ON pp_digest_runs(capture_id, started_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_entities_kind_name
             ON pp_entities(entity_kind, normalized_name);
         CREATE INDEX IF NOT EXISTS idx_pp_relations_subject_relation
             ON pp_relations(subject_entity_id, relation_type);
         CREATE INDEX IF NOT EXISTS idx_pp_observations_capture_created
             ON pp_observations(capture_id, created_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_personal_facts_category
             ON pp_personal_facts(category, updated_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_preferences_target
             ON pp_preferences(normalized_target, updated_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_projects_name
             ON pp_projects(project_name, updated_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_methods_name
             ON pp_methods(method_name, updated_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_evidence_record
             ON pp_evidence(record_id);
         CREATE INDEX IF NOT EXISTS idx_pp_bridges_source
             ON pp_cross_project_bridges(source_repo_root, bridge_key);",
    )?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS pp_claims(
             id TEXT PRIMARY KEY,
             record_id TEXT UNIQUE,
             capture_id TEXT,
             category TEXT NOT NULL,
             subcategory TEXT,
             subject TEXT NOT NULL,
             attribute TEXT,
             value TEXT NOT NULL,
             claim_origin TEXT NOT NULL,
             truth_status TEXT NOT NULL,
             stability_class TEXT NOT NULL,
             sensitivity TEXT NOT NULL,
             confidence REAL NOT NULL,
             review_status TEXT NOT NULL,
             evidence_summary TEXT,
             valid_from_ms INTEGER,
             valid_to_ms INTEGER,
             supersedes_claim_id TEXT,
             contradicted_by_claim_id TEXT,
             created_at_ms INTEGER NOT NULL,
             updated_at_ms INTEGER NOT NULL,
             metadata_json TEXT NOT NULL,
             FOREIGN KEY(record_id) REFERENCES derived_records(id) ON DELETE CASCADE,
             FOREIGN KEY(capture_id) REFERENCES captured_conversations(id) ON DELETE CASCADE
         );
         CREATE TABLE IF NOT EXISTS pp_claim_versions(
             id TEXT PRIMARY KEY,
             claim_id TEXT NOT NULL,
             change_json TEXT NOT NULL,
             created_at_ms INTEGER NOT NULL,
             FOREIGN KEY(claim_id) REFERENCES pp_claims(id) ON DELETE CASCADE
         );
         CREATE TABLE IF NOT EXISTS pp_claim_evidence(
             id TEXT PRIMARY KEY,
             claim_id TEXT NOT NULL,
             capture_id TEXT,
             evidence_text TEXT NOT NULL,
             metadata_json TEXT NOT NULL,
             created_at_ms INTEGER NOT NULL,
             FOREIGN KEY(claim_id) REFERENCES pp_claims(id) ON DELETE CASCADE,
             FOREIGN KEY(capture_id) REFERENCES captured_conversations(id) ON DELETE SET NULL
         );
         CREATE TABLE IF NOT EXISTS pp_claim_links(
             id TEXT PRIMARY KEY,
             claim_id TEXT NOT NULL,
             linked_claim_id TEXT,
             link_type TEXT NOT NULL,
             metadata_json TEXT NOT NULL,
             created_at_ms INTEGER NOT NULL,
             FOREIGN KEY(claim_id) REFERENCES pp_claims(id) ON DELETE CASCADE,
             FOREIGN KEY(linked_claim_id) REFERENCES pp_claims(id) ON DELETE CASCADE
         );
         CREATE TABLE IF NOT EXISTS pp_feedback_events(
             id TEXT PRIMARY KEY,
             claim_id TEXT,
             capture_id TEXT,
             event_type TEXT NOT NULL,
             notes TEXT,
             created_at_ms INTEGER NOT NULL,
             metadata_json TEXT NOT NULL,
             FOREIGN KEY(claim_id) REFERENCES pp_claims(id) ON DELETE SET NULL,
             FOREIGN KEY(capture_id) REFERENCES captured_conversations(id) ON DELETE SET NULL
         );
         CREATE TABLE IF NOT EXISTS pp_identity_snapshots(
             id TEXT PRIMARY KEY,
             snapshot_kind TEXT NOT NULL,
             summary TEXT NOT NULL,
             stable_summary TEXT,
             changed_summary TEXT,
             active_projects_summary TEXT,
             created_at_ms INTEGER NOT NULL,
             metadata_json TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS pp_decision_patterns(
             id TEXT PRIMARY KEY,
             snapshot_id TEXT,
             pattern_key TEXT NOT NULL,
             summary TEXT NOT NULL,
             confidence REAL NOT NULL,
             created_at_ms INTEGER NOT NULL,
             updated_at_ms INTEGER NOT NULL,
             metadata_json TEXT NOT NULL,
             FOREIGN KEY(snapshot_id) REFERENCES pp_identity_snapshots(id) ON DELETE SET NULL
         );
         CREATE TABLE IF NOT EXISTS pp_style_signals(
             id TEXT PRIMARY KEY,
             snapshot_id TEXT,
             signal_key TEXT NOT NULL,
             summary TEXT NOT NULL,
             confidence REAL NOT NULL,
             created_at_ms INTEGER NOT NULL,
             updated_at_ms INTEGER NOT NULL,
             metadata_json TEXT NOT NULL,
             FOREIGN KEY(snapshot_id) REFERENCES pp_identity_snapshots(id) ON DELETE SET NULL
         );
         CREATE TABLE IF NOT EXISTS pp_clone_profiles(
             id TEXT PRIMARY KEY,
             mode TEXT NOT NULL UNIQUE,
             summary TEXT NOT NULL,
             updated_at_ms INTEGER NOT NULL,
             metadata_json TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS pp_clone_context_packs(
             id TEXT PRIMARY KEY,
             mode TEXT NOT NULL,
             query TEXT NOT NULL,
             query_hash TEXT NOT NULL,
             current_repo_root TEXT,
             summary TEXT NOT NULL,
             explanation_json TEXT NOT NULL,
             created_at_ms INTEGER NOT NULL,
             metadata_json TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS pp_clone_evaluations(
             id TEXT PRIMARY KEY,
             mode TEXT NOT NULL,
             score REAL NOT NULL,
             query TEXT NOT NULL,
             notes TEXT,
             created_at_ms INTEGER NOT NULL,
             metadata_json TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS pp_project_timelines(
             id TEXT PRIMARY KEY,
             claim_id TEXT,
             snapshot_id TEXT,
             project_name TEXT NOT NULL,
             repo_root TEXT,
             lifecycle_state TEXT NOT NULL,
             valid_from_ms INTEGER,
             valid_to_ms INTEGER,
             created_at_ms INTEGER NOT NULL,
             updated_at_ms INTEGER NOT NULL,
             metadata_json TEXT NOT NULL,
             FOREIGN KEY(claim_id) REFERENCES pp_claims(id) ON DELETE CASCADE,
             FOREIGN KEY(snapshot_id) REFERENCES pp_identity_snapshots(id) ON DELETE SET NULL
         );
         CREATE TABLE IF NOT EXISTS pp_goal_graph(
             id TEXT PRIMARY KEY,
             claim_id TEXT,
             snapshot_id TEXT,
             goal_key TEXT NOT NULL,
             summary TEXT NOT NULL,
             status TEXT NOT NULL,
             project_name TEXT,
             created_at_ms INTEGER NOT NULL,
             updated_at_ms INTEGER NOT NULL,
             metadata_json TEXT NOT NULL,
             FOREIGN KEY(claim_id) REFERENCES pp_claims(id) ON DELETE CASCADE,
             FOREIGN KEY(snapshot_id) REFERENCES pp_identity_snapshots(id) ON DELETE SET NULL
         );
         CREATE TABLE IF NOT EXISTS pp_operator_routines(
             id TEXT PRIMARY KEY,
             routine_key TEXT NOT NULL UNIQUE,
             title TEXT NOT NULL,
             summary TEXT NOT NULL,
             purpose TEXT NOT NULL DEFAULT '',
             trigger_terms_json TEXT NOT NULL,
             applies_when_json TEXT NOT NULL DEFAULT '[]',
             confidence REAL NOT NULL,
             support_count INTEGER NOT NULL,
             cross_project_support_count INTEGER NOT NULL DEFAULT 0,
             event_support_count INTEGER NOT NULL DEFAULT 0,
             risk_level TEXT NOT NULL DEFAULT 'low',
             autonomy_level TEXT NOT NULL DEFAULT 'advisory',
             version INTEGER NOT NULL DEFAULT 1,
             valid_from_ms INTEGER,
             valid_to_ms INTEGER,
             drift_status TEXT NOT NULL DEFAULT 'stable',
             drift_score REAL NOT NULL DEFAULT 0,
             status TEXT NOT NULL,
             created_at_ms INTEGER NOT NULL,
             updated_at_ms INTEGER NOT NULL,
             metadata_json TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS pp_operator_routine_steps(
             id TEXT PRIMARY KEY,
             routine_id TEXT NOT NULL,
             step_order INTEGER NOT NULL,
             step_key TEXT NOT NULL,
             title TEXT NOT NULL,
             instruction TEXT NOT NULL,
             required INTEGER NOT NULL DEFAULT 1,
             tool_hints_json TEXT NOT NULL DEFAULT '[]',
             expected_artifacts_json TEXT NOT NULL DEFAULT '[]',
             evidence_query TEXT NOT NULL DEFAULT '',
             success_check TEXT NOT NULL DEFAULT '',
             failure_recovery TEXT NOT NULL DEFAULT '',
             approval_required INTEGER NOT NULL DEFAULT 0,
             evidence_claim_ids_json TEXT NOT NULL,
             event_evidence_ids_json TEXT NOT NULL DEFAULT '[]',
             confidence REAL NOT NULL,
             created_at_ms INTEGER NOT NULL,
             updated_at_ms INTEGER NOT NULL,
             metadata_json TEXT NOT NULL,
             FOREIGN KEY(routine_id) REFERENCES pp_operator_routines(id) ON DELETE CASCADE
         );
         CREATE TABLE IF NOT EXISTS pp_operator_events(
             id TEXT PRIMARY KEY,
             source TEXT NOT NULL,
             source_session_id TEXT,
             event_kind TEXT NOT NULL,
             action TEXT NOT NULL,
             summary TEXT NOT NULL,
             command_text TEXT,
             repo_id TEXT,
             repo_root TEXT,
             capture_id TEXT,
             artifact_path TEXT,
             occurred_at_ms INTEGER NOT NULL,
             created_at_ms INTEGER NOT NULL,
             content_hash TEXT NOT NULL UNIQUE,
             metadata_json TEXT NOT NULL,
             FOREIGN KEY(capture_id) REFERENCES captured_conversations(id) ON DELETE SET NULL
         );
         CREATE TABLE IF NOT EXISTS pp_override_rules(
             id TEXT PRIMARY KEY,
             claim_id TEXT,
             category TEXT NOT NULL,
             attribute TEXT,
             subject TEXT,
             override_value TEXT NOT NULL,
             reason TEXT,
             created_at_ms INTEGER NOT NULL,
             updated_at_ms INTEGER NOT NULL,
             metadata_json TEXT NOT NULL,
             FOREIGN KEY(claim_id) REFERENCES pp_claims(id) ON DELETE SET NULL
         );
         CREATE TABLE IF NOT EXISTS pp_redaction_spans(
             id TEXT PRIMARY KEY,
             capture_id TEXT NOT NULL,
             claim_id TEXT,
             span_kind TEXT NOT NULL,
             start_offset INTEGER,
             end_offset INTEGER,
             replacement_text TEXT NOT NULL,
             reason TEXT,
             created_at_ms INTEGER NOT NULL,
             metadata_json TEXT NOT NULL,
             FOREIGN KEY(capture_id) REFERENCES captured_conversations(id) ON DELETE CASCADE,
             FOREIGN KEY(claim_id) REFERENCES pp_claims(id) ON DELETE SET NULL
         );
         CREATE TABLE IF NOT EXISTS pp_retention_policies(
             id TEXT PRIMARY KEY,
             policy_key TEXT NOT NULL UNIQUE,
             lane TEXT NOT NULL,
             category TEXT,
             raw_retention_days INTEGER,
             derived_retention_days INTEGER,
             claim_retention_days INTEGER,
             snapshot_retention_days INTEGER,
             export_retention_days INTEGER,
             updated_at_ms INTEGER NOT NULL,
             metadata_json TEXT NOT NULL
         );
         CREATE INDEX IF NOT EXISTS idx_pp_claims_truth_updated
             ON pp_claims(truth_status, updated_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_claims_origin_updated
             ON pp_claims(claim_origin, updated_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_claims_category_updated
             ON pp_claims(category, updated_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_claims_review_status
             ON pp_claims(review_status, updated_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_claim_versions_claim_created
             ON pp_claim_versions(claim_id, created_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_claim_evidence_claim
             ON pp_claim_evidence(claim_id, created_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_claim_links_claim
             ON pp_claim_links(claim_id, link_type, created_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_feedback_events_created
             ON pp_feedback_events(created_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_snapshots_created
             ON pp_identity_snapshots(created_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_decision_patterns_snapshot
             ON pp_decision_patterns(snapshot_id, updated_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_style_signals_snapshot
             ON pp_style_signals(snapshot_id, updated_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_clone_context_query
             ON pp_clone_context_packs(query_hash, created_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_clone_evaluations_mode_created
             ON pp_clone_evaluations(mode, created_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_project_timelines_project
             ON pp_project_timelines(project_name, updated_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_goal_graph_key
             ON pp_goal_graph(goal_key, updated_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_operator_routines_key
             ON pp_operator_routines(routine_key, updated_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_operator_routine_steps_routine
             ON pp_operator_routine_steps(routine_id, step_order);
         CREATE INDEX IF NOT EXISTS idx_pp_operator_events_kind_occurred
             ON pp_operator_events(event_kind, occurred_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_operator_events_repo_occurred
             ON pp_operator_events(repo_root, occurred_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_operator_events_hash
             ON pp_operator_events(content_hash);
         CREATE INDEX IF NOT EXISTS idx_pp_override_rules_lookup
             ON pp_override_rules(category, attribute, updated_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_redaction_spans_capture
             ON pp_redaction_spans(capture_id, created_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_retention_policies_lane
             ON pp_retention_policies(lane, updated_at_ms);",
    )?;
    ensure_column(&conn, "captured_conversations", "archive_path", "TEXT")?;
    ensure_column(
        &conn,
        "captured_conversations",
        "raw_message_count",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
    ensure_column(
        &conn,
        "captured_conversations",
        "archive_redacted_at_ms",
        "INTEGER",
    )?;
    ensure_column(
        &conn,
        "derived_records",
        "projected_to_profile_at_ms",
        "INTEGER",
    )?;
    ensure_column(
        &conn,
        "derived_records",
        "review_status",
        "TEXT NOT NULL DEFAULT 'approved'",
    )?;
    ensure_column(&conn, "derived_records", "review_updated_at_ms", "INTEGER")?;
    ensure_column(
        &conn,
        "pp_operator_routines",
        "purpose",
        "TEXT NOT NULL DEFAULT ''",
    )?;
    ensure_column(
        &conn,
        "pp_operator_routines",
        "applies_when_json",
        "TEXT NOT NULL DEFAULT '[]'",
    )?;
    ensure_column(
        &conn,
        "pp_operator_routines",
        "cross_project_support_count",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
    ensure_column(
        &conn,
        "pp_operator_routines",
        "event_support_count",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
    ensure_column(
        &conn,
        "pp_operator_routines",
        "risk_level",
        "TEXT NOT NULL DEFAULT 'low'",
    )?;
    ensure_column(
        &conn,
        "pp_operator_routines",
        "autonomy_level",
        "TEXT NOT NULL DEFAULT 'advisory'",
    )?;
    ensure_column(
        &conn,
        "pp_operator_routines",
        "version",
        "INTEGER NOT NULL DEFAULT 1",
    )?;
    ensure_column(&conn, "pp_operator_routines", "valid_from_ms", "INTEGER")?;
    ensure_column(&conn, "pp_operator_routines", "valid_to_ms", "INTEGER")?;
    ensure_column(
        &conn,
        "pp_operator_routines",
        "drift_status",
        "TEXT NOT NULL DEFAULT 'stable'",
    )?;
    ensure_column(
        &conn,
        "pp_operator_routines",
        "drift_score",
        "REAL NOT NULL DEFAULT 0",
    )?;
    ensure_column(
        &conn,
        "pp_operator_routine_steps",
        "required",
        "INTEGER NOT NULL DEFAULT 1",
    )?;
    ensure_column(
        &conn,
        "pp_operator_routine_steps",
        "tool_hints_json",
        "TEXT NOT NULL DEFAULT '[]'",
    )?;
    ensure_column(
        &conn,
        "pp_operator_routine_steps",
        "expected_artifacts_json",
        "TEXT NOT NULL DEFAULT '[]'",
    )?;
    ensure_column(
        &conn,
        "pp_operator_routine_steps",
        "evidence_query",
        "TEXT NOT NULL DEFAULT ''",
    )?;
    ensure_column(
        &conn,
        "pp_operator_routine_steps",
        "success_check",
        "TEXT NOT NULL DEFAULT ''",
    )?;
    ensure_column(
        &conn,
        "pp_operator_routine_steps",
        "failure_recovery",
        "TEXT NOT NULL DEFAULT ''",
    )?;
    ensure_column(
        &conn,
        "pp_operator_routine_steps",
        "approval_required",
        "INTEGER NOT NULL DEFAULT 0",
    )?;
    ensure_column(
        &conn,
        "pp_operator_routine_steps",
        "event_evidence_ids_json",
        "TEXT NOT NULL DEFAULT '[]'",
    )?;
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS pp_ai_terminal_integrations(
             integration_id TEXT PRIMARY KEY,
             terminal TEXT NOT NULL,
             enabled INTEGER NOT NULL DEFAULT 1,
             capture_enabled INTEGER NOT NULL DEFAULT 1,
             skill_sync_enabled INTEGER NOT NULL DEFAULT 1,
             activation_enabled INTEGER NOT NULL DEFAULT 1,
             capture_mode TEXT NOT NULL,
             skill_roots_json TEXT NOT NULL,
             mcp_registration_status TEXT NOT NULL,
             last_capture_at_ms INTEGER,
             last_digest_at_ms INTEGER,
             last_skill_sync_at_ms INTEGER,
             last_activation_check_at_ms INTEGER,
             last_error TEXT,
             metadata_json TEXT NOT NULL,
             created_at_ms INTEGER NOT NULL,
             updated_at_ms INTEGER NOT NULL
         );
         CREATE TABLE IF NOT EXISTS pp_ai_terminal_capture_events(
             event_id TEXT PRIMARY KEY,
             integration_id TEXT NOT NULL,
             terminal TEXT NOT NULL,
             source_session_id TEXT,
             event_kind TEXT NOT NULL,
             repo_scope TEXT,
             summary TEXT NOT NULL,
             payload_json TEXT NOT NULL,
             capture_id TEXT,
             redaction_status TEXT NOT NULL,
             digest_status TEXT NOT NULL,
             created_at_ms INTEGER NOT NULL,
             processed_at_ms INTEGER,
             FOREIGN KEY(integration_id) REFERENCES pp_ai_terminal_integrations(integration_id) ON DELETE CASCADE,
             FOREIGN KEY(capture_id) REFERENCES captured_conversations(id) ON DELETE SET NULL
         );
         CREATE TABLE IF NOT EXISTS pp_generated_skills(
             skill_id TEXT PRIMARY KEY,
             slug TEXT NOT NULL UNIQUE,
             name TEXT NOT NULL,
             description TEXT NOT NULL,
             category TEXT NOT NULL,
             scope TEXT NOT NULL,
             scope_key TEXT,
             source_compiler TEXT NOT NULL,
             status TEXT NOT NULL,
             risk_level TEXT NOT NULL,
             autonomy_level TEXT NOT NULL,
             confidence REAL NOT NULL,
             support_count INTEGER NOT NULL,
             current_version_id TEXT,
             created_at_ms INTEGER NOT NULL,
             updated_at_ms INTEGER NOT NULL,
             metadata_json TEXT NOT NULL
         );
         CREATE TABLE IF NOT EXISTS pp_generated_skill_versions(
             version_id TEXT PRIMARY KEY,
             skill_id TEXT NOT NULL,
             version TEXT NOT NULL,
             evidence_hash TEXT NOT NULL,
             skill_markdown TEXT NOT NULL,
             sidecar_json TEXT NOT NULL,
             rendered_at_ms INTEGER NOT NULL,
             rendered_by TEXT NOT NULL,
             validation_status TEXT NOT NULL,
             validation_summary TEXT NOT NULL,
             install_policy TEXT NOT NULL,
             rollback_from_version_id TEXT,
             FOREIGN KEY(skill_id) REFERENCES pp_generated_skills(skill_id) ON DELETE CASCADE
         );
         CREATE TABLE IF NOT EXISTS pp_generated_skill_sources(
             id TEXT PRIMARY KEY,
             skill_id TEXT NOT NULL,
             version_id TEXT NOT NULL,
             source_type TEXT NOT NULL,
             source_id TEXT NOT NULL,
             source_hash TEXT NOT NULL,
             sensitivity TEXT NOT NULL,
             included_in_body INTEGER NOT NULL DEFAULT 0,
             included_in_sidecar INTEGER NOT NULL DEFAULT 1,
             reason TEXT NOT NULL,
             created_at_ms INTEGER NOT NULL,
             FOREIGN KEY(skill_id) REFERENCES pp_generated_skills(skill_id) ON DELETE CASCADE,
             FOREIGN KEY(version_id) REFERENCES pp_generated_skill_versions(version_id) ON DELETE CASCADE
         );
         CREATE TABLE IF NOT EXISTS pp_generated_skill_validations(
             validation_id TEXT PRIMARY KEY,
             skill_id TEXT NOT NULL,
             version_id TEXT NOT NULL,
             validator TEXT NOT NULL,
             status TEXT NOT NULL,
             details_json TEXT NOT NULL,
             created_at_ms INTEGER NOT NULL,
             FOREIGN KEY(skill_id) REFERENCES pp_generated_skills(skill_id) ON DELETE CASCADE,
             FOREIGN KEY(version_id) REFERENCES pp_generated_skill_versions(version_id) ON DELETE CASCADE
         );
         CREATE TABLE IF NOT EXISTS pp_generated_skill_installations(
             installation_id TEXT PRIMARY KEY,
             skill_id TEXT NOT NULL,
             version_id TEXT NOT NULL,
             integration_id TEXT NOT NULL,
             agent_target TEXT NOT NULL,
             install_root TEXT NOT NULL,
             installed_path TEXT NOT NULL,
             status TEXT NOT NULL,
             installed_at_ms INTEGER NOT NULL,
             last_seen_at_ms INTEGER,
             last_error TEXT,
             FOREIGN KEY(skill_id) REFERENCES pp_generated_skills(skill_id) ON DELETE CASCADE,
             FOREIGN KEY(version_id) REFERENCES pp_generated_skill_versions(version_id) ON DELETE CASCADE,
             FOREIGN KEY(integration_id) REFERENCES pp_ai_terminal_integrations(integration_id) ON DELETE CASCADE
         );
         CREATE TABLE IF NOT EXISTS pp_generated_skill_activation_events(
             activation_id TEXT PRIMARY KEY,
             skill_id TEXT NOT NULL,
             version_id TEXT NOT NULL,
             integration_id TEXT NOT NULL,
             terminal TEXT NOT NULL,
             activation_kind TEXT NOT NULL,
             trigger_query TEXT,
             used INTEGER NOT NULL DEFAULT 0,
             accepted INTEGER NOT NULL DEFAULT 0,
             rejected_reason TEXT,
             created_at_ms INTEGER NOT NULL,
             FOREIGN KEY(skill_id) REFERENCES pp_generated_skills(skill_id) ON DELETE CASCADE,
             FOREIGN KEY(version_id) REFERENCES pp_generated_skill_versions(version_id) ON DELETE CASCADE,
             FOREIGN KEY(integration_id) REFERENCES pp_ai_terminal_integrations(integration_id) ON DELETE CASCADE
         );
         CREATE TABLE IF NOT EXISTS pp_generated_skill_events(
             event_id TEXT PRIMARY KEY,
             skill_id TEXT NOT NULL,
             version_id TEXT,
             event_kind TEXT NOT NULL,
             summary TEXT NOT NULL,
             metadata_json TEXT NOT NULL,
             created_at_ms INTEGER NOT NULL,
             FOREIGN KEY(skill_id) REFERENCES pp_generated_skills(skill_id) ON DELETE CASCADE,
             FOREIGN KEY(version_id) REFERENCES pp_generated_skill_versions(version_id) ON DELETE SET NULL
         );
         CREATE INDEX IF NOT EXISTS idx_pp_ai_terminal_terminal
             ON pp_ai_terminal_integrations(terminal, enabled);
         CREATE INDEX IF NOT EXISTS idx_pp_ai_terminal_capture_status
             ON pp_ai_terminal_capture_events(digest_status, created_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_generated_skills_status
             ON pp_generated_skills(status, risk_level, updated_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_generated_skill_versions_skill
             ON pp_generated_skill_versions(skill_id, rendered_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_generated_skill_sources_skill
             ON pp_generated_skill_sources(skill_id, source_type);
         CREATE INDEX IF NOT EXISTS idx_pp_generated_skill_installations_target
             ON pp_generated_skill_installations(agent_target, status);
         CREATE INDEX IF NOT EXISTS idx_pp_generated_skill_activation_skill
             ON pp_generated_skill_activation_events(skill_id, created_at_ms);
         CREATE INDEX IF NOT EXISTS idx_pp_generated_skill_events_skill
             ON pp_generated_skill_events(skill_id, created_at_ms);",
    )?;
    seed_default_category_policies(&conn)?;
    seed_default_sensitivity_levels(&conn)?;
    seed_default_context_policies(&conn)?;
    seed_default_retention_policies(&conn)?;
    backfill_rich_capture_lineage(&conn)?;
    backfill_rich_derived_materialization(&conn)?;
    backfill_claims_from_records(&conn, None)?;
    let claims = load_all_claims(&conn)?;
    rebuild_operator_routines_tx(&conn, None, &claims, now_ms())?;
    conn.execute(
        "INSERT OR REPLACE INTO personal_preferences_meta(key, value) VALUES (?1, ?2)",
        params!["schema_version", SCHEMA_VERSION.to_string()],
    )?;
    Ok(())
}

pub(super) fn ensure_column(
    conn: &Connection,
    table: &str,
    column: &str,
    spec: &str,
) -> Result<()> {
    let pragma = format!("PRAGMA table_info({table})");
    let mut stmt = conn.prepare(&pragma)?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let existing = row.get::<_, String>(1)?;
        if existing == column {
            return Ok(());
        }
    }
    let sql = format!("ALTER TABLE {table} ADD COLUMN {column} {spec}");
    conn.execute(&sql, [])?;
    Ok(())
}
