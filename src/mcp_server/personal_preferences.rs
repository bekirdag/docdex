use super::*;

impl McpServer {
    pub(super) async fn handle_personal_preferences_status(
        &self,
        _args: PersonalPreferencesStatusArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        crate::personal_preferences::status_payload_with_config(
            personal_preferences.store.status()?,
            &personal_preferences.config,
        )
    }

    pub(super) async fn handle_personal_preferences_categories(
        &self,
        _args: PersonalPreferencesCategoriesArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        Ok(serde_json::to_value(
            personal_preferences.store.list_categories()?,
        )?)
    }

    pub(super) async fn handle_personal_preferences_retention_policies(
        &self,
        _args: PersonalPreferencesRetentionPoliciesArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        Ok(serde_json::to_value(
            personal_preferences.store.list_retention_policies()?,
        )?)
    }

    pub(super) async fn handle_personal_preferences_list(
        &self,
        args: PersonalPreferencesListArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        Ok(serde_json::to_value(
            personal_preferences.store.list_captures(
                args.status.as_deref(),
                args.limit.unwrap_or(20).clamp(1, 200),
                args.offset.unwrap_or(0),
            )?,
        )?)
    }

    pub(super) async fn handle_personal_preferences_read(
        &self,
        args: PersonalPreferencesReadArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        let capture_id = args.capture_id.trim().to_string();
        if capture_id.is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "capture_id must not be empty").into());
        }
        let Some(capture) = personal_preferences.store.read_capture(&capture_id)? else {
            return Err(AppError::new(
                ERR_INVALID_ARGUMENT,
                "personal preferences capture not found",
            )
            .into());
        };
        Ok(serde_json::to_value(capture)?)
    }

    pub(super) async fn handle_personal_preferences_search(
        &self,
        args: PersonalPreferencesSearchArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        let query = args.query.trim().to_string();
        Ok(serde_json::to_value(
            personal_preferences.store.search_records_with_policy(
                &query,
                args.limit.unwrap_or(10).clamp(1, 100),
                args.include_sensitive.unwrap_or(true),
            )?,
        )?)
    }

    pub(super) async fn handle_personal_preferences_reviews(
        &self,
        args: PersonalPreferencesReviewQueueArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        Ok(serde_json::to_value(
            personal_preferences.store.list_review_records(
                args.status.as_deref(),
                args.limit.unwrap_or(20).clamp(1, 200),
                args.offset.unwrap_or(0),
            )?,
        )?)
    }

    pub(super) async fn handle_personal_preferences_review(
        &self,
        args: PersonalPreferencesReviewArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        Ok(serde_json::to_value(
            personal_preferences.store.review_record(
                args.record_id.trim(),
                args.verdict.trim(),
                args.notes.as_deref(),
            )?,
        )?)
    }

    pub(super) async fn handle_personal_preferences_process(
        &self,
        args: PersonalPreferencesProcessArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        if !personal_preferences.config.digest_enabled {
            return Err(AppError::new(
                ERR_MEMORY_DISABLED,
                "personal preferences digest is disabled; enable [personal_preferences].digest_enabled",
            )
            .into());
        }
        if let Some(stale_ms) = args.retry_stale_processing_ms {
            if stale_ms < 0 {
                return Err(AppError::new(
                    ERR_INVALID_ARGUMENT,
                    "retry_stale_processing_ms must be >= 0",
                )
                .into());
            }
        }
        let requeued = personal_preferences.store.requeue_captures_for_processing(
            args.retry_failed,
            args.retry_stale_processing_ms,
            args.limit,
        )?;
        let mut summary = crate::personal_preferences::process_pending_with_local_agents(
            &personal_preferences.store,
            self.global_state_dir.as_deref(),
            &self.llm_config,
            &personal_preferences.config,
            args.limit,
        )
        .await?;
        summary.requeued_captures = requeued;
        if let Some(profile_state) = self.profile_state.as_ref() {
            summary.projected_profile_preferences =
                crate::personal_preferences::project_safe_preferences_to_profile(
                    &personal_preferences.store,
                    &profile_state.manager,
                    profile_state.embedder.as_ref(),
                    &personal_preferences.config,
                    self.default_agent_id.as_deref(),
                )
                .await?;
        }
        Ok(serde_json::to_value(summary)?)
    }

    pub(super) async fn handle_personal_preferences_scan(
        &self,
        args: PersonalPreferencesScanArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        if !personal_preferences
            .config
            .capture_supported_client_transcripts
        {
            return Err(AppError::new(
                ERR_MEMORY_DISABLED,
                "supported client transcript capture is disabled; enable [personal_preferences].capture_supported_client_transcripts",
            )
            .into());
        }
        if matches!(args.limit, Some(0)) {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "limit must be > 0").into());
        }
        Ok(serde_json::to_value(
            personal_preferences
                .store
                .scan_supported_client_transcripts(&personal_preferences.config, args.limit)?,
        )?)
    }

    pub(super) async fn handle_personal_preferences_export(
        &self,
        args: PersonalPreferencesExportArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        if !personal_preferences.config.export_enabled {
            return Err(AppError::new(
                ERR_MEMORY_DISABLED,
                "personal preferences export is disabled; enable [personal_preferences].export_enabled",
            )
            .into());
        }
        Ok(serde_json::to_value(
            personal_preferences
                .store
                .export_bundle(args.capture_id.as_deref())?,
        )?)
    }

    pub(super) async fn handle_personal_preferences_redact(
        &self,
        args: PersonalPreferencesDeleteArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        Ok(serde_json::to_value(
            personal_preferences
                .store
                .redact_capture(args.capture_id.trim())?,
        )?)
    }

    pub(super) async fn handle_personal_preferences_delete(
        &self,
        args: PersonalPreferencesDeleteArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        Ok(serde_json::to_value(
            personal_preferences
                .store
                .delete_capture(args.capture_id.trim())?,
        )?)
    }

    pub(super) async fn handle_personal_preferences_prune(
        &self,
        args: PersonalPreferencesPruneArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        Ok(serde_json::to_value(
            personal_preferences.store.prune_retention(
                args.raw_retention_days
                    .unwrap_or(personal_preferences.config.raw_retention_days),
                args.derived_retention_days
                    .unwrap_or(personal_preferences.config.derived_retention_days),
                args.apply.unwrap_or(false),
            )?,
        )?)
    }

    pub(super) async fn handle_personal_preferences_purge(
        &self,
        args: PersonalPreferencesPurgeArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        if !personal_preferences.config.purge_enabled {
            return Err(AppError::new(
                ERR_MEMORY_DISABLED,
                "personal preferences purge is disabled; enable [personal_preferences].purge_enabled",
            )
            .into());
        }
        Ok(serde_json::to_value(
            personal_preferences
                .store
                .purge_all(args.include_exports.unwrap_or(false))?,
        )?)
    }

    pub(super) async fn handle_personal_preferences_claims(
        &self,
        args: PersonalPreferencesClaimsArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        Ok(serde_json::to_value(
            personal_preferences.store.list_claims(
                crate::personal_preferences::PersonalPreferencesClaimsQuery {
                    query: args
                        .query
                        .map(|value| value.trim().to_string())
                        .filter(|value| !value.is_empty()),
                    truth_status: args
                        .truth_status
                        .map(|value| value.trim().to_string())
                        .filter(|value| !value.is_empty()),
                    claim_origin: args
                        .claim_origin
                        .map(|value| value.trim().to_string())
                        .filter(|value| !value.is_empty()),
                    include_sensitive: args.include_sensitive.unwrap_or(false),
                    limit: args.limit,
                    offset: args.offset,
                },
            )?,
        )?)
    }

    pub(super) async fn handle_personal_preferences_claim_read(
        &self,
        args: PersonalPreferencesClaimReadArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        let claim_id = args.claim_id.trim().to_string();
        if claim_id.is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "claim_id must not be empty").into());
        }
        let Some(claim) = personal_preferences.store.read_claim(&claim_id)? else {
            return Err(
                AppError::new(ERR_INVALID_ARGUMENT, "personal preference claim not found").into(),
            );
        };
        Ok(serde_json::to_value(claim)?)
    }

    pub(super) async fn handle_personal_preferences_claim_review(
        &self,
        args: PersonalPreferencesClaimReviewArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        Ok(serde_json::to_value(
            personal_preferences.store.review_claim(
                args.claim_id.trim(),
                args.verdict.trim(),
                args.notes.as_deref(),
            )?,
        )?)
    }

    pub(super) async fn handle_personal_preferences_claim_override(
        &self,
        args: PersonalPreferencesClaimOverrideArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        Ok(serde_json::to_value(
            personal_preferences.store.override_claim(
                args.claim_id.trim(),
                args.value.trim(),
                args.notes.as_deref(),
            )?,
        )?)
    }

    pub(super) async fn handle_personal_preferences_claim_forget(
        &self,
        args: PersonalPreferencesClaimForgetArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        Ok(serde_json::to_value(
            personal_preferences
                .store
                .forget_claim(args.claim_id.trim(), args.notes.as_deref())?,
        )?)
    }

    pub(super) async fn handle_personal_preferences_feedback(
        &self,
        args: PersonalPreferencesFeedbackArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        Ok(serde_json::to_value(
            personal_preferences.store.add_feedback_event(
                args.event_type.trim(),
                args.claim_id
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty()),
                args.capture_id
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty()),
                args.category
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty()),
                args.attribute
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty()),
                args.value
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty()),
                args.notes.as_deref(),
                args.metadata.unwrap_or(serde_json::Value::Null),
            )?,
        )?)
    }

    pub(super) async fn handle_personal_preferences_operator_events(
        &self,
        args: PersonalPreferencesOperatorEventsArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        Ok(serde_json::to_value(
            personal_preferences.store.list_operator_events(
                args.event_kind.as_deref(),
                args.action.as_deref(),
                args.repo_root.as_deref(),
                args.limit.unwrap_or(20).clamp(1, 200),
                args.offset.unwrap_or(0),
            )?,
        )?)
    }

    pub(super) async fn handle_personal_preferences_operator_event_record(
        &self,
        args: PersonalPreferencesOperatorEventRecordArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        let event = personal_preferences.store.record_operator_event(
            crate::personal_preferences::PersonalPreferenceOperatorEventRequest {
                event_kind: args.event_kind,
                action: args.action,
                summary: args.summary,
                command_text: args.command_text,
                source_session_id: args.source_session_id,
                repo_id: args.repo_id,
                repo_root: args.repo_root,
                capture_id: args.capture_id,
                artifact_path: args.artifact_path,
                occurred_at_ms: args.occurred_at_ms,
                metadata: args.metadata.unwrap_or(serde_json::Value::Null),
            },
            "mcp",
        )?;
        Ok(serde_json::to_value(event)?)
    }

    pub(super) async fn handle_personal_preferences_operator_events_scan_artifacts(
        &self,
        args: PersonalPreferencesOperatorEventScanArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        let repo_root = args
            .repo_root
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| self.repo_root.clone());
        Ok(serde_json::to_value(
            personal_preferences
                .store
                .scan_operator_artifacts(&repo_root, args.limit)?,
        )?)
    }

    pub(super) async fn handle_personal_preferences_snapshots(
        &self,
        args: PersonalPreferencesSnapshotsArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        Ok(serde_json::to_value(
            personal_preferences.store.list_snapshots(
                args.limit.unwrap_or(20).clamp(1, 200),
                args.offset.unwrap_or(0),
            )?,
        )?)
    }

    pub(super) async fn handle_personal_preferences_snapshot_read(
        &self,
        args: PersonalPreferencesSnapshotReadArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        let snapshot_id = args.snapshot_id.trim().to_string();
        if snapshot_id.is_empty() {
            return Err(
                AppError::new(ERR_INVALID_ARGUMENT, "snapshot_id must not be empty").into(),
            );
        }
        let Some(snapshot) = personal_preferences.store.read_snapshot(&snapshot_id)? else {
            return Err(AppError::new(
                ERR_INVALID_ARGUMENT,
                "personal preference snapshot not found",
            )
            .into());
        };
        Ok(serde_json::to_value(snapshot)?)
    }

    pub(super) async fn handle_personal_preferences_snapshots_rebuild(
        &self,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        Ok(serde_json::to_value(
            personal_preferences.store.rebuild_snapshots()?,
        )?)
    }

    pub(super) async fn handle_personal_preferences_routines(
        &self,
        args: PersonalPreferencesRoutinesArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        Ok(serde_json::to_value(
            personal_preferences.store.list_operator_routines(
                args.limit.unwrap_or(20).clamp(1, 200),
                args.offset.unwrap_or(0),
            )?,
        )?)
    }

    pub(super) async fn handle_personal_preferences_routine_read(
        &self,
        args: PersonalPreferencesRoutineReadArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        let routine_id = args.routine_id.trim().to_string();
        if routine_id.is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "routine_id must not be empty").into());
        }
        let Some(routine) = personal_preferences
            .store
            .read_operator_routine(&routine_id)?
        else {
            return Err(AppError::new(
                ERR_INVALID_ARGUMENT,
                "personal preference operator routine not found",
            )
            .into());
        };
        Ok(serde_json::to_value(routine)?)
    }

    pub(super) async fn handle_personal_preferences_routine_explain(
        &self,
        args: PersonalPreferencesRoutineReadArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        let routine_id = args.routine_id.trim().to_string();
        if routine_id.is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "routine_id must not be empty").into());
        }
        let Some(explanation) = personal_preferences
            .store
            .explain_operator_routine(&routine_id)?
        else {
            return Err(AppError::new(
                ERR_INVALID_ARGUMENT,
                "personal preference operator routine not found",
            )
            .into());
        };
        Ok(serde_json::to_value(explanation)?)
    }

    pub(super) async fn handle_personal_preferences_routines_rebuild(
        &self,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        Ok(serde_json::to_value(
            personal_preferences.store.rebuild_operator_routines()?,
        )?)
    }

    pub(super) async fn handle_personal_preferences_mind_map(
        &self,
        args: PersonalPreferencesMindMapArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        let query = args
            .query
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());
        Ok(serde_json::to_value(
            personal_preferences.store.compile_mind_map(
                query,
                args.limit.unwrap_or(50).clamp(4, 200),
                args.include_sensitive.unwrap_or(false),
            )?,
        )?)
    }

    pub(super) async fn handle_personal_preferences_playbooks(
        &self,
        args: PersonalPreferencesPlaybooksArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        Ok(serde_json::to_value(
            personal_preferences.store.compile_operator_playbooks(
                args.min_confidence.unwrap_or(0.7),
                args.min_support_count.unwrap_or(2),
                args.include_sensitive.unwrap_or(false),
            )?,
        )?)
    }

    pub(super) async fn handle_ai_terminal_integrations(
        &self,
        _args: AiTerminalIntegrationsArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        Ok(serde_json::to_value(
            personal_preferences.store.list_ai_terminal_integrations()?,
        )?)
    }

    pub(super) async fn handle_ai_terminal_status(
        &self,
        _args: AiTerminalStatusArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        Ok(serde_json::to_value(
            personal_preferences.store.ai_terminal_status()?,
        )?)
    }

    pub(super) async fn handle_ai_terminal_detect(
        &self,
        args: AiTerminalIntegrationsBootstrapArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        Ok(serde_json::to_value(
            personal_preferences
                .store
                .detect_ai_terminal_integrations(args.terminals)?,
        )?)
    }

    pub(super) async fn handle_ai_terminal_events(
        &self,
        args: AiTerminalEventsArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        Ok(serde_json::to_value(
            personal_preferences.store.list_ai_terminal_capture_events(
                args.limit.unwrap_or(50),
                args.offset.unwrap_or(0),
            )?,
        )?)
    }

    pub(super) async fn handle_ai_terminal_integrations_bootstrap(
        &self,
        args: AiTerminalIntegrationsBootstrapArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        Ok(serde_json::to_value(
            personal_preferences
                .store
                .bootstrap_ai_terminal_integrations(args.terminals)?,
        )?)
    }

    pub(super) async fn handle_ai_terminal_capture(
        &self,
        args: AiTerminalCaptureArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        Ok(serde_json::to_value(
            personal_preferences.store.record_ai_terminal_capture(
                crate::personal_preferences::PersonalPreferenceAiTerminalCaptureRequest {
                    terminal: args.terminal,
                    integration_id: args.integration_id,
                    source_session_id: args.source_session_id,
                    event_kind: args.event_kind,
                    repo_scope: args.repo_scope,
                    summary: args.summary,
                    transcript_text: args.transcript_text,
                    agent_id: args.agent_id,
                    metadata: args.metadata.unwrap_or_else(|| json!({})),
                },
            )?,
        )?)
    }

    pub(super) async fn handle_generated_skills_list(
        &self,
        _args: GeneratedSkillsListArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        Ok(serde_json::to_value(
            personal_preferences.store.list_generated_skills()?,
        )?)
    }

    pub(super) async fn handle_generated_skill_events(
        &self,
        args: GeneratedSkillEventsArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        Ok(serde_json::to_value(
            personal_preferences
                .store
                .list_generated_skill_events(args.limit.unwrap_or(50), args.offset.unwrap_or(0))?,
        )?)
    }

    pub(super) async fn handle_generated_skill_read(
        &self,
        args: GeneratedSkillReadArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        let skill_id = args.skill_id.trim().to_string();
        if skill_id.is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "skill_id must not be empty").into());
        }
        let Some(skill) = personal_preferences.store.read_generated_skill(&skill_id)? else {
            return Err(AppError::new(
                ERR_INVALID_ARGUMENT,
                "personal preference generated skill not found",
            )
            .into());
        };
        Ok(serde_json::to_value(skill)?)
    }

    pub(super) async fn handle_generated_skill_validate(
        &self,
        args: GeneratedSkillActionArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        let skill_id = normalized_generated_skill_arg(args.skill_id)?;
        Ok(serde_json::to_value(
            personal_preferences
                .store
                .validate_generated_skill(&skill_id)?,
        )?)
    }

    pub(super) async fn handle_generated_skill_install(
        &self,
        args: GeneratedSkillActionArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        let skill_id = normalized_generated_skill_arg(args.skill_id)?;
        Ok(serde_json::to_value(
            personal_preferences
                .store
                .install_generated_skill(&skill_id, args.terminals)?,
        )?)
    }

    pub(super) async fn handle_generated_skill_disable(
        &self,
        args: GeneratedSkillActionArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        let skill_id = normalized_generated_skill_arg(args.skill_id)?;
        Ok(serde_json::to_value(
            personal_preferences
                .store
                .disable_generated_skill(&skill_id, args.reason)?,
        )?)
    }

    pub(super) async fn handle_generated_skill_rollback(
        &self,
        args: GeneratedSkillActionArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        let skill_id = normalized_generated_skill_arg(args.skill_id)?;
        Ok(serde_json::to_value(
            personal_preferences
                .store
                .rollback_generated_skill(&skill_id, args.terminals)?,
        )?)
    }

    pub(super) async fn handle_generated_skills_sync(
        &self,
        args: GeneratedSkillsSyncArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        Ok(serde_json::to_value(
            personal_preferences.store.sync_generated_skills(
                crate::personal_preferences::PersonalPreferenceGeneratedSkillsSyncOptions {
                    min_confidence: args.min_confidence,
                    min_support_count: args.min_support_count,
                    include_sensitive: args.include_sensitive,
                    install: args.install,
                    terminals: args.terminals,
                },
            )?,
        )?)
    }

    pub(super) async fn handle_generated_skills_preview(
        &self,
        args: GeneratedSkillsSyncArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        Ok(serde_json::to_value(
            personal_preferences.store.preview_generated_skills(
                crate::personal_preferences::PersonalPreferenceGeneratedSkillsSyncOptions {
                    min_confidence: args.min_confidence,
                    min_support_count: args.min_support_count,
                    include_sensitive: args.include_sensitive,
                    install: Some(false),
                    terminals: args.terminals,
                },
            )?,
        )?)
    }

    pub(super) async fn handle_generated_skills_autopilot(
        &self,
        args: GeneratedSkillsSyncArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        let mut summary = personal_preferences.store.sync_generated_skills(
            crate::personal_preferences::PersonalPreferenceGeneratedSkillsSyncOptions {
                min_confidence: args.min_confidence,
                min_support_count: args.min_support_count,
                include_sensitive: args.include_sensitive,
                install: args.install,
                terminals: args.terminals,
            },
        )?;
        summary.notes.push(
            "Autopilot one-shot processed generated skills through registry, validation, and install policy."
                .to_string(),
        );
        Ok(serde_json::to_value(summary)?)
    }

    pub(super) async fn handle_clone_context(
        &self,
        args: PersonalPreferencesCloneArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        Ok(serde_json::to_value(
            personal_preferences.store.build_clone_context_pack(
                args.query.trim(),
                crate::personal_preferences::PersonalPreferencesCloneOptions {
                    mode: args
                        .mode
                        .map(|value| value.trim().to_string())
                        .filter(|value| !value.is_empty()),
                    allow_sensitive: args.allow_sensitive.unwrap_or(false),
                    current_repo_root: args
                        .current_repo_root
                        .map(|value| value.trim().to_string())
                        .filter(|value| !value.is_empty()),
                    max_records: args.max_records,
                    budget_tokens: args.budget_tokens,
                },
            )?,
        )?)
    }

    pub(super) async fn handle_clone_directive(
        &self,
        args: PersonalPreferencesCloneArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        Ok(serde_json::to_value(
            personal_preferences.store.build_clone_directive(
                args.query.trim(),
                crate::personal_preferences::PersonalPreferencesCloneOptions {
                    mode: args
                        .mode
                        .map(|value| value.trim().to_string())
                        .filter(|value| !value.is_empty()),
                    allow_sensitive: args.allow_sensitive.unwrap_or(false),
                    current_repo_root: args
                        .current_repo_root
                        .map(|value| value.trim().to_string())
                        .filter(|value| !value.is_empty()),
                    max_records: args.max_records,
                    budget_tokens: args.budget_tokens,
                },
                args.agent_id,
                args.task_type,
                args.risk_level,
                args.current_files,
                args.current_plan_path,
                args.enforcement_level,
            )?,
        )?)
    }

    pub(super) async fn handle_clone_explain(
        &self,
        args: PersonalPreferencesCloneArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        Ok(serde_json::to_value(
            personal_preferences.store.explain_clone_context(
                args.query.trim(),
                crate::personal_preferences::PersonalPreferencesCloneOptions {
                    mode: args
                        .mode
                        .map(|value| value.trim().to_string())
                        .filter(|value| !value.is_empty()),
                    allow_sensitive: args.allow_sensitive.unwrap_or(false),
                    current_repo_root: args
                        .current_repo_root
                        .map(|value| value.trim().to_string())
                        .filter(|value| !value.is_empty()),
                    max_records: args.max_records,
                    budget_tokens: args.budget_tokens,
                },
            )?,
        )?)
    }

    pub(super) async fn handle_clone_evaluate(
        &self,
        args: PersonalPreferencesCloneArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        Ok(serde_json::to_value(
            personal_preferences.store.evaluate_clone_context(
                args.query.trim(),
                crate::personal_preferences::PersonalPreferencesCloneOptions {
                    mode: args
                        .mode
                        .map(|value| value.trim().to_string())
                        .filter(|value| !value.is_empty()),
                    allow_sensitive: args.allow_sensitive.unwrap_or(false),
                    current_repo_root: args
                        .current_repo_root
                        .map(|value| value.trim().to_string())
                        .filter(|value| !value.is_empty()),
                    max_records: args.max_records,
                    budget_tokens: args.budget_tokens,
                },
            )?,
        )?)
    }

    pub(super) async fn handle_clone_replay_evaluate(
        &self,
        args: PersonalPreferencesCloneReplayArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        Ok(serde_json::to_value(
            personal_preferences.store.evaluate_clone_replay(
                args.query.trim(),
                crate::personal_preferences::PersonalPreferencesCloneOptions {
                    mode: args
                        .mode
                        .map(|value| value.trim().to_string())
                        .filter(|value| !value.is_empty()),
                    allow_sensitive: args.allow_sensitive.unwrap_or(false),
                    current_repo_root: args
                        .current_repo_root
                        .map(|value| value.trim().to_string())
                        .filter(|value| !value.is_empty()),
                    max_records: args.max_records,
                    budget_tokens: args.budget_tokens,
                },
                args.expected_categories,
            )?,
        )?)
    }

    pub(super) async fn handle_clone_replay_dataset(
        &self,
        args: PersonalPreferencesCloneReplayDatasetArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        Ok(serde_json::to_value(
            personal_preferences.store.build_clone_replay_dataset(
                args.ci_subset.unwrap_or(false),
                args.limit,
                args.current_repo_root
                    .map(|value| value.trim().to_string())
                    .filter(|value| !value.is_empty()),
            )?,
        )?)
    }

    pub(super) async fn handle_clone_replay_suite(
        &self,
        args: PersonalPreferencesCloneReplaySuiteArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        Ok(serde_json::to_value(
            personal_preferences.store.run_clone_replay_suite(
                args.ci_subset.unwrap_or(false),
                args.limit,
                args.threshold,
                crate::personal_preferences::PersonalPreferencesCloneOptions {
                    mode: None,
                    allow_sensitive: args.allow_sensitive.unwrap_or(false),
                    current_repo_root: args
                        .current_repo_root
                        .map(|value| value.trim().to_string())
                        .filter(|value| !value.is_empty()),
                    max_records: args.max_records,
                    budget_tokens: args.budget_tokens,
                },
            )?,
        )?)
    }
}

fn normalized_generated_skill_arg(skill_id: Option<String>) -> Result<String> {
    let skill_id = skill_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AppError::new(ERR_INVALID_ARGUMENT, "skill_id must not be empty"))?;
    Ok(skill_id.to_string())
}
