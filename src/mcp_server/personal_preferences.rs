use super::*;

impl McpServer {
    pub(super) async fn handle_personal_preferences_status(
        &self,
        _args: PersonalPreferencesStatusArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        Ok(serde_json::to_value(personal_preferences.store.status()?)?)
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
}
