use super::*;

impl PersonalPreferencesStore {
    pub fn list_ai_terminal_integrations(
        &self,
    ) -> Result<PersonalPreferenceAiTerminalIntegrationSummary> {
        let conn = open_db(&self.db_path)?;
        Ok(PersonalPreferenceAiTerminalIntegrationSummary {
            generated_at_ms: now_ms(),
            integrations: load_ai_terminal_integrations(&conn, None)?,
            notes: vec![
                "AI terminal integrations control automatic capture, skill sync, and activation hints."
                    .to_string(),
            ],
        })
    }

    pub fn detect_ai_terminal_integrations(
        &self,
        terminals: Vec<String>,
    ) -> Result<PersonalPreferenceAiTerminalIntegrationSummary> {
        let now = now_ms();
        let integrations = normalize_terminal_targets(terminals)
            .into_iter()
            .map(|terminal| build_terminal_integration(&terminal, now))
            .collect();
        Ok(PersonalPreferenceAiTerminalIntegrationSummary {
            generated_at_ms: now,
            integrations,
            notes: vec![
                "Detection is non-mutating; run integration bootstrap to persist enabled terminal targets."
                    .to_string(),
            ],
        })
    }

    pub fn ai_terminal_status(&self) -> Result<PersonalPreferenceAiTerminalStatus> {
        let conn = open_db(&self.db_path)?;
        Ok(PersonalPreferenceAiTerminalStatus {
            generated_at_ms: now_ms(),
            integrations: load_ai_terminal_integrations(&conn, None)?,
            capture_events_total: count_sql(&conn, "SELECT COUNT(*) FROM pp_ai_terminal_capture_events")?,
            pending_capture_events_total: count_sql(
                &conn,
                "SELECT COUNT(*) FROM pp_ai_terminal_capture_events WHERE digest_status = 'pending'",
            )?,
            failed_capture_events_total: count_sql(
                &conn,
                "SELECT COUNT(*) FROM pp_ai_terminal_capture_events
                 WHERE digest_status = 'failed' OR redaction_status IN ('blocked', 'failed')",
            )?,
            generated_skills_total: count_sql(&conn, "SELECT COUNT(*) FROM pp_generated_skills")?,
            installed_skills_total: count_sql(
                &conn,
                "SELECT COUNT(*) FROM pp_generated_skills WHERE status = 'installed'",
            )?,
            review_required_total: count_sql(
                &conn,
                "SELECT COUNT(*) FROM pp_generated_skill_versions WHERE install_policy = 'review'",
            )?,
            quarantined_total: count_sql(
                &conn,
                "SELECT COUNT(*) FROM pp_generated_skills WHERE status = 'quarantined'",
            )?,
            activation_events_total: count_sql(
                &conn,
                "SELECT COUNT(*) FROM pp_generated_skill_activation_events",
            )?,
            accepted_activation_events_total: count_sql(
                &conn,
                "SELECT COUNT(*) FROM pp_generated_skill_activation_events WHERE accepted = 1",
            )?,
            rejected_activation_events_total: count_sql(
                &conn,
                "SELECT COUNT(*) FROM pp_generated_skill_activation_events
                 WHERE used = 1 AND accepted = 0",
            )?,
            stale_generated_skills_total: count_stale_generated_skills(&conn)?,
            generated_skill_replay_validations_total: count_sql(
                &conn,
                "SELECT COUNT(*) FROM pp_generated_skill_validations WHERE validator = 'replay'",
            )?,
            clone_replay_evaluations_total: count_sql(
                &conn,
                "SELECT COUNT(*) FROM pp_clone_evaluations",
            )?,
            drifted_operator_routines_total: count_sql(
                &conn,
                "SELECT COUNT(*) FROM pp_operator_routines
                 WHERE drift_status IN ('changed', 'needs_review')",
            )?,
            notes: vec![
                "Status covers configured terminal targets, capture queue, generated skills, installs, activation records, stale-skill signals, replay coverage, and routine drift."
                    .to_string(),
            ],
        })
    }

    pub fn bootstrap_ai_terminal_integrations(
        &self,
        terminals: Vec<String>,
    ) -> Result<PersonalPreferenceAiTerminalIntegrationSummary> {
        let conn = open_db(&self.db_path)?;
        let now = now_ms();
        let terminals = normalize_terminal_targets(terminals);
        for terminal in terminals {
            let integration = build_terminal_integration(&terminal, now);
            upsert_ai_terminal_integration(&conn, &integration, now)?;
        }
        Ok(PersonalPreferenceAiTerminalIntegrationSummary {
            generated_at_ms: now,
            integrations: load_ai_terminal_integrations(&conn, None)?,
            notes: vec![
                "Bootstrap is idempotent and only manages Docdex-owned generated skill roots."
                    .to_string(),
            ],
        })
    }

    pub(crate) fn has_enabled_ai_terminal_capture_integrations(&self) -> Result<bool> {
        let conn = open_db(&self.db_path)?;
        Ok(load_ai_terminal_integrations(&conn, None)?
            .into_iter()
            .any(|integration| integration.enabled && integration.capture_enabled))
    }

    pub fn record_ai_terminal_capture(
        &self,
        request: PersonalPreferenceAiTerminalCaptureRequest,
    ) -> Result<PersonalPreferenceAiTerminalCaptureEvent> {
        let terminal = normalize_terminal_name(&request.terminal);
        if terminal.is_empty() {
            return Err(anyhow!("terminal must not be empty"));
        }
        let summary = normalize_text(&request.summary);
        if summary.is_empty() {
            return Err(anyhow!("summary must not be empty"));
        }
        let now = now_ms();
        let integration_id = request
            .integration_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| default_integration_id(&terminal));
        {
            let conn = open_db(&self.db_path)?;
            let integration =
                ensure_ai_terminal_integration_present(&conn, &terminal, &integration_id, now)?;
            if !integration.enabled || !integration.capture_enabled {
                return Err(anyhow!(
                    "AI terminal integration {} is disabled for capture",
                    integration.integration_id
                ));
            }
        }

        let capture = self.capture_conversation(
            PersonalPreferencesCaptureRequest {
                source: format!("ai_terminal:{terminal}"),
                source_session_id: request.source_session_id.clone(),
                capture_kind: Some(
                    request
                        .event_kind
                        .clone()
                        .unwrap_or_else(|| "session_summary".to_string()),
                ),
                title: Some(format!("{terminal} terminal capture")),
                agent_id: request.agent_id.clone(),
                transport: Some("ai_terminal_adapter".to_string()),
                repo_id: None,
                repo_root: request.repo_scope.clone(),
                scope_id: request.repo_scope.clone(),
                scope_label: request.repo_scope.clone(),
                started_at_ms: None,
                ended_at_ms: Some(now),
                messages: vec![PersonalPreferencesMessage {
                    role: "user".to_string(),
                    content: summary.clone(),
                    created_at_ms: Some(now),
                    metadata: json!({
                        "source": "ai_terminal_capture",
                        "terminal": terminal,
                    }),
                }],
                transcript_text: request
                    .transcript_text
                    .clone()
                    .or_else(|| Some(summary.clone())),
                summary_text: Some(summary.clone()),
                metadata: json!({
                    "terminal": terminal,
                    "integration_id": integration_id,
                    "event_kind": request.event_kind,
                    "repo_scope": request.repo_scope,
                    "metadata": request.metadata,
                }),
            },
            true,
            true,
        )?;

        let conn = open_db(&self.db_path)?;
        let event = PersonalPreferenceAiTerminalCaptureEvent {
            event_id: format!("aiterm_event_{}", Uuid::new_v4()),
            integration_id: integration_id.clone(),
            terminal: terminal.clone(),
            source_session_id: request.source_session_id.clone(),
            event_kind: request
                .event_kind
                .unwrap_or_else(|| "session_summary".to_string()),
            repo_scope: request.repo_scope.clone(),
            summary,
            capture_id: Some(capture.id.clone()),
            redaction_status: "redacted".to_string(),
            digest_status: DIGEST_STATUS_PENDING.to_string(),
            created_at_ms: now,
            processed_at_ms: None,
            payload: json!({
                "capture_id": capture.id,
                "terminal": terminal,
            }),
        };
        insert_ai_terminal_capture_event(&conn, &event)?;
        record_generated_skill_usage_feedback_from_event(&conn, &event, &request.metadata, now)?;
        conn.execute(
            "UPDATE pp_ai_terminal_integrations
             SET last_capture_at_ms = ?1, last_digest_at_ms = ?1, updated_at_ms = ?1
             WHERE integration_id = ?2",
            params![now, integration_id],
        )?;
        let should_sync = load_ai_terminal_integrations(&conn, Some(&integration_id))?
            .into_iter()
            .next()
            .map(|integration| {
                integration.enabled
                    && integration.skill_sync_enabled
                    && should_sync_generated_skills_after_capture(&event.event_kind)
            })
            .unwrap_or(false);
        drop(conn);
        if should_sync {
            let sync_result =
                self.sync_generated_skills(PersonalPreferenceGeneratedSkillsSyncOptions {
                    min_confidence: None,
                    min_support_count: None,
                    include_sensitive: Some(false),
                    install: Some(true),
                    terminals: vec![terminal.clone()],
                });
            match sync_result {
                Ok(summary) => {
                    let conn = open_db(&self.db_path)?;
                    conn.execute(
                        "UPDATE pp_ai_terminal_integrations
                         SET last_skill_sync_at_ms = ?1, last_activation_check_at_ms = ?1,
                             last_error = NULL, updated_at_ms = ?1
                         WHERE integration_id = ?2",
                        params![summary.generated_at_ms, integration_id],
                    )?;
                }
                Err(err) => {
                    let conn = open_db(&self.db_path)?;
                    let error = err.to_string();
                    conn.execute(
                        "UPDATE pp_ai_terminal_integrations
                         SET last_error = ?1, updated_at_ms = ?2
                         WHERE integration_id = ?3",
                        params![error, now_ms(), integration_id],
                    )?;
                }
            }
        }
        Ok(event)
    }

    pub(super) fn record_scanned_ai_terminal_capture_event(
        &self,
        terminal: &str,
        source_session_id: Option<String>,
        repo_scope: Option<String>,
        summary: &str,
        capture_id: &str,
        metadata: Value,
    ) -> Result<Option<PersonalPreferenceAiTerminalCaptureEvent>> {
        let terminal = normalize_terminal_name(terminal);
        if terminal.is_empty() {
            return Ok(None);
        }
        let summary = truncate_to_tokens(&normalize_text(summary), 256);
        if summary.trim().is_empty() {
            return Ok(None);
        }
        let now = now_ms();
        let integration_id = default_integration_id(&terminal);
        let conn = open_db(&self.db_path)?;
        let Some(integration) = load_ai_terminal_integrations(&conn, Some(&integration_id))?
            .into_iter()
            .next()
        else {
            return Ok(None);
        };
        if !integration.enabled || !integration.capture_enabled {
            return Ok(None);
        }
        let event = PersonalPreferenceAiTerminalCaptureEvent {
            event_id: format!("aiterm_event_{}", Uuid::new_v4()),
            integration_id: integration_id.clone(),
            terminal: terminal.clone(),
            source_session_id,
            event_kind: "session_close".to_string(),
            repo_scope,
            summary,
            capture_id: Some(capture_id.to_string()),
            redaction_status: "redacted".to_string(),
            digest_status: DIGEST_STATUS_PENDING.to_string(),
            created_at_ms: now,
            processed_at_ms: None,
            payload: json!({
                "capture_id": capture_id,
                "terminal": terminal,
                "source": "client_transcript_scan",
                "metadata": metadata,
            }),
        };
        insert_ai_terminal_capture_event(&conn, &event)?;
        conn.execute(
            "UPDATE pp_ai_terminal_integrations
             SET last_capture_at_ms = ?1, last_digest_at_ms = ?1, updated_at_ms = ?1
             WHERE integration_id = ?2",
            params![now, integration_id],
        )?;
        Ok(Some(event))
    }

    pub fn list_ai_terminal_capture_events(
        &self,
        limit: usize,
        offset: usize,
    ) -> Result<PersonalPreferenceAiTerminalCaptureEventList> {
        let conn = open_db(&self.db_path)?;
        Ok(PersonalPreferenceAiTerminalCaptureEventList {
            total: count_sql(&conn, "SELECT COUNT(*) FROM pp_ai_terminal_capture_events")?,
            items: load_ai_terminal_capture_events(&conn, limit, offset)?,
            notes: vec![
                "Capture events are normalized AI-terminal observations routed into personal-preferences captures."
                    .to_string(),
            ],
        })
    }

    pub fn list_generated_skills(&self) -> Result<PersonalPreferenceGeneratedSkillList> {
        let conn = open_db(&self.db_path)?;
        let items = load_generated_skills(&conn, None)?;
        let quality = generated_skill_quality_summary(&conn, &items)?;
        Ok(PersonalPreferenceGeneratedSkillList {
            generated_at_ms: now_ms(),
            items,
            quality,
            notes: vec![
                "Generated skills are derived from personal preferences and mind-clone operator routines."
                    .to_string(),
                "Quality report derives replay, drift, stale, and activation recommendations from registry evidence."
                    .to_string(),
            ],
        })
    }

    pub fn read_generated_skill(
        &self,
        skill_id: &str,
    ) -> Result<Option<PersonalPreferenceGeneratedSkill>> {
        let conn = open_db(&self.db_path)?;
        Ok(load_generated_skills(&conn, Some(skill_id))?
            .into_iter()
            .next())
    }

    pub fn list_generated_skill_events(
        &self,
        limit: usize,
        offset: usize,
    ) -> Result<PersonalPreferenceGeneratedSkillEventList> {
        let conn = open_db(&self.db_path)?;
        Ok(PersonalPreferenceGeneratedSkillEventList {
            total: count_sql(&conn, "SELECT COUNT(*) FROM pp_generated_skill_events")?,
            items: load_generated_skill_events(&conn, limit, offset)?,
        })
    }

    pub fn preview_generated_skills(
        &self,
        mut options: PersonalPreferenceGeneratedSkillsSyncOptions,
    ) -> Result<PersonalPreferenceGeneratedSkillsSyncSummary> {
        options.install = Some(false);
        let mut summary = self.sync_generated_skills(options)?;
        summary.notes.push(
            "Preview rendered registry-backed candidates without installing them.".to_string(),
        );
        Ok(summary)
    }

    pub fn validate_generated_skill(
        &self,
        skill_id: &str,
    ) -> Result<PersonalPreferenceGeneratedSkillActionSummary> {
        let conn = open_db(&self.db_path)?;
        let skill = load_generated_skills(&conn, Some(skill_id))?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("generated skill not found"))?;
        let version = skill
            .current_version
            .as_ref()
            .ok_or_else(|| anyhow!("generated skill has no current version"))?;
        let validation = validate_generated_skill_version(&skill, version);
        let replay_validation = validate_generated_skill_replay(&conn, &skill, version)?;
        replace_generated_skill_validations(&conn, &validation)?;
        replace_generated_skill_validations(&conn, &replay_validation)?;
        insert_generated_skill_event(
            &conn,
            &skill.skill_id,
            Some(&version.version_id),
            "validated",
            &format!("Generated skill validation {}", validation.status),
            json!({
                "validator": validation.validator,
                "status": validation.status,
            }),
            now_ms(),
        )?;
        let skill = load_generated_skills(&conn, Some(&skill.skill_id))?
            .into_iter()
            .next();
        Ok(PersonalPreferenceGeneratedSkillActionSummary {
            generated_at_ms: now_ms(),
            action: "validate".to_string(),
            skill,
            validation: Some(validation),
            installed: 0,
            rolled_back: false,
            notes: vec![
                "Validation result was persisted to the generated-skill registry.".to_string(),
            ],
        })
    }

    pub fn install_generated_skill(
        &self,
        skill_id: &str,
        terminals: Vec<String>,
    ) -> Result<PersonalPreferenceGeneratedSkillActionSummary> {
        let conn = open_db(&self.db_path)?;
        let skill = load_generated_skills(&conn, Some(skill_id))?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("generated skill not found"))?;
        let version = skill
            .current_version
            .as_ref()
            .ok_or_else(|| anyhow!("generated skill has no current version"))?
            .clone();
        if version.validation_status != GENERATED_SKILL_VALIDATION_PASSED {
            return Err(anyhow!("generated skill version has not passed validation"));
        }
        if version.install_policy == GENERATED_SKILL_INSTALL_POLICY_QUARANTINE {
            return Err(anyhow!("quarantined generated skills cannot be installed"));
        }
        let now = now_ms();
        let targets = normalize_terminal_targets_for_existing(terminals);
        if !targets.is_empty() {
            for terminal in &targets {
                let integration_id = default_integration_id(terminal);
                ensure_ai_terminal_integration_present(&conn, terminal, &integration_id, now)?;
            }
        } else if load_ai_terminal_integrations(&conn, None)?.is_empty() {
            for terminal in normalize_terminal_targets(Vec::new()) {
                let integration_id = default_integration_id(&terminal);
                ensure_ai_terminal_integration_present(&conn, &terminal, &integration_id, now)?;
            }
        }
        let mut integrations = load_ai_terminal_integrations(&conn, None)?
            .into_iter()
            .filter(|integration| integration.enabled && integration.skill_sync_enabled)
            .collect::<Vec<_>>();
        if !targets.is_empty() {
            integrations.retain(|integration| targets.contains(&integration.terminal));
        }
        let mut installed = 0usize;
        for integration in &integrations {
            match install_generated_skill_for_terminal(&conn, &skill, &version, integration, now) {
                Ok(_) => {
                    installed += 1;
                    insert_generated_skill_event(
                        &conn,
                        &skill.skill_id,
                        Some(&version.version_id),
                        "installed",
                        &format!("Installed generated skill for {}", integration.terminal),
                        json!({ "integration_id": integration.integration_id }),
                        now,
                    )?;
                }
                Err(err) => {
                    insert_failed_installation(
                        &conn,
                        &skill,
                        &version,
                        integration,
                        now,
                        &err.to_string(),
                    )?;
                }
            }
        }
        let skill = load_generated_skills(&conn, Some(&skill.skill_id))?
            .into_iter()
            .next();
        Ok(PersonalPreferenceGeneratedSkillActionSummary {
            generated_at_ms: now,
            action: "install".to_string(),
            skill,
            validation: None,
            installed,
            rolled_back: false,
            notes: vec![
                "Install writes only under configured Docdex-owned generated skill roots."
                    .to_string(),
            ],
        })
    }

    pub fn disable_generated_skill(
        &self,
        skill_id: &str,
        reason: Option<String>,
    ) -> Result<PersonalPreferenceGeneratedSkillActionSummary> {
        let conn = open_db(&self.db_path)?;
        let skill = load_generated_skills(&conn, Some(skill_id))?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("generated skill not found"))?;
        let now = now_ms();
        conn.execute(
            "UPDATE pp_generated_skills SET status = ?1, updated_at_ms = ?2 WHERE skill_id = ?3",
            params![GENERATED_SKILL_STATUS_DISABLED, now, skill.skill_id],
        )?;
        conn.execute(
            "UPDATE pp_generated_skill_installations SET status = ?1, last_seen_at_ms = ?2 WHERE skill_id = ?3",
            params![GENERATED_SKILL_STATUS_DISABLED, now, skill.skill_id],
        )?;
        insert_generated_skill_event(
            &conn,
            &skill.skill_id,
            skill.current_version_id.as_deref(),
            "disabled",
            reason.as_deref().unwrap_or("Generated skill disabled"),
            json!({ "reason": reason }),
            now,
        )?;
        let skill = load_generated_skills(&conn, Some(&skill.skill_id))?
            .into_iter()
            .next();
        Ok(PersonalPreferenceGeneratedSkillActionSummary {
            generated_at_ms: now,
            action: "disable".to_string(),
            skill,
            validation: None,
            installed: 0,
            rolled_back: false,
            notes: vec![
                "Disable keeps registry provenance while preventing active install status."
                    .to_string(),
            ],
        })
    }

    pub fn rollback_generated_skill(
        &self,
        skill_id: &str,
        terminals: Vec<String>,
    ) -> Result<PersonalPreferenceGeneratedSkillActionSummary> {
        let conn = open_db(&self.db_path)?;
        let skill = load_generated_skills(&conn, Some(skill_id))?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("generated skill not found"))?;
        let current_version_id = skill.current_version_id.clone().unwrap_or_default();
        let previous_version_id: Option<String> = conn
            .query_row(
                "SELECT version_id FROM pp_generated_skill_versions
                 WHERE skill_id = ?1 AND version_id <> ?2
                 ORDER BY rendered_at_ms DESC LIMIT 1",
                params![skill.skill_id, current_version_id],
                |row| row.get(0),
            )
            .optional()?;
        let Some(previous_version_id) = previous_version_id else {
            return Ok(PersonalPreferenceGeneratedSkillActionSummary {
                generated_at_ms: now_ms(),
                action: "rollback".to_string(),
                skill: Some(skill),
                validation: None,
                installed: 0,
                rolled_back: false,
                notes: vec![
                    "No previous generated-skill version is available to roll back to.".to_string(),
                ],
            });
        };
        let now = now_ms();
        conn.execute(
            "UPDATE pp_generated_skills
             SET current_version_id = ?1, status = ?2, updated_at_ms = ?3
             WHERE skill_id = ?4",
            params![
                previous_version_id,
                GENERATED_SKILL_STATUS_ROLLED_BACK,
                now,
                skill.skill_id
            ],
        )?;
        insert_generated_skill_event(
            &conn,
            &skill.skill_id,
            Some(&previous_version_id),
            "rolled_back",
            "Generated skill current version rolled back",
            json!({ "from_version_id": current_version_id }),
            now,
        )?;
        drop(conn);
        let mut summary = self.install_generated_skill(skill_id, terminals)?;
        summary.action = "rollback".to_string();
        summary.rolled_back = true;
        summary.notes.push(
            "Rollback selected the previous rendered version and reinstalled it where possible."
                .to_string(),
        );
        Ok(summary)
    }

    pub fn sync_generated_skills(
        &self,
        options: PersonalPreferenceGeneratedSkillsSyncOptions,
    ) -> Result<PersonalPreferenceGeneratedSkillsSyncSummary> {
        let min_confidence = options.min_confidence.unwrap_or(0.7).clamp(0.0, 0.99);
        let min_support_count = options.min_support_count.unwrap_or(2).max(1);
        let include_sensitive = options.include_sensitive.unwrap_or(false);
        let install = options.install.unwrap_or(true);
        let bundle =
            self.compile_operator_playbooks(min_confidence, min_support_count, include_sensitive)?;

        let conn = open_db(&self.db_path)?;
        let now = now_ms();
        let targets = normalize_terminal_targets_for_existing(options.terminals.clone());
        if install {
            if targets.is_empty() {
                if load_ai_terminal_integrations(&conn, None)?.is_empty() {
                    for terminal in normalize_terminal_targets(Vec::new()) {
                        let integration_id = default_integration_id(&terminal);
                        ensure_ai_terminal_integration_present(
                            &conn,
                            &terminal,
                            &integration_id,
                            now,
                        )?;
                    }
                }
            } else {
                for terminal in &targets {
                    let integration_id = default_integration_id(terminal);
                    ensure_ai_terminal_integration_present(&conn, terminal, &integration_id, now)?;
                }
            }
        }
        let integrations = load_ai_terminal_integrations(&conn, None)?;
        let mut enabled_integrations = integrations
            .iter()
            .filter(|integration| integration.enabled && integration.skill_sync_enabled)
            .cloned()
            .collect::<Vec<_>>();
        if !targets.is_empty() {
            enabled_integrations.retain(|integration| targets.contains(&integration.terminal));
        }

        let mut rendered = 0usize;
        let mut installed = 0usize;
        let mut validation_failures = 0usize;
        let mut auto_installed = 0usize;
        let mut review_required = 0usize;
        let mut quarantined = 0usize;

        for playbook in &bundle.items {
            let mut candidate = generated_skill_candidate_from_playbook(playbook, now)?;
            let validation = validate_generated_skill_playbook(playbook, &candidate);
            if validation.status == GENERATED_SKILL_VALIDATION_FAILED {
                validation_failures += 1;
                candidate.status = GENERATED_SKILL_STATUS_QUARANTINED.to_string();
            }
            if let Some(version) = candidate.current_version.as_mut() {
                version.validation_status = validation.status.clone();
                version.validation_summary = validation
                    .details
                    .get("failures")
                    .and_then(Value::as_array)
                    .filter(|items| !items.is_empty())
                    .map(|items| format!("{} validation failure(s)", items.len()))
                    .unwrap_or_else(|| "validation passed".to_string());
                if validation.status == GENERATED_SKILL_VALIDATION_FAILED {
                    version.install_policy = GENERATED_SKILL_INSTALL_POLICY_QUARANTINE.to_string();
                }
            }
            if candidate.status == GENERATED_SKILL_STATUS_QUARANTINED {
                quarantined += 1;
            }
            let replay_validation = if let Some(version) = candidate.current_version.as_ref() {
                Some(validate_generated_skill_replay(&conn, &candidate, version)?)
            } else {
                None
            };
            if candidate
                .current_version
                .as_ref()
                .map(|version| version.install_policy.as_str())
                == Some(GENERATED_SKILL_INSTALL_POLICY_REVIEW)
            {
                review_required += 1;
            }
            let version_existed = candidate
                .current_version
                .as_ref()
                .map(|version| {
                    conn.query_row(
                        "SELECT COUNT(*) FROM pp_generated_skill_versions WHERE version_id = ?1",
                        params![version.version_id],
                        |row| row.get::<_, i64>(0),
                    )
                    .map(|count| count > 0)
                })
                .transpose()?
                .unwrap_or(false);
            upsert_generated_skill(&conn, &candidate)?;
            if let Some(version) = candidate.current_version.as_ref() {
                upsert_generated_skill_version(&conn, version)?;
                replace_generated_skill_sources(&conn, &candidate, version, playbook, now)?;
                replace_generated_skill_validations(&conn, &validation)?;
                if let Some(replay_validation) = replay_validation.as_ref() {
                    replace_generated_skill_validations(&conn, replay_validation)?;
                }
                if !version_existed {
                    insert_generated_skill_event(
                        &conn,
                        &candidate.skill_id,
                        Some(&version.version_id),
                        "rendered",
                        "Rendered generated skill version from operator playbook",
                        json!({
                            "routine_key": playbook.routine_key,
                            "install_policy": version.install_policy,
                            "validation_status": validation.status,
                        }),
                        now,
                    )?;
                }
            }
            rendered += 1;

            let Some(version) = candidate.current_version.as_ref() else {
                continue;
            };
            if !install
                || validation.status != GENERATED_SKILL_VALIDATION_PASSED
                || version.install_policy != GENERATED_SKILL_INSTALL_POLICY_AUTO
            {
                continue;
            }
            for integration in &enabled_integrations {
                match install_generated_skill_for_terminal(
                    &conn,
                    &candidate,
                    version,
                    integration,
                    now,
                ) {
                    Ok(installation) => {
                        installed += 1;
                        auto_installed += 1;
                        insert_generated_skill_activation_event(
                            &conn,
                            &PersonalPreferenceGeneratedSkillActivationEvent {
                                activation_id: format!("activation_{}", Uuid::new_v4()),
                                skill_id: candidate.skill_id.clone(),
                                version_id: version.version_id.clone(),
                                integration_id: integration.integration_id.clone(),
                                terminal: integration.terminal.clone(),
                                activation_kind: if installation.status == "installed" {
                                    "native_discovery".to_string()
                                } else {
                                    "context_hint".to_string()
                                },
                                trigger_query: None,
                                used: false,
                                accepted: false,
                                rejected_reason: None,
                                created_at_ms: now,
                            },
                        )?;
                        insert_generated_skill_event(
                            &conn,
                            &candidate.skill_id,
                            Some(&version.version_id),
                            "installed",
                            &format!(
                                "Auto-installed generated skill for {}",
                                integration.terminal
                            ),
                            json!({
                                "integration_id": integration.integration_id,
                                "activation_kind": "native_discovery",
                            }),
                            now,
                        )?;
                    }
                    Err(err) => {
                        insert_failed_installation(
                            &conn,
                            &candidate,
                            version,
                            integration,
                            now,
                            &err.to_string(),
                        )?;
                    }
                }
            }
        }

        let items = load_generated_skills(&conn, None)?;
        let quality = generated_skill_quality_summary(&conn, &items)?;
        Ok(PersonalPreferenceGeneratedSkillsSyncSummary {
            generated_at_ms: now,
            candidates: bundle.items.len(),
            rendered,
            installed,
            skipped: bundle.skipped,
            validation_failures,
            auto_installed,
            review_required,
            quarantined,
            items,
            integrations,
            quality,
            notes: vec![
                "Generated skills are promoted from deterministic operator playbooks.".to_string(),
                "Low-risk validated skills are installed automatically into enabled Docdex-owned terminal roots.".to_string(),
            ],
        })
    }

    pub(super) fn generated_skill_context_items(
        &self,
        query: &str,
        max_items: usize,
        budget_tokens: usize,
    ) -> Result<Vec<PersonalPreferencesContextItem>> {
        if max_items == 0 || budget_tokens == 0 {
            return Ok(Vec::new());
        }
        let conn = open_db(&self.db_path)?;
        let query_tokens = query_terms(query);
        let mut scored = load_generated_skills(&conn, None)?
            .into_iter()
            .filter(|skill| {
                matches!(
                    skill.status.as_str(),
                    GENERATED_SKILL_STATUS_INSTALLED | GENERATED_SKILL_STATUS_VALIDATED
                ) && skill
                    .current_version
                    .as_ref()
                    .map(|version| {
                        version.validation_status == GENERATED_SKILL_VALIDATION_PASSED
                            && version.install_policy != GENERATED_SKILL_INSTALL_POLICY_QUARANTINE
                    })
                    .unwrap_or(false)
            })
            .map(|skill| {
                let score = generated_skill_query_score(&skill, &query_tokens);
                (score, skill)
            })
            .collect::<Vec<_>>();
        scored.sort_by(|left, right| {
            right
                .0
                .partial_cmp(&left.0)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| right.1.confidence.total_cmp(&left.1.confidence))
                .then_with(|| left.1.slug.cmp(&right.1.slug))
        });

        let mut out = Vec::new();
        let mut used_tokens = 0usize;
        for (_, skill) in scored.into_iter().take(max_items.saturating_mul(3)) {
            let version = skill.current_version.as_ref();
            let installed_paths = skill
                .installations
                .iter()
                .filter(|installation| installation.status == GENERATED_SKILL_STATUS_INSTALLED)
                .filter_map(|installation| {
                    if installation.installed_path.trim().is_empty() {
                        None
                    } else {
                        Some(installation.installed_path.as_str())
                    }
                })
                .collect::<Vec<_>>();
            let install_hint = if installed_paths.is_empty() {
                "available through Docdex generated-skill MCP/context hints".to_string()
            } else {
                format!("installed at {}", installed_paths.join(", "))
            };
            let content = format!(
                "Generated skill available: {} ({}) status={} risk={} policy={} confidence={:.2}. Trigger: {}. {}. Load the native SKILL.md or Docdex generated-skill record only when this task matches.",
                skill.name,
                skill.slug,
                skill.status,
                skill.risk_level,
                version
                    .map(|item| item.install_policy.as_str())
                    .unwrap_or("unknown"),
                skill.confidence,
                skill.description,
                install_hint
            );
            let token_estimate = estimate_tokens(&content);
            if token_estimate == 0 || used_tokens.saturating_add(token_estimate) > budget_tokens {
                continue;
            }
            used_tokens += token_estimate;
            out.push(PersonalPreferencesContextItem {
                section: "generated_skills".to_string(),
                content,
                category: "generated_skill".to_string(),
                record_type: "skill_hint".to_string(),
                confidence: skill.confidence,
                claim_id: Some(skill.skill_id),
                claim_origin: Some(skill.source_compiler),
                truth_status: Some(skill.status),
                source_repo_root: skill.scope_key,
                token_estimate,
            });
            if out.len() >= max_items {
                break;
            }
        }
        Ok(out)
    }
}

fn count_sql(conn: &Connection, sql: &str) -> Result<usize> {
    conn.query_row(sql, [], |row| row.get::<_, i64>(0))
        .map(|value| value.max(0) as usize)
        .map_err(Into::into)
}

fn count_stale_generated_skills(conn: &Connection) -> Result<usize> {
    conn.query_row(
        "SELECT COUNT(*)
         FROM pp_generated_skills AS skill
         JOIN pp_operator_routines AS routine
           ON routine.routine_key = json_extract(skill.metadata_json, '$.routine_key')
         WHERE routine.updated_at_ms > skill.updated_at_ms
           AND skill.status NOT IN ('disabled', 'quarantined')",
        [],
        |row| row.get::<_, i64>(0),
    )
    .map(|value| value.max(0) as usize)
    .map_err(Into::into)
}

#[derive(Debug, Clone, Copy, Default)]
struct GeneratedSkillActivationStats {
    accepted: usize,
    rejected: usize,
    last_activation_at_ms: Option<i64>,
}

fn generated_skill_quality_summary(
    conn: &Connection,
    items: &[PersonalPreferenceGeneratedSkill],
) -> Result<PersonalPreferenceGeneratedSkillQualitySummary> {
    let mut summary = PersonalPreferenceGeneratedSkillQualitySummary {
        total: items.len(),
        notes: vec![
            "Quality report is derived from generated-skill validations, activation feedback, routine drift, and stale-source checks.".to_string(),
        ],
        ..PersonalPreferenceGeneratedSkillQualitySummary::default()
    };
    for skill in items {
        let item = generated_skill_quality_item(conn, skill)?;
        match item.recommendation.as_str() {
            "promote" => summary.promote += 1,
            "review" => summary.review += 1,
            "demote" => summary.demote += 1,
            "quarantine" => summary.quarantine += 1,
            _ => summary.keep += 1,
        }
        if item.stale {
            summary.stale += 1;
        }
        match item.replay_validation_status.as_deref() {
            Some(GENERATED_SKILL_VALIDATION_PASSED) => summary.replay_passed += 1,
            Some(GENERATED_SKILL_VALIDATION_WARNING) => summary.replay_warning += 1,
            Some(GENERATED_SKILL_VALIDATION_FAILED) => summary.replay_failed += 1,
            _ => {}
        }
        summary.items.push(item);
    }
    Ok(summary)
}

fn generated_skill_quality_item(
    conn: &Connection,
    skill: &PersonalPreferenceGeneratedSkill,
) -> Result<PersonalPreferenceGeneratedSkillQualityItem> {
    let version = skill.current_version.as_ref();
    let version_id = version
        .map(|item| item.version_id.clone())
        .or_else(|| skill.current_version_id.clone());
    let install_policy = version
        .map(|item| item.install_policy.clone())
        .unwrap_or_else(|| "unknown".to_string());
    let activation =
        generated_skill_activation_stats(conn, &skill.skill_id, version_id.as_deref())?;
    let replay_validation = latest_replay_validation_for_skill(skill);
    let replay_validation_status = replay_validation.map(|item| item.status.clone());
    let latest_replay_score = replay_validation.and_then(latest_replay_score_from_validation);
    let (routine_key, routine_drift_status, stale) = generated_skill_routine_drift(conn, skill)?;
    let (recommendation, reasons) = generated_skill_quality_recommendation(
        skill,
        version,
        &install_policy,
        replay_validation_status.as_deref(),
        &routine_drift_status,
        stale,
        activation,
    );

    Ok(PersonalPreferenceGeneratedSkillQualityItem {
        skill_id: skill.skill_id.clone(),
        slug: skill.slug.clone(),
        name: skill.name.clone(),
        status: skill.status.clone(),
        risk_level: skill.risk_level.clone(),
        install_policy,
        version_id,
        confidence: skill.confidence,
        support_count: skill.support_count,
        replay_validation_status,
        latest_replay_score,
        routine_key,
        routine_drift_status,
        stale,
        accepted_activation_events: activation.accepted,
        rejected_activation_events: activation.rejected,
        last_activation_at_ms: activation.last_activation_at_ms,
        recommendation,
        reasons,
    })
}

fn generated_skill_activation_stats(
    conn: &Connection,
    skill_id: &str,
    version_id: Option<&str>,
) -> Result<GeneratedSkillActivationStats> {
    conn.query_row(
        "SELECT
             COALESCE(SUM(CASE WHEN accepted = 1 THEN 1 ELSE 0 END), 0),
             COALESCE(SUM(CASE WHEN used = 1 AND accepted = 0 THEN 1 ELSE 0 END), 0),
             MAX(created_at_ms)
         FROM pp_generated_skill_activation_events
         WHERE skill_id = ?1
           AND (?2 IS NULL OR version_id = ?2)",
        params![skill_id, version_id],
        |row| {
            Ok(GeneratedSkillActivationStats {
                accepted: row.get::<_, i64>(0)?.max(0) as usize,
                rejected: row.get::<_, i64>(1)?.max(0) as usize,
                last_activation_at_ms: row.get(2)?,
            })
        },
    )
    .map_err(Into::into)
}

fn latest_replay_validation_for_skill(
    skill: &PersonalPreferenceGeneratedSkill,
) -> Option<&PersonalPreferenceGeneratedSkillValidation> {
    skill
        .validations
        .iter()
        .filter(|validation| validation.validator == "replay")
        .max_by_key(|validation| validation.created_at_ms)
}

fn latest_replay_score_from_validation(
    validation: &PersonalPreferenceGeneratedSkillValidation,
) -> Option<f32> {
    validation
        .details
        .pointer("/details/latest_score")
        .or_else(|| validation.details.get("latest_score"))
        .or_else(|| validation.details.get("score"))
        .and_then(Value::as_f64)
        .map(|score| score as f32)
}

fn generated_skill_routine_drift(
    conn: &Connection,
    skill: &PersonalPreferenceGeneratedSkill,
) -> Result<(Option<String>, Option<String>, bool)> {
    let Some(routine_key) = metadata_text(&skill.metadata, &["routine_key"]) else {
        return Ok((None, None, false));
    };
    let routine = conn
        .query_row(
            "SELECT drift_status, updated_at_ms
             FROM pp_operator_routines
             WHERE routine_key = ?1
             LIMIT 1",
            params![&routine_key],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?)),
        )
        .optional()?;
    let Some((drift_status, routine_updated_at_ms)) = routine else {
        return Ok((Some(routine_key), None, false));
    };
    let stale = routine_updated_at_ms > skill.updated_at_ms
        && !matches!(
            skill.status.as_str(),
            GENERATED_SKILL_STATUS_DISABLED | GENERATED_SKILL_STATUS_QUARANTINED
        );
    Ok((Some(routine_key), Some(drift_status), stale))
}

fn generated_skill_quality_recommendation(
    skill: &PersonalPreferenceGeneratedSkill,
    version: Option<&PersonalPreferenceGeneratedSkillVersion>,
    install_policy: &str,
    replay_status: Option<&str>,
    routine_drift_status: &Option<String>,
    stale: bool,
    activation: GeneratedSkillActivationStats,
) -> (String, Vec<String>) {
    let mut reasons = Vec::new();
    let validation_passed = version
        .map(|item| item.validation_status == GENERATED_SKILL_VALIDATION_PASSED)
        .unwrap_or(false);
    if skill.status == GENERATED_SKILL_STATUS_QUARANTINED
        || install_policy == GENERATED_SKILL_INSTALL_POLICY_QUARANTINE
    {
        reasons.push("skill is quarantined by risk or generated-skill policy".to_string());
        return ("quarantine".to_string(), reasons);
    }
    if activation.rejected > activation.accepted && activation.rejected > 0 {
        reasons.push("rejected activation feedback outweighs accepted usage".to_string());
        return ("demote".to_string(), reasons);
    }
    if replay_status == Some(GENERATED_SKILL_VALIDATION_FAILED) {
        reasons.push("latest generated-skill replay validation failed".to_string());
        return ("demote".to_string(), reasons);
    }
    if skill.confidence < 0.5 {
        reasons.push("skill confidence is below the demotion threshold".to_string());
        return ("demote".to_string(), reasons);
    }
    if stale {
        reasons.push(
            "source operator routine changed after this skill version was updated".to_string(),
        );
    }
    if matches!(
        routine_drift_status.as_deref(),
        Some("changed" | "needs_review")
    ) {
        reasons.push("source operator routine drift requires review".to_string());
    }
    if replay_status == Some(GENERATED_SKILL_VALIDATION_WARNING) {
        reasons.push("generated-skill replay evidence is warning or incomplete".to_string());
    }
    if matches!(
        install_policy,
        GENERATED_SKILL_INSTALL_POLICY_REVIEW | GENERATED_SKILL_INSTALL_POLICY_MANUAL_ONLY
    ) {
        reasons.push("install policy requires review or manual activation".to_string());
    }
    if !validation_passed {
        reasons
            .push("current version has not passed generated-skill policy validation".to_string());
    }
    if !reasons.is_empty() {
        return ("review".to_string(), reasons);
    }
    if skill.risk_level == GENERATED_SKILL_RISK_LOW
        && install_policy == GENERATED_SKILL_INSTALL_POLICY_AUTO
        && !matches!(skill.status.as_str(), GENERATED_SKILL_STATUS_INSTALLED)
    {
        reasons.push("low-risk validated auto-install skill is eligible for promotion".to_string());
        return ("promote".to_string(), reasons);
    }
    reasons.push(
        "current skill version has no negative drift, replay, or activation signals".to_string(),
    );
    ("keep".to_string(), reasons)
}

fn ensure_ai_terminal_integration_present(
    conn: &Connection,
    terminal: &str,
    integration_id: &str,
    now: i64,
) -> Result<PersonalPreferenceAiTerminalIntegration> {
    if let Some(integration) = load_ai_terminal_integrations(conn, Some(integration_id))?
        .into_iter()
        .next()
    {
        return Ok(integration);
    }
    let mut integration = build_terminal_integration(terminal, now);
    integration.integration_id = integration_id.to_string();
    upsert_ai_terminal_integration(conn, &integration, now)?;
    Ok(integration)
}

fn normalize_terminal_targets_for_existing(terminals: Vec<String>) -> Vec<String> {
    let mut out = terminals
        .into_iter()
        .map(|value| normalize_terminal_name(&value))
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    out.sort();
    out.dedup();
    out
}

fn should_sync_generated_skills_after_capture(event_kind: &str) -> bool {
    matches!(
        slugify_identifier(event_kind).as_str(),
        "session_summary"
            | "session_close"
            | "periodic_summary"
            | "pre_compaction"
            | "user_correction"
    )
}

fn record_generated_skill_usage_feedback_from_event(
    conn: &Connection,
    event: &PersonalPreferenceAiTerminalCaptureEvent,
    metadata: &Value,
    now: i64,
) -> Result<()> {
    let event_kind = slugify_identifier(&event.event_kind);
    if !matches!(
        event_kind.as_str(),
        "skill_usage" | "skill_rejection" | "skill_rejected" | "rejected_skill_usage"
    ) {
        return Ok(());
    }
    let Some(skill_id) = metadata_text(metadata, &["skill_id", "generated_skill_id", "skill_slug"])
    else {
        return Ok(());
    };
    let Some(skill) = load_generated_skills(conn, Some(&skill_id))?
        .into_iter()
        .next()
    else {
        return Ok(());
    };
    let version_id = metadata_text(metadata, &["version_id", "skill_version_id"])
        .or_else(|| skill.current_version_id.clone())
        .unwrap_or_else(|| "unknown".to_string());
    let rejected_reason = metadata_text(
        metadata,
        &["rejected_reason", "rejection_reason", "reason", "feedback"],
    );
    let accepted = metadata_bool(metadata, &["accepted", "success"])
        .unwrap_or_else(|| !event_kind.contains("reject") && rejected_reason.is_none());
    let used = metadata_bool(metadata, &["used"]).unwrap_or(true);
    let trigger_query = metadata_text(metadata, &["trigger_query", "query", "task"]);
    insert_generated_skill_activation_event(
        conn,
        &PersonalPreferenceGeneratedSkillActivationEvent {
            activation_id: format!("activation_{}", Uuid::new_v4()),
            skill_id: skill.skill_id.clone(),
            version_id: version_id.clone(),
            integration_id: event.integration_id.clone(),
            terminal: event.terminal.clone(),
            activation_kind: event_kind.clone(),
            trigger_query,
            used,
            accepted,
            rejected_reason: rejected_reason.clone(),
            created_at_ms: now,
        },
    )?;
    let feedback_kind = if accepted { "used" } else { "rejected" };
    insert_generated_skill_event(
        conn,
        &skill.skill_id,
        Some(&version_id),
        feedback_kind,
        if accepted {
            "Generated skill usage accepted"
        } else {
            "Generated skill usage rejected"
        },
        json!({
            "terminal": event.terminal,
            "integration_id": event.integration_id,
            "event_id": event.event_id,
            "rejected_reason": rejected_reason,
        }),
        now,
    )?;
    let delta = if accepted { 0.02 } else { -0.10 };
    let confidence = (skill.confidence + delta).clamp(0.0, 1.0);
    conn.execute(
        "UPDATE pp_generated_skills
         SET confidence = ?1, updated_at_ms = ?2
         WHERE skill_id = ?3",
        params![confidence, now, skill.skill_id],
    )?;
    Ok(())
}

fn generated_skill_candidate_from_playbook(
    playbook: &PersonalPreferenceSkillPlaybook,
    now: i64,
) -> Result<PersonalPreferenceGeneratedSkill> {
    let slug = skill_slug(&playbook.routine_key, &playbook.title);
    let skill_id = format!("skill_{slug}");
    let evidence_hash = playbook
        .metadata
        .get("evidence_hash")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| sha256_hex(&playbook.skill_markdown));
    let risk_level = playbook
        .metadata
        .get("risk_level")
        .and_then(Value::as_str)
        .unwrap_or(GENERATED_SKILL_RISK_LOW)
        .to_string();
    let autonomy_level = playbook
        .metadata
        .get("autonomy_level")
        .and_then(Value::as_str)
        .unwrap_or("instruction_only")
        .to_string();
    let install_policy = install_policy_for_playbook(playbook, &risk_level, &autonomy_level);
    let status = if install_policy == GENERATED_SKILL_INSTALL_POLICY_QUARANTINE {
        GENERATED_SKILL_STATUS_QUARANTINED
    } else if install_policy == GENERATED_SKILL_INSTALL_POLICY_AUTO {
        GENERATED_SKILL_STATUS_VALIDATED
    } else {
        GENERATED_SKILL_STATUS_DRAFT
    };
    let version = PersonalPreferenceGeneratedSkillVersion {
        version_id: format!(
            "skill_version_{}_{}",
            slug,
            evidence_hash.chars().take(12).collect::<String>()
        ),
        skill_id: skill_id.clone(),
        version: playbook.version.clone(),
        evidence_hash: evidence_hash.clone(),
        skill_markdown: playbook.skill_markdown.clone(),
        sidecar: json!({
            "playbook_id": playbook.id,
            "routine_id": playbook.routine_id,
            "routine_key": playbook.routine_key,
            "trigger_terms": playbook.trigger_terms,
            "review_reasons": playbook.review_reasons,
            "source_metadata": playbook.metadata,
        }),
        rendered_at_ms: now,
        rendered_by: "personal_preferences_operator_playbook_v1".to_string(),
        validation_status: GENERATED_SKILL_VALIDATION_PASSED.to_string(),
        validation_summary: "pending validation".to_string(),
        install_policy,
        rollback_from_version_id: None,
    };
    Ok(PersonalPreferenceGeneratedSkill {
        skill_id,
        slug,
        name: skill_name_from_slug(&playbook.routine_key, &playbook.title),
        description: skill_description(playbook),
        category: "operator_workflow".to_string(),
        scope: "global".to_string(),
        scope_key: None,
        source_compiler: "operator_playbook".to_string(),
        status: status.to_string(),
        risk_level,
        autonomy_level,
        confidence: playbook.confidence,
        support_count: playbook.support_count,
        current_version_id: Some(version.version_id.clone()),
        current_version: Some(version),
        validations: Vec::new(),
        installations: Vec::new(),
        created_at_ms: now,
        updated_at_ms: now,
        metadata: json!({
            "playbook_id": playbook.id,
            "routine_id": playbook.routine_id,
            "routine_key": playbook.routine_key,
        }),
    })
}

fn validate_generated_skill_version(
    skill: &PersonalPreferenceGeneratedSkill,
    version: &PersonalPreferenceGeneratedSkillVersion,
) -> PersonalPreferenceGeneratedSkillValidation {
    let now = now_ms();
    let mut failures = Vec::new();
    let markdown = &version.skill_markdown;
    if !markdown.contains("---")
        || !markdown.contains("name:")
        || !markdown.contains("description:")
    {
        failures.push("missing YAML frontmatter with name and description");
    }
    if markdown.trim().len() < 80 {
        failures.push("skill body is too short");
    }
    if markdown.len() > 20_000 {
        failures.push("skill body exceeds generated skill length limit");
    }
    let lower = markdown.to_ascii_lowercase();
    for marker in [
        "api_key",
        "secret_key",
        "private key",
        "password=",
        "authorization: bearer",
        "ignore previous instructions",
    ] {
        if lower.contains(marker) {
            failures.push("potential secret or instruction-injection marker detected");
            break;
        }
    }
    if skill.risk_level == GENERATED_SKILL_RISK_CRITICAL
        || version.install_policy == GENERATED_SKILL_INSTALL_POLICY_QUARANTINE
    {
        failures.push("critical or quarantined generated skills cannot be installed");
    }
    let status = if failures.is_empty() {
        GENERATED_SKILL_VALIDATION_PASSED
    } else {
        GENERATED_SKILL_VALIDATION_FAILED
    };
    PersonalPreferenceGeneratedSkillValidation {
        validation_id: format!("validation_{}_{}", skill.skill_id, version.version_id),
        skill_id: skill.skill_id.clone(),
        version_id: version.version_id.clone(),
        validator: "generated_skill_policy".to_string(),
        status: status.to_string(),
        details: json!({
            "failures": failures,
            "install_policy": version.install_policy,
            "risk_level": skill.risk_level,
        }),
        created_at_ms: now,
    }
}

fn validate_generated_skill_playbook(
    playbook: &PersonalPreferenceSkillPlaybook,
    candidate: &PersonalPreferenceGeneratedSkill,
) -> PersonalPreferenceGeneratedSkillValidation {
    let Some(version) = candidate.current_version.as_ref() else {
        return PersonalPreferenceGeneratedSkillValidation {
            validation_id: format!("validation_{}_unknown", candidate.skill_id),
            skill_id: candidate.skill_id.clone(),
            version_id: "unknown".to_string(),
            validator: "generated_skill_policy".to_string(),
            status: GENERATED_SKILL_VALIDATION_FAILED.to_string(),
            details: json!({
                "failures": ["missing current generated skill version"],
                "review_required": playbook.review_required,
                "review_reasons": playbook.review_reasons,
            }),
            created_at_ms: now_ms(),
        };
    };
    let mut validation = validate_generated_skill_version(candidate, version);
    if playbook.review_required {
        validation.details = json!({
            "failures": validation
                .details
                .get("failures")
                .cloned()
                .unwrap_or_else(|| json!([])),
            "review_required": playbook.review_required,
            "review_reasons": playbook.review_reasons,
        });
    }
    validation
}

fn validate_generated_skill_replay(
    conn: &Connection,
    skill: &PersonalPreferenceGeneratedSkill,
    version: &PersonalPreferenceGeneratedSkillVersion,
) -> Result<PersonalPreferenceGeneratedSkillValidation> {
    let total = count_sql(conn, "SELECT COUNT(*) FROM pp_clone_evaluations")?;
    let latest = conn
        .query_row(
            "SELECT mode, score, created_at_ms
             FROM pp_clone_evaluations
             WHERE mode LIKE 'replay_suite:%' OR mode LIKE 'replay:%'
             ORDER BY created_at_ms DESC
             LIMIT 1",
            [],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, f32>(1)?,
                    row.get::<_, i64>(2)?,
                ))
            },
        )
        .optional()?;
    let threshold = 0.75_f32;
    let (status, message, details) = match latest {
        Some((mode, score, created_at_ms)) if score >= threshold => (
            GENERATED_SKILL_VALIDATION_PASSED,
            "latest clone replay score meets generated-skill promotion threshold",
            json!({
                "replay_evaluations_total": total,
                "latest_mode": mode,
                "latest_score": score,
                "latest_created_at_ms": created_at_ms,
                "threshold": threshold,
                "warnings": [],
            }),
        ),
        Some((mode, score, created_at_ms)) => (
            GENERATED_SKILL_VALIDATION_WARNING,
            "latest clone replay score is below generated-skill promotion threshold",
            json!({
                "replay_evaluations_total": total,
                "latest_mode": mode,
                "latest_score": score,
                "latest_created_at_ms": created_at_ms,
                "threshold": threshold,
                "warnings": ["latest clone replay score is below threshold"],
            }),
        ),
        None => (
            GENERATED_SKILL_VALIDATION_WARNING,
            "no clone replay evidence is available yet",
            json!({
                "replay_evaluations_total": total,
                "latest_mode": Value::Null,
                "latest_score": Value::Null,
                "threshold": threshold,
                "warnings": ["no clone replay evidence is available yet"],
            }),
        ),
    };

    Ok(PersonalPreferenceGeneratedSkillValidation {
        validation_id: format!(
            "validation_replay_{}_{}",
            skill.skill_id, version.version_id
        ),
        skill_id: skill.skill_id.clone(),
        version_id: version.version_id.clone(),
        validator: "replay".to_string(),
        status: status.to_string(),
        details: json!({
            "summary": message,
            "skill_id": skill.skill_id,
            "version_id": version.version_id,
            "details": details,
        }),
        created_at_ms: now_ms(),
    })
}

fn install_policy_for_playbook(
    playbook: &PersonalPreferenceSkillPlaybook,
    risk_level: &str,
    autonomy_level: &str,
) -> String {
    if matches!(risk_level, GENERATED_SKILL_RISK_CRITICAL) {
        return GENERATED_SKILL_INSTALL_POLICY_QUARANTINE.to_string();
    }
    if matches!(risk_level, GENERATED_SKILL_RISK_HIGH)
        || autonomy_level.contains("production")
        || autonomy_level.contains("destructive")
    {
        return GENERATED_SKILL_INSTALL_POLICY_MANUAL_ONLY.to_string();
    }
    if playbook.review_required || matches!(risk_level, GENERATED_SKILL_RISK_MEDIUM) {
        return GENERATED_SKILL_INSTALL_POLICY_REVIEW.to_string();
    }
    GENERATED_SKILL_INSTALL_POLICY_AUTO.to_string()
}

fn skill_slug(routine_key: &str, title: &str) -> String {
    let raw = if !routine_key.trim().is_empty() {
        routine_key
    } else {
        title
    };
    let slug = slugify_identifier(raw).replace('_', "-");
    if slug.is_empty() {
        "operator-skill".to_string()
    } else {
        slug
    }
}

fn skill_name_from_slug(routine_key: &str, title: &str) -> String {
    let slug = skill_slug(routine_key, title);
    if slug.starts_with("operator-") {
        slug
    } else {
        format!("operator-{slug}")
    }
}

fn skill_description(playbook: &PersonalPreferenceSkillPlaybook) -> String {
    let trigger = if playbook.trigger_terms.is_empty() {
        playbook.title.clone()
    } else {
        playbook.trigger_terms.join(", ")
    };
    format!(
        "Use when an AI terminal task matches the operator routine '{}', especially triggers: {}. Applies the user's learned Docdex/mind-clone workflow without loading raw personal memory.",
        playbook.title, trigger
    )
}

fn normalize_terminal_targets(terminals: Vec<String>) -> Vec<String> {
    let mut out = terminals
        .into_iter()
        .map(|value| normalize_terminal_name(&value))
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    if out.is_empty() {
        out.push(AI_TERMINAL_CODEX.to_string());
        out.push(AI_TERMINAL_CLAUDE.to_string());
    }
    out.sort();
    out.dedup();
    out
}

fn normalize_terminal_name(value: &str) -> String {
    match slugify_identifier(value).as_str() {
        "codex" | "openai_codex" => AI_TERMINAL_CODEX.to_string(),
        "claude" | "claude_code" => AI_TERMINAL_CLAUDE.to_string(),
        "generic" | "generic_mcp" | "mcp" => AI_TERMINAL_GENERIC_MCP.to_string(),
        other => other.to_string(),
    }
}

fn default_integration_id(terminal: &str) -> String {
    format!("terminal_{}_default", slugify_identifier(terminal))
}

fn build_terminal_integration(terminal: &str, now: i64) -> PersonalPreferenceAiTerminalIntegration {
    let terminal = normalize_terminal_name(terminal);
    let skill_roots = default_skill_roots_for_terminal(&terminal);
    let command = terminal_command_name(&terminal);
    let command_path = command.and_then(find_command_on_path);
    let mcp_config_paths = mcp_config_candidates_for_terminal(&terminal);
    let registered_mcp_paths = mcp_config_paths
        .iter()
        .filter(|path| file_contains_docdex(path))
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>();
    let existing_skill_roots = skill_roots
        .iter()
        .filter(|path| Path::new(path.as_str()).exists())
        .cloned()
        .collect::<Vec<_>>();
    let mcp_registration_status = if !registered_mcp_paths.is_empty() {
        "registered"
    } else {
        "missing"
    };
    PersonalPreferenceAiTerminalIntegration {
        integration_id: default_integration_id(&terminal),
        terminal: terminal.clone(),
        enabled: true,
        capture_enabled: true,
        skill_sync_enabled: true,
        activation_enabled: true,
        capture_mode: "session_summary".to_string(),
        skill_roots: skill_roots.clone(),
        mcp_registration_status: mcp_registration_status.to_string(),
        last_capture_at_ms: None,
        last_digest_at_ms: None,
        last_skill_sync_at_ms: None,
        last_activation_check_at_ms: None,
        last_error: None,
        metadata: json!({
            "bootstrap": "docdex_ai_terminal_integration",
            "created_at_ms": now,
            "terminal_detected": command_path.is_some(),
            "terminal_command": command,
            "terminal_command_path": command_path,
            "skill_roots": skill_roots,
            "existing_skill_roots": existing_skill_roots,
            "mcp_config_paths": mcp_config_paths
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>(),
            "mcp_registered_paths": registered_mcp_paths,
            "docdex_generated_namespace": "docdex-generated",
        }),
    }
}

fn terminal_command_name(terminal: &str) -> Option<&'static str> {
    match terminal {
        AI_TERMINAL_CODEX => Some("codex"),
        AI_TERMINAL_CLAUDE => Some("claude"),
        _ => None,
    }
}

fn find_command_on_path(command: &str) -> Option<String> {
    let paths = std::env::var_os("PATH")?;
    std::env::split_paths(&paths)
        .map(|path| path.join(command))
        .find(|path| path.is_file())
        .map(|path| path.display().to_string())
}

fn mcp_config_candidates_for_terminal(terminal: &str) -> Vec<PathBuf> {
    match terminal {
        AI_TERMINAL_CODEX => vec![home_relative_config_path(
            "CODEX_HOME",
            ".codex",
            "config.toml",
        )],
        AI_TERMINAL_CLAUDE => vec![
            home_relative_config_path("CLAUDE_HOME", ".claude", "settings.json"),
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".claude.json"),
        ],
        _ => Vec::new(),
    }
}

fn home_relative_config_path(env_var: &str, fallback_dir: &str, file_name: &str) -> PathBuf {
    if let Some(base) = std::env::var_os(env_var).filter(|value| !value.is_empty()) {
        return PathBuf::from(base).join(file_name);
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(fallback_dir)
        .join(file_name)
}

fn file_contains_docdex(path: &Path) -> bool {
    fs::read_to_string(path)
        .map(|content| content.to_ascii_lowercase().contains("docdex"))
        .unwrap_or(false)
}

fn default_skill_roots_for_terminal(terminal: &str) -> Vec<String> {
    match terminal {
        AI_TERMINAL_CODEX => vec![home_relative_skill_root("CODEX_HOME", ".codex")],
        AI_TERMINAL_CLAUDE => vec![home_relative_skill_root("CLAUDE_HOME", ".claude")],
        _ => Vec::new(),
    }
}

fn home_relative_skill_root(env_var: &str, fallback_dir: &str) -> String {
    if let Some(base) = std::env::var_os(env_var).filter(|value| !value.is_empty()) {
        return PathBuf::from(base)
            .join("skills")
            .join("docdex-generated")
            .display()
            .to_string();
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(fallback_dir)
        .join("skills")
        .join("docdex-generated")
        .display()
        .to_string()
}

fn query_terms(query: &str) -> Vec<String> {
    query
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| value.len() >= 3)
        .collect()
}

fn generated_skill_query_score(
    skill: &PersonalPreferenceGeneratedSkill,
    query_terms: &[String],
) -> f32 {
    if query_terms.is_empty() {
        return skill.confidence;
    }
    let haystack = format!(
        "{} {} {} {}",
        skill.name, skill.slug, skill.description, skill.category
    )
    .to_ascii_lowercase();
    let matches = query_terms
        .iter()
        .filter(|term| haystack.contains(term.as_str()))
        .count() as f32;
    skill.confidence + matches / query_terms.len().max(1) as f32
}

fn metadata_text(metadata: &Value, keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Some(value) = metadata.get(*key).and_then(Value::as_str) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

fn metadata_bool(metadata: &Value, keys: &[&str]) -> Option<bool> {
    for key in keys {
        if let Some(value) = metadata.get(*key).and_then(Value::as_bool) {
            return Some(value);
        }
    }
    None
}

fn upsert_ai_terminal_integration(
    conn: &Connection,
    integration: &PersonalPreferenceAiTerminalIntegration,
    now: i64,
) -> Result<()> {
    conn.execute(
        "INSERT INTO pp_ai_terminal_integrations(
            integration_id, terminal, enabled, capture_enabled, skill_sync_enabled,
            activation_enabled, capture_mode, skill_roots_json, mcp_registration_status,
            last_capture_at_ms, last_digest_at_ms, last_skill_sync_at_ms,
            last_activation_check_at_ms, last_error, metadata_json, created_at_ms, updated_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)
         ON CONFLICT(integration_id) DO UPDATE SET
            enabled = excluded.enabled,
            capture_enabled = excluded.capture_enabled,
            skill_sync_enabled = excluded.skill_sync_enabled,
            activation_enabled = excluded.activation_enabled,
            capture_mode = excluded.capture_mode,
            skill_roots_json = CASE
                WHEN pp_ai_terminal_integrations.skill_roots_json IS NULL
                  OR pp_ai_terminal_integrations.skill_roots_json = ''
                  OR pp_ai_terminal_integrations.skill_roots_json = '[]'
                THEN excluded.skill_roots_json
                ELSE pp_ai_terminal_integrations.skill_roots_json
            END,
            updated_at_ms = excluded.updated_at_ms",
        params![
            integration.integration_id,
            integration.terminal,
            integration.enabled as i64,
            integration.capture_enabled as i64,
            integration.skill_sync_enabled as i64,
            integration.activation_enabled as i64,
            integration.capture_mode,
            serde_json::to_string(&integration.skill_roots)?,
            integration.mcp_registration_status,
            integration.last_capture_at_ms,
            integration.last_digest_at_ms,
            integration.last_skill_sync_at_ms,
            integration.last_activation_check_at_ms,
            integration.last_error,
            serde_json::to_string(&integration.metadata)?,
            now,
            now,
        ],
    )?;
    Ok(())
}

fn load_ai_terminal_integrations(
    conn: &Connection,
    integration_id: Option<&str>,
) -> Result<Vec<PersonalPreferenceAiTerminalIntegration>> {
    let mut sql = "SELECT integration_id, terminal, enabled, capture_enabled, skill_sync_enabled,
            activation_enabled, capture_mode, skill_roots_json, mcp_registration_status,
            last_capture_at_ms, last_digest_at_ms, last_skill_sync_at_ms,
            last_activation_check_at_ms, last_error, metadata_json
        FROM pp_ai_terminal_integrations"
        .to_string();
    if integration_id.is_some() {
        sql.push_str(" WHERE integration_id = ?1");
    }
    sql.push_str(" ORDER BY terminal, integration_id");
    let mut stmt = conn.prepare(&sql)?;
    let mapper =
        |row: &rusqlite::Row<'_>| -> rusqlite::Result<PersonalPreferenceAiTerminalIntegration> {
            let roots_json: String = row.get(7)?;
            let metadata_json: String = row.get(14)?;
            Ok(PersonalPreferenceAiTerminalIntegration {
                integration_id: row.get(0)?,
                terminal: row.get(1)?,
                enabled: row.get::<_, i64>(2)? != 0,
                capture_enabled: row.get::<_, i64>(3)? != 0,
                skill_sync_enabled: row.get::<_, i64>(4)? != 0,
                activation_enabled: row.get::<_, i64>(5)? != 0,
                capture_mode: row.get(6)?,
                skill_roots: parse_json_string_array(&roots_json),
                mcp_registration_status: row.get(8)?,
                last_capture_at_ms: row.get(9)?,
                last_digest_at_ms: row.get(10)?,
                last_skill_sync_at_ms: row.get(11)?,
                last_activation_check_at_ms: row.get(12)?,
                last_error: row.get(13)?,
                metadata: parse_json_value(&metadata_json),
            })
        };
    let integrations = if let Some(integration_id) = integration_id {
        stmt.query_map(params![integration_id], mapper)?
            .collect::<rusqlite::Result<Vec<_>>>()?
    } else {
        stmt.query_map([], mapper)?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    Ok(integrations)
}

fn load_ai_terminal_capture_events(
    conn: &Connection,
    limit: usize,
    offset: usize,
) -> Result<Vec<PersonalPreferenceAiTerminalCaptureEvent>> {
    let mut stmt = conn.prepare(
        "SELECT event_id, integration_id, terminal, source_session_id, event_kind, repo_scope,
            summary, payload_json, capture_id, redaction_status, digest_status, created_at_ms,
            processed_at_ms
         FROM pp_ai_terminal_capture_events
         ORDER BY created_at_ms DESC
         LIMIT ?1 OFFSET ?2",
    )?;
    let items = stmt
        .query_map(params![limit.max(1) as i64, offset as i64], |row| {
            let payload_json: String = row.get(7)?;
            Ok(PersonalPreferenceAiTerminalCaptureEvent {
                event_id: row.get(0)?,
                integration_id: row.get(1)?,
                terminal: row.get(2)?,
                source_session_id: row.get(3)?,
                event_kind: row.get(4)?,
                repo_scope: row.get(5)?,
                summary: row.get(6)?,
                payload: parse_json_value(&payload_json),
                capture_id: row.get(8)?,
                redaction_status: row.get(9)?,
                digest_status: row.get(10)?,
                created_at_ms: row.get(11)?,
                processed_at_ms: row.get(12)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(items)
}

fn insert_ai_terminal_capture_event(
    conn: &Connection,
    event: &PersonalPreferenceAiTerminalCaptureEvent,
) -> Result<()> {
    conn.execute(
        "INSERT INTO pp_ai_terminal_capture_events(
            event_id, integration_id, terminal, source_session_id, event_kind, repo_scope,
            summary, payload_json, capture_id, redaction_status, digest_status, created_at_ms,
            processed_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![
            event.event_id,
            event.integration_id,
            event.terminal,
            event.source_session_id,
            event.event_kind,
            event.repo_scope,
            event.summary,
            serde_json::to_string(&event.payload)?,
            event.capture_id,
            event.redaction_status,
            event.digest_status,
            event.created_at_ms,
            event.processed_at_ms,
        ],
    )?;
    Ok(())
}

fn insert_generated_skill_event(
    conn: &Connection,
    skill_id: &str,
    version_id: Option<&str>,
    event_kind: &str,
    summary: &str,
    metadata: Value,
    now: i64,
) -> Result<()> {
    conn.execute(
        "INSERT INTO pp_generated_skill_events(
            event_id, skill_id, version_id, event_kind, summary, metadata_json, created_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            format!("skill_event_{}", Uuid::new_v4()),
            skill_id,
            version_id,
            event_kind,
            summary,
            serde_json::to_string(&metadata)?,
            now,
        ],
    )?;
    Ok(())
}

fn upsert_generated_skill(
    conn: &Connection,
    skill: &PersonalPreferenceGeneratedSkill,
) -> Result<()> {
    conn.execute(
        "INSERT INTO pp_generated_skills(
            skill_id, slug, name, description, category, scope, scope_key, source_compiler,
            status, risk_level, autonomy_level, confidence, support_count, current_version_id,
            created_at_ms, updated_at_ms, metadata_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)
         ON CONFLICT(skill_id) DO UPDATE SET
            slug = excluded.slug,
            name = excluded.name,
            description = excluded.description,
            category = excluded.category,
            scope = excluded.scope,
            scope_key = excluded.scope_key,
            source_compiler = excluded.source_compiler,
            status = excluded.status,
            risk_level = excluded.risk_level,
            autonomy_level = excluded.autonomy_level,
            confidence = excluded.confidence,
            support_count = excluded.support_count,
            current_version_id = excluded.current_version_id,
            updated_at_ms = excluded.updated_at_ms,
            metadata_json = excluded.metadata_json",
        params![
            skill.skill_id,
            skill.slug,
            skill.name,
            skill.description,
            skill.category,
            skill.scope,
            skill.scope_key,
            skill.source_compiler,
            skill.status,
            skill.risk_level,
            skill.autonomy_level,
            skill.confidence,
            skill.support_count as i64,
            skill.current_version_id,
            skill.created_at_ms,
            skill.updated_at_ms,
            serde_json::to_string(&skill.metadata)?,
        ],
    )?;
    Ok(())
}

fn upsert_generated_skill_version(
    conn: &Connection,
    version: &PersonalPreferenceGeneratedSkillVersion,
) -> Result<()> {
    conn.execute(
        "INSERT INTO pp_generated_skill_versions(
            version_id, skill_id, version, evidence_hash, skill_markdown, sidecar_json,
            rendered_at_ms, rendered_by, validation_status, validation_summary, install_policy,
            rollback_from_version_id
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
         ON CONFLICT(version_id) DO UPDATE SET
            skill_markdown = excluded.skill_markdown,
            sidecar_json = excluded.sidecar_json,
            rendered_at_ms = excluded.rendered_at_ms,
            validation_status = excluded.validation_status,
            validation_summary = excluded.validation_summary,
            install_policy = excluded.install_policy",
        params![
            version.version_id,
            version.skill_id,
            version.version,
            version.evidence_hash,
            version.skill_markdown,
            serde_json::to_string(&version.sidecar)?,
            version.rendered_at_ms,
            version.rendered_by,
            version.validation_status,
            version.validation_summary,
            version.install_policy,
            version.rollback_from_version_id,
        ],
    )?;
    Ok(())
}

fn replace_generated_skill_sources(
    conn: &Connection,
    skill: &PersonalPreferenceGeneratedSkill,
    version: &PersonalPreferenceGeneratedSkillVersion,
    playbook: &PersonalPreferenceSkillPlaybook,
    now: i64,
) -> Result<()> {
    conn.execute(
        "DELETE FROM pp_generated_skill_sources WHERE version_id = ?1",
        params![version.version_id],
    )?;
    conn.execute(
        "INSERT INTO pp_generated_skill_sources(
            id, skill_id, version_id, source_type, source_id, source_hash, sensitivity,
            included_in_body, included_in_sidecar, reason, created_at_ms
         ) VALUES (?1, ?2, ?3, 'routine', ?4, ?5, 'low', 0, 1, ?6, ?7)",
        params![
            format!("skill_source_{}_routine", version.version_id),
            skill.skill_id,
            version.version_id,
            playbook.routine_id,
            version.evidence_hash,
            "source operator routine",
            now,
        ],
    )?;
    for claim_id in &playbook.evidence_claim_ids {
        conn.execute(
            "INSERT INTO pp_generated_skill_sources(
                id, skill_id, version_id, source_type, source_id, source_hash, sensitivity,
                included_in_body, included_in_sidecar, reason, created_at_ms
             ) VALUES (?1, ?2, ?3, 'claim', ?4, ?5, 'low', 0, 1, ?6, ?7)",
            params![
                format!(
                    "skill_source_{}_claim_{}",
                    version.version_id,
                    slugify_identifier(claim_id)
                ),
                skill.skill_id,
                version.version_id,
                claim_id,
                sha256_hex(claim_id),
                "supporting claim evidence",
                now,
            ],
        )?;
    }
    Ok(())
}

fn replace_generated_skill_validations(
    conn: &Connection,
    validation: &PersonalPreferenceGeneratedSkillValidation,
) -> Result<()> {
    conn.execute(
        "DELETE FROM pp_generated_skill_validations WHERE version_id = ?1 AND validator = ?2",
        params![validation.version_id, validation.validator],
    )?;
    conn.execute(
        "INSERT INTO pp_generated_skill_validations(
            validation_id, skill_id, version_id, validator, status, details_json, created_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            validation.validation_id,
            validation.skill_id,
            validation.version_id,
            validation.validator,
            validation.status,
            serde_json::to_string(&validation.details)?,
            validation.created_at_ms,
        ],
    )?;
    if validation.validator == "generated_skill_policy" {
        conn.execute(
            "UPDATE pp_generated_skill_versions
             SET validation_status = ?1, validation_summary = ?2
             WHERE version_id = ?3",
            params![
                validation.status,
                validation
                    .details
                    .get("failures")
                    .and_then(Value::as_array)
                    .filter(|items| !items.is_empty())
                    .map(|items| format!("{} validation failure(s)", items.len()))
                    .unwrap_or_else(|| "validation passed".to_string()),
                validation.version_id,
            ],
        )?;
    }
    Ok(())
}

fn install_generated_skill_for_terminal(
    conn: &Connection,
    skill: &PersonalPreferenceGeneratedSkill,
    version: &PersonalPreferenceGeneratedSkillVersion,
    integration: &PersonalPreferenceAiTerminalIntegration,
    now: i64,
) -> Result<PersonalPreferenceGeneratedSkillInstallation> {
    let install_root = integration
        .skill_roots
        .first()
        .ok_or_else(|| anyhow!("terminal integration has no skill root"))?;
    let skill_dir = PathBuf::from(install_root).join(&skill.slug);
    ensure_state_dir_secure(&skill_dir)?;
    let skill_path = skill_dir.join("SKILL.md");
    let tmp_path = skill_dir.join(".SKILL.md.tmp");
    fs::write(&tmp_path, &version.skill_markdown)
        .with_context(|| format!("write {}", tmp_path.display()))?;
    fs::rename(&tmp_path, &skill_path)
        .with_context(|| format!("install {}", skill_path.display()))?;
    let installation = PersonalPreferenceGeneratedSkillInstallation {
        installation_id: format!(
            "install_{}_{}_{}",
            skill.skill_id, version.version_id, integration.integration_id
        ),
        skill_id: skill.skill_id.clone(),
        version_id: version.version_id.clone(),
        integration_id: integration.integration_id.clone(),
        agent_target: integration.terminal.clone(),
        install_root: install_root.clone(),
        installed_path: skill_path.display().to_string(),
        status: GENERATED_SKILL_STATUS_INSTALLED.to_string(),
        installed_at_ms: now,
        last_seen_at_ms: Some(now),
        last_error: None,
    };
    upsert_generated_skill_installation(conn, &installation)?;
    conn.execute(
        "UPDATE pp_generated_skills
         SET status = ?1, updated_at_ms = ?2
         WHERE skill_id = ?3",
        params![GENERATED_SKILL_STATUS_INSTALLED, now, skill.skill_id],
    )?;
    conn.execute(
        "UPDATE pp_ai_terminal_integrations
         SET last_skill_sync_at_ms = ?1, last_activation_check_at_ms = ?1, updated_at_ms = ?1
         WHERE integration_id = ?2",
        params![now, integration.integration_id],
    )?;
    Ok(installation)
}

fn insert_failed_installation(
    conn: &Connection,
    skill: &PersonalPreferenceGeneratedSkill,
    version: &PersonalPreferenceGeneratedSkillVersion,
    integration: &PersonalPreferenceAiTerminalIntegration,
    now: i64,
    error: &str,
) -> Result<()> {
    let installation = PersonalPreferenceGeneratedSkillInstallation {
        installation_id: format!(
            "install_{}_{}_{}",
            skill.skill_id, version.version_id, integration.integration_id
        ),
        skill_id: skill.skill_id.clone(),
        version_id: version.version_id.clone(),
        integration_id: integration.integration_id.clone(),
        agent_target: integration.terminal.clone(),
        install_root: integration.skill_roots.first().cloned().unwrap_or_default(),
        installed_path: String::new(),
        status: "failed".to_string(),
        installed_at_ms: now,
        last_seen_at_ms: None,
        last_error: Some(error.to_string()),
    };
    upsert_generated_skill_installation(conn, &installation)?;
    conn.execute(
        "UPDATE pp_ai_terminal_integrations
         SET last_error = ?1, updated_at_ms = ?2
         WHERE integration_id = ?3",
        params![error, now, integration.integration_id],
    )?;
    Ok(())
}

fn upsert_generated_skill_installation(
    conn: &Connection,
    installation: &PersonalPreferenceGeneratedSkillInstallation,
) -> Result<()> {
    conn.execute(
        "INSERT INTO pp_generated_skill_installations(
            installation_id, skill_id, version_id, integration_id, agent_target, install_root,
            installed_path, status, installed_at_ms, last_seen_at_ms, last_error
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
         ON CONFLICT(installation_id) DO UPDATE SET
            install_root = excluded.install_root,
            installed_path = excluded.installed_path,
            status = excluded.status,
            installed_at_ms = excluded.installed_at_ms,
            last_seen_at_ms = excluded.last_seen_at_ms,
            last_error = excluded.last_error",
        params![
            installation.installation_id,
            installation.skill_id,
            installation.version_id,
            installation.integration_id,
            installation.agent_target,
            installation.install_root,
            installation.installed_path,
            installation.status,
            installation.installed_at_ms,
            installation.last_seen_at_ms,
            installation.last_error,
        ],
    )?;
    Ok(())
}

fn insert_generated_skill_activation_event(
    conn: &Connection,
    event: &PersonalPreferenceGeneratedSkillActivationEvent,
) -> Result<()> {
    conn.execute(
        "INSERT INTO pp_generated_skill_activation_events(
            activation_id, skill_id, version_id, integration_id, terminal, activation_kind,
            trigger_query, used, accepted, rejected_reason, created_at_ms
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        params![
            event.activation_id,
            event.skill_id,
            event.version_id,
            event.integration_id,
            event.terminal,
            event.activation_kind,
            event.trigger_query,
            event.used as i64,
            event.accepted as i64,
            event.rejected_reason,
            event.created_at_ms,
        ],
    )?;
    Ok(())
}

fn load_generated_skills(
    conn: &Connection,
    skill_id: Option<&str>,
) -> Result<Vec<PersonalPreferenceGeneratedSkill>> {
    let mut sql = "SELECT skill_id, slug, name, description, category, scope, scope_key,
            source_compiler, status, risk_level, autonomy_level, confidence, support_count,
            current_version_id, created_at_ms, updated_at_ms, metadata_json
        FROM pp_generated_skills"
        .to_string();
    if skill_id.is_some() {
        sql.push_str(" WHERE skill_id = ?1 OR slug = ?1 OR name = ?1");
    }
    sql.push_str(" ORDER BY updated_at_ms DESC, slug ASC");
    let mut stmt = conn.prepare(&sql)?;
    let mapper = |row: &rusqlite::Row<'_>| -> rusqlite::Result<PersonalPreferenceGeneratedSkill> {
        let metadata_json: String = row.get(16)?;
        Ok(PersonalPreferenceGeneratedSkill {
            skill_id: row.get(0)?,
            slug: row.get(1)?,
            name: row.get(2)?,
            description: row.get(3)?,
            category: row.get(4)?,
            scope: row.get(5)?,
            scope_key: row.get(6)?,
            source_compiler: row.get(7)?,
            status: row.get(8)?,
            risk_level: row.get(9)?,
            autonomy_level: row.get(10)?,
            confidence: row.get(11)?,
            support_count: row.get::<_, i64>(12)? as usize,
            current_version_id: row.get(13)?,
            current_version: None,
            validations: Vec::new(),
            installations: Vec::new(),
            created_at_ms: row.get(14)?,
            updated_at_ms: row.get(15)?,
            metadata: parse_json_value(&metadata_json),
        })
    };
    let mut items = if let Some(skill_id) = skill_id {
        stmt.query_map(params![skill_id], mapper)?
            .collect::<rusqlite::Result<Vec<_>>>()?
    } else {
        stmt.query_map([], mapper)?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    for item in &mut items {
        item.current_version = if let Some(version_id) = item.current_version_id.as_deref() {
            load_generated_skill_version(conn, version_id)?
        } else {
            None
        };
        item.validations = load_generated_skill_validations(conn, &item.skill_id)?;
        item.installations = load_generated_skill_installations(conn, &item.skill_id)?;
    }
    Ok(items)
}

fn load_generated_skill_version(
    conn: &Connection,
    version_id: &str,
) -> Result<Option<PersonalPreferenceGeneratedSkillVersion>> {
    conn.query_row(
        "SELECT version_id, skill_id, version, evidence_hash, skill_markdown, sidecar_json,
            rendered_at_ms, rendered_by, validation_status, validation_summary, install_policy,
            rollback_from_version_id
         FROM pp_generated_skill_versions WHERE version_id = ?1",
        params![version_id],
        |row| {
            let sidecar_json: String = row.get(5)?;
            Ok(PersonalPreferenceGeneratedSkillVersion {
                version_id: row.get(0)?,
                skill_id: row.get(1)?,
                version: row.get(2)?,
                evidence_hash: row.get(3)?,
                skill_markdown: row.get(4)?,
                sidecar: parse_json_value(&sidecar_json),
                rendered_at_ms: row.get(6)?,
                rendered_by: row.get(7)?,
                validation_status: row.get(8)?,
                validation_summary: row.get(9)?,
                install_policy: row.get(10)?,
                rollback_from_version_id: row.get(11)?,
            })
        },
    )
    .optional()
    .map_err(Into::into)
}

fn load_generated_skill_validations(
    conn: &Connection,
    skill_id: &str,
) -> Result<Vec<PersonalPreferenceGeneratedSkillValidation>> {
    let mut stmt = conn.prepare(
        "SELECT validation_id, skill_id, version_id, validator, status, details_json, created_at_ms
         FROM pp_generated_skill_validations
         WHERE skill_id = ?1
         ORDER BY created_at_ms DESC",
    )?;
    let items = stmt
        .query_map(params![skill_id], |row| {
            let details_json: String = row.get(5)?;
            Ok(PersonalPreferenceGeneratedSkillValidation {
                validation_id: row.get(0)?,
                skill_id: row.get(1)?,
                version_id: row.get(2)?,
                validator: row.get(3)?,
                status: row.get(4)?,
                details: parse_json_value(&details_json),
                created_at_ms: row.get(6)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(items)
}

fn load_generated_skill_installations(
    conn: &Connection,
    skill_id: &str,
) -> Result<Vec<PersonalPreferenceGeneratedSkillInstallation>> {
    let mut stmt = conn.prepare(
        "SELECT installation_id, skill_id, version_id, integration_id, agent_target, install_root,
            installed_path, status, installed_at_ms, last_seen_at_ms, last_error
         FROM pp_generated_skill_installations
         WHERE skill_id = ?1
         ORDER BY installed_at_ms DESC",
    )?;
    let items = stmt
        .query_map(params![skill_id], |row| {
            Ok(PersonalPreferenceGeneratedSkillInstallation {
                installation_id: row.get(0)?,
                skill_id: row.get(1)?,
                version_id: row.get(2)?,
                integration_id: row.get(3)?,
                agent_target: row.get(4)?,
                install_root: row.get(5)?,
                installed_path: row.get(6)?,
                status: row.get(7)?,
                installed_at_ms: row.get(8)?,
                last_seen_at_ms: row.get(9)?,
                last_error: row.get(10)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(items)
}

fn load_generated_skill_events(
    conn: &Connection,
    limit: usize,
    offset: usize,
) -> Result<Vec<PersonalPreferenceGeneratedSkillEvent>> {
    let mut stmt = conn.prepare(
        "SELECT event_id, skill_id, version_id, event_kind, summary, metadata_json, created_at_ms
         FROM pp_generated_skill_events
         ORDER BY created_at_ms DESC
         LIMIT ?1 OFFSET ?2",
    )?;
    let items = stmt
        .query_map(params![limit.max(1) as i64, offset as i64], |row| {
            let metadata_json: String = row.get(5)?;
            Ok(PersonalPreferenceGeneratedSkillEvent {
                event_id: row.get(0)?,
                skill_id: row.get(1)?,
                version_id: row.get(2)?,
                event_kind: row.get(3)?,
                summary: row.get(4)?,
                metadata: parse_json_value(&metadata_json),
                created_at_ms: row.get(6)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(items)
}
