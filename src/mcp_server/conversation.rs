use super::*;

impl McpServer {
    pub(super) async fn handle_conversation_import(
        &self,
        args: ConversationImportArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences_namespace = args.conversation_namespace.clone();
        let scope = self.resolve_conversation_scope(
            args.project_root.clone(),
            args.repo_path.clone(),
            args.conversation_namespace.clone(),
        )?;
        let conversations = scope.conversations();
        let payload = crate::conversations::normalize_import_request(
            crate::conversations::ConversationImportEnvelope {
                source: args.source,
                source_session_id: args.source_session_id,
                title: args.title,
                agent_id: args.agent_id.or_else(|| self.default_agent_id.clone()),
                transport: args.transport,
                started_at_ms: args.started_at_ms,
                ended_at_ms: args.ended_at_ms,
                format: args.format,
                messages: map_conversation_import_messages(args.messages),
                transcript_text: args.transcript_text,
                metadata: args.metadata.unwrap_or_else(|| json!({})),
            },
        )
        .map_err(|message| AppError::new(ERR_INVALID_ARGUMENT, message))?;
        if !conversations.config.allows_source(&payload.source) {
            return Err(AppError::new(
                ERR_INVALID_ARGUMENT,
                "conversation source is blocked by memory.conversations source policy",
            )
            .into());
        }
        let personal_preferences_capture = self
            .personal_preferences
            .as_ref()
            .filter(|personal_preferences| {
                crate::personal_preferences::should_capture_external_source(
                    &personal_preferences.config,
                    &payload.source,
                    personal_preferences.config.capture_imported_conversations,
                )
            })
            .map(|personal_preferences| {
                (
                    personal_preferences.clone(),
                    build_personal_preferences_capture_request_from_import(
                        &self.repo_root,
                        &scope,
                        personal_preferences_namespace.as_deref(),
                        &payload,
                    ),
                )
            });
        let route_targets = crate::conversations::build_conversation_route_targets(
            scope.repo_memory_target(),
            self.profile_state.as_ref().map(|profile| {
                crate::conversations::build_conversation_profile_target(
                    profile.manager.clone(),
                    profile.embedder.clone(),
                    "conversation_import",
                )
            }),
            conversations.knowledge.clone(),
            conversations.config.graph.clone(),
            self.default_agent_id.clone(),
        );
        let store = conversations.store.clone();
        let imported = crate::conversations::import_conversation_with_routing_options(
            store,
            payload,
            crate::conversations::ConversationImportOptions {
                capture_kind: crate::conversations::ConversationCaptureKind::Manual,
                store_raw_messages: conversations.config.archive_raw_transcripts,
            },
            route_targets,
        )
        .await?;
        if let Some((personal_preferences, capture_request)) = personal_preferences_capture {
            personal_preferences.store.capture_conversation(
                capture_request,
                personal_preferences.config.digest_enabled,
                personal_preferences.config.archive_raw_conversations,
            )?;
        }
        self.update_conversation_archive_metric(&conversations);
        Ok(json!({
            "session_id": imported.session_id,
            "deduplicated": imported.deduplicated,
            "message_count": imported.message_count,
            "capture_kind": imported.capture_kind,
            "raw_messages_stored": imported.raw_messages_stored,
            "summary": imported.summary,
            "working_memory": imported.working_memory,
            "durable_memories": imported.durable_memories,
            "knowledge_facts": imported.knowledge_facts,
        }))
    }

    pub(super) async fn handle_conversation_search(
        &self,
        args: ConversationSearchArgs,
    ) -> Result<serde_json::Value> {
        let scope = self.resolve_conversation_scope(
            args.project_root.clone(),
            args.repo_path.clone(),
            args.conversation_namespace.clone(),
        )?;
        let conversations = scope.conversations();
        let query = args.query.trim().to_string();
        if query.is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "query must not be empty").into());
        }
        if matches!(args.limit, Some(0)) {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "limit must be greater than 0").into());
        }
        let limit = args
            .limit
            .unwrap_or(CONVERSATION_LIST_DEFAULT_LIMIT)
            .clamp(1, CONVERSATION_LIST_MAX_LIMIT);
        let offset = args.offset.unwrap_or(0);
        let agent_id = args
            .agent_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        let store = conversations.store.clone();
        let query_for_task = query.clone();
        let result = tokio::task::spawn_blocking(move || {
            store.search_sessions(&query_for_task, agent_id.as_deref(), limit, offset)
        })
        .await??;
        Ok(serde_json::to_value(result)?)
    }

    pub(super) async fn handle_conversation_list(
        &self,
        args: ConversationListArgs,
    ) -> Result<serde_json::Value> {
        let scope = self.resolve_conversation_scope(
            args.project_root.clone(),
            args.repo_path.clone(),
            args.conversation_namespace.clone(),
        )?;
        let conversations = scope.conversations();
        if matches!(args.limit, Some(0)) {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "limit must be greater than 0").into());
        }
        let limit = args
            .limit
            .unwrap_or(CONVERSATION_LIST_DEFAULT_LIMIT)
            .clamp(1, CONVERSATION_LIST_MAX_LIMIT);
        let offset = args.offset.unwrap_or(0);
        let agent_id = args
            .agent_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        let store = conversations.store.clone();
        let list = tokio::task::spawn_blocking(move || {
            store.list_sessions(agent_id.as_deref(), limit, offset)
        })
        .await??;
        Ok(serde_json::to_value(list)?)
    }

    pub(super) async fn handle_conversation_read(
        &self,
        args: ConversationReadArgs,
    ) -> Result<serde_json::Value> {
        let scope = self.resolve_conversation_scope(
            args.project_root.clone(),
            args.repo_path.clone(),
            args.conversation_namespace.clone(),
        )?;
        let conversations = scope.conversations();
        let session_id = args.session_id.trim().to_string();
        if session_id.is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "session_id must not be empty").into());
        }
        let store = conversations.store.clone();
        let session_id_for_task = session_id.clone();
        let session =
            tokio::task::spawn_blocking(move || store.read_session(&session_id_for_task)).await??;
        let Some(session) = session else {
            return Err(AppError::new(
                ERR_CONVERSATION_NOT_FOUND,
                "conversation session not found",
            )
            .with_details(json!({ "session_id": session_id }))
            .into());
        };
        Ok(json!({ "session": session }))
    }

    pub(super) async fn handle_conversation_delete(
        &self,
        args: ConversationDeleteArgs,
    ) -> Result<serde_json::Value> {
        let scope = self.resolve_conversation_scope(
            args.project_root.clone(),
            args.repo_path.clone(),
            args.conversation_namespace.clone(),
        )?;
        let conversations = scope.conversations();
        let session_id = args.session_id.trim().to_string();
        if session_id.is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "session_id must not be empty").into());
        }
        let store = conversations.store.clone();
        let session_id_for_task = session_id.clone();
        let knowledge = conversations.knowledge.clone();
        let deleted = tokio::task::spawn_blocking(move || -> anyhow::Result<bool> {
            let deleted = store.delete_session(&session_id_for_task)?;
            if deleted {
                let _ = knowledge.delete_facts_for_session(&session_id_for_task)?;
            }
            Ok(deleted)
        })
        .await??;
        if !deleted {
            return Err(AppError::new(
                ERR_CONVERSATION_NOT_FOUND,
                "conversation session not found",
            )
            .with_details(json!({ "session_id": session_id }))
            .into());
        }
        self.update_conversation_archive_metric(&conversations);
        Ok(json!({
            "session_id": session_id,
            "deleted": true,
        }))
    }

    pub(super) async fn handle_conversation_export(
        &self,
        args: ConversationExportArgs,
    ) -> Result<serde_json::Value> {
        let scope = self.resolve_conversation_scope(
            args.project_root.clone(),
            args.repo_path.clone(),
            args.conversation_namespace.clone(),
        )?;
        let conversations = scope.conversations();
        let session_id = args.session_id.trim().to_string();
        if session_id.is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "session_id must not be empty").into());
        }
        let store = conversations.store.clone();
        let session_id_for_task = session_id.clone();
        let knowledge = conversations.knowledge.clone();
        let export = tokio::task::spawn_blocking(
            move || -> anyhow::Result<Option<crate::conversations::ConversationExportRecord>> {
                let Some(mut export) = store.export_session(&session_id_for_task)? else {
                    return Ok(None);
                };
                export.knowledge_facts = knowledge.facts_for_session(&session_id_for_task)?;
                Ok(Some(export))
            },
        )
        .await??;
        let Some(export) = export else {
            return Err(AppError::new(
                ERR_CONVERSATION_NOT_FOUND,
                "conversation session not found",
            )
            .with_details(json!({ "session_id": session_id }))
            .into());
        };
        Ok(json!({ "export": export }))
    }

    pub(super) async fn handle_conversation_redact(
        &self,
        args: ConversationRedactArgs,
    ) -> Result<serde_json::Value> {
        let scope = self.resolve_conversation_scope(
            args.project_root.clone(),
            args.repo_path.clone(),
            args.conversation_namespace.clone(),
        )?;
        let conversations = scope.conversations();
        let session_id = args.session_id.trim().to_string();
        if session_id.is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "session_id must not be empty").into());
        }
        let store = conversations.store.clone();
        let session_id_for_task = session_id.clone();
        let knowledge = conversations.knowledge.clone();
        let result = tokio::task::spawn_blocking(
            move || -> anyhow::Result<Option<crate::conversations::ConversationRedactResult>> {
                let result = store.redact_session(&session_id_for_task)?;
                if result.as_ref().map(|item| item.redacted).unwrap_or(false) {
                    let _ = knowledge.delete_facts_for_session(&session_id_for_task)?;
                }
                Ok(result)
            },
        )
        .await??;
        let Some(result) = result else {
            return Err(AppError::new(
                ERR_CONVERSATION_NOT_FOUND,
                "conversation session not found",
            )
            .with_details(json!({ "session_id": session_id }))
            .into());
        };
        self.update_conversation_archive_metric(&conversations);
        Ok(json!({ "result": result }))
    }

    pub(super) async fn handle_conversation_prune(
        &self,
        args: ConversationPruneArgs,
    ) -> Result<serde_json::Value> {
        let scope = self.resolve_conversation_scope(
            args.project_root.clone(),
            args.repo_path.clone(),
            args.conversation_namespace.clone(),
        )?;
        let conversations = scope.conversations();
        let policy = crate::conversations::ConversationRetentionPolicy {
            manual_retention_days: args
                .manual_retention_days
                .unwrap_or(conversations.config.manual_retention_days),
            auto_capture_retention_days: args
                .auto_capture_retention_days
                .unwrap_or(conversations.config.auto_capture_retention_days),
            diary_retention_days: args
                .diary_retention_days
                .unwrap_or(conversations.config.diary_retention_days),
            hook_event_retention_days: args
                .hook_event_retention_days
                .unwrap_or(conversations.config.hook_event_retention_days),
            working_memory_retention_days: args
                .working_memory_retention_days
                .unwrap_or(conversations.config.working_memory_retention_days),
            episodic_rollup_retention_days: args
                .episodic_rollup_retention_days
                .unwrap_or(conversations.config.episodic_rollup_retention_days),
        };
        let apply = args.apply.unwrap_or(false);
        let store = conversations.store.clone();
        let knowledge = conversations.knowledge.clone();
        let result = tokio::task::spawn_blocking(
            move || -> anyhow::Result<(crate::conversations::ConversationPruneResult, u64, u64)> {
                let before = crate::conversations::combined_archive_size_bytes(&store, &knowledge);
                let result = crate::conversations::prune_with_knowledge(
                    &store, &knowledge, &policy, apply, true,
                )?;
                let after = crate::conversations::combined_archive_size_bytes(&store, &knowledge);
                Ok((result, before, after))
            },
        )
        .await??;
        let (result, before_size, after_size) = result;
        if result.applied && result.has_deletions() {
            metrics::global().record_conversation_compaction(
                result.deleted_sessions_total(),
                result.deleted_diary_entries,
                result.deleted_hook_events,
                result.deleted_knowledge_facts,
                before_size.saturating_sub(after_size),
            );
        }
        self.update_conversation_archive_metric(&conversations);
        Ok(json!({ "result": result }))
    }

    pub(super) async fn handle_kg_query(&self, args: KgQueryArgs) -> Result<serde_json::Value> {
        let scope = self.resolve_conversation_scope(
            args.project_root.clone(),
            args.repo_path.clone(),
            args.conversation_namespace.clone(),
        )?;
        let conversations = scope.conversations();
        let query = args.query.trim().to_string();
        if query.is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "query must not be empty").into());
        }
        if matches!(args.limit, Some(0)) {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "limit must be greater than 0").into());
        }
        let knowledge = conversations.knowledge.clone();
        let relation = args.relation.clone();
        let limit = args
            .limit
            .unwrap_or(CONVERSATION_LIST_DEFAULT_LIMIT)
            .clamp(1, CONVERSATION_LIST_MAX_LIMIT);
        let offset = args.offset.unwrap_or(0);
        let result = tokio::task::spawn_blocking(move || {
            knowledge.query_facts(&query, relation.as_deref(), limit, offset)
        })
        .await??;
        Ok(serde_json::to_value(result)?)
    }

    pub(super) async fn handle_kg_search_nodes(
        &self,
        args: KgNodeSearchArgs,
    ) -> Result<serde_json::Value> {
        let scope = self.resolve_conversation_scope(
            args.project_root.clone(),
            args.repo_path.clone(),
            args.conversation_namespace.clone(),
        )?;
        let conversations = scope.conversations();
        let query = args.query.trim().to_string();
        if query.is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "query must not be empty").into());
        }
        if matches!(args.limit, Some(0)) {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "limit must be greater than 0").into());
        }
        let knowledge = conversations.knowledge.clone();
        let entity_type = args.entity_type.clone();
        let limit = args
            .limit
            .unwrap_or(CONVERSATION_LIST_DEFAULT_LIMIT)
            .clamp(1, CONVERSATION_LIST_MAX_LIMIT);
        let offset = args.offset.unwrap_or(0);
        let result = tokio::task::spawn_blocking(move || {
            knowledge.search_nodes(&query, entity_type.as_deref(), limit, offset)
        })
        .await??;
        Ok(serde_json::to_value(result)?)
    }

    pub(super) async fn handle_kg_search_edges(
        &self,
        args: KgEdgeSearchArgs,
    ) -> Result<serde_json::Value> {
        let scope = self.resolve_conversation_scope(
            args.project_root.clone(),
            args.repo_path.clone(),
            args.conversation_namespace.clone(),
        )?;
        let conversations = scope.conversations();
        let query = args.query.trim().to_string();
        if query.is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "query must not be empty").into());
        }
        if matches!(args.limit, Some(0)) {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "limit must be greater than 0").into());
        }
        let knowledge = conversations.knowledge.clone();
        let relation = args.relation.clone();
        let limit = args
            .limit
            .unwrap_or(CONVERSATION_LIST_DEFAULT_LIMIT)
            .clamp(1, CONVERSATION_LIST_MAX_LIMIT);
        let offset = args.offset.unwrap_or(0);
        let result = tokio::task::spawn_blocking(move || {
            knowledge.search_edges(&query, relation.as_deref(), limit, offset)
        })
        .await??;
        Ok(serde_json::to_value(result)?)
    }

    pub(super) async fn handle_kg_timeline(
        &self,
        args: KgTimelineArgs,
    ) -> Result<serde_json::Value> {
        let scope = self.resolve_conversation_scope(
            args.project_root.clone(),
            args.repo_path.clone(),
            args.conversation_namespace.clone(),
        )?;
        let conversations = scope.conversations();
        let entity = args.entity.trim().to_string();
        if entity.is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "entity must not be empty").into());
        }
        if matches!(args.limit, Some(0)) {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "limit must be greater than 0").into());
        }
        let knowledge = conversations.knowledge.clone();
        let relation = args.relation.clone();
        let limit = args
            .limit
            .unwrap_or(CONVERSATION_LIST_DEFAULT_LIMIT)
            .clamp(1, CONVERSATION_LIST_MAX_LIMIT);
        let result = tokio::task::spawn_blocking(move || {
            knowledge.timeline_for_entity(&entity, relation.as_deref(), limit)
        })
        .await??;
        Ok(serde_json::to_value(result)?)
    }

    pub(super) async fn handle_kg_search_episodes(
        &self,
        args: KgEpisodeSearchArgs,
    ) -> Result<serde_json::Value> {
        let scope = self.resolve_conversation_scope(
            args.project_root.clone(),
            args.repo_path.clone(),
            args.conversation_namespace.clone(),
        )?;
        let conversations = scope.conversations();
        let query = args.query.trim().to_string();
        if query.is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "query must not be empty").into());
        }
        if matches!(args.limit, Some(0)) {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "limit must be greater than 0").into());
        }
        let knowledge = conversations.knowledge.clone();
        let source_type = args.source_type.clone();
        let limit = args
            .limit
            .unwrap_or(CONVERSATION_LIST_DEFAULT_LIMIT)
            .clamp(1, CONVERSATION_LIST_MAX_LIMIT);
        let offset = args.offset.unwrap_or(0);
        let result = tokio::task::spawn_blocking(move || {
            knowledge.search_episodes(&query, source_type.as_deref(), limit, offset)
        })
        .await??;
        Ok(serde_json::to_value(result)?)
    }

    pub(super) async fn handle_kg_neighborhood(
        &self,
        args: KgNeighborhoodArgs,
    ) -> Result<serde_json::Value> {
        let scope = self.resolve_conversation_scope(
            args.project_root.clone(),
            args.repo_path.clone(),
            args.conversation_namespace.clone(),
        )?;
        let conversations = scope.conversations();
        let entity = args.entity.trim().to_string();
        if entity.is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "entity must not be empty").into());
        }
        if matches!(args.limit, Some(0)) {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "limit must be greater than 0").into());
        }
        let knowledge = conversations.knowledge.clone();
        let relation = args.relation.clone();
        let limit = args
            .limit
            .unwrap_or(CONVERSATION_LIST_DEFAULT_LIMIT)
            .clamp(1, CONVERSATION_LIST_MAX_LIMIT);
        let result = tokio::task::spawn_blocking(move || {
            knowledge.neighborhood_for_entity(&entity, relation.as_deref(), limit)
        })
        .await??;
        Ok(serde_json::to_value(result)?)
    }

    pub(super) async fn handle_kg_entity_links(
        &self,
        args: KgEntityLinksArgs,
    ) -> Result<serde_json::Value> {
        let scope = self.resolve_conversation_scope(
            args.project_root.clone(),
            args.repo_path.clone(),
            args.conversation_namespace.clone(),
        )?;
        let conversations = scope.conversations();
        let entity = args.entity.trim().to_string();
        if entity.is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "entity must not be empty").into());
        }
        if matches!(args.limit, Some(0)) {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "limit must be greater than 0").into());
        }
        let knowledge = conversations.knowledge.clone();
        let link_type = args.link_type.clone();
        let limit = args
            .limit
            .unwrap_or(CONVERSATION_LIST_DEFAULT_LIMIT)
            .clamp(1, CONVERSATION_LIST_MAX_LIMIT);
        let result = tokio::task::spawn_blocking(move || {
            knowledge.entity_links_for_entity(&entity, link_type.as_deref(), limit)
        })
        .await??;
        Ok(serde_json::to_value(result)?)
    }

    pub(super) async fn handle_kg_episode(&self, args: KgEpisodeArgs) -> Result<serde_json::Value> {
        let scope = self.resolve_conversation_scope(
            args.project_root.clone(),
            args.repo_path.clone(),
            args.conversation_namespace.clone(),
        )?;
        let conversations = scope.conversations();
        let episode_id = args.episode_id.trim().to_string();
        if episode_id.is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "episode_id must not be empty").into());
        }
        if matches!(args.limit, Some(0)) {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "limit must be greater than 0").into());
        }
        let knowledge = conversations.knowledge.clone();
        let limit = args
            .limit
            .unwrap_or(CONVERSATION_LIST_DEFAULT_LIMIT)
            .clamp(1, CONVERSATION_LIST_MAX_LIMIT);
        let result =
            tokio::task::spawn_blocking(move || knowledge.episode_details(&episode_id, limit))
                .await??;
        let Some(result) = result else {
            return Err(AppError::new(
                ERR_KNOWLEDGE_EPISODE_NOT_FOUND,
                "knowledge episode not found",
            )
            .into());
        };
        Ok(serde_json::to_value(result)?)
    }

    pub(super) async fn handle_kg_delete_edge(
        &self,
        args: KgDeleteEdgeArgs,
    ) -> Result<serde_json::Value> {
        let scope = self.resolve_conversation_scope(
            args.project_root.clone(),
            args.repo_path.clone(),
            args.conversation_namespace.clone(),
        )?;
        let conversations = scope.conversations();
        let edge_id = args.edge_id.trim().to_string();
        if edge_id.is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "edge_id must not be empty").into());
        }
        let knowledge = conversations.knowledge.clone();
        let result = tokio::task::spawn_blocking(move || knowledge.delete_edge(&edge_id)).await??;
        Ok(serde_json::to_value(result)?)
    }

    pub(super) async fn handle_kg_delete_episode(
        &self,
        args: KgDeleteEpisodeArgs,
    ) -> Result<serde_json::Value> {
        let scope = self.resolve_conversation_scope(
            args.project_root.clone(),
            args.repo_path.clone(),
            args.conversation_namespace.clone(),
        )?;
        let conversations = scope.conversations();
        let episode_id = args.episode_id.trim().to_string();
        if episode_id.is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "episode_id must not be empty").into());
        }
        let knowledge = conversations.knowledge.clone();
        let result =
            tokio::task::spawn_blocking(move || knowledge.delete_episode(&episode_id)).await??;
        Ok(serde_json::to_value(result)?)
    }

    pub(super) async fn handle_kg_rebuild(
        &self,
        args: KgMaintenanceArgs,
    ) -> Result<serde_json::Value> {
        let scope = self.resolve_conversation_scope(
            args.project_root.clone(),
            args.repo_path.clone(),
            args.conversation_namespace.clone(),
        )?;
        let conversations = scope.conversations();
        let knowledge = conversations.knowledge.clone();
        let result = tokio::task::spawn_blocking(move || knowledge.rebuild()).await??;
        Ok(serde_json::to_value(result)?)
    }

    pub(super) async fn handle_kg_clear(
        &self,
        args: KgMaintenanceArgs,
    ) -> Result<serde_json::Value> {
        let scope = self.resolve_conversation_scope(
            args.project_root.clone(),
            args.repo_path.clone(),
            args.conversation_namespace.clone(),
        )?;
        let conversations = scope.conversations();
        let knowledge = conversations.knowledge.clone();
        let result = tokio::task::spawn_blocking(move || knowledge.clear()).await??;
        Ok(serde_json::to_value(result)?)
    }

    pub(super) async fn handle_diary_write(
        &self,
        args: DiaryWriteArgs,
    ) -> Result<serde_json::Value> {
        let scope = self.resolve_conversation_scope(
            args.project_root.clone(),
            args.repo_path.clone(),
            args.conversation_namespace.clone(),
        )?;
        let conversations = scope.conversations();
        let content = args.content.trim().to_string();
        if content.is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "content must not be empty").into());
        }
        let entry = crate::conversations::write_diary_entry(
            conversations.store.clone(),
            args.agent_id.or_else(|| self.default_agent_id.clone()),
            args.entry_type
                .unwrap_or_else(|| "note".to_string())
                .trim()
                .to_string(),
            content,
            args.source_session_id,
            args.metadata.unwrap_or_else(|| json!({})),
        )
        .await?;
        crate::conversations::record_diary_entry_episode(
            conversations.knowledge.clone(),
            entry.clone(),
        )
        .await?;
        Ok(serde_json::to_value(entry)?)
    }

    pub(super) async fn handle_diary_read(&self, args: DiaryReadArgs) -> Result<serde_json::Value> {
        let scope = self.resolve_conversation_scope(
            args.project_root.clone(),
            args.repo_path.clone(),
            args.conversation_namespace.clone(),
        )?;
        let conversations = scope.conversations();
        if matches!(args.limit, Some(0)) {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "limit must be greater than 0").into());
        }
        let limit = args
            .limit
            .unwrap_or(CONVERSATION_LIST_DEFAULT_LIMIT)
            .clamp(1, CONVERSATION_LIST_MAX_LIMIT);
        let offset = args.offset.unwrap_or(0);
        let entries = crate::conversations::read_diary_entries(
            conversations.store.clone(),
            args.agent_id,
            limit,
            offset,
        )
        .await?;
        Ok(serde_json::to_value(entries)?)
    }

    pub(super) async fn handle_conversation_hook(
        &self,
        args: ConversationHookArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences_namespace = args.conversation_namespace.clone();
        let scope = self.resolve_conversation_scope(
            args.project_root.clone(),
            args.repo_path.clone(),
            args.conversation_namespace.clone(),
        )?;
        let conversations = scope.conversations();
        let has_messages = args
            .messages
            .as_ref()
            .map(|items| !items.is_empty())
            .unwrap_or(false);
        let has_transcript = args
            .transcript_text
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_some();
        let has_summary = args
            .summary_text
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_some();
        if !has_messages && !has_transcript && !has_summary {
            return Err(AppError::new(
                ERR_INVALID_ARGUMENT,
                "conversation hook requires transcript/messages or summary_text",
            )
            .into());
        }
        let source = args
            .source
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| format!("hook:{}", args.action.as_str()));
        if !conversations.config.allows_source(&source) {
            return Err(AppError::new(
                ERR_INVALID_ARGUMENT,
                "conversation source is blocked by memory.conversations source policy",
            )
            .into());
        }
        let wait_for_processing = args.wait_for_processing.unwrap_or(false);
        let payload = crate::conversations::ConversationHookPayload {
            action: args.action.clone(),
            source: Some(source),
            source_session_id: args.source_session_id,
            title: args.title,
            agent_id: args.agent_id.or_else(|| self.default_agent_id.clone()),
            transport: args.transport,
            started_at_ms: args.started_at_ms,
            ended_at_ms: args.ended_at_ms,
            format: args.format,
            messages: map_conversation_import_messages(args.messages),
            transcript_text: args.transcript_text,
            summary_text: args.summary_text,
            metadata: args.metadata.unwrap_or_else(|| json!({})),
        };
        let personal_preferences_capture = self
            .personal_preferences
            .as_ref()
            .filter(|personal_preferences| {
                crate::personal_preferences::should_capture_external_source(
                    &personal_preferences.config,
                    payload.source.as_deref().unwrap_or_default(),
                    personal_preferences.config.capture_conversation_hooks,
                )
            })
            .map(|personal_preferences| {
                (
                    personal_preferences.clone(),
                    build_personal_preferences_capture_request_from_hook(
                        &self.repo_root,
                        &scope,
                        personal_preferences_namespace.as_deref(),
                        &payload,
                    ),
                )
            });
        let route_targets = crate::conversations::build_conversation_route_targets(
            scope.repo_memory_target(),
            self.profile_state.as_ref().map(|profile| {
                crate::conversations::build_conversation_profile_target(
                    profile.manager.clone(),
                    profile.embedder.clone(),
                    "conversation_hook",
                )
            }),
            conversations.knowledge.clone(),
            conversations.config.graph.clone(),
            self.default_agent_id.clone(),
        );
        let result = crate::conversations::enqueue_conversation_hook(
            conversations.store.clone(),
            payload,
            crate::conversations::ConversationImportOptions {
                capture_kind: crate::conversations::ConversationCaptureKind::Auto,
                store_raw_messages: conversations.config.archive_raw_transcripts,
            },
            route_targets,
            wait_for_processing,
        )
        .await?;
        if let Some((personal_preferences, capture_request)) = personal_preferences_capture {
            personal_preferences.store.capture_conversation(
                capture_request,
                personal_preferences.config.digest_enabled,
                personal_preferences.config.archive_raw_conversations,
            )?;
        }
        Ok(serde_json::to_value(result)?)
    }

    pub(super) async fn handle_wakeup(&self, args: WakeupArgs) -> Result<serde_json::Value> {
        let scope = self.resolve_conversation_scope(
            args.project_root.clone(),
            args.repo_path.clone(),
            args.conversation_namespace.clone(),
        )?;
        let conversations = scope.conversations();
        if matches!(args.max_tokens, Some(0)) {
            return Err(
                AppError::new(ERR_INVALID_ARGUMENT, "max_tokens must be greater than 0").into(),
            );
        }
        let max_tokens = args
            .max_tokens
            .unwrap_or(conversations.max_wakeup_tokens)
            .min(conversations.max_wakeup_tokens)
            .max(1);
        let agent_id = args
            .agent_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        let query = args
            .query
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        let store = conversations.store.clone();
        let knowledge = conversations.knowledge.clone();
        let conversation_config = conversations.config.clone();
        let summary_limit = conversations.max_episodic_summaries;
        let knowledge_limit = conversations.max_knowledge_facts;
        let snippet_limit = conversations.max_transcript_snippets;
        let bundle = tokio::task::spawn_blocking(move || {
            crate::conversations::assemble_wakeup_bundle(
                &store,
                &knowledge,
                &conversation_config,
                agent_id.as_deref(),
                query.as_deref(),
                summary_limit,
                knowledge_limit,
                snippet_limit,
            )
        })
        .await??;
        let (text, render_trace) = crate::conversations::render_wakeup_bundle(&bundle, max_tokens);
        metrics::global().record_conversation_wakeup(
            render_trace.selected > 0,
            render_trace.saved_tokens,
            render_trace.working_memory_tokens,
            render_trace.summary_tokens,
            render_trace.knowledge_tokens,
            render_trace.snippet_tokens,
        );
        Ok(json!({
            "text": text,
            "trace": {
                "budget_tokens": max_tokens,
                "available_items": render_trace.available,
                "selected_items": render_trace.selected,
                "truncated_items": render_trace.truncated,
                "summary_candidates": bundle.trace.summary_candidates,
                "kg_candidates": bundle.trace.kg_candidates,
                "graph_edge_candidates": bundle.trace.graph_edge_candidates,
                "graph_episode_candidates": bundle.trace.graph_episode_candidates,
                "graph_link_candidates": bundle.trace.graph_link_candidates,
                "snippet_candidates": bundle.trace.snippet_candidates,
                "startup_diary_candidates": bundle.trace.startup_diary_candidates,
                "startup_diary_selected": bundle.trace.startup_diary_selected,
                "available_tokens": render_trace.available_tokens,
                "selected_tokens": render_trace.selected_tokens,
                "saved_tokens": render_trace.saved_tokens,
                "working_memory_tokens": render_trace.working_memory_tokens,
                "summary_tokens": render_trace.summary_tokens,
                "knowledge_tokens": render_trace.knowledge_tokens,
                "snippet_tokens": render_trace.snippet_tokens,
            },
            "working_memory": bundle.working_memory,
            "episodic_summaries": bundle.episodic_summaries,
            "knowledge_facts": bundle.knowledge_facts,
            "knowledge_edges": bundle.knowledge_edges,
            "knowledge_episodes": bundle.knowledge_episodes,
            "knowledge_entity_links": bundle.knowledge_entity_links,
            "transcript_snippets": bundle.transcript_snippets,
        }))
    }

    pub(super) fn update_conversation_archive_metric(&self, conversations: &McpConversationState) {
        let repo_total = crate::conversations::combined_archive_size_bytes(
            &conversations.store,
            &conversations.knowledge,
        );
        metrics::global().set_conversation_archive_size_bytes(
            crate::conversations::archive_size_bytes_total(
                repo_total,
                self.global_state_dir.as_deref(),
            ),
        );
    }

    pub(super) fn personal_preferences_state(&self) -> Result<search::PersonalPreferencesState> {
        self.personal_preferences.clone().ok_or_else(|| {
            AppError::new(
                ERR_MEMORY_DISABLED,
                "personal preferences memory is disabled; enable [personal_preferences].enabled",
            )
            .into()
        })
    }
}
