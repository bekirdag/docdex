use super::*;

impl McpServer {
    pub(super) async fn handle_memory_store(
        &self,
        args: MemoryStoreArgs,
    ) -> Result<serde_json::Value> {
        let project_root = self.resolve_project_root_arg(args.project_root, args.repo_path)?;
        self.ensure_project_root(project_root.as_deref())?;
        let Some(memory) = self.memory.clone() else {
            return Err(AppError::new(
                ERR_MEMORY_DISABLED,
                "memory is disabled; set DOCDEX_ENABLE_MEMORY=1",
            )
            .into());
        };
        let text = args.text.trim();
        if text.is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "text must not be empty").into());
        }

        let repo_state_root = repo_state_root_from_state_dir(self.indexer.state_dir());
        let session_id = format!("mcp-{}", Uuid::new_v4());
        queue_dag_log(
            &repo_state_root,
            &session_id,
            "ToolCall",
            json!({
                "tool": "memory_store",
                "text_len": text.len(),
            }),
        );
        let started = Instant::now();
        let embedding = self.embed_memory_text(&memory, text).await?;

        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis() as i64;
        let metadata =
            inject_embedding_metadata(args.metadata, &embedding.provider, &embedding.model);
        let store = memory.store.clone();
        let text_owned = text.to_string();
        let stored = tokio::task::spawn_blocking(move || {
            store.store(&text_owned, &embedding.embedding, metadata, created_at)
        })
        .await??;
        queue_dag_log(
            &repo_state_root,
            &session_id,
            "Observation",
            json!({
                "tool": "memory_store",
                "id": stored.0.to_string(),
                "latency_ms": started.elapsed().as_millis(),
            }),
        );
        debug!(
            repo = %self.repo_root.display(),
            latency_ms = started.elapsed().as_millis(),
            id = %stored.0,
            "docdex mcp: memory_store"
        );
        Ok(json!({
            "id": stored.0.to_string(),
            "created_at": stored.1
        }))
    }

    pub(super) async fn handle_memory_recall(
        &self,
        args: MemoryRecallArgs,
    ) -> Result<serde_json::Value> {
        let project_root = self.resolve_project_root_arg(args.project_root, args.repo_path)?;
        self.ensure_project_root(project_root.as_deref())?;
        let Some(memory) = self.memory.clone() else {
            return Err(AppError::new(
                ERR_MEMORY_DISABLED,
                "memory is disabled; set DOCDEX_ENABLE_MEMORY=1",
            )
            .into());
        };
        let query = args.query.trim();
        if query.is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "query must not be empty").into());
        }

        let top_k = args.top_k.unwrap_or(5).max(1).min(50);
        let repo_state_root = repo_state_root_from_state_dir(self.indexer.state_dir());
        let session_id = format!("mcp-{}", Uuid::new_v4());
        queue_dag_log(
            &repo_state_root,
            &session_id,
            "ToolCall",
            json!({
                "tool": "memory_recall",
                "top_k": top_k,
                "query_len": query.len(),
            }),
        );
        let started = Instant::now();
        let embedding = self.embed_memory_text(&memory, query).await?;

        let store = memory.store.clone();
        let items = tokio::task::spawn_blocking(move || store.recall(&embedding.embedding, top_k))
            .await??;
        queue_dag_log(
            &repo_state_root,
            &session_id,
            "Observation",
            json!({
                "tool": "memory_recall",
                "results": items.len(),
                "latency_ms": started.elapsed().as_millis(),
            }),
        );
        debug!(
            repo = %self.repo_root.display(),
            top_k,
            results = items.len(),
            latency_ms = started.elapsed().as_millis(),
            "docdex mcp: memory_recall"
        );
        Ok(json!({
            "top_k": top_k,
            "results": items.into_iter().map(|item| json!({
                "content": item.content,
                "score": item.score,
                "metadata": item.metadata
            })).collect::<Vec<_>>()
        }))
    }

    pub(super) async fn handle_memory_layers(
        &self,
        args: MemoryLayersArgs,
    ) -> Result<serde_json::Value> {
        let namespace = args
            .conversation_namespace
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        let scope =
            self.resolve_conversation_scope(args.project_root, args.repo_path, namespace.clone())?;
        let value = match scope {
            McpConversationScope::Repo {
                repo_id,
                conversations,
                memory,
            } => crate::memory_layers::build_memory_layers_map(
                crate::memory_layers::MemoryLayersInput {
                    scope: crate::memory_layers::MemoryLayerScopeInput::Repo {
                        repo_id: &repo_id,
                        repo_root: self.indexer.repo_root(),
                    },
                    default_agent_id: self.default_agent_id.as_deref(),
                    repo_memory: memory.as_ref().map(|value| &value.store),
                    profile: self.profile_state.as_ref().map(|value| &value.manager),
                    conversations: Some(&conversations.store),
                    knowledge: Some(&conversations.knowledge),
                    conversation_config: Some(&conversations.config),
                    personal_preferences: self
                        .personal_preferences
                        .as_ref()
                        .map(|value| &value.store),
                    personal_preferences_config: self
                        .personal_preferences
                        .as_ref()
                        .map(|value| &value.config),
                },
            ),
            McpConversationScope::Namespace { conversations } => {
                let namespace = namespace.as_deref().ok_or_else(|| {
                    AppError::new(
                        ERR_INTERNAL_ERROR,
                        "conversation namespace context is missing the namespace value",
                    )
                })?;
                crate::memory_layers::build_memory_layers_map(
                    crate::memory_layers::MemoryLayersInput {
                        scope: crate::memory_layers::MemoryLayerScopeInput::Namespace { namespace },
                        default_agent_id: self.default_agent_id.as_deref(),
                        repo_memory: None,
                        profile: self.profile_state.as_ref().map(|value| &value.manager),
                        conversations: Some(&conversations.store),
                        knowledge: Some(&conversations.knowledge),
                        conversation_config: Some(&conversations.config),
                        personal_preferences: self
                            .personal_preferences
                            .as_ref()
                            .map(|value| &value.store),
                        personal_preferences_config: self
                            .personal_preferences
                            .as_ref()
                            .map(|value| &value.config),
                    },
                )
            }
        };
        Ok(serde_json::to_value(value)?)
    }

    pub(super) async fn handle_memory_route(
        &self,
        args: MemoryRouteArgs,
    ) -> Result<serde_json::Value> {
        let namespace = args
            .conversation_namespace
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        let scope =
            self.resolve_conversation_scope(args.project_root, args.repo_path, namespace.clone())?;
        let value = match scope {
            McpConversationScope::Repo {
                repo_id,
                conversations,
                memory,
            } => crate::memory_layers::build_memory_route(
                crate::memory_layers::MemoryLayersInput {
                    scope: crate::memory_layers::MemoryLayerScopeInput::Repo {
                        repo_id: &repo_id,
                        repo_root: self.indexer.repo_root(),
                    },
                    default_agent_id: self.default_agent_id.as_deref(),
                    repo_memory: memory.as_ref().map(|value| &value.store),
                    profile: self.profile_state.as_ref().map(|value| &value.manager),
                    conversations: Some(&conversations.store),
                    knowledge: Some(&conversations.knowledge),
                    conversation_config: Some(&conversations.config),
                    personal_preferences: self
                        .personal_preferences
                        .as_ref()
                        .map(|value| &value.store),
                    personal_preferences_config: self
                        .personal_preferences
                        .as_ref()
                        .map(|value| &value.config),
                },
                &args.query,
                args.intent.as_deref(),
            ),
            McpConversationScope::Namespace { conversations } => {
                let namespace = namespace.as_deref().ok_or_else(|| {
                    AppError::new(
                        ERR_INTERNAL_ERROR,
                        "conversation namespace context is missing the namespace value",
                    )
                })?;
                crate::memory_layers::build_memory_route(
                    crate::memory_layers::MemoryLayersInput {
                        scope: crate::memory_layers::MemoryLayerScopeInput::Namespace { namespace },
                        default_agent_id: self.default_agent_id.as_deref(),
                        repo_memory: None,
                        profile: self.profile_state.as_ref().map(|value| &value.manager),
                        conversations: Some(&conversations.store),
                        knowledge: Some(&conversations.knowledge),
                        conversation_config: Some(&conversations.config),
                        personal_preferences: self
                            .personal_preferences
                            .as_ref()
                            .map(|value| &value.store),
                        personal_preferences_config: self
                            .personal_preferences
                            .as_ref()
                            .map(|value| &value.config),
                    },
                    &args.query,
                    args.intent.as_deref(),
                )
            }
        };
        Ok(serde_json::to_value(value)?)
    }
}
