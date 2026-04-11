use super::*;

impl McpServer {
    pub(super) async fn handle_search(
        &self,
        request_id: String,
        args: SearchArgs,
    ) -> Result<serde_json::Value> {
        let SearchArgs {
            query,
            limit,
            force_web: force_web_arg,
            async_web: async_web_arg,
            diff,
            dag_session_id,
            project_root,
            repo_path,
        } = args;
        let project_root = self.resolve_project_root_arg(project_root, repo_path)?;
        self.ensure_project_root(project_root.as_deref())?;
        if !self.indexer.index_ready() {
            let indexing_in_progress = self.indexer.indexing_in_progress()?;
            if !indexing_in_progress && !self.indexer.is_read_only() {
                let indexer = self.indexer.clone();
                tokio::spawn(async move {
                    let _ = crate::index::ensure_indexed(indexer).await;
                });
            }
            let details = json!({
                "status": if indexing_in_progress { "indexing" } else { "missing" },
                "indexing_in_progress": indexing_in_progress,
                "status_url": format!("/v1/index/status?repo_id={}", self.repo_id),
                "retry_after_ms": 2000,
                "recovery_steps": [
                    "Wait for indexing to complete, then retry the search.",
                    "Call /v1/index/status to check readiness.",
                    "If indexing is stuck, run POST /v1/index/rebuild."
                ]
            });
            return Err(
                AppError::new(ERR_INDEXING_IN_PROGRESS, "indexing in progress")
                    .with_details(details)
                    .into(),
            );
        }
        self.ensure_index_ready().await?;
        let query_owned = query;
        let query = query_owned.trim();
        let limit = limit.unwrap_or(self.max_results).clamp(1, self.max_results);
        let project_root_path = self
            .default_project_root
            .as_ref()
            .unwrap_or(&self.repo_root)
            .display()
            .to_string();
        let repo_state_root = repo_state_root_from_state_dir(self.indexer.state_dir());
        let force_web = force_web_arg.unwrap_or(false);
        let async_web = async_web_arg.unwrap_or(true);
        let diff_request = diff::resolve_diff_request_from_options(diff.as_ref())?;
        let request_id_ref = request_id.as_str();
        let dag_session_id = dag_session_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(request_id_ref);
        queue_dag_log(
            &repo_state_root,
            dag_session_id,
            "UserRequest",
            json!({
                "query": query,
                "limit": limit,
                "force_web": force_web,
                "project_root": project_root_path.clone(),
                "diff": diff.as_ref().map(|opts| json!(opts)),
            }),
        );
        let plan = WaterfallPlan::new(
            WebGateConfig::from_env(),
            Tier2Config::enabled(),
            memory_budget_from_max_answer_tokens(self.max_answer_tokens),
            ProfileBudget::default(),
        );
        let repo_id =
            crate::repo_manager::repo_fingerprint_sha256(&self.repo_root).unwrap_or_else(|_| {
                crate::repo_manager::fingerprint::legacy_repo_id_for_root(&self.repo_root)
            });
        let memory_state = self.memory.as_ref().map(|state| search::MemoryState {
            store: state.store.clone(),
            embedder: state.embedder.clone(),
            repo_id: repo_id.clone(),
        });
        let waterfall = run_waterfall(WaterfallRequest {
            request_id: request_id_ref,
            dag_session_id: Some(dag_session_id),
            global_state_dir: self.global_state_dir.clone(),
            query,
            limit,
            diff: diff_request,
            web_limit: None,
            force_web,
            skip_local_search: false,
            disable_web_cache: false,
            llm_filter_local_results: false,
            llm_model: None,
            llm_agent: None,
            indexer: self.indexer.clone(),
            libs_indexer: self.libs_indexer.clone(),
            plan,
            tier2_limiter: None,
            memory: memory_state.as_ref(),
            profile_state: None,
            profile_agent_id: None,
            memory_route: None,
            ranking_surface: search::RankingSurface::Search,
            async_web,
        })
        .await?;
        queue_dag_log(
            &repo_state_root,
            dag_session_id,
            "Decision",
            json!({
                "hits": waterfall.search_response.hits.len(),
                "top_score": waterfall.search_response.top_score,
                "web_status": waterfall.tier2.status.status,
            }),
        );
        let mut response = waterfall.search_response;
        response.web_discovery = Some(waterfall.tier2.status.clone());
        response.impact_context = waterfall.impact_context;
        response.memory_context = waterfall.memory_context;
        let hits_value = serde_json::to_value(&response.hits)?;
        let top_score = response.top_score;
        let top_score_camel = response.top_score_camel;
        let web_discovery = response.web_discovery.clone();
        let memory_context = response.memory_context.clone();
        let mut meta = response.meta.unwrap_or_else(|| search::SearchMeta {
            generated_at_epoch_ms: 0,
            index_last_updated_epoch_ms: None,
            dag_session_id: None,
            repo_root: self.repo_root.display().to_string(),
            repo_id: None,
            query: None,
            context_assembly: None,
        });
        meta.repo_root = project_root_path.clone();
        meta.dag_session_id = Some(dag_session_id.to_string());
        if meta.repo_id.is_none() {
            meta.repo_id = crate::repo_manager::repo_fingerprint_sha256(&self.repo_root).ok();
        }
        let mut payload = json!({
            "hits": hits_value.clone(),
            "results": hits_value,
            "top_score": top_score,
            "topScore": top_score_camel,
            "repo_root": self.repo_root.display().to_string(),
            "state_dir": self.indexer.config().state_dir().display().to_string(),
            "limit": limit,
            "project_root": project_root_path,
            "meta": meta
        });
        if let Some(status) = web_discovery {
            payload["webDiscovery"] = json!(status);
        }
        if let Some(context) = memory_context {
            payload["memoryContext"] = json!(context);
        }
        Ok(payload)
    }

    pub(super) async fn handle_capabilities(
        &self,
        _args: CapabilitiesArgs,
    ) -> Result<serde_json::Value> {
        Ok(serde_json::to_value(capabilities::current_capabilities())?)
    }

    pub(super) async fn handle_rerank(&self, args: RerankArgs) -> Result<serde_json::Value> {
        let RerankArgs {
            query,
            candidates,
            limit,
            project_root,
            repo_path,
        } = args;
        let project_root = self.resolve_project_root_arg(project_root, repo_path)?;
        if project_root.is_some() {
            self.ensure_project_root(project_root.as_deref())?;
        }

        let query = query.trim();
        if query.is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "query is required").into());
        }
        if candidates.is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "candidates must not be empty").into());
        }

        let input_count = candidates.len();
        let mut candidates = candidates;
        let truncated = input_count > RERANK_MAX_CANDIDATES;
        if truncated {
            candidates.truncate(RERANK_MAX_CANDIDATES);
        }

        let max_limit = self.max_results.min(RERANK_MAX_CANDIDATES).max(1);
        let limit = limit.unwrap_or(candidates.len()).clamp(1, max_limit);
        let hits = search::rerank_hits(query, candidates, limit);
        let hits_value = serde_json::to_value(&hits)?;

        Ok(json!({
            "hits": hits_value.clone(),
            "results": hits_value,
            "input_count": input_count,
            "returned_count": hits.len(),
            "limit": limit,
            "truncated": truncated,
            "project_root": self.repo_root.display().to_string()
        }))
    }

    pub(super) async fn handle_batch_search(
        &self,
        _request_id: String,
        args: BatchSearchArgs,
    ) -> Result<serde_json::Value> {
        let BatchSearchArgs {
            queries,
            limit,
            include_libs,
            project_root,
            repo_path,
        } = args;
        let project_root = self.resolve_project_root_arg(project_root, repo_path)?;
        if project_root.is_some() {
            self.ensure_project_root(project_root.as_deref())?;
        }

        if queries.is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "queries must not be empty").into());
        }

        let query_count = queries.len();
        let mut normalized = queries
            .into_iter()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>();
        if normalized.is_empty() {
            return Err(AppError::new(
                ERR_INVALID_ARGUMENT,
                "queries must include non-empty values",
            )
            .into());
        }

        let truncated = normalized.len() > BATCH_SEARCH_MAX_QUERIES;
        if truncated {
            normalized.truncate(BATCH_SEARCH_MAX_QUERIES);
        }

        let limit = limit.unwrap_or(self.max_results).clamp(1, self.max_results);
        let include_libs = include_libs.unwrap_or(true);
        let libs_indexer = if include_libs {
            self.libs_indexer.as_deref()
        } else {
            None
        };

        let mut results = Vec::with_capacity(normalized.len());
        for query in normalized {
            let response = search::run_query(
                &self.indexer,
                libs_indexer,
                &query,
                limit,
                search::RankingSurface::Search,
            )
            .await?;
            results.push(json!({
                "query": query,
                "response": response,
            }));
        }

        Ok(json!({
            "results": results,
            "query_count": query_count,
            "effective_query_count": results.len(),
            "limit": limit,
            "truncated": truncated,
            "project_root": self.repo_root.display().to_string(),
        }))
    }

    pub(super) async fn handle_delegate(&self, args: DelegateArgs) -> Result<serde_json::Value> {
        if args.task_type.trim().is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "task_type is required").into());
        }
        if args.instruction.trim().is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "instruction is required").into());
        }
        if args.context.trim().is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "context is required").into());
        }

        let project_root = self.resolve_project_root_arg(args.project_root, args.repo_path)?;
        if project_root.is_some() {
            self.ensure_project_root(project_root.as_deref())?;
        }

        // Local completion is intentionally local-only; do not fall back to primary models.
        let mut llm_config = self.llm_config.clone();
        llm_config.delegation.enforce_local = true;
        llm_config.delegation.allow_fallback_to_primary = false;

        let task_type = TaskType::parse(&args.task_type)
            .ok_or_else(|| AppError::new(ERR_INVALID_ARGUMENT, "task_type is invalid"))?;
        let mut llm_config = resolve_task_scoped_delegation_config(&llm_config, task_type);
        llm_config.delegation.enforce_local = true;
        llm_config.delegation.allow_fallback_to_primary = false;
        let web_gate = WebGateConfig::from_env();
        let library_result = if web_gate.enabled {
            let indexer = self.indexer.clone();
            let libs_indexer = self.libs_indexer.as_deref();
            let global_state_dir = self.global_state_dir.clone();
            let request_id = Uuid::new_v4().to_string();
            let mut fetcher = move |query: String| {
                let indexer = indexer.clone();
                let request_id = request_id.clone();
                let web_gate = web_gate.clone();
                let libs_indexer = libs_indexer;
                let global_state_dir = global_state_dir.clone();
                async move {
                    let response = run_web_research(
                        &request_id,
                        indexer.as_ref(),
                        libs_indexer,
                        global_state_dir.as_deref(),
                        &query,
                        5,
                        Some(3),
                        true,
                        &web_gate,
                        false,
                        true,
                        false,
                        None,
                        None,
                    )
                    .await?;
                    Ok(format_web_text(&response))
                }
            };
            if local_selection_policy_requires_fresh_library(&llm_config) {
                refresh_local_library_with_web(
                    self.global_state_dir.as_deref(),
                    &llm_config,
                    true,
                    Some(&mut fetcher),
                )
                .await
            } else {
                refresh_local_library_if_stale_with_web(
                    self.global_state_dir.as_deref(),
                    &llm_config,
                    true,
                    Some(&mut fetcher),
                )
                .await
            }
        } else {
            if local_selection_policy_requires_fresh_library(&llm_config) {
                refresh_local_library(self.global_state_dir.as_deref(), &llm_config, true).await
            } else {
                refresh_local_library_if_stale(self.global_state_dir.as_deref(), &llm_config, true)
                    .await
            }
        };
        let mut library = match library_result {
            Ok(library) => Some(library),
            Err(err) => {
                warn!(
                    target: "docdexd",
                    error = ?err,
                    "local model library refresh failed"
                );
                load_local_library(self.global_state_dir.as_deref()).ok()
            }
        };
        if !delegation_is_enabled(&llm_config.delegation, library.as_ref()) {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "delegation is disabled").into());
        }
        if !allowlist_allows(task_type, &llm_config.delegation.task_allowlist) {
            return Err(AppError::new(
                ERR_INVALID_ARGUMENT,
                "task_type not allowed by delegation allowlist",
            )
            .into());
        }
        let mode = match args.mode.as_deref() {
            Some(value) => DelegationMode::parse(value)
                .ok_or_else(|| AppError::new(ERR_INVALID_ARGUMENT, "mode is invalid"))?,
            None => mode_from_config(&llm_config.delegation.mode),
        };
        let max_context_chars = args
            .max_context_chars
            .filter(|value| *value > 0)
            .unwrap_or(llm_config.delegation.max_context_chars);
        let agent_override = args
            .agent
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let override_target =
            agent_override.and_then(|value| parse_local_target_override(value, library.as_ref()));
        let mut local_targets: Vec<LocalTarget> = override_target.clone().into_iter().collect();
        if local_targets.is_empty() {
            if let Some(library) = library.as_ref() {
                let mut library = library.clone();
                local_targets = build_local_target_candidates_with_config(
                    self.global_state_dir.as_deref(),
                    &llm_config,
                    task_type,
                    &mut library,
                );
            }
        }
        if local_targets.is_empty() {
            if let Some(target) =
                resolve_explicit_target(&llm_config.delegation.local_agent_id, library.as_ref())
            {
                local_targets.push(target);
            }
        }
        if local_targets.is_empty() {
            if let Some(target) =
                resolve_explicit_target(&llm_config.delegation.cloud_agent_id, library.as_ref())
            {
                local_targets.push(target);
            }
        }
        if local_targets.is_empty() {
            let model = llm_config.default_model.trim();
            if model.is_empty() {
                local_targets.clear();
            } else if resolve_local_ollama_base_url(&llm_config).is_some() {
                local_targets.push(LocalTarget::OllamaModel(model.to_string()));
            }
        }
        let local_agent_override = match (&override_target, agent_override) {
            (Some(LocalTarget::OllamaModel(model)), _) => Some(format!("model:{model}")),
            (Some(LocalTarget::McodaAgent(_)), Some(value)) => Some(value.to_string()),
            (None, Some(value)) => Some(value.to_string()),
            _ => None,
        };
        let pricing_context = DelegationPricingContext {
            caller_agent_id: args
                .caller_agent_id
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .or_else(|| self.default_agent_id.clone()),
            caller_model: args
                .caller_model
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .or_else(|| self.default_agent_model.clone()),
            primary_cost_per_million: args.primary_cost_per_million,
            fallback_primary_cost_per_million: self
                .delegation_metrics
                .snapshot()
                .effective_avoided_primary_usd_per_million_tokens()
                .or_else(|| {
                    DelegationTelemetrySnapshot::from_metrics(metrics::global().as_ref())
                        .effective_avoided_primary_usd_per_million_tokens()
                }),
        };
        let local_override = local_agent_override
            .as_deref()
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false);
        let mut primary_targets = library
            .as_ref()
            .map(|library| {
                build_primary_target_candidates(
                    &llm_config,
                    task_type,
                    library,
                    local_targets.first(),
                )
            })
            .unwrap_or_default();
        if !local_override {
            local_targets = filter_automatic_local_targets_by_cost(
                &llm_config,
                Some(&pricing_context),
                &primary_targets,
                &local_targets,
                library.as_ref(),
            );
            primary_targets = library
                .as_ref()
                .map(|library| {
                    build_primary_target_candidates(
                        &llm_config,
                        task_type,
                        library,
                        local_targets.first(),
                    )
                })
                .unwrap_or_default();
        }
        let metrics = metrics::global();
        let started_at = Instant::now();
        metrics.inc_delegate_request();
        self.delegation_metrics.inc_delegate_request();
        let persist_delegation_metrics = || {
            let repo_state_root = repo_state_root_from_state_dir(self.indexer.state_dir());
            let telemetry_global_state_dir = delegation_telemetry::effective_global_state_dir(
                self.global_state_dir.as_deref(),
                self.indexer.state_dir(),
            );
            delegation_telemetry::persist_metrics(
                telemetry_global_state_dir.as_deref(),
                metrics.as_ref(),
                Some(repo_state_root.as_path()),
                Some(self.delegation_metrics.as_ref()),
            );
        };
        if llm_config.delegation.enforce_local && local_targets.is_empty() && !local_override {
            let elapsed_ms = started_at.elapsed().as_millis();
            metrics.inc_delegate_failed();
            self.delegation_metrics.inc_delegate_failed();
            metrics.inc_delegate_local_enforced_failure();
            self.delegation_metrics
                .inc_delegate_local_enforced_failure();
            metrics.record_delegate_latency(elapsed_ms);
            self.delegation_metrics.record_delegate_latency(elapsed_ms);
            persist_delegation_metrics();
            return Err(AppError::new(
                ERR_DELEGATION_LOCAL_REQUIRED,
                "local delegation required but no local target is configured",
            )
            .into());
        }
        let failure_history = DelegationFailureHistoryContext {
            global_state_dir: self.global_state_dir.clone(),
            repo_id: Some(self.repo_id.clone()),
            repo_root: Some(self.repo_root.display().to_string()),
            source: Some("mcp".to_string()),
        };
        let result = run_delegation_flow_with_failure_history(
            &llm_config,
            local_agent_override.as_deref(),
            &local_targets,
            &primary_targets,
            task_type,
            &args.instruction,
            &args.context,
            max_context_chars,
            args.max_tokens,
            args.timeout_ms,
            mode,
            Some(failure_history),
        )
        .await;
        let result = match result {
            Ok(result) => result,
            Err(err) => {
                let elapsed_ms = started_at.elapsed().as_millis();
                metrics.inc_delegate_failed();
                self.delegation_metrics.inc_delegate_failed();
                metrics.record_delegate_latency(elapsed_ms);
                self.delegation_metrics.record_delegate_latency(elapsed_ms);
                if err.downcast_ref::<DelegationEnforcementError>().is_some() {
                    metrics.inc_delegate_local_enforced_failure();
                    self.delegation_metrics
                        .inc_delegate_local_enforced_failure();
                    persist_delegation_metrics();
                    return Err(
                        AppError::new(ERR_DELEGATION_LOCAL_REQUIRED, err.to_string()).into(),
                    );
                }
                persist_delegation_metrics();
                return Err(err);
            }
        };

        if !result.primary_used {
            if let Some(library) = library.as_mut() {
                update_cached_local_selection_from_completion(
                    self.global_state_dir.as_deref(),
                    &llm_config,
                    library,
                    task_type,
                    &result.completion,
                );
            }
        }

        let elapsed_ms = started_at.elapsed().as_millis();
        metrics.record_delegate_latency(elapsed_ms);
        self.delegation_metrics.record_delegate_latency(elapsed_ms);
        metrics.record_delegate_token_estimate(result.token_estimate);
        self.delegation_metrics
            .record_delegate_token_estimate(result.token_estimate);
        let local_cost_per_million = resolve_local_cost_per_million(
            &llm_config,
            local_agent_override.as_deref(),
            local_targets.first(),
            library.as_ref(),
        );
        let primary_cost_per_million = resolve_primary_cost_per_million(
            &llm_config,
            Some(&pricing_context),
            primary_targets.first(),
            library.as_ref(),
        );
        let local_cost_micros = compute_cost_micros(result.local_tokens, local_cost_per_million);
        let primary_cost_micros =
            compute_cost_micros(result.primary_tokens, primary_cost_per_million);
        if result.local_tokens > 0 {
            metrics.inc_delegate_offloaded();
            self.delegation_metrics.inc_delegate_offloaded();
        }
        metrics.record_delegate_local_tokens(result.local_tokens);
        self.delegation_metrics
            .record_delegate_local_tokens(result.local_tokens);
        metrics.record_delegate_primary_tokens(result.primary_tokens);
        self.delegation_metrics
            .record_delegate_primary_tokens(result.primary_tokens);
        metrics.record_delegate_local_cost_micros(local_cost_micros);
        self.delegation_metrics
            .record_delegate_local_cost_micros(local_cost_micros);
        metrics.record_delegate_primary_cost_micros(primary_cost_micros);
        self.delegation_metrics
            .record_delegate_primary_cost_micros(primary_cost_micros);
        let savings = compute_delegation_savings(
            result.local_tokens,
            local_cost_per_million,
            primary_cost_per_million,
        );
        metrics.record_delegate_token_savings(savings.token_savings);
        self.delegation_metrics
            .record_delegate_token_savings(savings.token_savings);
        metrics.record_delegate_cost_savings_micros(savings.cost_savings_micros);
        self.delegation_metrics
            .record_delegate_cost_savings_micros(savings.cost_savings_micros);
        if result.fallback_used {
            metrics.inc_delegate_fallback();
            self.delegation_metrics.inc_delegate_fallback();
        }
        persist_delegation_metrics();

        Ok(json!({
            "id": Uuid::new_v4().to_string(),
            "task_type": task_type.as_str(),
            "adapter": result.completion.adapter,
            "model": result.completion.model,
            "output": result.completion.output,
            "draft": result.draft,
            "truncated": result.truncated,
            "warnings": result.warnings
        }))
    }

    pub(super) async fn handle_web_research(
        &self,
        request_id: String,
        args: WebResearchArgs,
    ) -> Result<serde_json::Value> {
        let WebResearchArgs {
            query,
            limit,
            web_limit,
            force_web,
            skip_local_search,
            no_cache,
            llm_filter_local_results,
            repo_only,
            llm_model,
            llm_agent,
            dag_session_id,
            project_root,
            repo_path,
        } = args;
        let project_root = self.resolve_project_root_arg(project_root, repo_path)?;
        self.ensure_project_root(project_root.as_deref())?;
        let query_owned = query;
        let query = query_owned.trim();
        let limit = limit.unwrap_or(self.max_results).clamp(1, self.max_results);
        let web_limit = web_limit.map(|value| value.max(1));
        let project_root_path = self
            .default_project_root
            .as_ref()
            .unwrap_or(&self.repo_root)
            .display()
            .to_string();
        let repo_state_root = repo_state_root_from_state_dir(self.indexer.state_dir());
        let request_id_ref = request_id.as_str();
        let dag_session_id = dag_session_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(request_id_ref);
        let force_web = force_web.unwrap_or(false);
        let skip_local_search = skip_local_search.unwrap_or(false);
        let disable_web_cache = no_cache.unwrap_or(false);
        let llm_filter_local_results = llm_filter_local_results.unwrap_or(false);
        if !skip_local_search {
            self.ensure_index_ready().await?;
        }
        let libs_indexer = if repo_only.unwrap_or(false) {
            None
        } else {
            self.libs_indexer.as_deref()
        };
        queue_dag_log(
            &repo_state_root,
            dag_session_id,
            "UserRequest",
            json!({
                "query": query,
                "limit": limit,
                "web_limit": web_limit,
                "force_web": force_web,
                "skip_local_search": skip_local_search,
                "disable_web_cache": disable_web_cache,
                "project_root": project_root_path.clone(),
            }),
        );
        let response = run_web_research(
            request_id_ref,
            self.indexer.as_ref(),
            libs_indexer,
            self.global_state_dir.as_deref(),
            query,
            limit,
            web_limit,
            force_web,
            &WebGateConfig::from_env(),
            llm_filter_local_results,
            skip_local_search,
            disable_web_cache,
            llm_model.as_deref(),
            llm_agent.as_deref(),
        )
        .await?;
        queue_dag_log(
            &repo_state_root,
            dag_session_id,
            "Decision",
            json!({
                "hits": response.hits.len(),
                "top_score": response.top_score,
                "web_status": response.web_discovery.status,
            }),
        );
        let mut payload = serde_json::to_value(&response)?;
        if let Some(obj) = payload.as_object_mut() {
            obj.insert(
                "repo_root".to_string(),
                json!(self.repo_root.display().to_string()),
            );
            obj.insert(
                "state_dir".to_string(),
                json!(self.indexer.config().state_dir().display().to_string()),
            );
            obj.insert("limit".to_string(), json!(limit));
            obj.insert("project_root".to_string(), json!(project_root_path));
            obj.insert("dag_session_id".to_string(), json!(dag_session_id));
        }
        Ok(payload)
    }
}
