use super::*;

impl McpServer {
    pub(super) async fn handle_symbols(&self, args: SymbolsArgs) -> Result<serde_json::Value> {
        let project_root = self.resolve_project_root_arg(args.project_root, args.repo_path)?;
        self.ensure_project_root(project_root.as_deref())?;
        self.ensure_index_ready().await?;
        self.ensure_code_intelligence_allowed("symbol extraction")?;
        if !self.indexer.config().symbols_enabled() {
            return Err(MissingSymbolsDependencyError.into());
        }
        let rel_path = normalize_rel_path(&args.path).ok_or(InvalidPathError)?;
        let rel_str = rel_path.to_string_lossy().replace('\\', "/");
        let store = SymbolsStore::new(self.indexer.repo_root(), self.indexer.config().state_dir())
            .context("open symbols store")?;
        if store.requires_reindex()? {
            return Err(StaleSymbolsIndexError.into());
        }
        let payload = store
            .read_symbols(&rel_str)?
            .ok_or_else(|| MissingSymbolsIndexError {
                rel_path: rel_str.to_string(),
            })?;
        Ok(serde_json::to_value(payload).context("serialize symbols payload")?)
    }

    pub(super) async fn handle_ast(&self, args: AstArgs) -> Result<serde_json::Value> {
        let project_root = self.resolve_project_root_arg(args.project_root, args.repo_path)?;
        self.ensure_project_root(project_root.as_deref())?;
        self.ensure_index_ready().await?;
        self.ensure_code_intelligence_allowed("ast extraction")?;
        if !self.indexer.config().symbols_enabled() {
            return Err(MissingSymbolsDependencyError.into());
        }
        let rel_path = normalize_rel_path(&args.path).ok_or(InvalidPathError)?;
        let rel_str = rel_path.to_string_lossy().replace('\\', "/");
        let store = SymbolsStore::new(self.indexer.repo_root(), self.indexer.config().state_dir())
            .context("open symbols store")?;
        if store.requires_reindex()? {
            return Err(StaleSymbolsIndexError.into());
        }
        let max_nodes = args
            .max_nodes
            .unwrap_or(AST_DEFAULT_MAX_NODES)
            .clamp(1, AST_MAX_NODES);
        let payload = store
            .read_ast(&rel_str, max_nodes)?
            .ok_or_else(|| MissingAstIndexError {
                rel_path: rel_str.to_string(),
            })?;
        Ok(serde_json::to_value(payload).context("serialize ast payload")?)
    }

    pub(super) async fn handle_impact_diagnostics(
        &self,
        args: ImpactDiagnosticsArgs,
    ) -> Result<serde_json::Value> {
        let project_root = self.resolve_project_root_arg(args.project_root, args.repo_path)?;
        self.ensure_project_root(project_root.as_deref())?;
        self.ensure_index_ready().await?;
        self.ensure_code_intelligence_allowed("impact diagnostics")?;
        let repo_id = crate::symbols::repo_id_for_root(self.indexer.repo_root())?;
        let store = ImpactGraphStore::new(self.indexer.state_dir());
        let diagnostics_map = store.read_diagnostics_map()?;
        let file = match args.file.as_deref().map(str::trim) {
            None => None,
            Some("") => {
                return Err(AppError::new(ERR_INVALID_ARGUMENT, "file must not be empty").into());
            }
            Some(value) => {
                let rel = normalize_rel_path(value).ok_or_else(|| {
                    AppError::new(ERR_INVALID_ARGUMENT, "file must be repo-relative")
                })?;
                Some(rel.to_string_lossy().replace('\\', "/"))
            }
        };

        let (entries, total, limit, offset) = if let Some(file) = file {
            let entry = diagnostics_map
                .get(&file)
                .cloned()
                .map(|diag| ImpactDiagnosticsEntry {
                    file: file.clone(),
                    diagnostics: diag,
                });
            let diagnostics = entry.into_iter().collect::<Vec<_>>();
            let count = diagnostics.len();
            (diagnostics, count, 1, 0)
        } else {
            let mut entries = diagnostics_map
                .into_iter()
                .map(|(file, diagnostics)| ImpactDiagnosticsEntry { file, diagnostics })
                .collect::<Vec<_>>();
            entries.sort_by(|a, b| a.file.cmp(&b.file));
            let total = entries.len();
            let limit = args
                .limit
                .unwrap_or(DIAGNOSTICS_DEFAULT_LIMIT)
                .min(DIAGNOSTICS_MAX_LIMIT)
                .max(1);
            let offset = args.offset.unwrap_or(0);
            let diagnostics = entries
                .into_iter()
                .skip(offset)
                .take(limit)
                .collect::<Vec<_>>();
            (diagnostics, total, limit, offset)
        };

        let payload = build_impact_diagnostics_response(&repo_id, entries, total, limit, offset);
        Ok(serde_json::to_value(payload).context("serialize impact diagnostics")?)
    }

    pub(super) async fn handle_impact_graph(
        &self,
        args: ImpactGraphArgs,
    ) -> Result<serde_json::Value> {
        let project_root = self.resolve_project_root_arg(args.project_root, args.repo_path)?;
        self.ensure_project_root(project_root.as_deref())?;
        self.ensure_index_ready().await?;
        self.ensure_code_intelligence_allowed("impact graph access")?;

        let file = args.file.trim();
        if file.is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "file must not be empty").into());
        }
        let rel = normalize_rel_path(file)
            .ok_or_else(|| AppError::new(ERR_INVALID_ARGUMENT, "file must be repo-relative"))?;
        let file = rel.to_string_lossy().replace('\\', "/");

        let edge_types = args.edge_types.map(|values| {
            values
                .into_iter()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .collect::<Vec<_>>()
        });
        let controls_raw = crate::impact::ImpactQueryControlsRaw {
            max_edges: args.max_edges.map(|value| value as i64),
            max_depth: args.max_depth.map(|value| value as i64),
            edge_types: edge_types.filter(|values| !values.is_empty()),
        };
        let controls = match controls_raw.validate() {
            Ok(value) => value,
            Err(err) => {
                let details = serde_json::to_value(err.details).unwrap_or_else(|_| json!({}));
                return Err(AppError::new(ERR_INVALID_ARGUMENT, "invalid argument")
                    .with_details(details)
                    .into());
            }
        };

        let repo_id = crate::symbols::repo_id_for_root(self.indexer.repo_root())?;
        let store = ImpactGraphStore::new(self.indexer.state_dir());
        let all_edges = store.read_edges()?;
        let traversal = crate::impact::traverse_impact(&file, &all_edges, &controls);
        let diagnostics = store.read_diagnostics(&file).ok().flatten();
        let response = crate::impact::build_impact_response(
            &repo_id,
            &file,
            traversal,
            &controls,
            diagnostics,
        );
        Ok(serde_json::to_value(response).context("serialize impact graph")?)
    }

    fn ensure_code_intelligence_allowed(&self, surface: &str) -> Result<()> {
        if self.indexer.config().repo_encryption().is_enabled() {
            return Err(AppError::new(
                ERR_REPO_ENCRYPTION_UNSUPPORTED,
                format!("{surface} is disabled when repository encryption is enabled"),
            )
            .into());
        }
        Ok(())
    }

    pub(super) async fn handle_dag_export(&self, args: DagExportArgs) -> Result<serde_json::Value> {
        let project_root = self.resolve_project_root_arg(args.project_root, args.repo_path)?;
        self.ensure_project_root(project_root.as_deref())?;

        let session_id = args
            .session_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let Some(session_id) = session_id else {
            let details = json!({
                "hint": "Pass the dag_session_id from docdex_search/docdex_web_research responses (meta.dag_session_id or top-level dag_session_id).",
                "expected_params": ["session_id", "dag_session_id"]
            });
            return Err(
                AppError::new(ERR_INVALID_ARGUMENT, "session_id is required")
                    .with_details(details)
                    .into(),
            );
        };
        let format = args
            .format
            .as_deref()
            .unwrap_or("json")
            .trim()
            .to_ascii_lowercase();
        let max_nodes = args.max_nodes;

        match format.as_str() {
            "json" => {
                let payload = crate::dag::view::export_session(
                    self.indexer.repo_root(),
                    session_id,
                    Some(self.indexer.state_dir().to_path_buf()),
                    max_nodes,
                )?;
                Ok(serde_json::to_value(payload).context("serialize dag export")?)
            }
            "text" => {
                let output = crate::dag::view::render_session_as_text(
                    self.indexer.repo_root(),
                    session_id,
                    Some(self.indexer.state_dir().to_path_buf()),
                    max_nodes,
                )?;
                Ok(json!({ "format": "text", "content": output }))
            }
            "dot" => {
                let output = crate::dag::view::render_session_as_dot(
                    self.indexer.repo_root(),
                    session_id,
                    Some(self.indexer.state_dir().to_path_buf()),
                    max_nodes,
                )?;
                Ok(json!({ "format": "dot", "content": output }))
            }
            _ => {
                Err(AppError::new(ERR_INVALID_ARGUMENT, "format must be json, text, or dot").into())
            }
        }
    }

    pub(super) async fn embed_memory_text(
        &self,
        memory: &McpMemoryState,
        text: &str,
    ) -> Result<MemoryEmbedding> {
        let stored_dim = match memory.store.embedding_dim() {
            Ok(dim) => dim,
            Err(err) => {
                warn!(
                    error = ?err,
                    "memory embedding_dim lookup failed; falling back to default"
                );
                None
            }
        };
        match memory.embedder.embed(text).await {
            Ok(embedding) => {
                if let Some(expected) = stored_dim {
                    if embedding.len() != expected {
                        warn!(
                            provider = memory.embedder.provider(),
                            model = memory.embedder.model(),
                            expected,
                            actual = embedding.len(),
                            "memory embedding dimension mismatch; falling back to local hash"
                        );
                        let fallback = ProfileEmbedder::fallback_embedding(text, expected);
                        return Ok(MemoryEmbedding {
                            embedding: fallback,
                            provider: "fallback".to_string(),
                            model: "hash-embed-v1".to_string(),
                        });
                    }
                }
                Ok(MemoryEmbedding {
                    embedding,
                    provider: memory.embedder.provider().to_string(),
                    model: memory.embedder.model().to_string(),
                })
            }
            Err(err) => {
                warn!(
                    error = ?err,
                    "memory embedding failed; falling back to local hash"
                );
                let expected = stored_dim.unwrap_or(memory.fallback_dim).max(1);
                let fallback = ProfileEmbedder::fallback_embedding(text, expected);
                Ok(MemoryEmbedding {
                    embedding: fallback,
                    provider: "fallback".to_string(),
                    model: "hash-embed-v1".to_string(),
                })
            }
        }
    }
}
