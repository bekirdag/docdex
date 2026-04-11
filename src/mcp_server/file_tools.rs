use super::*;

impl McpServer {
    pub(super) async fn handle_index(&mut self, args: IndexArgs) -> Result<serde_json::Value> {
        let project_root =
            self.resolve_project_root_arg(args.project_root.clone(), args.repo_path.clone())?;
        self.ensure_project_root(project_root.as_deref())?;
        if self.indexer.is_read_only() {
            return self.handle_index_via_http(args).await;
        }
        if args.paths.is_empty() {
            self.indexer.reindex_all().await?;
            return Ok(json!({
                "status": "ok",
                "action": "reindex_all",
                "repo_root": self.repo_root.display().to_string(),
                "state_dir": self.indexer.config().state_dir().display().to_string(),
                "project_root": self
                    .default_project_root
                    .as_ref()
                    .unwrap_or(&self.repo_root)
                    .display()
                    .to_string(),
            }));
        }
        let mut ingested = Vec::new();
        let mut decisions = Vec::new();
        for path in args.paths {
            let resolved = if path.is_absolute() {
                path
            } else {
                self.repo_root.join(path)
            };
            let path_display = resolved.display().to_string();
            let decision = self.indexer.ingest_file(resolved.clone()).await?;
            ingested.push(resolved);
            decisions.push(json!({
                "path": path_display,
                "decision": decision.decision,
                "reason": decision.reason,
            }));
        }
        Ok(json!({
            "status": "ok",
            "action": "ingest",
            "paths": ingested
                .into_iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>(),
            "decisions": decisions,
            "repo_root": self.repo_root.display().to_string(),
            "state_dir": self.indexer.config().state_dir().display().to_string(),
            "project_root": self
                .default_project_root
                .as_ref()
                .unwrap_or(&self.repo_root)
                .display()
                .to_string(),
        }))
    }

    pub(super) async fn handle_index_via_http(&self, args: IndexArgs) -> Result<serde_json::Value> {
        let repo_id = self.repo_id.as_str();
        if args.paths.is_empty() {
            let report = self
                .call_index_endpoint("/v1/index/rebuild", json!({ "repo_id": repo_id }))
                .await?;
            return Ok(json!({
                "status": "ok",
                "action": "reindex_all",
                "repo_root": self.repo_root.display().to_string(),
                "state_dir": self.indexer.config().state_dir().display().to_string(),
                "project_root": self
                    .default_project_root
                    .as_ref()
                    .unwrap_or(&self.repo_root)
                    .display()
                    .to_string(),
                "via": "http",
                "report": report,
            }));
        }
        let mut ingested = Vec::new();
        let mut decisions = Vec::new();
        for path in args.paths {
            let resolved = if path.is_absolute() {
                path
            } else {
                self.repo_root.join(path)
            };
            let path_display = resolved.display().to_string();
            let payload = self
                .call_index_endpoint(
                    "/v1/index/ingest",
                    json!({
                        "file": path_display.as_str(),
                        "repo_id": repo_id,
                    }),
                )
                .await?;
            let (decision, reason) = payload
                .as_object()
                .map(|obj| {
                    (
                        obj.get("decision").cloned().unwrap_or(Value::Null),
                        obj.get("reason").cloned().unwrap_or(Value::Null),
                    )
                })
                .unwrap_or((payload.clone(), Value::Null));
            ingested.push(path_display.clone());
            decisions.push(json!({
                "path": path_display,
                "decision": decision,
                "reason": reason,
            }));
        }
        Ok(json!({
            "status": "ok",
            "action": "ingest",
            "paths": ingested,
            "decisions": decisions,
            "repo_root": self.repo_root.display().to_string(),
            "state_dir": self.indexer.config().state_dir().display().to_string(),
            "project_root": self
                .default_project_root
                .as_ref()
                .unwrap_or(&self.repo_root)
                .display()
                .to_string(),
            "via": "http",
        }))
    }

    pub(super) async fn handle_files(&self, args: FilesArgs) -> Result<serde_json::Value> {
        let project_root = self.resolve_project_root_arg(args.project_root, args.repo_path)?;
        self.ensure_project_root(project_root.as_deref())?;
        self.ensure_index_ready().await?;
        let limit = args
            .limit
            .unwrap_or(FILES_DEFAULT_LIMIT)
            .clamp(1, FILES_MAX_LIMIT);
        let offset = args.offset.unwrap_or(0).min(FILES_MAX_OFFSET);
        let (docs, total) = self.indexer.list_docs(offset, limit)?;
        Ok(json!({
            "results": docs,
            "total": total,
            "limit": limit,
            "offset": offset,
            "repo_root": self.repo_root.display().to_string(),
            "project_root": self
                .default_project_root
                .as_ref()
                .unwrap_or(&self.repo_root)
                .display()
                .to_string(),
        }))
    }

    pub(super) async fn handle_stats(&self, args: StatsArgs) -> Result<serde_json::Value> {
        let project_root = self.resolve_project_root_arg(args.project_root, args.repo_path)?;
        self.ensure_project_root(project_root.as_deref())?;
        self.ensure_index_ready().await?;
        let stats = self.indexer.stats()?;
        Ok(json!({
            "num_docs": stats.num_docs,
            "state_dir": stats.state_dir.display().to_string(),
            "index_size_bytes": stats.index_size_bytes,
            "segments": stats.segments,
            "avg_bytes_per_doc": stats.avg_bytes_per_doc,
            "generated_at_epoch_ms": stats.generated_at_epoch_ms,
            "last_updated_epoch_ms": stats.last_updated_epoch_ms,
            "repo_root": self.repo_root.display().to_string(),
            "project_root": self
                .default_project_root
                .as_ref()
                .unwrap_or(&self.repo_root)
                .display()
                .to_string(),
        }))
    }

    pub(super) async fn handle_repo_inspect(
        &self,
        args: RepoInspectArgs,
    ) -> Result<serde_json::Value> {
        let project_root = self.resolve_project_root_arg(args.project_root, args.repo_path)?;
        self.ensure_project_root(project_root.as_deref())?;
        let report = crate::repo_manager::inspect_repo(
            &self.repo_root,
            Some(self.indexer.config().state_dir()),
        )?;
        Ok(serde_json::to_value(&report).context("serialize docdex_repo_inspect")?)
    }

    pub(super) async fn handle_open(&self, args: OpenArgs) -> Result<serde_json::Value> {
        let project_root = self.resolve_project_root_arg(args.project_root, args.repo_path)?;
        self.ensure_project_root(project_root.as_deref())?;
        let rel_path = normalize_rel_path(&args.path).ok_or(InvalidPathError)?;
        let abs_path = self.repo_root.join(&rel_path);
        let canonical = abs_path
            .canonicalize()
            .with_context(|| format!("resolve path {}", rel_path.display()))?;
        if !canonical.starts_with(&self.repo_root) {
            return Err(PathOutsideRepoError.into());
        }
        let content = fs::read_to_string(&canonical)
            .with_context(|| format!("read {}", rel_path.display()))?;
        if content.len() > OPEN_MAX_BYTES {
            return Err(MaxContentError {
                actual_bytes: content.len(),
                max_bytes: OPEN_MAX_BYTES,
            }
            .into());
        }
        let lines: Vec<&str> = content.lines().collect();
        let total_lines = lines.len();
        if total_lines == 0 {
            return Ok(json!({
                "path": rel_path.display().to_string(),
                "start_line": 0,
                "end_line": 0,
                "total_lines": 0,
                "content": "",
                "repo_root": self.repo_root.display().to_string(),
                "project_root": self
                    .default_project_root
                    .as_ref()
                    .unwrap_or(&self.repo_root)
                    .display()
                    .to_string(),
            }));
        }
        let (start, end_raw) = resolve_open_range(
            total_lines,
            args.start_line,
            args.end_line,
            args.head,
            args.clamp.unwrap_or(false),
        )?;
        let start_idx = start.saturating_sub(1);
        let end_idx = end_raw.saturating_sub(1);
        let slice = lines[start_idx..=end_idx].join("\n");
        Ok(json!({
            "path": rel_path.display().to_string(),
            "start_line": start,
            "end_line": end_raw,
            "total_lines": total_lines,
            "content": slice,
            "repo_root": self.repo_root.display().to_string(),
            "project_root": self
                .default_project_root
                .as_ref()
                .unwrap_or(&self.repo_root)
                .display()
                .to_string(),
        }))
    }

    pub(super) async fn handle_tree(&self, args: TreeArgs) -> Result<serde_json::Value> {
        let project_root = self.resolve_project_root_arg(args.project_root, args.repo_path)?;
        self.ensure_project_root(project_root.as_deref())?;
        let root = resolve_tree_root(&self.repo_root, args.path.as_deref())?;
        let options = TreeOptions {
            max_depth: args.max_depth,
            dirs_only: args.dirs_only.unwrap_or(false),
            include_hidden: args.include_hidden.unwrap_or(false),
            extra_excludes: args.extra_excludes.unwrap_or_default(),
        };
        let output = render_tree(&root, &options)?;
        Ok(json!({
            "root": output.root.display().to_string(),
            "tree": output.tree,
            "repo_root": self.repo_root.display().to_string(),
            "project_root": self
                .default_project_root
                .as_ref()
                .unwrap_or(&self.repo_root)
                .display()
                .to_string(),
            "max_depth": options.max_depth,
            "dirs_only": options.dirs_only,
            "include_hidden": options.include_hidden,
            "excludes": output.excludes,
        }))
    }
}
