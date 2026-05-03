use super::*;

#[cfg(test)]
mod repo_context_tests {
    use super::*;
    use crate::daemon::multi_repo::{RepoManager, RepoRuntime};
    use crate::error::ERR_MISSING_REPO;
    use crate::http_api::REPO_ID_HEADER;
    use crate::index::{IndexConfig, Indexer};
    use anyhow::{anyhow, Result};
    use axum::http::{HeaderMap, HeaderValue};
    use std::fs;
    use std::path::Path;
    use std::sync::Arc;
    use tempfile::TempDir;

    fn write_repo(repo_root: &Path, marker: &str) -> Result<()> {
        fs::create_dir_all(repo_root.join(".git"))?;
        fs::write(repo_root.join("README.md"), marker)?;
        Ok(())
    }

    fn build_state(
        repo_count: usize,
        multi_repo: bool,
    ) -> Result<(AppState, Vec<String>, TempDir)> {
        let temp = TempDir::new()?;
        let state_root = temp.path().join("state");
        fs::create_dir_all(&state_root)?;

        let manager = if multi_repo {
            Some(Arc::new(RepoManager::new(
                None,
                None,
                false,
                crate::config::MemoryConversationConfig::default(),
                crate::repo_encryption::RepoEncryptionConfig::default(),
            )))
        } else {
            None
        };

        let mut repo_ids = Vec::new();
        let mut default_indexer: Option<Arc<Indexer>> = None;
        let mut default_repo_id: Option<String> = None;
        let mut default_legacy_id: Option<String> = None;
        let mut default_delegation_metrics: Option<Arc<crate::metrics::DelegationMetrics>> = None;

        for idx in 0..repo_count {
            let repo_root = temp.path().join(format!("repo_{idx}"));
            write_repo(&repo_root, &format!("repo {idx}"))?;
            let state_dir = state_root.join(format!("repo_{idx}"));
            let config = IndexConfig::with_overrides(
                &repo_root,
                Some(state_dir),
                Vec::new(),
                Vec::new(),
                true,
            )?;
            let indexer = Arc::new(Indexer::with_config(repo_root.clone(), config)?);
            let repo_id = repo_manager::repo_fingerprint_sha256(&repo_root)?;
            let legacy_repo_id = repo_manager::fingerprint::legacy_repo_id_for_root(&repo_root);
            let delegation_metrics = Arc::new(crate::metrics::DelegationMetrics::default());

            if idx == 0 {
                default_indexer = Some(indexer.clone());
                default_repo_id = Some(repo_id.clone());
                default_legacy_id = Some(legacy_repo_id.clone());
                default_delegation_metrics = Some(delegation_metrics.clone());
            }

            if let Some(manager) = manager.as_ref() {
                let runtime = Arc::new(RepoRuntime {
                    repo_id: repo_id.clone(),
                    legacy_repo_id,
                    repo_root: repo_root.clone(),
                    indexer,
                    libs_indexer: None,
                    memory: None,
                    conversations: None,
                    delegation_metrics,
                });
                manager.insert_repo(runtime, None);
            }
            repo_ids.push(repo_id);
        }

        let security = SecurityConfig::from_options(
            None,
            &[],
            10,
            1024,
            1024,
            0,
            0,
            false,
            false,
            false,
            false,
            false,
        )?;

        let default_indexer = default_indexer.expect("build_state requires at least one repo");
        let default_repo_id = default_repo_id.expect("build_state requires at least one repo");
        let default_legacy_id = default_legacy_id.expect("build_state requires at least one repo");
        let default_delegation_metrics =
            default_delegation_metrics.expect("build_state requires at least one repo");

        if let Some(manager) = manager.as_ref() {
            manager.pin_repo(default_repo_id.clone());
        }

        let state = AppState {
            repo_id: default_repo_id,
            legacy_repo_id: default_legacy_id,
            indexer: default_indexer,
            libs_indexer: None,
            security,
            access_log: false,
            audit: None,
            metrics: Arc::new(crate::metrics::Metrics::default()),
            delegation_metrics: default_delegation_metrics,
            memory: None,
            conversations: None,
            personal_preferences: None,
            profile_state: None,
            features: crate::config::FeatureFlagsConfig::default(),
            auth: crate::auth::AuthRuntime::new_for_tests(
                crate::auth::AuthConfig::default(),
                temp.path(),
            ),
            repo_encryption: crate::repo_encryption::RepoEncryptionConfig::default(),
            default_agent_id: None,
            max_answer_tokens: 256,
            llm_config: config::LlmConfig {
                base_url: "http://127.0.0.1".to_string(),
                default_model: "test".to_string(),
                ..config::LlmConfig::default()
            },
            llm_base_url: "http://127.0.0.1".to_string(),
            llm_default_model: "test".to_string(),
            global_state_dir: None,
            repos: manager,
            multi_repo,
            require_repo_id: false,
            mcp_router: None,
        };

        Ok((state, repo_ids, temp))
    }

    #[test]
    fn missing_repo_id_errors_in_multi_repo_mode() -> Result<()> {
        let (state, _repo_ids, _temp) = build_state(2, true)?;
        let headers = HeaderMap::new();
        let err = match resolve_repo_context(&state, &headers, None, None, false) {
            Ok(_) => return Err(anyhow!("expected missing repo error")),
            Err(err) => err,
        };
        assert_eq!(err.code, ERR_MISSING_REPO);
        assert!(err.message.contains("multiple repos"));
        let details = err.details.expect("expected error details");
        assert_eq!(details.get("repoCount").and_then(|v| v.as_u64()), Some(2));
        Ok(())
    }

    #[test]
    fn missing_repo_id_defaults_in_single_repo_mode() -> Result<()> {
        let (state, repo_ids, _temp) = build_state(1, false)?;
        let headers = HeaderMap::new();
        let repo = match resolve_repo_context(&state, &headers, None, None, false) {
            Ok(repo) => repo,
            Err(err) => return Err(anyhow!("unexpected error: {}", err.message)),
        };
        assert_eq!(repo.repo_id, repo_ids[0]);
        Ok(())
    }

    #[test]
    fn mismatched_repo_id_rejected() -> Result<()> {
        let (state, _repo_ids, _temp) = build_state(1, false)?;
        let mut headers = HeaderMap::new();
        headers.insert(REPO_ID_HEADER, HeaderValue::from_static("alpha"));
        let err = match resolve_repo_context(&state, &headers, Some("bravo"), None, false) {
            Ok(_) => return Err(anyhow!("expected mismatch error")),
            Err(err) => err,
        };
        assert_eq!(err.code, ERR_INVALID_ARGUMENT);
        Ok(())
    }
}

#[cfg(test)]
mod rate_limit_contract_tests {
    use crate::error::RateLimited;
    use crate::http_api::{ErrorBody, ErrorDetail, MAX_RATE_LIMIT_MESSAGE_BYTES};
    use chrono::Utc;
    use serde_json::Value;
    use std::time::Duration;

    #[test]
    fn http_rate_limited_error_truncates_message_and_bounds_payload() {
        let err = RateLimited::new(
            Duration::from_millis(1234),
            "http_ip".to_string(),
            "ip".to_string(),
        )
        .with_message("x".repeat(10_000))
        .with_retry_at(Utc::now());

        let body = ErrorBody {
            error: ErrorDetail::rate_limited(&err),
        };

        let bytes = serde_json::to_vec(&body).expect("rate-limit error body should serialize");
        assert!(
            bytes.len() <= 1024,
            "rate-limit payload should remain small (got {} bytes)",
            bytes.len()
        );

        let json: Value = serde_json::from_slice(&bytes).expect("rate-limit body should parse");
        let error = json
            .get("error")
            .and_then(|v| v.as_object())
            .expect("rate-limit response should contain error object");
        let message = error
            .get("message")
            .and_then(|v| v.as_str())
            .expect("rate-limit response should contain error message");

        assert_eq!(
            error.get("code").and_then(|v| v.as_str()),
            Some("rate_limited")
        );
        assert!(
            message.len() <= MAX_RATE_LIMIT_MESSAGE_BYTES + "…".len(),
            "rate-limit error message should be bounded"
        );
        assert!(error
            .get("retry_after_ms")
            .and_then(|v| v.as_u64())
            .is_some());
        assert!(error.get("limit_key").and_then(|v| v.as_str()).is_some());
        assert!(error.get("scope").and_then(|v| v.as_str()).is_some());
    }
}

#[cfg(test)]
mod latency_perf_tests {
    use super::RankingSurface;
    use crate::{index, libs};
    use std::fs;
    use std::time::Instant;
    use tempfile::TempDir;

    fn percentile(sorted: &[u128], p: f64) -> u128 {
        if sorted.is_empty() {
            return 0;
        }
        let p = p.clamp(0.0, 1.0);
        let idx = ((p * ((sorted.len() - 1) as f64)).ceil() as usize).min(sorted.len() - 1);
        sorted[idx]
    }

    fn summarize(mut samples_us: Vec<u128>) -> (u128, u128, u128) {
        samples_us.sort_unstable();
        let p50 = percentile(&samples_us, 0.50);
        let p95 = percentile(&samples_us, 0.95);
        let max = *samples_us.last().unwrap_or(&0);
        (p50, p95, max)
    }

    /// NFR check: repo-only search p95 should remain under 50ms even when a libs index exists.
    /// See `docs/sds/sds.md` (latency: local search p95 < 50ms, < 20ms typical).
    #[tokio::test]
    #[ignore]
    async fn repo_only_search_p95_under_50ms_with_libs_index_present() -> anyhow::Result<()> {
        let repo = TempDir::new()?;
        let repo_root = repo.path();

        fs::write(
            repo_root.join("readme.md"),
            "# Repo\n\nThis repo contains REPO_NEEDLE_ABC.\n",
        )?;

        let docs_dir = repo_root.join("docs");
        fs::create_dir_all(&docs_dir)?;
        for i in 0..250usize {
            let body = if i % 9 == 0 {
                format!("# Doc {i}\n\nREPO_NEEDLE_ABC appears in this document.\n\nMore text.\n")
            } else {
                format!("# Doc {i}\n\nFiller content for indexing.\n")
            };
            fs::write(docs_dir.join(format!("doc_{i}.md")), body)?;
        }

        let index_config =
            index::IndexConfig::with_overrides(repo_root, None, Vec::new(), Vec::new(), true)?;
        let indexer = index::Indexer::with_config(repo_root.to_path_buf(), index_config)?;
        indexer.reindex_all().await?;

        let libs_doc_path = repo_root.join("vendor").join("serde").join("README.md");
        fs::create_dir_all(libs_doc_path.parent().expect("libs doc parent"))?;
        fs::write(
            &libs_doc_path,
            "# Serde\n\nLIBS_ONLY_TERM_123 appears only in library docs.\n",
        )?;

        let libs_dir = libs::libs_state_dir_from_index_state_dir(indexer.state_dir());
        let libs_writer = libs::LibsIndexer::open_or_create(libs_dir.clone())?;
        let sources = [libs::LibSource {
            library: "serde".to_string(),
            version: Some("1.0.0".to_string()),
            source: "local_file".to_string(),
            path: libs_doc_path,
            title: Some("Serde".to_string()),
        }];
        let report = libs_writer.ingest_sources(&repo_root, &sources)?;
        drop(libs_writer);
        assert!(
            report.succeeded_sources >= 1,
            "expected libs ingestion to succeed (report: {})",
            serde_json::to_string(&report).unwrap_or_default()
        );
        let libs_indexer = libs::LibsIndexer::open_read_only(libs_dir)?.expect("libs indexer");

        let query = "REPO_NEEDLE_ABC";
        let limit = 8usize;
        for _ in 0..20usize {
            let _ = indexer.search_with_query_meta(query, limit)?;
            let _ = super::search_with_optional_libs(
                &indexer,
                Some(&libs_indexer),
                query,
                limit,
                RankingSurface::Search,
            )?;
        }

        let iterations = 250usize;
        let mut repo_only_us = Vec::with_capacity(iterations);
        for _ in 0..iterations {
            let start = Instant::now();
            let _ = indexer.search_with_query_meta(query, limit)?;
            repo_only_us.push(start.elapsed().as_micros());
        }

        let mut combined_us = Vec::with_capacity(iterations);
        for _ in 0..iterations {
            let start = Instant::now();
            let _ = super::search_with_optional_libs(
                &indexer,
                Some(&libs_indexer),
                query,
                limit,
                RankingSurface::Search,
            )?;
            combined_us.push(start.elapsed().as_micros());
        }

        let (repo_p50, repo_p95, repo_max) = summarize(repo_only_us);
        let (combined_p50, combined_p95, combined_max) = summarize(combined_us);

        eprintln!(
            "repo-only search: p50={}us p95={}us max={}us (libs index exists)",
            repo_p50, repo_p95, repo_max
        );
        eprintln!(
            "combined search:  p50={}us p95={}us max={}us (repo + libs)",
            combined_p50, combined_p95, combined_max
        );

        if cfg!(debug_assertions) {
            eprintln!(
                "note: perf assertions are enforced in release builds; re-run with `cargo test --release ... -- --ignored --nocapture`"
            );
            return Ok(());
        }

        assert!(
            repo_p95 < 50_000,
            "repo-only search p95 {}us exceeds 50ms (see docs/sds/sds.md)",
            repo_p95
        );

        Ok(())
    }
}

#[cfg(test)]
mod rerank_contract_tests {
    use super::*;
    use crate::index::{DocType, DocumentKind};

    fn make_hit(path: &str, summary: &str, score: f32) -> Hit {
        Hit {
            doc_id: format!("doc-{path}"),
            rel_path: path.to_string(),
            path: path.to_string(),
            kind: DocumentKind::Code,
            doc_type: Some(DocType::Code),
            score,
            summary: summary.to_string(),
            snippet: summary.to_string(),
            token_estimate: 10,
            snippet_origin: Some(SearchSnippetOrigin::Summary),
            snippet_truncated: Some(false),
            line_start: None,
            line_end: None,
            score_breakdown: None,
            provenance: None,
            retrieval_explanation: None,
        }
    }

    #[test]
    fn rerank_prefers_query_overlap_and_enriches_metadata() {
        let low_match = make_hit("src/low.rs", "unrelated text", 1.0);
        let high_match = make_hit("src/high.rs", "contains alpha token", 1.0);

        let reranked = rerank_hits("alpha", vec![low_match, high_match], 2);
        assert_eq!(reranked.len(), 2);
        assert_eq!(reranked[0].rel_path, "src/high.rs");
        assert!(reranked[0].score_breakdown.is_some());
        assert!(reranked[0].provenance.is_some());
        assert!(reranked[0].retrieval_explanation.is_some());
        let signals = &reranked[0]
            .retrieval_explanation
            .as_ref()
            .expect("explanation")
            .signals;
        assert!(signals.iter().any(|signal| signal == "rerank_applied"));
    }

    #[test]
    fn rerank_truncates_to_limit() {
        let hits = vec![
            make_hit("src/a.rs", "alpha", 1.0),
            make_hit("src/b.rs", "beta", 1.0),
            make_hit("src/c.rs", "gamma", 1.0),
        ];

        let reranked = rerank_hits("alpha", hits, 1);
        assert_eq!(reranked.len(), 1);
    }
}

#[cfg(test)]
mod path_lookup_tests {
    use super::{path_hit_for_query, DEFAULT_SNIPPET_WINDOW};
    use crate::index::{IndexConfig, Indexer};
    use anyhow::Result;
    use std::fs;
    use tempfile::TempDir;

    #[tokio::test]
    async fn open_by_path_resolves_yaml() -> Result<()> {
        let repo = TempDir::new()?;
        let state_root = TempDir::new()?;
        let openapi_dir = repo.path().join("openapi");
        fs::create_dir_all(&openapi_dir)?;
        fs::write(openapi_dir.join("spec.yaml"), "openapi: 3.0.0\n")?;

        let config = IndexConfig::with_overrides(
            repo.path(),
            Some(state_root.path().to_path_buf()),
            Vec::new(),
            Vec::new(),
            true,
        )?;
        let indexer = Indexer::with_config(repo.path().to_path_buf(), config)?;
        indexer.reindex_all().await?;

        let hit = path_hit_for_query(&indexer, "openapi/spec.yaml", DEFAULT_SNIPPET_WINDOW)?;
        assert!(hit.is_some(), "expected open-by-path hit for yaml");
        Ok(())
    }
}

#[cfg(test)]
mod security_tests {
    use super::SecurityConfig;
    use anyhow::Result;
    use std::net::IpAddr;

    fn security_with_allowlist(allowlist: Vec<String>) -> Result<SecurityConfig> {
        SecurityConfig::from_options(
            None,
            &allowlist,
            50,
            16 * 1024,
            512 * 1024,
            0,
            0,
            false,
            true,
            false,
            false,
            false,
        )
    }

    #[test]
    fn ip_allowed_allows_matching_net() -> Result<()> {
        let security = security_with_allowlist(vec!["10.0.0.0/8".to_string()])?;
        let ip: IpAddr = "10.1.2.3".parse()?;
        assert!(security.ip_allowed(ip));
        Ok(())
    }

    #[test]
    fn ip_allowed_blocks_non_matching_net() -> Result<()> {
        let security = security_with_allowlist(vec!["10.0.0.0/8".to_string()])?;
        let ip: IpAddr = "127.0.0.1".parse()?;
        assert!(!security.ip_allowed(ip));
        Ok(())
    }
}
