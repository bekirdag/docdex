use axum::{
    extract::{Query, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
    Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::metrics::DelegationTelemetrySnapshot;
use crate::search::{repo_error_response, resolve_repo_context, AppState};

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
struct DelegationTelemetryPricing {
    primary_usd_per_1k_tokens: f64,
    local_usd_per_1k_tokens: f64,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
struct DelegationTelemetryResponse {
    generated_at_epoch_ms: i64,
    delegate_requests_total: u64,
    delegate_offloaded_total: u64,
    delegate_fallbacks_total: u64,
    delegate_token_estimate_total: u64,
    delegate_local_tokens_total: u64,
    delegate_primary_tokens_total: u64,
    delegate_tokens_total: u64,
    delegate_token_savings_total: u64,
    delegate_local_cost_micros_total: u64,
    delegate_primary_cost_micros_total: u64,
    delegate_cost_savings_micros_total: u64,
    delegate_cost_savings_usd: f64,
    pricing: DelegationTelemetryPricing,
}

#[derive(Debug, Default, Deserialize)]
pub struct DelegationTelemetryQuery {
    #[serde(default)]
    repo_id: Option<String>,
    #[serde(default)]
    all: bool,
}

pub async fn delegation_telemetry_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<DelegationTelemetryQuery>,
) -> Response {
    if params.all {
        return Json(build_delegation_response(
            delegation_snapshot_for_all(&state),
            &state.llm_config.delegation,
        ))
        .into_response();
    }
    let repo = match resolve_repo_context(&state, &headers, params.repo_id.as_deref(), None, false)
    {
        Ok(repo) => repo,
        Err(err) => return repo_error_response(err),
    };
    Json(build_delegation_response(
        DelegationTelemetrySnapshot::from_delegation_metrics(repo.delegation_metrics.as_ref()),
        &state.llm_config.delegation,
    ))
    .into_response()
}

fn delegation_snapshot_for_all(state: &AppState) -> DelegationTelemetrySnapshot {
    if let Some(manager) = state.repos.as_ref() {
        let snapshot = manager.delegation_metrics_snapshot();
        if !snapshot.is_zero() {
            return snapshot;
        }
    }
    let snapshot =
        DelegationTelemetrySnapshot::from_delegation_metrics(state.delegation_metrics.as_ref());
    if !snapshot.is_zero() {
        return snapshot;
    }
    DelegationTelemetrySnapshot::from_metrics(state.metrics.as_ref())
}

fn build_delegation_response(
    metrics: DelegationTelemetrySnapshot,
    config: &crate::config::DelegationConfig,
) -> DelegationTelemetryResponse {
    let cost_micros = metrics.delegate_cost_savings_micros_total;
    let cost_usd = cost_micros as f64 / 1_000_000.0;
    let local_tokens = metrics.delegate_local_tokens_total;
    let primary_tokens = metrics.delegate_primary_tokens_total;
    let local_cost = metrics.delegate_local_cost_micros_total;
    let primary_cost = metrics.delegate_primary_cost_micros_total;
    let pricing = DelegationTelemetryPricing {
        primary_usd_per_1k_tokens: config.primary_usd_per_1k_tokens,
        local_usd_per_1k_tokens: config.local_usd_per_1k_tokens,
    };

    DelegationTelemetryResponse {
        generated_at_epoch_ms: Utc::now().timestamp_millis(),
        delegate_requests_total: metrics.delegate_requests_total,
        delegate_offloaded_total: metrics.delegate_offloaded_total,
        delegate_fallbacks_total: metrics.delegate_fallbacks_total,
        delegate_token_estimate_total: metrics.delegate_token_estimate_total,
        delegate_local_tokens_total: local_tokens,
        delegate_primary_tokens_total: primary_tokens,
        delegate_tokens_total: local_tokens.saturating_add(primary_tokens),
        delegate_token_savings_total: metrics.delegate_token_savings_total,
        delegate_local_cost_micros_total: local_cost,
        delegate_primary_cost_micros_total: primary_cost,
        delegate_cost_savings_micros_total: cost_micros,
        delegate_cost_savings_usd: cost_usd,
        pricing,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon::multi_repo::{RepoManager, RepoRuntime};
    use crate::index::{IndexConfig, Indexer};
    use crate::search::SecurityConfig;
    use http_body_util::BodyExt;
    use std::fs;
    use std::path::Path;
    use std::sync::Arc;
    use tempfile::TempDir;

    fn write_repo(repo_root: &Path, marker: &str) -> Result<(), Box<dyn std::error::Error>> {
        fs::create_dir_all(repo_root)?;
        fs::write(repo_root.join("README.md"), format!("# Repo\n\n{marker}\n"))?;
        Ok(())
    }

    fn build_test_state(
        repo_count: usize,
    ) -> Result<
        (
            AppState,
            Vec<(String, Arc<crate::metrics::DelegationMetrics>)>,
            TempDir,
        ),
        Box<dyn std::error::Error>,
    > {
        let temp = TempDir::new()?;
        let state_root = temp.path().join("state");
        fs::create_dir_all(&state_root)?;

        let manager = Arc::new(RepoManager::new(None, None));
        let mut repo_metrics = Vec::new();
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
            let repo_id = crate::repo_manager::repo_fingerprint_sha256(&repo_root)?;
            let legacy_repo_id =
                crate::repo_manager::fingerprint::legacy_repo_id_for_root(&repo_root);
            let delegation_metrics = Arc::new(crate::metrics::DelegationMetrics::default());

            if idx == 0 {
                default_indexer = Some(indexer.clone());
                default_repo_id = Some(repo_id.clone());
                default_legacy_id = Some(legacy_repo_id.clone());
                default_delegation_metrics = Some(delegation_metrics.clone());
            }

            let runtime = Arc::new(RepoRuntime {
                repo_id: repo_id.clone(),
                legacy_repo_id,
                repo_root,
                indexer,
                libs_indexer: None,
                memory: None,
                delegation_metrics: delegation_metrics.clone(),
            });
            manager.insert_repo(runtime, None);
            repo_metrics.push((repo_id, delegation_metrics));
        }

        let default_indexer = default_indexer.expect("build_test_state requires at least one repo");
        let default_repo_id = default_repo_id.expect("build_test_state requires at least one repo");
        let default_legacy_id =
            default_legacy_id.expect("build_test_state requires at least one repo");
        let default_delegation_metrics =
            default_delegation_metrics.expect("build_test_state requires at least one repo");
        manager.pin_repo(default_repo_id.clone());

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
            profile_state: None,
            features: crate::config::FeatureFlagsConfig::default(),
            default_agent_id: None,
            max_answer_tokens: 256,
            llm_config: crate::config::LlmConfig {
                base_url: "http://127.0.0.1".to_string(),
                default_model: "test".to_string(),
                ..crate::config::LlmConfig::default()
            },
            llm_base_url: "http://127.0.0.1".to_string(),
            llm_default_model: "test".to_string(),
            global_state_dir: None,
            repos: Some(manager),
            multi_repo: true,
            require_repo_id: false,
            mcp_router: None,
        };
        Ok((state, repo_metrics, temp))
    }

    #[tokio::test]
    async fn delegation_telemetry_handler_uses_selected_repo_metrics(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (state, repo_metrics, _temp) = build_test_state(2)?;
        let repo_one_metrics = repo_metrics[0].1.clone();
        let repo_two_id = repo_metrics[1].0.clone();
        let repo_two_metrics = repo_metrics[1].1.clone();

        repo_one_metrics.inc_delegate_request();
        repo_one_metrics.record_delegate_token_estimate(12);
        repo_one_metrics.record_delegate_local_tokens(11);
        repo_one_metrics.record_delegate_token_savings(11);

        repo_two_metrics.inc_delegate_request();
        repo_two_metrics.inc_delegate_request();
        repo_two_metrics.inc_delegate_offloaded();
        repo_two_metrics.record_delegate_token_estimate(40);
        repo_two_metrics.record_delegate_local_tokens(25);
        repo_two_metrics.record_delegate_primary_tokens(4);
        repo_two_metrics.record_delegate_token_savings(25);
        repo_two_metrics.record_delegate_local_cost_micros(40);
        repo_two_metrics.record_delegate_primary_cost_micros(10);
        repo_two_metrics.record_delegate_cost_savings_micros(5);

        let mut headers = HeaderMap::new();
        headers.insert(
            "x-docdex-repo-id",
            axum::http::HeaderValue::from_str(&repo_two_id)?,
        );
        let response = delegation_telemetry_handler(
            State(state),
            headers,
            Query(DelegationTelemetryQuery::default()),
        )
        .await;
        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = response.into_body().collect().await?.to_bytes();
        let payload: serde_json::Value = serde_json::from_slice(&body)?;
        assert_eq!(
            payload
                .get("delegate_requests_total")
                .and_then(|value| value.as_u64()),
            Some(2)
        );
        assert_eq!(
            payload
                .get("delegate_offloaded_total")
                .and_then(|value| value.as_u64()),
            Some(1)
        );
        assert_eq!(
            payload
                .get("delegate_token_estimate_total")
                .and_then(|value| value.as_u64()),
            Some(40)
        );
        assert_eq!(
            payload
                .get("delegate_local_tokens_total")
                .and_then(|value| value.as_u64()),
            Some(25)
        );
        assert_eq!(
            payload
                .get("delegate_primary_tokens_total")
                .and_then(|value| value.as_u64()),
            Some(4)
        );
        assert_eq!(
            payload
                .get("delegate_tokens_total")
                .and_then(|value| value.as_u64()),
            Some(29)
        );
        assert_eq!(
            payload
                .get("delegate_token_savings_total")
                .and_then(|value| value.as_u64()),
            Some(25)
        );
        assert_eq!(
            payload
                .get("delegate_local_cost_micros_total")
                .and_then(|value| value.as_u64()),
            Some(40)
        );
        assert_eq!(
            payload
                .get("delegate_primary_cost_micros_total")
                .and_then(|value| value.as_u64()),
            Some(10)
        );
        assert_eq!(
            payload
                .get("delegate_cost_savings_micros_total")
                .and_then(|value| value.as_u64()),
            Some(5)
        );
        Ok(())
    }

    #[tokio::test]
    async fn delegation_telemetry_handler_returns_aggregated_repo_metrics_for_all_flag(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (state, repo_metrics, _temp) = build_test_state(2)?;
        let repo_one_metrics = repo_metrics[0].1.clone();
        let repo_two_metrics = repo_metrics[1].1.clone();

        repo_one_metrics.inc_delegate_request();
        repo_one_metrics.record_delegate_token_estimate(12);
        repo_one_metrics.record_delegate_local_tokens(11);
        repo_one_metrics.record_delegate_token_savings(11);

        repo_two_metrics.inc_delegate_request();
        repo_two_metrics.inc_delegate_request();
        repo_two_metrics.inc_delegate_offloaded();
        repo_two_metrics.record_delegate_token_estimate(40);
        repo_two_metrics.record_delegate_local_tokens(25);
        repo_two_metrics.record_delegate_primary_tokens(4);
        repo_two_metrics.record_delegate_token_savings(25);
        repo_two_metrics.record_delegate_local_cost_micros(40);
        repo_two_metrics.record_delegate_primary_cost_micros(10);
        repo_two_metrics.record_delegate_cost_savings_micros(5);

        let response = delegation_telemetry_handler(
            State(state),
            HeaderMap::new(),
            Query(DelegationTelemetryQuery {
                repo_id: None,
                all: true,
            }),
        )
        .await;
        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = response.into_body().collect().await?.to_bytes();
        let payload: serde_json::Value = serde_json::from_slice(&body)?;
        assert_eq!(
            payload
                .get("delegate_requests_total")
                .and_then(|value| value.as_u64()),
            Some(3)
        );
        assert_eq!(
            payload
                .get("delegate_offloaded_total")
                .and_then(|value| value.as_u64()),
            Some(1)
        );
        assert_eq!(
            payload
                .get("delegate_token_estimate_total")
                .and_then(|value| value.as_u64()),
            Some(52)
        );
        assert_eq!(
            payload
                .get("delegate_local_tokens_total")
                .and_then(|value| value.as_u64()),
            Some(36)
        );
        assert_eq!(
            payload
                .get("delegate_primary_tokens_total")
                .and_then(|value| value.as_u64()),
            Some(4)
        );
        assert_eq!(
            payload
                .get("delegate_tokens_total")
                .and_then(|value| value.as_u64()),
            Some(40)
        );
        assert_eq!(
            payload
                .get("delegate_token_savings_total")
                .and_then(|value| value.as_u64()),
            Some(36)
        );
        assert_eq!(
            payload
                .get("delegate_local_cost_micros_total")
                .and_then(|value| value.as_u64()),
            Some(40)
        );
        assert_eq!(
            payload
                .get("delegate_primary_cost_micros_total")
                .and_then(|value| value.as_u64()),
            Some(10)
        );
        assert_eq!(
            payload
                .get("delegate_cost_savings_micros_total")
                .and_then(|value| value.as_u64()),
            Some(5)
        );
        Ok(())
    }

    #[tokio::test]
    async fn delegation_telemetry_handler_falls_back_to_global_metrics_for_all_flag(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (state, _repo_metrics, _temp) = build_test_state(2)?;

        state.metrics.inc_delegate_request();
        state.metrics.inc_delegate_request();
        state.metrics.inc_delegate_offloaded();
        state.metrics.record_delegate_token_estimate(20);
        state.metrics.record_delegate_local_tokens(18);
        state.metrics.record_delegate_primary_tokens(2);
        state.metrics.record_delegate_token_savings(18);
        state.metrics.record_delegate_local_cost_micros(9);
        state.metrics.record_delegate_primary_cost_micros(3);
        state.metrics.record_delegate_cost_savings_micros(6);

        let response = delegation_telemetry_handler(
            State(state),
            HeaderMap::new(),
            Query(DelegationTelemetryQuery {
                repo_id: None,
                all: true,
            }),
        )
        .await;
        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = response.into_body().collect().await?.to_bytes();
        let payload: serde_json::Value = serde_json::from_slice(&body)?;
        assert_eq!(
            payload
                .get("delegate_requests_total")
                .and_then(|value| value.as_u64()),
            Some(2)
        );
        assert_eq!(
            payload
                .get("delegate_offloaded_total")
                .and_then(|value| value.as_u64()),
            Some(1)
        );
        assert_eq!(
            payload
                .get("delegate_token_estimate_total")
                .and_then(|value| value.as_u64()),
            Some(20)
        );
        assert_eq!(
            payload
                .get("delegate_local_tokens_total")
                .and_then(|value| value.as_u64()),
            Some(18)
        );
        assert_eq!(
            payload
                .get("delegate_primary_tokens_total")
                .and_then(|value| value.as_u64()),
            Some(2)
        );
        assert_eq!(
            payload
                .get("delegate_tokens_total")
                .and_then(|value| value.as_u64()),
            Some(20)
        );
        assert_eq!(
            payload
                .get("delegate_token_savings_total")
                .and_then(|value| value.as_u64()),
            Some(18)
        );
        assert_eq!(
            payload
                .get("delegate_local_cost_micros_total")
                .and_then(|value| value.as_u64()),
            Some(9)
        );
        assert_eq!(
            payload
                .get("delegate_primary_cost_micros_total")
                .and_then(|value| value.as_u64()),
            Some(3)
        );
        assert_eq!(
            payload
                .get("delegate_cost_savings_micros_total")
                .and_then(|value| value.as_u64()),
            Some(6)
        );
        Ok(())
    }
}
