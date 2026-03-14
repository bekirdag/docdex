use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use uuid::Uuid;

use crate::delegation_telemetry;
use crate::error::{
    AppError, ERR_DELEGATION_LOCAL_REQUIRED, ERR_INTERNAL_ERROR, ERR_INVALID_ARGUMENT,
};
use crate::llm::delegation::{
    allowlist_allows, build_local_target_candidates_with_config, build_primary_target_candidates,
    compute_cost_micros, compute_delegation_savings, local_selection_policy_requires_fresh_library,
    mode_from_config, parse_local_target_override, resolve_local_cost_per_million,
    resolve_primary_cost_per_million, run_delegation_flow_with_failure_history,
    update_cached_local_selection_from_completion, DelegationEnforcementError,
    DelegationFailureHistoryContext, DelegationMode, DelegationPricingContext, LocalTarget,
    TaskType,
};
use crate::llm::local_library::resolve_local_ollama_base_url;
use crate::llm::local_library::{
    delegation_is_enabled, load_local_library, refresh_local_library,
    refresh_local_library_if_stale, refresh_local_library_if_stale_with_web,
    refresh_local_library_with_web,
};
use crate::memory::repo_state_root_from_state_dir;
use crate::orchestrator::web::{run_web_research, WebResearchResponse};
use crate::orchestrator::WebGateConfig;
use crate::search::resolve_repo_context;
use crate::search::{json_error, json_error_with_details, status_for_app_error, AppState};
use tracing::warn;

#[derive(Debug, Deserialize)]
pub struct DelegateRequest {
    task_type: String,
    instruction: String,
    context: String,
    #[serde(default)]
    agent: Option<String>,
    #[serde(default, alias = "callerAgentId")]
    caller_agent_id: Option<String>,
    #[serde(default, alias = "callerModel")]
    caller_model: Option<String>,
    #[serde(default, alias = "primaryCostPerMillion")]
    primary_cost_per_million: Option<f64>,
    #[serde(default)]
    max_tokens: Option<u32>,
    #[serde(default)]
    timeout_ms: Option<u64>,
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    repo_id: Option<String>,
    #[serde(default)]
    max_context_chars: Option<usize>,
}

#[derive(Debug, Serialize)]
pub struct DelegateResponse {
    id: String,
    adapter: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    model: Option<String>,
    output: String,
    draft: bool,
    truncated: bool,
    warnings: Vec<String>,
}

pub async fn delegate_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<DelegateRequest>,
) -> Result<Json<DelegateResponse>, axum::response::Response> {
    if payload.task_type.trim().is_empty() {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "task_type is required",
        ));
    }
    if payload.instruction.trim().is_empty() {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "instruction is required",
        ));
    }
    if payload.context.trim().is_empty() {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "context is required",
        ));
    }

    let repo = match resolve_repo_context(&state, &headers, None, payload.repo_id.as_deref(), false)
    {
        Ok(repo) => repo,
        Err(err) => return Err(crate::search::repo_error_response(err)),
    };

    let task_type = TaskType::parse(&payload.task_type).ok_or_else(|| {
        json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "task_type is invalid",
        )
    })?;

    let web_gate = WebGateConfig::from_env();
    let prefer_fresh_library = local_selection_policy_requires_fresh_library(&state.llm_config);
    let library_result = if web_gate.enabled {
        let indexer = state.indexer.clone();
        let libs_indexer = state.libs_indexer.clone();
        let request_id = Uuid::new_v4().to_string();
        let mut fetcher = move |query: String| {
            let indexer = indexer.clone();
            let libs_indexer = libs_indexer.clone();
            let web_gate = web_gate.clone();
            let request_id = request_id.clone();
            async move {
                let response = run_web_research(
                    &request_id,
                    &indexer,
                    libs_indexer.as_deref(),
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
        if prefer_fresh_library {
            refresh_local_library_with_web(
                state.global_state_dir.as_deref(),
                &state.llm_config,
                true,
                Some(&mut fetcher),
            )
            .await
        } else {
            refresh_local_library_if_stale_with_web(
                state.global_state_dir.as_deref(),
                &state.llm_config,
                true,
                Some(&mut fetcher),
            )
            .await
        }
    } else {
        if prefer_fresh_library {
            refresh_local_library(state.global_state_dir.as_deref(), &state.llm_config, true).await
        } else {
            refresh_local_library_if_stale(
                state.global_state_dir.as_deref(),
                &state.llm_config,
                true,
            )
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
            load_local_library(state.global_state_dir.as_deref()).ok()
        }
    };
    if !delegation_is_enabled(&state.llm_config.delegation, library.as_ref()) {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "delegation is disabled; enable [llm.delegation].enabled",
        ));
    }

    if !allowlist_allows(task_type, &state.llm_config.delegation.task_allowlist) {
        return Err(json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "task_type not allowed by delegation allowlist",
        ));
    }

    let mode = match payload.mode.as_deref() {
        Some(value) => DelegationMode::parse(value).ok_or_else(|| {
            json_error(
                StatusCode::BAD_REQUEST,
                ERR_INVALID_ARGUMENT,
                "mode is invalid",
            )
        })?,
        None => mode_from_config(&state.llm_config.delegation.mode),
    };

    let max_context_chars = payload
        .max_context_chars
        .filter(|value| *value > 0)
        .unwrap_or(state.llm_config.delegation.max_context_chars);

    let agent_override = payload
        .agent
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let override_target =
        agent_override.and_then(|value| parse_local_target_override(value, library.as_ref()));
    let mut local_targets: Vec<LocalTarget> = override_target.clone().into_iter().collect();
    if local_targets.is_empty() {
        if !state.llm_config.delegation.local_agent_id.trim().is_empty() {
            local_targets.clear();
        } else if let Some(library) = library.as_ref() {
            let mut library = library.clone();
            local_targets = build_local_target_candidates_with_config(
                state.global_state_dir.as_deref(),
                &state.llm_config,
                task_type,
                &mut library,
            );
        }
    }
    if local_targets.is_empty() {
        let model = state.llm_config.default_model.trim();
        if !model.is_empty() && resolve_local_ollama_base_url(&state.llm_config).is_some() {
            local_targets.push(LocalTarget::OllamaModel(model.to_string()));
        }
    }
    let primary_targets = library
        .as_ref()
        .map(|library| {
            build_primary_target_candidates(
                &state.llm_config,
                task_type,
                library,
                local_targets.first(),
            )
        })
        .unwrap_or_default();
    let local_agent_override = match (&override_target, agent_override) {
        (Some(LocalTarget::OllamaModel(model)), _) => Some(format!("model:{model}")),
        (Some(LocalTarget::McodaAgent(_)), Some(value)) => Some(value.to_string()),
        (None, Some(value)) => Some(value.to_string()),
        _ => None,
    };
    let caller_agent_id = headers
        .get("x-docdex-agent-id")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(|| {
            payload
                .caller_agent_id
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
        })
        .or_else(|| state.default_agent_id.clone());
    let caller_model = headers
        .get("x-docdex-agent-model")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(|| {
            payload
                .caller_model
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
        });
    let pricing_context = DelegationPricingContext {
        caller_agent_id,
        caller_model,
        primary_cost_per_million: payload.primary_cost_per_million,
    };
    let local_override = local_agent_override
        .as_deref()
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
        || !state.llm_config.delegation.local_agent_id.trim().is_empty();
    if state.llm_config.delegation.enforce_local && local_targets.is_empty() && !local_override {
        state.metrics.inc_delegate_local_enforced_failure();
        repo.delegation_metrics
            .inc_delegate_local_enforced_failure();
        return Err(json_error_with_details(
            StatusCode::BAD_REQUEST,
            ERR_DELEGATION_LOCAL_REQUIRED,
            "local delegation required but no local target is configured",
            serde_json::json!({
                "enforce_local": state.llm_config.delegation.enforce_local,
                "allow_fallback_to_primary": state.llm_config.delegation.allow_fallback_to_primary,
                "hint": "Configure a local agent/model or disable enforcement; set DOCDEX_DELEGATION_ALLOW_FALLBACK=1 to permit primary fallback."
            }),
        ));
    }

    let started_at = Instant::now();
    let failure_history = DelegationFailureHistoryContext {
        global_state_dir: state.global_state_dir.clone(),
        repo_id: Some(repo.repo_id.clone()),
        repo_root: Some(repo.indexer.repo_root().display().to_string()),
        source: Some("http".to_string()),
    };
    let result = run_delegation_flow_with_failure_history(
        &state.llm_config,
        local_agent_override.as_deref(),
        &local_targets,
        &primary_targets,
        task_type,
        &payload.instruction,
        &payload.context,
        max_context_chars,
        payload.max_tokens,
        payload.timeout_ms,
        mode,
        Some(failure_history),
    )
    .await
    .map_err(|err| {
        if let Some(enforcement) = err.downcast_ref::<DelegationEnforcementError>() {
            state.metrics.inc_delegate_local_enforced_failure();
            repo.delegation_metrics.inc_delegate_local_enforced_failure();
            return json_error_with_details(
                StatusCode::BAD_REQUEST,
                ERR_DELEGATION_LOCAL_REQUIRED,
                enforcement.reason.clone(),
                serde_json::json!({
                    "enforce_local": state.llm_config.delegation.enforce_local,
                    "allow_fallback_to_primary": state.llm_config.delegation.allow_fallback_to_primary,
                    "hint": "Configure a local agent/model or set DOCDEX_DELEGATION_ALLOW_FALLBACK=1 to permit primary fallback."
                }),
            );
        }
        warn!(target: "docdexd", error = ?err, "delegation completion failed");
        let app_error = AppError::new(ERR_INTERNAL_ERROR, "delegation failed");
        json_error(
            status_for_app_error(app_error.code),
            app_error.code,
            app_error.message,
        )
    })?;

    if !result.primary_used {
        if let Some(library) = library.as_mut() {
            update_cached_local_selection_from_completion(
                state.global_state_dir.as_deref(),
                &state.llm_config,
                library,
                &result.completion,
            );
        }
    }

    state.metrics.inc_delegate_request();
    repo.delegation_metrics.inc_delegate_request();
    state
        .metrics
        .record_delegate_latency(started_at.elapsed().as_millis());
    repo.delegation_metrics
        .record_delegate_latency(started_at.elapsed().as_millis());
    state
        .metrics
        .record_delegate_token_estimate(result.token_estimate);
    repo.delegation_metrics
        .record_delegate_token_estimate(result.token_estimate);
    let local_cost_per_million = resolve_local_cost_per_million(
        &state.llm_config,
        local_agent_override.as_deref(),
        local_targets.first(),
        library.as_ref(),
    );
    let primary_cost_per_million = resolve_primary_cost_per_million(
        &state.llm_config,
        Some(&pricing_context),
        primary_targets.first(),
        library.as_ref(),
    );
    let local_cost_micros = compute_cost_micros(result.local_tokens, local_cost_per_million);
    let primary_cost_micros = compute_cost_micros(result.primary_tokens, primary_cost_per_million);
    if result.local_tokens > 0 {
        state.metrics.inc_delegate_offloaded();
        repo.delegation_metrics.inc_delegate_offloaded();
    }
    state
        .metrics
        .record_delegate_local_tokens(result.local_tokens);
    repo.delegation_metrics
        .record_delegate_local_tokens(result.local_tokens);
    state
        .metrics
        .record_delegate_primary_tokens(result.primary_tokens);
    repo.delegation_metrics
        .record_delegate_primary_tokens(result.primary_tokens);
    state
        .metrics
        .record_delegate_local_cost_micros(local_cost_micros);
    repo.delegation_metrics
        .record_delegate_local_cost_micros(local_cost_micros);
    state
        .metrics
        .record_delegate_primary_cost_micros(primary_cost_micros);
    repo.delegation_metrics
        .record_delegate_primary_cost_micros(primary_cost_micros);
    let savings = compute_delegation_savings(
        result.local_tokens,
        local_cost_per_million,
        primary_cost_per_million,
    );
    state
        .metrics
        .record_delegate_token_savings(savings.token_savings);
    repo.delegation_metrics
        .record_delegate_token_savings(savings.token_savings);
    state
        .metrics
        .record_delegate_cost_savings_micros(savings.cost_savings_micros);
    repo.delegation_metrics
        .record_delegate_cost_savings_micros(savings.cost_savings_micros);
    if result.fallback_used {
        state.metrics.inc_delegate_fallback();
        repo.delegation_metrics.inc_delegate_fallback();
    }
    let repo_state_root = repo_state_root_from_state_dir(repo.indexer.state_dir());
    let telemetry_global_state_dir = delegation_telemetry::effective_global_state_dir(
        state.global_state_dir.as_deref(),
        repo.indexer.state_dir(),
    );
    delegation_telemetry::persist_metrics(
        telemetry_global_state_dir.as_deref(),
        state.metrics.as_ref(),
        Some(repo_state_root.as_path()),
        Some(repo.delegation_metrics.as_ref()),
    );

    Ok(Json(DelegateResponse {
        id: Uuid::new_v4().to_string(),
        adapter: result.completion.adapter,
        model: result.completion.model,
        output: result.completion.output,
        draft: result.draft,
        truncated: result.truncated,
        warnings: result.warnings,
    }))
}

fn format_web_text(response: &WebResearchResponse) -> String {
    let mut text = response.completion.trim().to_string();
    for hit in &response.hits {
        if !hit.summary.trim().is_empty() {
            text.push('\n');
            text.push_str(hit.summary.trim());
        }
        if !hit.snippet.trim().is_empty() {
            text.push('\n');
            text.push_str(hit.snippet.trim());
        }
    }
    text
}
