use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::Json;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use uuid::Uuid;

use crate::error::{
    AppError, ERR_DELEGATION_LOCAL_REQUIRED, ERR_INTERNAL_ERROR, ERR_INVALID_ARGUMENT,
};
use crate::llm::delegation::{
    allowlist_allows, compute_cost_micros, compute_delegation_savings, mode_from_config,
    parse_local_target_override, resolve_local_cost_per_million, resolve_primary_cost_per_million,
    run_delegation_flow, select_local_target, select_primary_target, DelegationEnforcementError,
    DelegationMode, LocalTarget, TaskType,
};
use crate::llm::local_library::{
    delegation_is_enabled, refresh_local_library_if_stale, refresh_local_library_if_stale_with_web,
};
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

    if let Err(err) =
        resolve_repo_context(&state, &headers, None, payload.repo_id.as_deref(), false)
    {
        return Err(crate::search::repo_error_response(err));
    }

    let task_type = TaskType::parse(&payload.task_type).ok_or_else(|| {
        json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "task_type is invalid",
        )
    })?;

    let web_gate = WebGateConfig::from_env();
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
        refresh_local_library_if_stale_with_web(
            state.global_state_dir.as_deref(),
            &state.llm_config,
            true,
            Some(&mut fetcher),
        )
        .await
    } else {
        refresh_local_library_if_stale(state.global_state_dir.as_deref(), &state.llm_config, true)
            .await
    };
    let library = match library_result {
        Ok(library) => Some(library),
        Err(err) => {
            warn!(
                target: "docdexd",
                error = ?err,
                "local model library refresh failed"
            );
            None
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
    let local_target = override_target.clone().or_else(|| {
        library
            .as_ref()
            .and_then(|library| select_local_target(task_type, library))
    });
    let primary_target = library
        .as_ref()
        .and_then(|library| select_primary_target(task_type, library, local_target.as_ref()));
    let local_agent_override = match (&override_target, agent_override) {
        (Some(LocalTarget::OllamaModel(model)), _) => Some(format!("model:{model}")),
        (Some(LocalTarget::McodaAgent(_)), Some(value)) => Some(value.to_string()),
        (None, Some(value)) => Some(value.to_string()),
        _ => None,
    };
    let local_override = local_agent_override
        .as_deref()
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
        || !state.llm_config.delegation.local_agent_id.trim().is_empty();
    if state.llm_config.delegation.enforce_local && local_target.is_none() && !local_override {
        state.metrics.inc_delegate_local_enforced_failure();
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
    let result = run_delegation_flow(
        &state.llm_config,
        local_agent_override.as_deref(),
        local_target.as_ref(),
        primary_target.as_ref(),
        task_type,
        &payload.instruction,
        &payload.context,
        max_context_chars,
        payload.max_tokens,
        payload.timeout_ms,
        mode,
    )
    .await
    .map_err(|err| {
        if let Some(enforcement) = err.downcast_ref::<DelegationEnforcementError>() {
            state.metrics.inc_delegate_local_enforced_failure();
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

    state.metrics.inc_delegate_request();
    state
        .metrics
        .record_delegate_latency(started_at.elapsed().as_millis());
    state
        .metrics
        .record_delegate_token_estimate(result.token_estimate);
    let local_cost_per_million = resolve_local_cost_per_million(
        &state.llm_config,
        local_agent_override.as_deref(),
        local_target.as_ref(),
        library.as_ref(),
    );
    let primary_cost_per_million = resolve_primary_cost_per_million(
        &state.llm_config,
        primary_target.as_ref(),
        library.as_ref(),
    );
    let local_cost_micros = compute_cost_micros(result.local_tokens, local_cost_per_million);
    let primary_cost_micros = compute_cost_micros(result.primary_tokens, primary_cost_per_million);
    if result.local_tokens > 0 {
        state.metrics.inc_delegate_offloaded();
    }
    state
        .metrics
        .record_delegate_local_tokens(result.local_tokens);
    state
        .metrics
        .record_delegate_primary_tokens(result.primary_tokens);
    state
        .metrics
        .record_delegate_local_cost_micros(local_cost_micros);
    state
        .metrics
        .record_delegate_primary_cost_micros(primary_cost_micros);
    let savings = compute_delegation_savings(
        result.local_tokens,
        local_cost_per_million,
        primary_cost_per_million,
    );
    state
        .metrics
        .record_delegate_token_savings(savings.token_savings);
    state
        .metrics
        .record_delegate_cost_savings_micros(savings.cost_savings_micros);
    if result.fallback_used {
        state.metrics.inc_delegate_fallback();
    }

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
