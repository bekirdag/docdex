use axum::{extract::State, response::IntoResponse, Json};
use chrono::Utc;
use serde::Serialize;

use crate::search::AppState;

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

pub async fn delegation_telemetry_handler(State(state): State<AppState>) -> impl IntoResponse {
    let metrics = &state.metrics;
    let cost_micros = metrics.delegate_cost_savings_micros_total();
    let cost_usd = cost_micros as f64 / 1_000_000.0;
    let local_tokens = metrics.delegate_local_tokens_total();
    let primary_tokens = metrics.delegate_primary_tokens_total();
    let local_cost = metrics.delegate_local_cost_micros_total();
    let primary_cost = metrics.delegate_primary_cost_micros_total();
    let pricing = DelegationTelemetryPricing {
        primary_usd_per_1k_tokens: state.llm_config.delegation.primary_usd_per_1k_tokens,
        local_usd_per_1k_tokens: state.llm_config.delegation.local_usd_per_1k_tokens,
    };

    Json(DelegationTelemetryResponse {
        generated_at_epoch_ms: Utc::now().timestamp_millis(),
        delegate_requests_total: metrics.delegate_requests_total(),
        delegate_offloaded_total: metrics.delegate_offloaded_total(),
        delegate_fallbacks_total: metrics.delegate_fallbacks_total(),
        delegate_token_estimate_total: metrics.delegate_token_estimate_total(),
        delegate_local_tokens_total: local_tokens,
        delegate_primary_tokens_total: primary_tokens,
        delegate_tokens_total: local_tokens.saturating_add(primary_tokens),
        delegate_token_savings_total: metrics.delegate_token_savings_total(),
        delegate_local_cost_micros_total: local_cost,
        delegate_primary_cost_micros_total: primary_cost,
        delegate_cost_savings_micros_total: cost_micros,
        delegate_cost_savings_usd: cost_usd,
        pricing,
    })
}
