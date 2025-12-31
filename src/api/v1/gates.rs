use axum::{extract::State, response::IntoResponse, response::Json};
use chrono::Utc;
use serde::Serialize;

use crate::search::AppState;

const ERROR_RATE_THRESHOLD: f64 = 0.005;
const HTTP_P95_THRESHOLD_MS: u64 = 50;

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum GateStatus {
    Pass,
    Fail,
    Unknown,
}

#[derive(Serialize)]
struct GateCheck {
    status: GateStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    threshold: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    unit: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<String>,
}

#[derive(Serialize)]
struct GatesSummary {
    error_rate: GateCheck,
    latency_p95_ms: GateCheck,
    soak: GateCheck,
}

#[derive(Serialize)]
struct GatesStatusResponse {
    generated_at: String,
    http_requests_total: u64,
    http_errors_total: u64,
    http_latency_avg_ms: Option<f64>,
    http_latency_p95_ms: Option<u64>,
    gates: GatesSummary,
}

fn error_rate_gate(total: u64, errors: u64) -> GateCheck {
    if total == 0 {
        return GateCheck {
            status: GateStatus::Unknown,
            value: None,
            threshold: Some(ERROR_RATE_THRESHOLD),
            unit: Some("ratio"),
            note: Some("no HTTP samples yet".to_string()),
        };
    }
    let value = errors as f64 / total as f64;
    let status = if value <= ERROR_RATE_THRESHOLD {
        GateStatus::Pass
    } else {
        GateStatus::Fail
    };
    GateCheck {
        status,
        value: Some(value),
        threshold: Some(ERROR_RATE_THRESHOLD),
        unit: Some("ratio"),
        note: None,
    }
}

fn latency_gate(p95_ms: Option<u64>) -> GateCheck {
    match p95_ms {
        None => GateCheck {
            status: GateStatus::Unknown,
            value: None,
            threshold: Some(HTTP_P95_THRESHOLD_MS as f64),
            unit: Some("ms"),
            note: Some("no latency samples yet".to_string()),
        },
        Some(value) => {
            let status = if value <= HTTP_P95_THRESHOLD_MS {
                GateStatus::Pass
            } else {
                GateStatus::Fail
            };
            GateCheck {
                status,
                value: Some(value as f64),
                threshold: Some(HTTP_P95_THRESHOLD_MS as f64),
                unit: Some("ms"),
                note: None,
            }
        }
    }
}

fn soak_gate() -> GateCheck {
    GateCheck {
        status: GateStatus::Unknown,
        value: None,
        threshold: None,
        unit: None,
        note: Some(
            "run scripts/load_test_http.sh and scripts/load_test_mcp.sh for soak validation"
                .to_string(),
        ),
    }
}

pub async fn gates_status_handler(State(state): State<AppState>) -> impl IntoResponse {
    let total = state.metrics.http_requests_total();
    let errors = state.metrics.http_error_responses_total();
    let http_latency_avg_ms = state.metrics.http_latency_avg_ms();
    let http_latency_p95_ms = state.metrics.http_latency_p95_ms();

    Json(GatesStatusResponse {
        generated_at: Utc::now().to_rfc3339(),
        http_requests_total: total,
        http_errors_total: errors,
        http_latency_avg_ms,
        http_latency_p95_ms,
        gates: GatesSummary {
            error_rate: error_rate_gate(total, errors),
            latency_p95_ms: latency_gate(http_latency_p95_ms),
            soak: soak_gate(),
        },
    })
}
