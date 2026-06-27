use axum::{
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Deserialize;
use serde_json::json;
use tracing::warn;

use crate::error::ERR_INTERNAL_ERROR;
use crate::http_api::json_error_with_details;
use crate::llm::local_library::{
    load_local_library, local_library_diagnostics, refresh_local_library_if_stale,
};
use crate::search::AppState;

#[derive(Debug, Default, Deserialize)]
pub struct LlmDiagnosticsParams {
    #[serde(default)]
    refresh: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
pub struct LlmDiagnosticsRequest {
    #[serde(default)]
    refresh: Option<bool>,
}

pub async fn llm_diagnostics_handler(
    State(state): State<AppState>,
    Query(params): Query<LlmDiagnosticsParams>,
) -> Response {
    build_llm_diagnostics_response(&state, params.refresh.unwrap_or(true)).await
}

pub async fn llm_diagnostics_post_handler(
    State(state): State<AppState>,
    Json(payload): Json<LlmDiagnosticsRequest>,
) -> Response {
    build_llm_diagnostics_response(&state, payload.refresh.unwrap_or(true)).await
}

async fn build_llm_diagnostics_response(state: &AppState, refresh: bool) -> Response {
    let library = if refresh {
        match refresh_local_library_if_stale(
            state.global_state_dir.as_deref(),
            &state.llm_config,
            false,
        )
        .await
        {
            Ok(library) => library,
            Err(err) => {
                warn!(
                    target: "docdexd",
                    error = ?err,
                    "local model library diagnostics refresh failed"
                );
                match load_local_library(state.global_state_dir.as_deref()) {
                    Ok(library) => library,
                    Err(load_err) => {
                        return json_error_with_details(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            ERR_INTERNAL_ERROR,
                            "failed to load local model library diagnostics",
                            json!({
                                "refresh_error": err.to_string(),
                                "load_error": load_err.to_string()
                            }),
                        );
                    }
                }
            }
        }
    } else {
        match load_local_library(state.global_state_dir.as_deref()) {
            Ok(library) => library,
            Err(err) => {
                return json_error_with_details(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ERR_INTERNAL_ERROR,
                    "failed to load local model library diagnostics",
                    json!({ "error": err.to_string() }),
                );
            }
        }
    };

    let diagnostics = local_library_diagnostics(&library, &state.llm_config);
    Json(json!({ "diagnostics": diagnostics })).into_response()
}
