use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::Instant;
use tracing::warn;

use crate::error::{ERR_INTERNAL_ERROR, ERR_PROFILE_DISABLED};
use crate::profiles::{
    check_any_type_usage, check_circular_dependencies, match_constraint_rules, ConstraintRule,
    PreferenceCategory,
};
use crate::search::{json_error, repo_error_response, resolve_repo_context, AppState};

#[derive(Deserialize)]
pub struct HookValidateRequest {
    pub files: Vec<String>,
}

#[derive(Serialize)]
pub struct HookValidateResponse {
    pub status: &'static str,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<HookViolation>,
}

#[derive(Serialize)]
pub struct HookViolation {
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
}

pub async fn hook_validate_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<HookValidateRequest>,
) -> Response {
    let started = Instant::now();
    let metrics = state.metrics.clone();
    metrics.inc_hook_check();
    let finalize = |response: Response, failed: bool| {
        if failed {
            metrics.inc_hook_failure();
        }
        metrics.record_hook_latency(started.elapsed().as_millis());
        response
    };
    if !state.features.hooks {
        return finalize(
            Json(HookValidateResponse {
                status: "pass",
                errors: Vec::new(),
            })
            .into_response(),
            false,
        );
    }
    let repo = match resolve_repo_context(&state, &headers, None, None, true) {
        Ok(repo) => repo,
        Err(err) => return finalize(repo_error_response(err), true),
    };

    let Some(profile_state) = state.profile_state.as_ref() else {
        return finalize(
            json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                ERR_PROFILE_DISABLED,
                "profile memory disabled",
            ),
            true,
        );
    };

    let files: Vec<String> = payload
        .files
        .into_iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect();
    if files.is_empty() {
        return finalize(
            Json(HookValidateResponse {
                status: "pass",
                errors: Vec::new(),
            })
            .into_response(),
            false,
        );
    }

    let preferences = match profile_state.manager.list_preferences(None) {
        Ok(prefs) => prefs,
        Err(err) => {
            state.metrics.inc_error();
            warn!(target: "docdexd", error = ?err, "hook validate failed to load preferences");
            return finalize(
                json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ERR_INTERNAL_ERROR,
                    "hook validate failed",
                ),
                true,
            );
        }
    };

    let mut rules: HashSet<ConstraintRule> = HashSet::new();
    for preference in preferences {
        if preference.category != PreferenceCategory::Constraint {
            continue;
        }
        for rule in match_constraint_rules(&preference.content) {
            rules.insert(rule);
        }
    }

    let mut violations = Vec::new();
    if rules.contains(&ConstraintRule::NoAnyTypes) {
        match check_any_type_usage(repo.indexer.as_ref(), &files) {
            Ok(found) => violations.extend(found),
            Err(err) => {
                state.metrics.inc_error();
                warn!(target: "docdexd", error = ?err, "hook validate any check failed");
                return finalize(
                    json_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        ERR_INTERNAL_ERROR,
                        "hook validate failed",
                    ),
                    true,
                );
            }
        }
    }

    if rules.contains(&ConstraintRule::NoCircularDependencies) {
        let store = crate::impact::ImpactGraphStore::new(repo.indexer.state_dir());
        match store.read_edges() {
            Ok(edges) => {
                violations.extend(check_circular_dependencies(&edges, &files));
            }
            Err(err) => {
                state.metrics.inc_error();
                warn!(target: "docdexd", error = ?err, "hook validate cycle check failed");
                return finalize(
                    json_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        ERR_INTERNAL_ERROR,
                        "hook validate failed",
                    ),
                    true,
                );
            }
        }
    }

    let errors = violations
        .into_iter()
        .map(|violation| HookViolation {
            message: violation.message,
            file: violation.file,
            line: violation.line,
        })
        .collect::<Vec<_>>();

    let status = if errors.is_empty() { "pass" } else { "fail" };
    finalize(
        Json(HookValidateResponse { status, errors }).into_response(),
        status == "fail",
    )
}
