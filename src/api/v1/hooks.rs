use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;
use std::time::Instant;
use tracing::warn;

use crate::error::status_for_app_error;
use crate::error::{
    AppError, ERR_INTERNAL_ERROR, ERR_INVALID_ARGUMENT, ERR_MEMORY_DISABLED, ERR_PROFILE_DISABLED,
};
use crate::http_api::{
    json_error, repo_error_response, resolve_conversation_context, resolve_repo_context,
};
use crate::profiles::{
    check_any_type_usage, check_circular_dependencies, match_constraint_rules, ConstraintRule,
    PreferenceCategory,
};
use crate::search::AppState;

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

#[derive(Deserialize)]
pub struct ConversationHookRequest {
    pub action: crate::conversations::ConversationHookAction,
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub source_session_id: Option<String>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub transport: Option<String>,
    #[serde(default)]
    pub started_at_ms: Option<i64>,
    #[serde(default)]
    pub ended_at_ms: Option<i64>,
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default)]
    pub messages: Option<Vec<crate::api::v1::conversations::ConversationImportMessage>>,
    #[serde(default)]
    pub transcript_text: Option<String>,
    #[serde(default)]
    pub summary_text: Option<String>,
    #[serde(default)]
    pub metadata: Option<Value>,
    #[serde(default)]
    pub wait_for_processing: Option<bool>,
    #[serde(default)]
    pub repo_id: Option<String>,
    #[serde(default, alias = "namespace")]
    pub conversation_namespace: Option<String>,
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
                if let Some(app) = err.downcast_ref::<AppError>() {
                    return finalize(
                        json_error(
                            status_for_app_error(app.code),
                            app.code,
                            app.message.clone(),
                        ),
                        true,
                    );
                }
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

pub async fn conversation_hook_handler(
    State(state): State<AppState>,
    axum::extract::Extension(request_id): axum::extract::Extension<crate::search::RequestId>,
    headers: HeaderMap,
    Json(payload): Json<ConversationHookRequest>,
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
    let scope = match resolve_conversation_context(
        &state,
        &headers,
        payload.repo_id.as_deref(),
        None,
        payload.conversation_namespace.as_deref(),
        None,
        false,
    ) {
        Ok(scope) => scope,
        Err(err) => return finalize(repo_error_response(err), true),
    };
    let Some(conversations) = scope.conversations() else {
        return finalize(
            json_error(
                StatusCode::CONFLICT,
                ERR_MEMORY_DISABLED,
                "conversation memory is disabled; enable [memory.conversations].enabled",
            ),
            true,
        );
    };
    let has_messages = payload
        .messages
        .as_ref()
        .map(|items| !items.is_empty())
        .unwrap_or(false);
    let has_transcript = payload
        .transcript_text
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_some();
    let has_summary = payload
        .summary_text
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_some();
    if !has_messages && !has_transcript && !has_summary {
        return finalize(
            json_error(
                StatusCode::BAD_REQUEST,
                ERR_INVALID_ARGUMENT,
                "conversation hook requires transcript/messages or summary_text",
            ),
            true,
        );
    }
    let source = payload
        .source
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| format!("hook:{}", payload.action.as_str()));
    if !conversations.config.allows_source(&source) {
        if let Some(audit) = state.audit.as_ref() {
            audit.log(
                "conversation.hook",
                "deny",
                Some(&request_id.0),
                Some("/v1/hooks/conversation"),
                Some("POST"),
                Some(StatusCode::FORBIDDEN.as_u16()),
                None,
                Some(&format!("scope={} source={}", scope.scope_id(), source)),
            );
        }
        return finalize(
            json_error(
                StatusCode::FORBIDDEN,
                ERR_INVALID_ARGUMENT,
                "conversation source is blocked by memory.conversations source policy",
            ),
            true,
        );
    }
    let wait_for_processing = payload.wait_for_processing.unwrap_or(false);
    let hook_payload = crate::conversations::ConversationHookPayload {
        action: payload.action.clone(),
        source: Some(source.clone()),
        source_session_id: payload.source_session_id,
        title: payload.title,
        agent_id: payload.agent_id.or_else(|| state.default_agent_id.clone()),
        transport: payload.transport,
        started_at_ms: payload.started_at_ms,
        ended_at_ms: payload.ended_at_ms,
        format: payload.format,
        messages: crate::api::v1::conversations::map_import_messages(payload.messages),
        transcript_text: payload.transcript_text,
        summary_text: payload.summary_text,
        metadata: payload.metadata.unwrap_or_else(|| serde_json::json!({})),
    };
    let personal_preferences_capture = state
        .personal_preferences
        .as_ref()
        .filter(|personal_preferences| {
            crate::personal_preferences::should_capture_external_source(
                &personal_preferences.config,
                &source,
                personal_preferences.config.capture_conversation_hooks,
            )
        })
        .map(|personal_preferences| {
            (
                personal_preferences.clone(),
                build_personal_preferences_capture_request(&scope, &hook_payload),
            )
        });
    let route_targets = crate::conversations::build_conversation_route_targets(
        scope.repo_memory_target(),
        state.profile_state.as_ref().map(|profile| {
            crate::conversations::build_conversation_profile_target(
                profile.manager.clone(),
                profile.embedder.clone(),
                "conversation_hook",
            )
        }),
        conversations.knowledge.clone(),
        conversations.config.graph.clone(),
        state.default_agent_id.clone(),
    );
    let import_options = crate::conversations::ConversationImportOptions {
        capture_kind: crate::conversations::ConversationCaptureKind::Auto,
        store_raw_messages: conversations.config.archive_raw_transcripts,
    };
    let scope_label = scope.scope_label();
    let scope_id = scope.scope_id();
    match crate::conversations::enqueue_conversation_hook(
        conversations.store.clone(),
        hook_payload,
        import_options,
        route_targets,
        wait_for_processing,
    )
    .await
    {
        Ok(result) => {
            if let Some((personal_preferences, capture_request)) = personal_preferences_capture {
                if let Err(err) = personal_preferences.store.capture_conversation(
                    capture_request,
                    personal_preferences.config.digest_enabled,
                    personal_preferences.config.archive_raw_conversations,
                ) {
                    warn!(
                        target: "docdexd",
                        request_id = %request_id.0,
                        error = ?err,
                        "personal preferences capture failed for conversation hook"
                    );
                }
            }
            tracing::info!(
                target: "docdexd",
                request_id = %request_id.0,
                scope = %scope_label,
                latency_ms = started.elapsed().as_millis(),
                event_id = %result.event_id,
                status = %result.status,
                "conversation hook accepted"
            );
            if let Some(audit) = state.audit.as_ref() {
                audit.log(
                    "conversation.hook",
                    "ok",
                    Some(&request_id.0),
                    Some("/v1/hooks/conversation"),
                    Some("POST"),
                    Some(StatusCode::OK.as_u16()),
                    None,
                    Some(&format!(
                        "scope={} source={} event_id={} status={}",
                        scope_id, source, result.event_id, result.status
                    )),
                );
            }
            finalize(Json(result).into_response(), false)
        }
        Err(err) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                request_id = %request_id.0,
                error = ?err,
                "conversation hook failed"
            );
            if let Some(audit) = state.audit.as_ref() {
                audit.log(
                    "conversation.hook",
                    "error",
                    Some(&request_id.0),
                    Some("/v1/hooks/conversation"),
                    Some("POST"),
                    Some(StatusCode::INTERNAL_SERVER_ERROR.as_u16()),
                    None,
                    Some(&format!(
                        "scope={} source={} error={}",
                        scope_id, source, err
                    )),
                );
            }
            finalize(
                json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ERR_INTERNAL_ERROR,
                    "conversation hook failed",
                ),
                true,
            )
        }
    }
}

fn build_personal_preferences_capture_request(
    scope: &crate::search::ConversationRequestContext,
    payload: &crate::conversations::ConversationHookPayload,
) -> crate::personal_preferences::PersonalPreferencesCaptureRequest {
    let (repo_id, repo_root) = scope
        .repo()
        .map(|repo| {
            (
                Some(repo.repo_id.clone()),
                Some(repo.indexer.repo_root().display().to_string()),
            )
        })
        .unwrap_or((None, None));
    crate::personal_preferences::PersonalPreferencesCaptureRequest {
        source: payload
            .source
            .clone()
            .unwrap_or_else(|| format!("hook:{}", payload.action.as_str())),
        source_session_id: payload.source_session_id.clone(),
        capture_kind: Some("conversation_hook".to_string()),
        title: payload.title.clone(),
        agent_id: payload.agent_id.clone(),
        transport: payload.transport.clone(),
        repo_id,
        repo_root,
        scope_id: Some(scope.scope_id()),
        scope_label: Some(scope.scope_label()),
        started_at_ms: payload.started_at_ms,
        ended_at_ms: payload.ended_at_ms,
        messages: payload
            .messages
            .clone()
            .unwrap_or_default()
            .into_iter()
            .map(
                |message| crate::personal_preferences::PersonalPreferencesMessage {
                    role: message.role.as_str().to_string(),
                    content: message.content,
                    created_at_ms: message.created_at_ms,
                    metadata: message.metadata,
                },
            )
            .collect(),
        transcript_text: payload.transcript_text.clone(),
        summary_text: payload.summary_text.clone(),
        metadata: serde_json::json!({
            "hook_action": payload.action.as_str(),
            "scope_id": scope.scope_id(),
            "scope_label": scope.scope_label(),
            "format": payload.format,
            "metadata": payload.metadata,
        }),
    }
}
