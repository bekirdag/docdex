use axum::{
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

use crate::error::{
    status_for_app_error, AppError, RateLimited, ERR_INTERNAL_ERROR, ERR_INVALID_ARGUMENT,
    ERR_MISSING_REPO, ERR_UNKNOWN_REPO,
};
use crate::search::{
    AppState, ConversationNamespaceContext, ConversationRequestContext, ConversationState,
    RepoContext,
};

pub(crate) const MAX_RATE_LIMIT_MESSAGE_BYTES: usize = 256;
pub(crate) const REPO_ID_HEADER: &str = "x-docdex-repo-id";
pub(crate) const CONVERSATION_NAMESPACE_HEADER: &str = "x-docdex-conversation-namespace";

#[derive(Serialize)]
pub(crate) struct ErrorBody {
    pub(crate) error: ErrorDetail,
}

#[derive(Serialize)]
pub(crate) struct ErrorDetail {
    code: &'static str,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_after_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    limit_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    limit_per_min: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    limit_burst: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    denied_total: Option<u64>,
}

impl ErrorDetail {
    pub(crate) fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            details: None,
            retry_after_ms: None,
            retry_at: None,
            limit_key: None,
            scope: None,
            resource_key: None,
            limit_per_min: None,
            limit_burst: None,
            denied_total: None,
        }
    }

    pub(crate) fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }

    pub(crate) fn rate_limited(err: &RateLimited) -> Self {
        Self {
            code: crate::error::ERR_RATE_LIMITED,
            message: truncate_bytes(&err.message, MAX_RATE_LIMIT_MESSAGE_BYTES),
            details: None,
            retry_after_ms: Some(err.retry_after_ms),
            retry_at: err.retry_at.as_ref().map(|at| at.to_rfc3339()),
            limit_key: Some(err.limit_key.clone()),
            scope: Some(err.scope.clone()),
            resource_key: None,
            limit_per_min: None,
            limit_burst: None,
            denied_total: None,
        }
    }

    pub(crate) fn rate_limited_with_context(
        err: &RateLimited,
        resource_key: Option<String>,
        limit_per_min: Option<u32>,
        limit_burst: Option<u32>,
        denied_total: Option<u64>,
    ) -> Self {
        let mut detail = Self::rate_limited(err);
        detail.resource_key = resource_key;
        detail.limit_per_min = limit_per_min;
        detail.limit_burst = limit_burst;
        detail.denied_total = denied_total;
        detail
    }
}

fn truncate_bytes(input: &str, max_bytes: usize) -> String {
    if input.len() <= max_bytes {
        return input.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !input.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = input[..end].to_string();
    out.push_str("…");
    out
}

pub(crate) fn json_error(
    status: StatusCode,
    code: &'static str,
    message: impl Into<String>,
) -> Response {
    (
        status,
        Json(ErrorBody {
            error: ErrorDetail::new(code, message),
        }),
    )
        .into_response()
}

pub(crate) fn json_error_with_details(
    status: StatusCode,
    code: &'static str,
    message: impl Into<String>,
    details: serde_json::Value,
) -> Response {
    (
        status,
        Json(ErrorBody {
            error: ErrorDetail::new(code, message).with_details(details),
        }),
    )
        .into_response()
}

pub(crate) fn app_error_response(err: &AppError) -> Response {
    match err.details.clone() {
        Some(details) => json_error_with_details(
            status_for_app_error(err.code),
            err.code,
            err.message.clone(),
            details,
        ),
        None => json_error(
            status_for_app_error(err.code),
            err.code,
            err.message.clone(),
        ),
    }
}

pub(crate) struct RepoIdError {
    pub(crate) status: StatusCode,
    pub(crate) code: &'static str,
    pub(crate) message: String,
    pub(crate) details: Option<serde_json::Value>,
}

pub(crate) fn repo_error_response(err: RepoIdError) -> Response {
    match err.details {
        Some(details) => json_error_with_details(err.status, err.code, err.message, details),
        None => json_error(err.status, err.code, err.message),
    }
}

fn touch_default_repo(state: &AppState) {
    if let Some(manager) = state.repos.as_ref() {
        let _ = manager.get_by_id(&state.repo_id);
    }
}

pub(crate) fn resolve_repo_context(
    state: &AppState,
    headers: &HeaderMap,
    query_repo_id: Option<&str>,
    body_repo_id: Option<&str>,
    require: bool,
) -> Result<RepoContext, RepoIdError> {
    let repo_count = if state.multi_repo {
        state
            .repos
            .as_ref()
            .map(|manager| manager.repo_count())
            .unwrap_or(0)
    } else {
        0
    };
    let explicit_required = state.multi_repo && repo_count > 1;
    let selected = parse_repo_id(
        headers,
        query_repo_id,
        body_repo_id,
        require || state.require_repo_id,
    )?;
    let default_repo = RepoContext {
        repo_id: state.repo_id.clone(),
        legacy_repo_id: state.legacy_repo_id.clone(),
        indexer: state.indexer.clone(),
        libs_indexer: state.libs_indexer.clone(),
        memory: state.memory.clone(),
        conversations: state.conversations.clone(),
        delegation_metrics: state.delegation_metrics.clone(),
    };
    let Some(candidate) = selected else {
        if explicit_required {
            return Err(RepoIdError {
                status: StatusCode::BAD_REQUEST,
                code: ERR_MISSING_REPO,
                message: "repo_id is required when multiple repos are mounted".to_string(),
                details: Some(serde_json::json!({
                    "repoCount": repo_count,
                    "header": REPO_ID_HEADER,
                    "queryParam": "repo_id",
                    "hint": "Send x-docdex-repo-id or repo_id, or call /v1/initialize for the target repo."
                })),
            });
        }
        if state.multi_repo {
            touch_default_repo(state);
        }
        return Ok(default_repo);
    };
    if default_repo.matches_id(&candidate) {
        if state.multi_repo {
            touch_default_repo(state);
        }
        return Ok(default_repo);
    }
    if !state.multi_repo {
        return Err(RepoIdError {
            status: StatusCode::NOT_FOUND,
            code: ERR_UNKNOWN_REPO,
            message: "unknown repo".to_string(),
            details: None,
        });
    }
    let Some(manager) = state.repos.as_ref() else {
        return Err(RepoIdError {
            status: StatusCode::NOT_FOUND,
            code: ERR_UNKNOWN_REPO,
            message: "unknown repo".to_string(),
            details: None,
        });
    };
    if let Some(repo) = manager.get_by_id(&candidate) {
        return Ok(RepoContext {
            repo_id: repo.repo_id.clone(),
            legacy_repo_id: repo.legacy_repo_id.clone(),
            indexer: repo.indexer.clone(),
            libs_indexer: repo.libs_indexer.clone(),
            memory: repo.memory.clone(),
            conversations: repo.conversations.clone(),
            delegation_metrics: repo.delegation_metrics.clone(),
        });
    }
    Err(RepoIdError {
        status: StatusCode::NOT_FOUND,
        code: ERR_UNKNOWN_REPO,
        message: "unknown repo".to_string(),
        details: None,
    })
}

pub(crate) fn resolve_conversation_context(
    state: &AppState,
    headers: &HeaderMap,
    query_repo_id: Option<&str>,
    body_repo_id: Option<&str>,
    query_namespace: Option<&str>,
    body_namespace: Option<&str>,
    require_repo: bool,
) -> Result<ConversationRequestContext, RepoIdError> {
    let selected_repo = parse_repo_id(headers, query_repo_id, body_repo_id, false)?;
    let selected_namespace =
        parse_conversation_namespace(headers, query_namespace, body_namespace)?;
    if let (Some(repo_id), Some(namespace)) =
        (selected_repo.as_deref(), selected_namespace.as_deref())
    {
        return Err(RepoIdError {
            status: StatusCode::BAD_REQUEST,
            code: ERR_INVALID_ARGUMENT,
            message: "repo_id and conversation_namespace are mutually exclusive; choose one scope"
                .to_string(),
            details: Some(serde_json::json!({
                "repo_id": repo_id,
                "conversation_namespace": namespace,
                "headerRepoId": REPO_ID_HEADER,
                "headerConversationNamespace": CONVERSATION_NAMESPACE_HEADER,
            })),
        });
    }
    if let Some(namespace) = selected_namespace {
        return Ok(ConversationRequestContext::Namespace(
            ConversationNamespaceContext {
                namespace: namespace.clone(),
                conversations: build_namespace_conversation_state(state, &namespace)?,
            },
        ));
    }
    resolve_repo_context(state, headers, query_repo_id, body_repo_id, require_repo)
        .map(ConversationRequestContext::Repo)
}

fn parse_repo_id(
    headers: &HeaderMap,
    query_repo_id: Option<&str>,
    body_repo_id: Option<&str>,
    require: bool,
) -> Result<Option<String>, RepoIdError> {
    let mut selected: Option<String> = None;
    if let Some(value) = headers.get(REPO_ID_HEADER) {
        let header_value = value.to_str().map_err(|_| RepoIdError {
            status: StatusCode::BAD_REQUEST,
            code: ERR_INVALID_ARGUMENT,
            message: format!("{REPO_ID_HEADER} must be valid UTF-8"),
            details: None,
        })?;
        let trimmed = header_value.trim();
        if trimmed.is_empty() {
            return Err(RepoIdError {
                status: StatusCode::BAD_REQUEST,
                code: ERR_INVALID_ARGUMENT,
                message: format!("{REPO_ID_HEADER} must not be empty"),
                details: None,
            });
        }
        selected = Some(trimmed.to_string());
    }

    for value in [query_repo_id, body_repo_id] {
        let Some(raw) = value else {
            continue;
        };
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(RepoIdError {
                status: StatusCode::BAD_REQUEST,
                code: ERR_INVALID_ARGUMENT,
                message: "repo_id must not be empty".to_string(),
                details: None,
            });
        }
        match selected.as_deref() {
            None => selected = Some(trimmed.to_string()),
            Some(existing) if existing != trimmed => {
                return Err(RepoIdError {
                    status: StatusCode::BAD_REQUEST,
                    code: ERR_INVALID_ARGUMENT,
                    message: "repo_id values must match across header, query, and body".to_string(),
                    details: None,
                });
            }
            _ => {}
        }
    }

    let Some(candidate) = selected else {
        return if require {
            Err(RepoIdError {
                status: StatusCode::BAD_REQUEST,
                code: ERR_MISSING_REPO,
                message: "repo_id is required".to_string(),
                details: None,
            })
        } else {
            Ok(None)
        };
    };
    Ok(Some(candidate))
}

fn parse_conversation_namespace(
    headers: &HeaderMap,
    query_namespace: Option<&str>,
    body_namespace: Option<&str>,
) -> Result<Option<String>, RepoIdError> {
    let mut selected: Option<String> = None;
    if let Some(value) = headers.get(CONVERSATION_NAMESPACE_HEADER) {
        let header_value = value.to_str().map_err(|_| RepoIdError {
            status: StatusCode::BAD_REQUEST,
            code: ERR_INVALID_ARGUMENT,
            message: format!("{CONVERSATION_NAMESPACE_HEADER} must be valid UTF-8"),
            details: None,
        })?;
        let trimmed = header_value.trim();
        if trimmed.is_empty() {
            return Err(RepoIdError {
                status: StatusCode::BAD_REQUEST,
                code: ERR_INVALID_ARGUMENT,
                message: format!("{CONVERSATION_NAMESPACE_HEADER} must not be empty"),
                details: None,
            });
        }
        selected = Some(trimmed.to_string());
    }

    for value in [query_namespace, body_namespace] {
        let Some(raw) = value else {
            continue;
        };
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(RepoIdError {
                status: StatusCode::BAD_REQUEST,
                code: ERR_INVALID_ARGUMENT,
                message: "conversation_namespace must not be empty".to_string(),
                details: None,
            });
        }
        match selected.as_deref() {
            None => selected = Some(trimmed.to_string()),
            Some(existing) if existing != trimmed => {
                return Err(RepoIdError {
                    status: StatusCode::BAD_REQUEST,
                    code: ERR_INVALID_ARGUMENT,
                    message:
                        "conversation_namespace values must match across header, query, and body"
                            .to_string(),
                    details: None,
                });
            }
            _ => {}
        }
    }

    Ok(selected)
}

fn build_namespace_conversation_state(
    state: &AppState,
    namespace: &str,
) -> Result<Option<ConversationState>, RepoIdError> {
    let trimmed = namespace.trim();
    if trimmed.is_empty() {
        return Err(RepoIdError {
            status: StatusCode::BAD_REQUEST,
            code: ERR_INVALID_ARGUMENT,
            message: "conversation_namespace must not be empty".to_string(),
            details: None,
        });
    }
    let Some(template) = state.conversations.as_ref() else {
        return Ok(None);
    };
    let base_state_dir = state
        .global_state_dir
        .clone()
        .or_else(|| {
            crate::repo_manager::split_scoped_state_dir(state.indexer.state_dir())
                .map(|(base_dir, _, _)| base_dir)
        })
        .ok_or_else(|| RepoIdError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: ERR_INTERNAL_ERROR,
            message: "conversation namespace requires a shared global state directory".to_string(),
            details: Some(serde_json::json!({
                "conversation_namespace": trimmed,
                "hint": "Start the daemon with a shared global state dir so repo-less conversation namespaces have an isolated home."
            })),
        })?;
    let config = template.config.clone();
    Ok(Some(ConversationState {
        store: crate::conversations::ConversationStore::for_namespace(&base_state_dir, trimmed),
        knowledge: crate::knowledge::KnowledgeStore::for_namespace(&base_state_dir, trimmed),
        max_wakeup_tokens: config.max_wakeup_tokens,
        max_episodic_summaries: config.max_episodic_summaries,
        max_knowledge_facts: config.max_knowledge_facts,
        max_transcript_snippets: config.max_transcript_snippets,
        config,
    }))
}
