use std::error::Error;
use std::fmt;
use std::time::Duration;

use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use serde_json::Value;
use thiserror::Error;

pub const ERR_EMBEDDING_TIMEOUT: &str = "embedding_timeout";
pub const ERR_EMBEDDING_MODEL_NOT_FOUND: &str = "embedding_model_not_found";
pub const ERR_EMBEDDING_FAILED: &str = "embedding_failed";
pub const ERR_MEMORY_DISABLED: &str = "memory_disabled";
pub const ERR_PROFILE_DISABLED: &str = "profile_disabled";
pub const ERR_CONVERSATION_NOT_FOUND: &str = "conversation_not_found";
pub const ERR_KNOWLEDGE_EPISODE_NOT_FOUND: &str = "knowledge_episode_not_found";
pub const ERR_INVALID_ARGUMENT: &str = "invalid_argument";
pub const ERR_MISSING_REPO: &str = "missing_repo";
pub const ERR_MISSING_REPO_PATH: &str = "missing_repo_path";
pub const ERR_UNKNOWN_REPO: &str = "unknown_repo";
pub const ERR_MISSING_INDEX: &str = "missing_index";
pub const ERR_STALE_INDEX: &str = "stale_index";
pub const ERR_INDEXING_IN_PROGRESS: &str = "indexing_in_progress";
pub const ERR_MISSING_DEPENDENCY: &str = "missing_dependency";
pub const ERR_RATE_LIMITED: &str = "rate_limited";
pub const ERR_BACKOFF_REQUIRED: &str = "backoff_required";
pub const ERR_REPO_STATE_MISMATCH: &str = "repo_state_mismatch";
pub const ERR_UNAUTHORIZED: &str = "unauthorized";
pub const ERR_DELEGATION_LOCAL_REQUIRED: &str = "delegation_local_required";
pub const ERR_INTERNAL_ERROR: &str = "internal_error";

#[derive(Debug, Clone)]
pub struct StartupError {
    pub code: &'static str,
    pub message: String,
    pub hint: Option<String>,
    pub remediation: Option<Vec<String>>,
}

impl StartupError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            hint: None,
            remediation: None,
        }
    }

    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    pub fn with_remediation(mut self, steps: Vec<String>) -> Self {
        if !steps.is_empty() {
            self.remediation = Some(steps);
        }
        self
    }
}

impl fmt::Display for StartupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl Error for StartupError {}

#[derive(Debug, Clone, Error)]
#[error("{message}")]
pub struct AppError {
    pub code: &'static str,
    pub message: String,
    pub details: Option<Value>,
}

impl AppError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            details: None,
        }
    }

    pub fn with_details(mut self, details: Value) -> Self {
        self.details = Some(details);
        self
    }
}

pub fn status_for_app_error(code: &str) -> StatusCode {
    match code {
        ERR_EMBEDDING_TIMEOUT => StatusCode::GATEWAY_TIMEOUT,
        ERR_EMBEDDING_MODEL_NOT_FOUND => StatusCode::BAD_REQUEST,
        ERR_EMBEDDING_FAILED => StatusCode::BAD_GATEWAY,
        ERR_INVALID_ARGUMENT => StatusCode::BAD_REQUEST,
        ERR_MISSING_REPO => StatusCode::BAD_REQUEST,
        ERR_MEMORY_DISABLED => StatusCode::CONFLICT,
        ERR_PROFILE_DISABLED => StatusCode::CONFLICT,
        ERR_CONVERSATION_NOT_FOUND => StatusCode::NOT_FOUND,
        ERR_KNOWLEDGE_EPISODE_NOT_FOUND => StatusCode::NOT_FOUND,
        ERR_MISSING_DEPENDENCY => StatusCode::CONFLICT,
        ERR_MISSING_INDEX => StatusCode::CONFLICT,
        ERR_STALE_INDEX => StatusCode::CONFLICT,
        ERR_INDEXING_IN_PROGRESS => StatusCode::ACCEPTED,
        ERR_REPO_STATE_MISMATCH => StatusCode::CONFLICT,
        ERR_MISSING_REPO_PATH => StatusCode::NOT_FOUND,
        ERR_UNKNOWN_REPO => StatusCode::NOT_FOUND,
        ERR_UNAUTHORIZED => StatusCode::UNAUTHORIZED,
        ERR_RATE_LIMITED => StatusCode::TOO_MANY_REQUESTS,
        ERR_BACKOFF_REQUIRED => StatusCode::TOO_MANY_REQUESTS,
        ERR_DELEGATION_LOCAL_REQUIRED => StatusCode::CONFLICT,
        ERR_INTERNAL_ERROR => StatusCode::INTERNAL_SERVER_ERROR,
        _ => {
            debug_assert!(
                false,
                "unmapped app error code `{code}` defaulted to 500; add it to status_for_app_error"
            );
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

pub fn repo_resolution_details(
    normalized_path: String,
    attempted_fingerprint: Option<String>,
    known_canonical_path: Option<String>,
    recovery_steps: Vec<String>,
) -> Value {
    let mut details = serde_json::Map::new();
    details.insert("normalizedPath".to_string(), Value::String(normalized_path));
    if let Some(fp) = attempted_fingerprint {
        details.insert("attemptedFingerprint".to_string(), Value::String(fp));
    }
    if let Some(path) = known_canonical_path {
        details.insert("knownCanonicalPath".to_string(), Value::String(path));
    }
    details.insert(
        "recoverySteps".to_string(),
        Value::Array(recovery_steps.into_iter().map(Value::String).collect()),
    );
    Value::Object(details)
}

#[derive(Debug, Clone, Error)]
#[error("{message}")]
pub struct RateLimited {
    pub code: &'static str,
    pub message: String,
    pub retry_after_ms: u64,
    pub retry_at: Option<DateTime<Utc>>,
    pub limit_key: String,
    pub scope: String,
}

impl RateLimited {
    pub fn new(retry_after: Duration, limit_key: String, scope: String) -> Self {
        let retry_after_ms = retry_after.as_millis().min(u128::from(u64::MAX)) as u64;
        Self {
            code: ERR_RATE_LIMITED,
            message: "rate limited".to_string(),
            retry_after_ms,
            retry_at: None,
            limit_key,
            scope,
        }
    }

    #[allow(dead_code)]
    pub fn with_message(mut self, message: impl Into<String>) -> Self {
        self.message = message.into();
        self
    }

    #[allow(dead_code)]
    pub fn with_retry_at(mut self, retry_at: DateTime<Utc>) -> Self {
        self.retry_at = Some(retry_at);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_mapping_covers_expected_http_contracts() {
        assert_eq!(
            status_for_app_error(ERR_INVALID_ARGUMENT),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            status_for_app_error(ERR_MISSING_REPO),
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            status_for_app_error(ERR_MISSING_REPO_PATH),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            status_for_app_error(ERR_UNKNOWN_REPO),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            status_for_app_error(ERR_MEMORY_DISABLED),
            StatusCode::CONFLICT
        );
        assert_eq!(
            status_for_app_error(ERR_PROFILE_DISABLED),
            StatusCode::CONFLICT
        );
        assert_eq!(
            status_for_app_error(ERR_CONVERSATION_NOT_FOUND),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            status_for_app_error(ERR_KNOWLEDGE_EPISODE_NOT_FOUND),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            status_for_app_error(ERR_INDEXING_IN_PROGRESS),
            StatusCode::ACCEPTED
        );
        assert_eq!(
            status_for_app_error(ERR_RATE_LIMITED),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            status_for_app_error(ERR_BACKOFF_REQUIRED),
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(
            status_for_app_error(ERR_DELEGATION_LOCAL_REQUIRED),
            StatusCode::CONFLICT
        );
    }
}
