use std::error::Error;
use std::fmt;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde_json::Value;
use thiserror::Error;

// Canonical error codes shared across MCP, HTTP, and CLI envelopes.
pub const ERR_PARSE_ERROR: &str = "parse_error";
pub const ERR_INVALID_REQUEST: &str = "invalid_request";
pub const ERR_METHOD_NOT_FOUND: &str = "method_not_found";
pub const ERR_INVALID_PARAMS: &str = "invalid_params";
pub const ERR_MISSING_QUERY: &str = "missing_query";
pub const ERR_INVALID_QUERY: &str = "invalid_query";
pub const ERR_INVALID_PATH: &str = "invalid_path";
pub const ERR_INVALID_RANGE: &str = "invalid_range";
pub const ERR_MAX_CONTENT_EXCEEDED: &str = "max_content_exceeded";
pub const ERR_EMBEDDING_TIMEOUT: &str = "embedding_timeout";
pub const ERR_EMBEDDING_MODEL_NOT_FOUND: &str = "embedding_model_not_found";
pub const ERR_EMBEDDING_FAILED: &str = "embedding_failed";
pub const ERR_MEMORY_DISABLED: &str = "memory_disabled";
pub const ERR_INVALID_ARGUMENT: &str = "invalid_argument";
pub const ERR_MISSING_REPO: &str = "missing_repo";
pub const ERR_MISSING_REPO_PATH: &str = "missing_repo_path";
pub const ERR_UNKNOWN_REPO: &str = "unknown_repo";
pub const ERR_MISSING_INDEX: &str = "missing_index";
pub const ERR_STALE_INDEX: &str = "stale_index";
pub const ERR_MISSING_DEPENDENCY: &str = "missing_dependency";
pub const ERR_RATE_LIMITED: &str = "rate_limited";
pub const ERR_BACKOFF_REQUIRED: &str = "backoff_required";
pub const ERR_REPO_STATE_MISMATCH: &str = "repo_state_mismatch";
pub const ERR_TIER2_UNAVAILABLE: &str = "tier2_unavailable";
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

pub fn default_message_for_code(code: &str) -> &'static str {
    match code {
        ERR_PARSE_ERROR => "parse error",
        ERR_INVALID_REQUEST => "invalid request",
        ERR_METHOD_NOT_FOUND => "method not found",
        ERR_INVALID_PARAMS => "invalid parameters",
        ERR_MISSING_QUERY => "missing query",
        ERR_INVALID_QUERY => "invalid query",
        ERR_INVALID_PATH => "invalid path",
        ERR_INVALID_RANGE => "invalid range",
        ERR_MAX_CONTENT_EXCEEDED => "content too large",
        ERR_EMBEDDING_TIMEOUT => "embedding timeout",
        ERR_EMBEDDING_MODEL_NOT_FOUND => "embedding model not found",
        ERR_EMBEDDING_FAILED => "embedding failed",
        ERR_MISSING_REPO => "missing repo",
        ERR_MISSING_REPO_PATH => "repo path not found",
        ERR_UNKNOWN_REPO => "unknown repo",
        ERR_MISSING_INDEX => "missing index",
        ERR_STALE_INDEX => "stale index",
        ERR_MISSING_DEPENDENCY => "missing dependency",
        ERR_RATE_LIMITED => "rate limited",
        ERR_BACKOFF_REQUIRED => "backoff required",
        ERR_REPO_STATE_MISMATCH => "repo state mismatch",
        ERR_TIER2_UNAVAILABLE => "tier 2 unavailable",
        ERR_INTERNAL_ERROR => "internal error",
        ERR_INVALID_ARGUMENT => "invalid argument",
        _ => "error",
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

pub fn startup_error_payload(startup: &StartupError) -> Value {
    let mut body = serde_json::Map::new();
    body.insert("code".to_string(), Value::String(startup.code.to_string()));
    body.insert("message".to_string(), Value::String(startup.message.clone()));
    if let Some(hint) = startup.hint.as_ref() {
        body.insert("hint".to_string(), Value::String(hint.clone()));
    }
    if let Some(steps) = startup.remediation.as_ref() {
        body.insert(
            "remediation".to_string(),
            Value::Array(steps.iter().cloned().map(Value::String).collect()),
        );
    }
    let mut root = serde_json::Map::new();
    root.insert("error".to_string(), Value::Object(body));
    Value::Object(root)
}

pub fn app_error_payload(app: &AppError) -> Value {
    let mut body = serde_json::Map::new();
    body.insert("code".to_string(), Value::String(app.code.to_string()));
    body.insert("message".to_string(), Value::String(app.message.clone()));
    if let Some(details) = app.details.as_ref() {
        body.insert("details".to_string(), details.clone());
    }
    let mut root = serde_json::Map::new();
    root.insert("error".to_string(), Value::Object(body));
    Value::Object(root)
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
