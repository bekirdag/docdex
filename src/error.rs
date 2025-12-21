use std::error::Error;
use std::fmt;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde_json::Value;
use thiserror::Error;

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
pub const ERR_SESSION_NOT_FOUND: &str = "session_not_found";
pub const ERR_RATE_LIMITED: &str = "rate_limited";
pub const ERR_BACKOFF_REQUIRED: &str = "backoff_required";
pub const ERR_REPO_STATE_MISMATCH: &str = "repo_state_mismatch";
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
