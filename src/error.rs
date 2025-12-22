use std::error::Error;
use std::fmt;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
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
pub const ERR_RATE_LIMITED: &str = "rate_limited";
pub const ERR_BACKOFF_REQUIRED: &str = "backoff_required";
pub const ERR_REPO_STATE_MISMATCH: &str = "repo_state_mismatch";
pub const ERR_INTERNAL_ERROR: &str = "internal_error";
pub const MCP_ERROR_CODE_REGISTRY: &[&str] = &[
    "parse_error",
    "invalid_request",
    "method_not_found",
    "invalid_params",
    "invalid_argument",
    "missing_query",
    "invalid_query",
    "invalid_path",
    "invalid_range",
    "max_content_exceeded",
    ERR_EMBEDDING_TIMEOUT,
    ERR_EMBEDDING_MODEL_NOT_FOUND,
    ERR_EMBEDDING_FAILED,
    ERR_MEMORY_DISABLED,
    ERR_MISSING_REPO,
    ERR_MISSING_REPO_PATH,
    ERR_UNKNOWN_REPO,
    ERR_REPO_STATE_MISMATCH,
    ERR_MISSING_INDEX,
    ERR_STALE_INDEX,
    ERR_MISSING_DEPENDENCY,
    ERR_RATE_LIMITED,
    ERR_BACKOFF_REQUIRED,
    ERR_INTERNAL_ERROR,
];

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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpRetryKind {
    RateLimited,
    BackoffRequired,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpRetryHint {
    pub kind: McpRetryKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

impl McpRetryHint {
    pub fn rate_limited(err: &RateLimited) -> Self {
        Self {
            kind: McpRetryKind::RateLimited,
            retry_after_ms: Some(err.retry_after_ms),
            retry_at: err.retry_at.as_ref().map(|at| at.to_rfc3339()),
            limit_key: Some(err.limit_key.clone()),
            scope: Some(err.scope.clone()),
        }
    }

    pub fn backoff_required() -> Self {
        Self {
            kind: McpRetryKind::BackoffRequired,
            retry_after_ms: None,
            retry_at: None,
            limit_key: None,
            scope: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpErrorCore {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry: Option<McpRetryHint>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpErrorEnvelope {
    #[serde(flatten)]
    pub core: McpErrorCore,
    pub error: McpErrorCore,
}

impl McpErrorEnvelope {
    pub fn new(core: McpErrorCore) -> Self {
        Self {
            error: core.clone(),
            core,
        }
    }
}
