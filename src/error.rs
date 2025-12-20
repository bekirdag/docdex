use std::error::Error;
use std::fmt;
use std::path::Path;
use std::time::Duration;

use chrono::{DateTime, Utc};
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
=======
>>>>>>> mcoda/task/bck-05-us-08-t31
use serde::Serialize;
use serde_json::Value;
=======
use serde_json::{json, Value};
>>>>>>> mcoda/task/bck-05-us-09-t28
=======
use serde_json::{json, Value};
>>>>>>> mcoda/task/bck-05-us-09-t24
=======
use serde_json::{json, Value};
>>>>>>> mcoda/task/bck-05-us-09-t37
use thiserror::Error;

pub const ERR_EMBEDDING_TIMEOUT: &str = "embedding_timeout";
pub const ERR_EMBEDDING_MODEL_NOT_FOUND: &str = "embedding_model_not_found";
pub const ERR_EMBEDDING_FAILED: &str = "embedding_failed";
pub const ERR_MEMORY_DISABLED: &str = "memory_disabled";
pub const ERR_INVALID_ARGUMENT: &str = "invalid_argument";
pub const ERR_UNSUPPORTED_VERSION: &str = "unsupported_version";
pub const ERR_MISSING_REPO: &str = "missing_repo";
pub const ERR_MISSING_REPO_PATH: &str = "missing_repo_path";
pub const ERR_UNKNOWN_REPO: &str = "unknown_repo";
pub const ERR_MISSING_INDEX: &str = "missing_index";
pub const ERR_INDEX_SCHEMA_MISMATCH: &str = "index_schema_mismatch";
pub const ERR_STALE_INDEX: &str = "stale_index";
pub const ERR_MISSING_DEPENDENCY: &str = "missing_dependency";
pub const ERR_TIER2_UNAVAILABLE: &str = "tier2_unavailable";
pub const ERR_RATE_LIMITED: &str = "rate_limited";
pub const ERR_BACKOFF_REQUIRED: &str = "backoff_required";
pub const ERR_REPO_STATE_MISMATCH: &str = "repo_state_mismatch";
pub const ERR_INTERNAL_ERROR: &str = "internal_error";
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
pub const MAX_RATE_LIMIT_FIELD_BYTES: usize = 128;

fn clamp_utf8(mut input: String, max_bytes: usize) -> String {
    if input.len() <= max_bytes {
        return input;
    }
    let mut end = max_bytes;
    while end > 0 && !input.is_char_boundary(end) {
        end -= 1;
    }
    input.truncate(end);
    input
}
=======
pub const ERR_RATE_LIMITED_RPC: i32 = -32029;
>>>>>>> mcoda/task/bck-05-us-09-t32
=======
const DEFAULT_BACKOFF_RETRY_AFTER_MS: u64 = 1000;
>>>>>>> mcoda/task/bck-05-us-09-t07
=======
pub const DEFAULT_BACKOFF_RETRY_AFTER_MS: u64 = 1000;
pub const MAX_RETRY_HINT_KEY_BYTES: usize = 64;
pub const MAX_RETRY_HINT_SCOPE_BYTES: usize = 64;
>>>>>>> mcoda/task/bck-05-us-09-t28
=======
pub const DEFAULT_BACKOFF_RETRY_AFTER_MS: u64 = 1000;

pub fn backoff_retry_details(retry_after_ms: u64) -> Value {
    json!({ "retry_after_ms": retry_after_ms })
}
>>>>>>> mcoda/task/bck-05-us-09-t24
=======
pub const DEFAULT_BACKOFF_REQUIRED_MS: u64 = 1000;

pub fn backoff_required_details(limit_key: impl Into<String>, scope: impl Into<String>) -> Value {
    json!({
        "retry_after_ms": DEFAULT_BACKOFF_REQUIRED_MS,
        "limit_key": limit_key.into(),
        "scope": scope.into(),
    })
}
>>>>>>> mcoda/task/bck-05-us-09-t37

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

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IndexState {
    Missing,
    Stale,
}

#[derive(Debug, Clone, Serialize)]
pub struct IndexStateDetails {
    pub index_state: IndexState,
    pub repo_root: String,
    pub state_dir: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index_last_updated_epoch_ms: Option<u128>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo_last_modified_epoch_ms: Option<u128>,
    pub hint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<Vec<String>>,
}

pub fn index_state_error(
    state: IndexState,
    repo_root: &Path,
    state_dir: &Path,
    index_last_updated_epoch_ms: Option<u128>,
    repo_last_modified_epoch_ms: Option<u128>,
    message: Option<String>,
) -> AppError {
    let (code, default_message, hint, remediation) = match state {
        IndexState::Missing => (
            ERR_MISSING_INDEX,
            "index not found; run `docdex_index`",
            "Run `docdex_index` (or `docdexd index --repo <repo>`) to build the index.".to_string(),
            vec![
                "Run `docdex_index` to build the repo index.".to_string(),
                "Or run `docdexd index --repo <repo>` if you are using the CLI.".to_string(),
            ],
        ),
        IndexState::Stale => (
            ERR_STALE_INDEX,
            "index is stale; run `docdex_index`",
            "Run `docdex_index` (or `docdexd index --repo <repo>`) to refresh the index.".to_string(),
            vec![
                "Run `docdex_index` to refresh the repo index.".to_string(),
                "Or run `docdexd index --repo <repo>` if you are using the CLI.".to_string(),
            ],
        ),
    };
    let details = IndexStateDetails {
        index_state: state,
        repo_root: repo_root.display().to_string(),
        state_dir: state_dir.display().to_string(),
        index_last_updated_epoch_ms,
        repo_last_modified_epoch_ms,
        hint,
        remediation: if remediation.is_empty() {
            None
        } else {
            Some(remediation)
        },
    };
    let details_value =
        serde_json::to_value(details).expect("index state details should serialize");
    AppError::new(code, message.unwrap_or_else(|| default_message.to_string()))
        .with_details(details_value)
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

fn truncate_bytes_ascii(input: &str, max_bytes: usize) -> String {
    if input.len() <= max_bytes {
        return input.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !input.is_char_boundary(end) {
        end -= 1;
    }
    input[..end].to_string()
}

pub fn retry_hint_details(retry_after_ms: u64, limit_key: &str, scope: &str) -> Value {
    let limit_key = truncate_bytes_ascii(limit_key, MAX_RETRY_HINT_KEY_BYTES);
    let scope = truncate_bytes_ascii(scope, MAX_RETRY_HINT_SCOPE_BYTES);
    json!({
        "retry_after_ms": retry_after_ms,
        "limit_key": limit_key,
        "scope": scope,
    })
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
    pub resource_key: String,
    pub limit_per_min: u32,
    pub limit_burst: u32,
    pub denied_total: u64,
}

impl RateLimited {
    pub fn new(
        retry_after: Duration,
        limit_key: String,
        scope: String,
        resource_key: String,
        limit_per_min: u32,
        limit_burst: u32,
        denied_total: u64,
    ) -> Self {
        let retry_after_ms = retry_after.as_millis().min(u128::from(u64::MAX)) as u64;
<<<<<<< HEAD
        let limit_key = clamp_utf8(limit_key, MAX_RATE_LIMIT_FIELD_BYTES);
        let scope = clamp_utf8(scope, MAX_RATE_LIMIT_FIELD_BYTES);
=======
        let limit_key = truncate_bytes_ascii(&limit_key, MAX_RETRY_HINT_KEY_BYTES);
        let scope = truncate_bytes_ascii(&scope, MAX_RETRY_HINT_SCOPE_BYTES);
>>>>>>> mcoda/task/bck-05-us-09-t28
        Self {
            code: ERR_RATE_LIMITED,
            message: "rate limited".to_string(),
            retry_after_ms,
            retry_at: None,
            limit_key,
            scope,
            resource_key,
            limit_per_min,
            limit_burst,
            denied_total,
        }
    }

    pub fn backoff_required(retry_after: Duration, limit_key: String, scope: String) -> Self {
        let mut err = Self::new(retry_after, limit_key, scope);
        err.code = ERR_BACKOFF_REQUIRED;
        err.message = "backoff required".to_string();
        err
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

    pub fn retry_hint(&self) -> RateLimitHint {
        RateLimitHint {
            code: self.code,
            retry_after_ms: self.retry_after_ms,
            retry_at: self.retry_at.as_ref().map(|at| at.to_rfc3339()),
            limit_key: self.limit_key.clone(),
            scope: self.scope.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RateLimitHint {
    pub code: &'static str,
    pub retry_after_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_at: Option<String>,
    pub limit_key: String,
    pub scope: String,
}

#[derive(Debug, Clone, Error)]
#[error("{message}")]
pub struct BackoffRequired {
    pub code: &'static str,
    pub message: String,
    pub retry_after_ms: u64,
    pub retry_at: Option<DateTime<Utc>>,
    pub limit_key: String,
    pub scope: String,
}

impl BackoffRequired {
    pub fn new(retry_after: Duration, limit_key: String, scope: String) -> Self {
        let retry_after_ms = retry_after.as_millis().min(u128::from(u64::MAX)) as u64;
        Self {
            code: ERR_BACKOFF_REQUIRED,
            message: "backoff required".to_string(),
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

<<<<<<< HEAD
#[derive(Debug, Clone, Serialize)]
pub struct RetryHint {
    pub code: &'static str,
    pub retry_after_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_at: Option<String>,
    pub limit_key: String,
    pub scope: String,
}

impl RetryHint {
    pub fn from_rate_limited(err: &RateLimited) -> Self {
        Self {
            code: err.code,
            retry_after_ms: err.retry_after_ms,
            retry_at: err.retry_at.as_ref().map(|at| at.to_rfc3339()),
            limit_key: err.limit_key.clone(),
            scope: err.scope.clone(),
        }
    }

    pub fn from_backoff(err: &BackoffRequired) -> Self {
        Self {
            code: err.code,
            retry_after_ms: err.retry_after_ms,
            retry_at: err.retry_at.as_ref().map(|at| at.to_rfc3339()),
            limit_key: err.limit_key.clone(),
            scope: err.scope.clone(),
        }
    }
}

=======
>>>>>>> mcoda/task/bck-05-us-07-t15
#[derive(Debug, Clone, Error)]
#[error("{message}")]
pub struct BackoffRequired {
    pub code: &'static str,
    pub message: String,
    pub retry_after_ms: u64,
    pub retry_at: Option<DateTime<Utc>>,
    pub limit_key: String,
    pub scope: String,
}

impl BackoffRequired {
    pub fn new(retry_after: Duration, limit_key: String, scope: String) -> Self {
        let retry_after_ms = retry_after.as_millis().min(u128::from(u64::MAX)) as u64;
        Self {
            code: ERR_BACKOFF_REQUIRED,
            message: "backoff required".to_string(),
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

#[derive(Debug, Clone, Error)]
#[error("{message}")]
pub struct BackoffRequired {
    pub code: &'static str,
    pub message: String,
    pub retry_after_ms: u64,
    pub retry_at: Option<DateTime<Utc>>,
    pub limit_key: String,
    pub scope: String,
}

impl BackoffRequired {
    pub fn new(retry_after: Duration, limit_key: String, scope: String) -> Self {
        let retry_after_ms = retry_after.as_millis().min(u128::from(u64::MAX)) as u64;
        Self {
            code: ERR_BACKOFF_REQUIRED,
            message: "backoff required".to_string(),
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
<<<<<<< HEAD

    pub fn retry_hint(&self) -> RetryHint {
        RetryHint {
            code: self.code,
            retry_after_ms: self.retry_after_ms,
            retry_at: self.retry_at.as_ref().map(|at| at.to_rfc3339()),
            limit_key: self.limit_key.clone(),
            scope: self.scope.clone(),
        }
    }
}

#[derive(Debug, Clone, Error)]
#[error("{message}")]
pub struct BackoffRequired {
    pub code: &'static str,
    pub message: String,
    pub retry_after_ms: u64,
    pub retry_at: Option<DateTime<Utc>>,
    pub limit_key: String,
    pub scope: String,
}

impl BackoffRequired {
    pub fn new(
        message: impl Into<String>,
        limit_key: impl Into<String>,
        scope: impl Into<String>,
    ) -> Self {
        Self {
            code: ERR_BACKOFF_REQUIRED,
            message: message.into(),
            retry_after_ms: DEFAULT_BACKOFF_RETRY_AFTER_MS,
            retry_at: None,
            limit_key: limit_key.into(),
            scope: scope.into(),
        }
    }

    #[allow(dead_code)]
    pub fn with_retry_after(mut self, retry_after: Duration) -> Self {
        self.retry_after_ms = retry_after.as_millis().min(u128::from(u64::MAX)) as u64;
        self
    }

    #[allow(dead_code)]
    pub fn with_retry_at(mut self, retry_at: DateTime<Utc>) -> Self {
        self.retry_at = Some(retry_at);
        self
    }

    pub fn retry_hint(&self) -> RetryHint {
        RetryHint {
            code: self.code,
            retry_after_ms: self.retry_after_ms,
            retry_at: self.retry_at.as_ref().map(|at| at.to_rfc3339()),
            limit_key: self.limit_key.clone(),
            scope: self.scope.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RetryHint {
    pub code: &'static str,
    pub retry_after_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_at: Option<String>,
    pub limit_key: String,
    pub scope: String,
}

impl RetryHint {
    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).expect("retry hint should serialize")
    }
=======
>>>>>>> mcoda/task/bck-05-us-07-t15
}
