use std::error::Error;
use std::fmt;
use std::path::Path;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::Serialize;
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
