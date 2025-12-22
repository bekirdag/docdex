use std::error::Error;
use std::fmt;
use std::path::Path;
use std::time::Duration;

use chrono::{DateTime, Utc};
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
=======
>>>>>>> mcoda/task/bck-05-us-08-t31
=======
>>>>>>> mcoda/task/bck-05-us-07-t05
use serde::Serialize;
=======
use serde::{Deserialize, Serialize};
>>>>>>> mcoda/task/bck-05-us-06-t25
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
pub const ERR_INVALID_ARGUMENT: &str = "invalid_argument";
pub const ERR_UNSUPPORTED_VERSION: &str = "unsupported_version";
pub const ERR_MISSING_REPO: &str = "missing_repo";
pub const ERR_MISSING_REPO_PATH: &str = "missing_repo_path";
pub const ERR_UNKNOWN_REPO: &str = "unknown_repo";
pub const ERR_REPO_CAPACITY: &str = "repo_capacity_exceeded";
pub const ERR_MISSING_INDEX: &str = "missing_index";
pub const ERR_INDEX_SCHEMA_MISMATCH: &str = "index_schema_mismatch";
pub const ERR_STALE_INDEX: &str = "stale_index";
pub const ERR_MISSING_DEPENDENCY: &str = "missing_dependency";
<<<<<<< HEAD
pub const ERR_TIER2_UNAVAILABLE: &str = "tier2_unavailable";
=======
pub const ERR_SESSION_NOT_FOUND: &str = "session_not_found";
>>>>>>> mcoda/task/bck-05-us-07-t26
pub const ERR_RATE_LIMITED: &str = "rate_limited";
pub const ERR_BACKOFF_REQUIRED: &str = "backoff_required";
pub const ERR_REPO_STATE_MISMATCH: &str = "repo_state_mismatch";
<<<<<<< HEAD
<<<<<<< HEAD
pub const ERR_INDEX_MIGRATION_REQUIRED: &str = "index_migration_required";
pub const ERR_INDEX_SCHEMA_UNSUPPORTED: &str = "index_schema_unsupported";
=======
pub const ERR_TIER2_UNAVAILABLE: &str = "tier2_unavailable";
>>>>>>> mcoda/task/bck-05-us-07-t33
pub const ERR_INTERNAL_ERROR: &str = "internal_error";
<<<<<<< HEAD
<<<<<<< HEAD
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
=======
pub const ERR_REPO_CAPACITY_EXCEEDED: &str = "repo_capacity_exceeded";
pub const ERR_INTERNAL_ERROR: &str = "internal_error";
#[allow(dead_code)]
pub const WARN_REPO_EVICTED: &str = "repo_evicted";
#[allow(dead_code)]
pub const WARN_REPO_THRASHING: &str = "repo_thrashing";
>>>>>>> mcoda/task/bck-05-us-07-t05
=======
pub const DEFAULT_BACKOFF_RETRY_AFTER_MS: u64 = 1000;
>>>>>>> mcoda/task/bck-05-us-06-t29
=======
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
>>>>>>> mcoda/task/bck-05-us-06-t25

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

<<<<<<< HEAD
<<<<<<< HEAD
#[derive(Debug, Clone, Serialize)]
<<<<<<< HEAD
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
=======
pub struct UserWarning {
    pub code: &'static str,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

impl UserWarning {
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
>>>>>>> mcoda/task/bck-05-us-07-t05
=======
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
>>>>>>> mcoda/task/bck-05-us-07-t33
=======
pub fn missing_dependency_details(
    dependency: &'static str,
    env: Option<&'static str>,
    flag: Option<&'static str>,
) -> Value {
    let mut details = serde_json::Map::new();
    details.insert("dependency".to_string(), Value::String(dependency.to_string()));
    if let Some(env) = env {
        details.insert("env".to_string(), Value::String(env.to_string()));
    }
    if let Some(flag) = flag {
        details.insert("flag".to_string(), Value::String(flag.to_string()));
    }
    Value::Object(details)
}

pub fn missing_dependency_error(
    dependency: &'static str,
    message: impl Into<String>,
    env: Option<&'static str>,
    flag: Option<&'static str>,
) -> AppError {
    AppError::new(ERR_MISSING_DEPENDENCY, message).with_details(missing_dependency_details(
        dependency, env, flag,
    ))
>>>>>>> mcoda/task/bck-05-us-06-t20
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

<<<<<<< HEAD
<<<<<<< HEAD
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
=======
#[allow(dead_code)]
pub fn repo_capacity_details(
    max_open_repos: usize,
    open_repos: usize,
    busy_repos: usize,
    requested_repo: Option<String>,
) -> Value {
    let mut details = serde_json::Map::new();
    details.insert("maxOpenRepos".to_string(), Value::Number(max_open_repos.into()));
    details.insert("openRepos".to_string(), Value::Number(open_repos.into()));
    details.insert("busyRepos".to_string(), Value::Number(busy_repos.into()));
    if let Some(repo) = requested_repo {
        details.insert("requestedRepo".to_string(), Value::String(repo));
    }
    details.insert(
        "recoverySteps".to_string(),
        Value::Array(
            vec![
                "Increase max-open-repos to allow more concurrent repos.".to_string(),
                "Reduce concurrent repo operations or wait for in-flight work to finish."
                    .to_string(),
            ]
            .into_iter()
            .map(Value::String)
            .collect(),
        ),
    );
    Value::Object(details)
}

#[allow(dead_code)]
pub fn repo_capacity_exceeded_error(
    max_open_repos: usize,
    open_repos: usize,
    busy_repos: usize,
    requested_repo: Option<String>,
) -> AppError {
    AppError::new(
        ERR_REPO_CAPACITY_EXCEEDED,
        "repo capacity exceeded; no idle repo available for eviction",
    )
    .with_details(repo_capacity_details(
        max_open_repos,
        open_repos,
        busy_repos,
        requested_repo,
    ))
}

#[allow(dead_code)]
pub fn repo_evicted_warning(
    evicted_repo: String,
    max_open_repos: usize,
    open_repos: usize,
    reason: String,
) -> UserWarning {
    let mut details = serde_json::Map::new();
    details.insert("evictedRepo".to_string(), Value::String(evicted_repo));
    details.insert("maxOpenRepos".to_string(), Value::Number(max_open_repos.into()));
    details.insert("openRepos".to_string(), Value::Number(open_repos.into()));
    details.insert("reason".to_string(), Value::String(reason));
    UserWarning::new(
        WARN_REPO_EVICTED,
        "repo evicted to enforce max-open-repos",
    )
    .with_details(Value::Object(details))
}

#[allow(dead_code)]
pub fn repo_thrashing_warning(
    max_open_repos: usize,
    evictions_in_window: usize,
    window_ms: u64,
) -> UserWarning {
    let mut details = serde_json::Map::new();
    details.insert("maxOpenRepos".to_string(), Value::Number(max_open_repos.into()));
    details.insert(
        "evictionsInWindow".to_string(),
        Value::Number(evictions_in_window.into()),
    );
    details.insert("windowMs".to_string(), Value::Number(window_ms.into()));
    UserWarning::new(
        WARN_REPO_THRASHING,
        "frequent repo evictions detected; consider increasing max-open-repos or reducing concurrency",
    )
    .with_details(Value::Object(details))
>>>>>>> mcoda/task/bck-05-us-07-t05
=======
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
>>>>>>> mcoda/task/bck-05-us-07-t33
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
<<<<<<< HEAD
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
=======
pub fn backoff_details(retry_after: Duration) -> Value {
    let retry_after_ms = retry_after.as_millis().min(u128::from(u64::MAX)) as u64;
    let mut details = serde_json::Map::new();
    details.insert("retry_after_ms".to_string(), Value::from(retry_after_ms));
    Value::Object(details)
>>>>>>> mcoda/task/bck-05-us-06-t29
=======
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
>>>>>>> mcoda/task/bck-05-us-06-t25
}
