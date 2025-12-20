use crate::browser_session::BrowserSessionError;
use crate::error::{
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
    AppError, RateLimited, ERR_BACKOFF_REQUIRED, ERR_EMBEDDING_FAILED, ERR_EMBEDDING_MODEL_NOT_FOUND,
    ERR_EMBEDDING_TIMEOUT, ERR_INTERNAL_ERROR, ERR_INVALID_ARGUMENT, ERR_MEMORY_DISABLED,
<<<<<<< HEAD
<<<<<<< HEAD
    ERR_UNSUPPORTED_VERSION, repo_resolution_details, ERR_MISSING_DEPENDENCY, ERR_MISSING_INDEX,
    ERR_MISSING_REPO, ERR_MISSING_REPO_PATH, ERR_RATE_LIMITED, ERR_REPO_STATE_MISMATCH, ERR_STALE_INDEX,
    ERR_UNKNOWN_REPO,
=======
    AppError, BackoffRequired, RateLimited, RetryHint, ERR_BACKOFF_REQUIRED, ERR_EMBEDDING_FAILED,
=======
    AppError, BackoffRequired, RateLimited, ERR_BACKOFF_REQUIRED, ERR_EMBEDDING_FAILED,
>>>>>>> mcoda/task/bck-05-us-09-t22
=======
    AppError, BackoffRequired, RateLimited, ERR_BACKOFF_REQUIRED, ERR_EMBEDDING_FAILED,
>>>>>>> mcoda/task/bck-05-us-09-t07
=======
    AppError, BackoffRequired, RateLimited, ERR_BACKOFF_REQUIRED, ERR_EMBEDDING_FAILED,
>>>>>>> mcoda/task/bck-05-us-07-t15
    ERR_EMBEDDING_MODEL_NOT_FOUND, ERR_EMBEDDING_TIMEOUT, ERR_INTERNAL_ERROR, ERR_INVALID_ARGUMENT,
    ERR_MEMORY_DISABLED, repo_resolution_details, ERR_MISSING_DEPENDENCY, ERR_MISSING_INDEX,
    ERR_MISSING_REPO, ERR_MISSING_REPO_PATH, ERR_RATE_LIMITED, ERR_REPO_STATE_MISMATCH,
    ERR_STALE_INDEX, ERR_UNKNOWN_REPO,
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> mcoda/task/bck-05-us-09-t34
=======
    repo_resolution_details, AppError, RateLimited, ERR_BACKOFF_REQUIRED, ERR_EMBEDDING_FAILED,
    ERR_EMBEDDING_MODEL_NOT_FOUND, ERR_EMBEDDING_TIMEOUT, ERR_INTERNAL_ERROR, ERR_INVALID_ARGUMENT,
    ERR_MEMORY_DISABLED, ERR_MISSING_DEPENDENCY, ERR_MISSING_INDEX, ERR_MISSING_REPO,
    ERR_MISSING_REPO_PATH, ERR_RATE_LIMITED, ERR_RATE_LIMITED_RPC, ERR_REPO_STATE_MISMATCH,
    ERR_STALE_INDEX, ERR_UNKNOWN_REPO,
>>>>>>> mcoda/task/bck-05-us-09-t32
=======
>>>>>>> mcoda/task/bck-05-us-09-t22
=======
    repo_resolution_details, ERR_MISSING_DEPENDENCY, ERR_MISSING_INDEX, ERR_MISSING_REPO,
    ERR_MISSING_REPO_PATH, ERR_RATE_LIMITED, ERR_REPO_STATE_MISMATCH, ERR_STALE_INDEX,
    ERR_TIER2_UNAVAILABLE, ERR_UNKNOWN_REPO,
>>>>>>> mcoda/task/bck-05-us-09-t21
=======
>>>>>>> mcoda/task/bck-05-us-09-t07
=======
    repo_resolution_details, AppError, RateLimited, ERR_BACKOFF_REQUIRED, ERR_EMBEDDING_FAILED,
    ERR_EMBEDDING_MODEL_NOT_FOUND, ERR_EMBEDDING_TIMEOUT, ERR_INDEX_SCHEMA_MISMATCH,
    ERR_INTERNAL_ERROR, ERR_INVALID_ARGUMENT, ERR_MEMORY_DISABLED, ERR_MISSING_DEPENDENCY,
    ERR_MISSING_INDEX, ERR_MISSING_REPO, ERR_MISSING_REPO_PATH, ERR_RATE_LIMITED,
    ERR_REPO_STATE_MISMATCH, ERR_STALE_INDEX, ERR_UNKNOWN_REPO,
>>>>>>> mcoda/task/bck-05-us-07-t09
=======
>>>>>>> mcoda/task/bck-05-us-07-t15
=======
    ERR_MISSING_DEPENDENCY, ERR_MISSING_INDEX, ERR_MISSING_REPO, ERR_MISSING_REPO_PATH,
    ERR_RATE_LIMITED, ERR_REPO_STATE_MISMATCH, ERR_STALE_INDEX, ERR_UNKNOWN_REPO,
>>>>>>> mcoda/task/bck-05-us-07-t30
};
<<<<<<< HEAD
use crate::explainability::ExplainabilityStore;
use crate::index::{IndexConfig, Indexer};
=======
use crate::index::{IndexConfig, Indexer, SymbolsBudget};
>>>>>>> mcoda/task/bck-05-us-10-t05
use crate::libs;
<<<<<<< HEAD
use crate::limits::{self, MaxSizePolicy};
=======
use crate::max_size::{
    clamp_option, DEFAULT_MEMORY_RECALL, FILES_DEFAULT_LIMIT, FILES_MAX_LIMIT, FILES_MAX_OFFSET,
    MAX_ERROR_MESSAGE_BYTES, MAX_ERROR_REASON_BYTES, MAX_MEMORY_RECALL, MaxSizePolicy,
    OPEN_MAX_BYTES, truncate_utf8_bytes,
};
>>>>>>> mcoda/task/bck-05-us-10-t25
use crate::memory::{inject_embedding_metadata, MemoryStore};
use crate::ollama::OllamaEmbedder;
<<<<<<< HEAD
<<<<<<< HEAD
use crate::ratelimit::{RateLimitConfig, RateLimiter};
=======
use crate::ratelimit::ResourceLimiter;
#[cfg(test)]
=======
use crate::repo_manager::RepoManagerConfig;
>>>>>>> mcoda/task/bck-05-us-07-t02
use crate::ratelimit::RateLimiter;
>>>>>>> mcoda/task/bck-05-us-09-t20
use crate::search;
<<<<<<< HEAD
<<<<<<< HEAD
use crate::symbols::{SymbolsResponseV1, SymbolsStore};
=======
use crate::symbols::{SymbolsStore, MAX_SYMBOLS_PER_FILE};
>>>>>>> mcoda/task/bck-05-us-10-t03
=======
use crate::symbols::SymbolsStore;
<<<<<<< HEAD
<<<<<<< HEAD
use crate::tier2::Tier2Unavailable;
>>>>>>> mcoda/task/bck-05-us-09-t21
=======
use crate::web;
>>>>>>> mcoda/task/bck-05-us-07-t16
=======
use crate::{policy, policy::Dependency, policy::RepoSurface};
>>>>>>> mcoda/task/bck-05-us-07-t30
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};
use tantivy::directory::error::LockError;
use tantivy::TantivyError;
use thiserror::Error;
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use walkdir::WalkDir;

const JSONRPC_VERSION: &str = "2.0";
const ERR_PARSE: i32 = -32700;
const ERR_INVALID_REQUEST: i32 = -32600;
const ERR_METHOD_NOT_FOUND: i32 = -32601;
const ERR_INVALID_PARAMS: i32 = -32602;
const ERR_INTERNAL: i32 = -32000;
<<<<<<< HEAD
const ERR_RATE_LIMITED_RPC: i32 = -32029;
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
=======
const TOOL_SCHEMA_VERSION_MIN: u32 = 1;
const TOOL_SCHEMA_VERSION_MAX: u32 = 1;
=======
>>>>>>> mcoda/task/bck-05-us-09-t32
=======
const ERR_BACKOFF_REQUIRED_RPC: i32 = -32030;
>>>>>>> mcoda/task/bck-05-us-07-t15
const FILES_DEFAULT_LIMIT: usize = 200;
const FILES_MAX_LIMIT: usize = 1000;
const FILES_MAX_OFFSET: usize = 50_000;
const OPEN_MAX_BYTES: usize = 512 * 1024; // guard rail for returning file content
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> mcoda/task/bck-05-us-10-t21
=======
const INDEX_MAX_PATHS: usize = 1000;
const SYMBOLS_MAX_ITEMS: usize = 5000;
const SYMBOLS_MAX_BYTES: usize = 512 * 1024;
>>>>>>> mcoda/task/bck-05-us-10-t14
=======
const SYMBOLS_MAX_LIMIT: usize = 1000;
const SYMBOLS_MAX_SIGNATURE_BYTES: usize = 512;
const SYMBOLS_MAX_OUTCOME_BYTES: usize = 512;
>>>>>>> mcoda/task/bck-05-us-10-t07
const MAX_ERROR_MESSAGE_BYTES: usize = 256;
const MAX_ERROR_REASON_BYTES: usize = 768;
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
=======
>>>>>>> mcoda/task/bck-05-us-10-t25
=======
const MCP_RATE_LIMIT_DEFAULT_PER_MIN: u32 = 0;
const MCP_RATE_LIMIT_DEFAULT_BURST: u32 = 0;
const MCP_RATE_LIMIT_SCOPE: &str = "global";
const MCP_RATE_LIMIT_KEY: &str = "mcp_tools";

fn effective_rate_limit_burst(per_minute: u32, burst: u32) -> u32 {
    if per_minute == 0 {
        return 0;
    }
    if burst == 0 {
        per_minute
    } else {
        burst
    }
}
>>>>>>> mcoda/task/bck-05-us-09-t41
=======
const MCP_RATE_LIMIT_PAYLOAD_MAX_BYTES: usize = 2048;
>>>>>>> mcoda/task/bck-05-us-09-t40
=======
const MAX_RATE_LIMIT_FIELD_BYTES: usize = 64;
>>>>>>> mcoda/task/bck-05-us-09-t30
=======
const MAX_RETRY_HINT_LABEL_BYTES: usize = 64;
const MAX_RATE_LIMIT_PAYLOAD_BYTES: usize = 2048;
>>>>>>> mcoda/task/bck-05-us-09-t37

fn mcp_rate_limit_note(rate_limit_per_min: u32, rate_limit_burst: u32, effective_burst: u32) -> String {
    if rate_limit_per_min == 0 {
        "Rate limits (MCP): disabled (DOCDEX_MCP_RATE_LIMIT_PER_MIN=0); backoff_required errors include retry_after_ms in error.data.details.".to_string()
    } else {
        let burst_source = if rate_limit_burst == 0 { "default" } else { "explicit" };
        format!(
            "Rate limits (MCP): {rate_limit_per_min}/min burst {effective_burst} (burst source: {burst_source}); rate_limited errors include retry_after_ms in error.data; backoff_required errors include retry_after_ms in error.data.details."
        )
    }
}
=======
const INDEX_STATE_CACHE_TTL_MS: u64 = 2000;
>>>>>>> mcoda/task/bck-05-us-08-t04

#[derive(Error, Debug)]
#[error("path must be relative and not contain parent components")]
struct InvalidPathError;

#[derive(Error, Debug)]
#[error("line range is invalid (start_line={start_line}, end_line={end_line}, total_lines={total_lines})")]
struct InvalidRangeError {
    start_line: usize,
    end_line: usize,
    total_lines: usize,
}

#[derive(Error, Debug)]
#[error("path must be under repo root")]
struct PathOutsideRepoError;

#[derive(Error, Debug)]
#[error("unsupported uri scheme")]
struct InvalidUriError;

#[derive(Error, Debug)]
#[error("no symbols record found for {rel_path}; run docdex_index")]
struct MissingSymbolsIndexError {
    rel_path: String,
}

<<<<<<< HEAD
#[derive(Clone, Copy, PartialEq, Eq)]
enum IndexState {
    Fresh,
    Missing,
    Stale,
}

#[derive(Clone)]
struct IndexStateSnapshot {
    state: IndexState,
    index_last_updated_epoch_ms: Option<u128>,
    repo_last_modified_epoch_ms: Option<u128>,
}

struct IndexStateCache {
    checked_at: Instant,
    snapshot: IndexStateSnapshot,
}

struct RepoScanResult {
    has_indexable: bool,
    latest_epoch_ms: Option<u128>,
    newer_than_index: bool,
=======
#[derive(Default)]
struct RepoIndexScan {
    indexable_files: u64,
    latest_mtime_epoch_ms: Option<u128>,
}

fn scan_repo_indexable_files(repo_root: &Path, config: &IndexConfig) -> RepoIndexScan {
    let mut scan = RepoIndexScan::default();
    for entry in WalkDir::new(repo_root).into_iter().filter_map(|entry| entry.ok()) {
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        if !crate::index::should_index(path, repo_root, config) {
            continue;
        }
        scan.indexable_files = scan.indexable_files.saturating_add(1);
        if let Ok(meta) = entry.metadata() {
            if let Ok(modified) = meta.modified() {
                if let Ok(dur) = modified.duration_since(std::time::UNIX_EPOCH) {
                    let millis = dur.as_millis();
                    if scan
                        .latest_mtime_epoch_ms
                        .map(|current| millis > current)
                        .unwrap_or(true)
                    {
                        scan.latest_mtime_epoch_ms = Some(millis);
                    }
                }
            }
        }
    }
    scan
>>>>>>> mcoda/task/bck-05-us-08-t02
}

fn mcp_error_data(
    code: &'static str,
    message: String,
    reason: Option<String>,
    tool: Option<&str>,
    details: Option<serde_json::Value>,
) -> serde_json::Value {
<<<<<<< HEAD
    let message = truncate_error_bytes(message, MAX_ERROR_MESSAGE_BYTES);
=======
    let message = truncate_utf8_bytes(&message, MAX_ERROR_MESSAGE_BYTES);
>>>>>>> mcoda/task/bck-05-us-10-t25
    let message_for_data = message.clone();
    let mut envelope_error = serde_json::Map::new();
    envelope_error.insert("code".to_string(), json!(code));
    envelope_error.insert("message".to_string(), json!(message));
<<<<<<< HEAD
    if let Some(reason) =
        reason.clone().map(|value| truncate_error_bytes(value, MAX_ERROR_REASON_BYTES))
=======
    if let Some(reason) = reason
        .clone()
        .map(|value| truncate_utf8_bytes(&value, MAX_ERROR_REASON_BYTES))
>>>>>>> mcoda/task/bck-05-us-10-t25
    {
        envelope_error.insert("reason".to_string(), json!(reason.clone()));
    }
    if let Some(tool) = tool {
        envelope_error.insert("tool".to_string(), json!(tool));
    }
    if let Some(details) = details.clone() {
        envelope_error.insert("details".to_string(), details);
    }
    let envelope_error_value = serde_json::Value::Object(envelope_error);

    let mut data = serde_json::Map::new();
    data.insert("code".to_string(), json!(code));
    data.insert("message".to_string(), json!(message_for_data));
    data.insert("error".to_string(), envelope_error_value);
<<<<<<< HEAD
    if let Some(reason) = reason.map(|value| truncate_error_bytes(value, MAX_ERROR_REASON_BYTES)) {
=======
    if let Some(reason) = reason.map(|value| truncate_utf8_bytes(&value, MAX_ERROR_REASON_BYTES)) {
>>>>>>> mcoda/task/bck-05-us-10-t25
        data.insert("reason".to_string(), json!(reason));
    }
    if let Some(tool) = tool {
        data.insert("tool".to_string(), json!(tool));
    }
    if let Some(details) = details {
        data.insert("details".to_string(), details);
    }
    serde_json::Value::Object(data)
}

<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
fn rate_limit_fields(err: &RateLimited) -> serde_json::Map<String, serde_json::Value> {
    let mut fields = serde_json::Map::new();
    fields.insert("retry_after_ms".to_string(), json!(err.retry_after_ms));
    if let Some(retry_at) = err.retry_at.as_ref().map(|at| at.to_rfc3339()) {
        fields.insert("retry_at".to_string(), json!(retry_at));
    }
    fields.insert("limit_key".to_string(), json!(&err.limit_key));
    fields.insert("scope".to_string(), json!(&err.scope));
    fields
}

fn mcp_rate_limited_data(err: &RateLimited, tool: Option<&str>) -> serde_json::Value {
    let fields = rate_limit_fields(err);
    let details = serde_json::Value::Object(fields.clone());
    let mut data = match mcp_error_data(
        ERR_RATE_LIMITED,
        err.message.clone(),
        None,
        tool,
        Some(details),
    ) {
        serde_json::Value::Object(map) => map,
        _ => unreachable!("mcp_error_data must return object"),
    };

    for (key, value) in fields {
        data.insert(key, value);
    }

    serde_json::Value::Object(data)
}

<<<<<<< HEAD
<<<<<<< HEAD
fn truncate_error_bytes(input: String, max_bytes: usize) -> String {
=======
fn schema_version_details(schema_name: &'static str, requested: u32) -> serde_json::Value {
    json!({
        "schema": {
            "name": schema_name,
            "requested": requested,
            "supported": {
                "min": TOOL_SCHEMA_VERSION_MIN,
                "max": TOOL_SCHEMA_VERSION_MAX
            }
        }
=======
fn mcp_rate_limited_data(err: &RateLimited) -> serde_json::Value {
<<<<<<< HEAD
    #[derive(Serialize)]
    struct RateLimitData {
        code: &'static str,
        retry_after_ms: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        retry_at: Option<String>,
        limit_key: String,
        scope: String,
    }

    serde_json::to_value(RateLimitData {
        code: ERR_RATE_LIMITED,
        retry_after_ms: err.retry_after_ms,
        retry_at: err
            .retry_at
            .as_ref()
            .map(|at| truncate_bytes(at.to_rfc3339(), MAX_RATE_LIMIT_FIELD_BYTES)),
        limit_key: truncate_bytes(err.limit_key.clone(), MAX_RATE_LIMIT_FIELD_BYTES),
        scope: truncate_bytes(err.scope.clone(), MAX_RATE_LIMIT_FIELD_BYTES),
>>>>>>> mcoda/task/bck-05-us-09-t30
    })
=======
fn mcp_retry_data(hint: RetryHint) -> serde_json::Value {
    serde_json::to_value(hint).expect("retry-hint data should serialize")
}

fn mcp_rate_limited_data(err: &RateLimited) -> serde_json::Value {
    mcp_retry_data(RetryHint::from_rate_limited(err))
}

fn mcp_backoff_data(err: &BackoffRequired) -> serde_json::Value {
    mcp_retry_data(RetryHint::from_backoff(err))
>>>>>>> mcoda/task/bck-05-us-09-t34
=======
fn mcp_rate_limited_data(err: &RateLimited) -> serde_json::Value {
    serde_json::to_value(err.retry_hint()).expect("rate-limit data should serialize")
>>>>>>> mcoda/task/bck-05-us-09-t32
}

fn mcp_backoff_required_data(err: &BackoffRequired) -> serde_json::Value {
    #[derive(Serialize)]
    struct BackoffData<'a> {
        code: &'static str,
        retry_after_ms: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        retry_at: Option<String>,
        limit_key: &'a str,
        scope: &'a str,
<<<<<<< HEAD
=======
fn rate_limit_details(err: &RateLimited, retry_at: Option<&str>) -> serde_json::Value {
    let mut details = serde_json::Map::new();
    details.insert("retry_after_ms".to_string(), json!(err.retry_after_ms));
    if let Some(retry_at) = retry_at {
        details.insert("retry_at".to_string(), json!(retry_at));
>>>>>>> mcoda/task/bck-05-us-09-t24
=======
        resource_key: &'a str,
        limit_per_min: u32,
        limit_burst: u32,
        denied_total: u64,
>>>>>>> mcoda/task/bck-05-us-09-t05
    }
    details.insert("limit_key".to_string(), json!(err.limit_key.as_str()));
    details.insert("scope".to_string(), json!(err.scope.as_str()));
    serde_json::Value::Object(details)
}

<<<<<<< HEAD
<<<<<<< HEAD
    serde_json::to_value(BackoffData {
        code: ERR_BACKOFF_REQUIRED,
=======
    serde_json::to_value(RateLimitData {
        code: err.code,
>>>>>>> mcoda/task/bck-05-us-09-t18
=======
#[derive(Clone)]
struct RetryHints {
    retry_after_ms: u64,
    retry_at: Option<String>,
    limit_key: String,
    scope: String,
}

fn truncate_label(input: &str) -> String {
    truncate_bytes(input.to_string(), MAX_RETRY_HINT_LABEL_BYTES)
}

fn retry_hints_from_rate_limited(err: &RateLimited) -> RetryHints {
    RetryHints {
>>>>>>> mcoda/task/bck-05-us-09-t37
        retry_after_ms: err.retry_after_ms,
        retry_at: err.retry_at.as_ref().map(|at| at.to_rfc3339()),
<<<<<<< HEAD
        limit_key: truncate_label(&err.limit_key),
        scope: truncate_label(&err.scope),
    }
}

fn retry_hints_from_details(details: &serde_json::Value) -> Option<RetryHints> {
    let obj = details.as_object()?;
    let retry_after_ms = obj.get("retry_after_ms")?.as_u64()?;
    let limit_key = obj.get("limit_key")?.as_str()?.to_string();
    let scope = obj.get("scope")?.as_str()?.to_string();
    let retry_at = obj
        .get("retry_at")
        .and_then(|value| value.as_str())
        .map(|value| value.to_string());
    Some(RetryHints {
        retry_after_ms,
        retry_at,
        limit_key: truncate_label(&limit_key),
        scope: truncate_label(&scope),
=======
        limit_key: &err.limit_key,
        scope: &err.scope,
        resource_key: &err.resource_key,
        limit_per_min: err.limit_per_min,
        limit_burst: err.limit_burst,
        denied_total: err.denied_total,
>>>>>>> mcoda/task/bck-05-us-09-t05
    })
<<<<<<< HEAD
    .expect("backoff data should serialize")
}

fn tier2_unavailable_details(err: &Tier2Unavailable) -> serde_json::Value {
    let mut details = serde_json::Map::new();
    details.insert("reason".to_string(), json!(err.reason.as_str()));
    if let Some(correlation_id) = err.correlation_id.as_ref() {
        details.insert("correlation_id".to_string(), json!(correlation_id));
    }
    serde_json::Value::Object(details)
=======
    err.retry_hint().to_value()
}

fn mcp_backoff_required_data(err: &BackoffRequired) -> serde_json::Value {
    err.retry_hint().to_value()
>>>>>>> mcoda/task/bck-05-us-09-t07
=======
fn mcp_rate_limited_data(err: &RateLimited, tool: Option<&str>, message: String) -> serde_json::Value {
    let retry_at = err.retry_at.as_ref().map(|at| at.to_rfc3339());
    let details = rate_limit_details(err, retry_at.as_deref());
    let mut data = match mcp_error_data(ERR_RATE_LIMITED, message, None, tool, Some(details)) {
        serde_json::Value::Object(map) => map,
        _ => serde_json::Map::new(),
    };
    data.insert("retry_after_ms".to_string(), json!(err.retry_after_ms));
    if let Some(retry_at) = retry_at {
        data.insert("retry_at".to_string(), json!(retry_at));
    }
    data.insert("limit_key".to_string(), json!(err.limit_key.as_str()));
    data.insert("scope".to_string(), json!(err.scope.as_str()));
    serde_json::Value::Object(data)
>>>>>>> mcoda/task/bck-05-us-09-t24
=======
}

fn retry_hints_to_value(hints: &RetryHints) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    map.insert("retry_after_ms".to_string(), json!(hints.retry_after_ms));
    if let Some(retry_at) = hints.retry_at.as_ref() {
        map.insert("retry_at".to_string(), json!(retry_at));
    }
    map.insert("limit_key".to_string(), json!(hints.limit_key));
    map.insert("scope".to_string(), json!(hints.scope));
    serde_json::Value::Object(map)
}

fn insert_retry_hints(
    data: &mut serde_json::Map<String, serde_json::Value>,
    hints: &RetryHints,
) {
    data.insert("retry_after_ms".to_string(), json!(hints.retry_after_ms));
    if let Some(retry_at) = hints.retry_at.as_ref() {
        data.insert("retry_at".to_string(), json!(retry_at));
    }
    data.insert("limit_key".to_string(), json!(hints.limit_key));
    data.insert("scope".to_string(), json!(hints.scope));
}

fn mcp_rate_limited_data(err: &RateLimited) -> serde_json::Value {
    let hints = retry_hints_from_rate_limited(err);
    let details = retry_hints_to_value(&hints);
    let mut data = match mcp_error_data(err.code, err.message.clone(), None, None, Some(details)) {
        serde_json::Value::Object(map) => map,
        _ => serde_json::Map::new(),
    };
    insert_retry_hints(&mut data, &hints);
    serde_json::Value::Object(data)
>>>>>>> mcoda/task/bck-05-us-09-t37
}

fn mcp_backoff_required_data(err: &BackoffRequired) -> serde_json::Value {
    #[derive(Serialize)]
    struct BackoffData<'a> {
        code: &'static str,
        retry_after_ms: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        retry_at: Option<String>,
        limit_key: &'a str,
        scope: &'a str,
    }

    serde_json::to_value(BackoffData {
        code: ERR_BACKOFF_REQUIRED,
        retry_after_ms: err.retry_after_ms,
        retry_at: err.retry_at.as_ref().map(|at| at.to_rfc3339()),
        limit_key: &err.limit_key,
        scope: &err.scope,
    })
    .expect("backoff data should serialize")
}

fn truncate_bytes(input: String, max_bytes: usize) -> String {
>>>>>>> mcoda/task/bck-05-us-10-t21
    if input.len() <= max_bytes {
        return input;
    }
    let mut end = max_bytes;
    while end > 0 && !input.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = input[..end].to_string();
    out.push_str("…");
    out
}

<<<<<<< HEAD
=======
>>>>>>> mcoda/task/bck-05-us-10-t25
=======
fn clamp_symbols_payload(payload: &mut SymbolsResponseV1, limit: usize) {
    if payload.symbols.len() > limit {
        payload.symbols.truncate(limit);
    }
    for symbol in &mut payload.symbols {
        if let Some(signature) = symbol.signature.take() {
            symbol.signature = Some(truncate_bytes(signature, SYMBOLS_MAX_SIGNATURE_BYTES));
        }
    }
    if let Some(outcome) = payload.outcome.as_mut() {
        if let Some(reason) = outcome.reason.take() {
            outcome.reason = Some(truncate_bytes(reason, SYMBOLS_MAX_OUTCOME_BYTES));
        }
        if let Some(summary) = outcome.error_summary.take() {
            outcome.error_summary = Some(truncate_bytes(summary, SYMBOLS_MAX_OUTCOME_BYTES));
        }
    }
}

>>>>>>> mcoda/task/bck-05-us-10-t07
fn rpc_error(
    rpc_code: i32,
    message: impl Into<String>,
    mcp_code: &'static str,
    reason: Option<String>,
    tool: Option<&str>,
    details: Option<serde_json::Value>,
) -> RpcError {
<<<<<<< HEAD
<<<<<<< HEAD
    let message = truncate_error_bytes(message.into(), MAX_ERROR_MESSAGE_BYTES);
=======
    let message = message.into();
    let message = truncate_utf8_bytes(&message, MAX_ERROR_MESSAGE_BYTES);
>>>>>>> mcoda/task/bck-05-us-10-t25
=======
    let message = truncate_bytes(message.into(), MAX_ERROR_MESSAGE_BYTES);
    let details_for_retry = details.clone();
    let mut data = mcp_error_data(mcp_code, message.clone(), reason, tool, details);
    if mcp_code == ERR_BACKOFF_REQUIRED {
        if let Some(hints) = details_for_retry.as_ref().and_then(retry_hints_from_details) {
            if let serde_json::Value::Object(ref mut map) = data {
                insert_retry_hints(map, &hints);
            }
        }
    }
>>>>>>> mcoda/task/bck-05-us-09-t37
    RpcError {
        code: rpc_code,
        message: message.clone(),
        data: Some(data),
    }
}

fn rpc_rate_limited(err: &RateLimited, tool: Option<&str>) -> RpcError {
<<<<<<< HEAD
    RpcError {
        code: ERR_RATE_LIMITED_RPC,
<<<<<<< HEAD
<<<<<<< HEAD
        message: truncate_error_bytes(err.message.clone(), MAX_ERROR_MESSAGE_BYTES),
=======
        message: truncate_utf8_bytes(&err.message, MAX_ERROR_MESSAGE_BYTES),
>>>>>>> mcoda/task/bck-05-us-10-t25
        data: Some(mcp_rate_limited_data(err)),
=======
        message: truncate_bytes(err.message.clone(), MAX_ERROR_MESSAGE_BYTES),
        data: Some(mcp_rate_limited_data(err, tool)),
>>>>>>> mcoda/task/bck-05-us-09-t39
=======
    let message = truncate_bytes(err.message.clone(), MAX_ERROR_MESSAGE_BYTES);
    RpcError {
        code: ERR_RATE_LIMITED_RPC,
        message: message.clone(),
        data: Some(mcp_rate_limited_data(err, tool, message)),
>>>>>>> mcoda/task/bck-05-us-09-t24
    }
}

<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
fn rpc_invalid_params_for_method(method: &'static str, err: impl std::fmt::Display) -> RpcError {
    rpc_error(
        ERR_INVALID_PARAMS,
        default_message_for_code("invalid_params"),
        "invalid_params",
        Some(err.to_string()),
        None,
        Some(json!({ "validation": "serde", "method": method })),
    )
}

fn rpc_invalid_params_for_tool(tool: &'static str, err: impl std::fmt::Display) -> RpcError {
    rpc_error(
        ERR_INVALID_PARAMS,
        default_message_for_code("invalid_params"),
        "invalid_params",
        Some(err.to_string()),
        Some(tool),
        Some(json!({ "validation": "serde", "tool": tool })),
    )
=======
=======
>>>>>>> mcoda/task/bck-05-us-09-t22
=======
>>>>>>> mcoda/task/bck-05-us-09-t07
fn rpc_backoff_required(err: &BackoffRequired) -> RpcError {
    RpcError {
        code: ERR_INVALID_PARAMS,
        message: truncate_bytes(err.message.clone(), MAX_ERROR_MESSAGE_BYTES),
<<<<<<< HEAD
<<<<<<< HEAD
        data: Some(mcp_backoff_data(err)),
    }
>>>>>>> mcoda/task/bck-05-us-09-t34
=======
        data: Some(mcp_backoff_required_data(err)),
    }
>>>>>>> mcoda/task/bck-05-us-09-t22
}

=======
fn rpc_tier2_unavailable(err: &Tier2Unavailable, tool: Option<&str>) -> RpcError {
    rpc_error(
        ERR_INVALID_PARAMS,
        err.message.clone(),
        ERR_TIER2_UNAVAILABLE,
        Some(err.reason.as_str().to_string()),
        tool,
        Some(tier2_unavailable_details(err)),
    )
}

>>>>>>> mcoda/task/bck-05-us-09-t21
=======
=======
fn rpc_backoff_required(err: &BackoffRequired) -> RpcError {
    RpcError {
        code: ERR_BACKOFF_REQUIRED_RPC,
        message: truncate_bytes(err.message.clone(), MAX_ERROR_MESSAGE_BYTES),
>>>>>>> mcoda/task/bck-05-us-07-t15
        data: Some(mcp_backoff_required_data(err)),
    }
}

<<<<<<< HEAD
>>>>>>> mcoda/task/bck-05-us-09-t07
=======
>>>>>>> mcoda/task/bck-05-us-07-t15
fn rpc_tool_error(err: &anyhow::Error, tool: Option<&str>) -> RpcError {
    if let Some(backoff) = err.downcast_ref::<BackoffRequired>() {
        return rpc_backoff_required(backoff);
    }
    if let Some(rate) = err.downcast_ref::<RateLimited>() {
        return rpc_rate_limited(rate, tool);
<<<<<<< HEAD
    }
    if let Some(backoff) = err.downcast_ref::<BackoffRequired>() {
        return rpc_backoff_required(backoff);
    }
    if let Some(backoff) = err.downcast_ref::<BackoffRequired>() {
        return rpc_backoff_required(backoff);
    }
    if let Some(unavailable) = err.downcast_ref::<Tier2Unavailable>() {
        return rpc_tier2_unavailable(unavailable, tool);
    }
    if let Some(browser_err) = err.downcast_ref::<BrowserSessionError>() {
        if let BrowserSessionError::RateLimited(rate) = browser_err {
            return rpc_rate_limited(rate);
        }
=======
>>>>>>> mcoda/task/bck-05-us-09-t24
    }
    if let Some(backoff) = err.downcast_ref::<BackoffRequired>() {
        return rpc_backoff_required(backoff);
    }
    let (mcp_code, details) = classify_tool_error(err);
    rpc_error(
        ERR_INVALID_PARAMS,
        default_message_for_code(mcp_code),
        mcp_code,
        Some(err.to_string()),
        tool,
        details,
    )
}

fn default_message_for_code(code: &str) -> &'static str {
    match code {
        "invalid_request" => "invalid request",
        "invalid_params" => "invalid parameters",
        "invalid_argument" => "invalid argument",
        "missing_query" => "missing query",
        "invalid_query" => "invalid query",
        "invalid_path" => "invalid path",
        "invalid_range" => "invalid range",
        "max_content_exceeded" => "content too large",
        ERR_UNSUPPORTED_VERSION => "unsupported version",
        ERR_EMBEDDING_TIMEOUT => "embedding timeout",
        ERR_EMBEDDING_MODEL_NOT_FOUND => "embedding model not found",
        ERR_EMBEDDING_FAILED => "embedding failed",
        ERR_MISSING_REPO => "missing repo",
        ERR_MISSING_REPO_PATH => "repo path not found",
        ERR_UNKNOWN_REPO => "unknown repo",
        ERR_MISSING_INDEX => "missing index",
        ERR_INDEX_SCHEMA_MISMATCH => "index schema mismatch",
        ERR_STALE_INDEX => "stale index",
        ERR_MISSING_DEPENDENCY => "missing dependency",
        ERR_TIER2_UNAVAILABLE => "tier2 unavailable",
        ERR_RATE_LIMITED => "rate limited",
        ERR_BACKOFF_REQUIRED => "backoff required",
        ERR_REPO_STATE_MISMATCH => "repo state mismatch",
        ERR_INTERNAL_ERROR => "internal error",
        _ => "error",
    }
}

fn index_recovery_steps(repo_root: &Path) -> Vec<String> {
    vec![
        "Run the MCP tool `docdex_index` with paths: [] to build a fresh index.".to_string(),
        format!("Or run `docdexd index --repo {}`.", repo_root.display()),
    ]
}

fn index_state_details(
    repo_root: &Path,
    state_dir: &Path,
    state_file: &Path,
    indexed_at_epoch_ms: Option<u64>,
    latest_repo_mtime_epoch_ms: Option<u64>,
    state_error: Option<String>,
) -> serde_json::Value {
    let mut details = serde_json::Map::new();
    details.insert(
        "repo_root".to_string(),
        json!(repo_root.display().to_string()),
    );
    details.insert(
        "state_dir".to_string(),
        json!(state_dir.display().to_string()),
    );
    details.insert(
        "state_file".to_string(),
        json!(state_file.display().to_string()),
    );
    if let Some(indexed_at_epoch_ms) = indexed_at_epoch_ms {
        details.insert(
            "indexed_at_epoch_ms".to_string(),
            json!(indexed_at_epoch_ms),
        );
    }
    if let Some(latest_repo_mtime_epoch_ms) = latest_repo_mtime_epoch_ms {
        details.insert(
            "latest_repo_mtime_epoch_ms".to_string(),
            json!(latest_repo_mtime_epoch_ms),
        );
    }
    if let Some(state_error) = state_error {
        details.insert("state_error".to_string(), json!(state_error));
    }
    details.insert(
        "recoverySteps".to_string(),
        json!(index_recovery_steps(repo_root)),
    );
    serde_json::Value::Object(details)
}

fn missing_index_error(repo_root: &Path, state_dir: &Path, state_file: &Path) -> AppError {
    AppError::new(
        ERR_MISSING_INDEX,
        "index not found; run docdex_index to build it",
    )
    .with_details(index_state_details(
        repo_root,
        state_dir,
        state_file,
        None,
        None,
        None,
    ))
}

fn stale_index_error(
    repo_root: &Path,
    state_dir: &Path,
    state_file: &Path,
    indexed_at_epoch_ms: Option<u64>,
    latest_repo_mtime_epoch_ms: Option<u64>,
    state_error: Option<String>,
) -> AppError {
    AppError::new(
        ERR_STALE_INDEX,
        "index is stale; run docdex_index to refresh it",
    )
    .with_details(index_state_details(
        repo_root,
        state_dir,
        state_file,
        indexed_at_epoch_ms,
        latest_repo_mtime_epoch_ms,
        state_error,
    ))
}

fn classify_tool_error(err: &anyhow::Error) -> (&'static str, Option<serde_json::Value>) {
    if let Some(backoff) = err.downcast_ref::<BackoffRequired>() {
        return (backoff.code, Some(mcp_backoff_required_data(backoff)));
    }
    if let Some(rate) = err.downcast_ref::<RateLimited>() {
<<<<<<< HEAD
        return (
            rate.code,
            Some(serde_json::Value::Object(rate_limit_fields(rate))),
        );
    }
    if let Some(backoff) = err.downcast_ref::<BackoffRequired>() {
        return (backoff.code, Some(mcp_backoff_data(backoff)));
    }
    if let Some(unavailable) = err.downcast_ref::<Tier2Unavailable>() {
        return (
            ERR_TIER2_UNAVAILABLE,
            Some(tier2_unavailable_details(unavailable)),
        );
=======
        let retry_at = rate.retry_at.as_ref().map(|at| at.to_rfc3339());
        return (rate.code, Some(rate_limit_details(rate, retry_at.as_deref())));
>>>>>>> mcoda/task/bck-05-us-09-t24
    }
    if let Some(backoff) = err.downcast_ref::<BackoffRequired>() {
        return (backoff.code, Some(mcp_backoff_required_data(backoff)));
    }
    if let Some(app) = err.downcast_ref::<AppError>() {
        return (app.code, app.details.clone());
    }
    if let Some(search_err) = err.downcast_ref::<crate::index::SearchError>() {
        match search_err {
            crate::index::SearchError::InvalidQuery { .. } => return ("invalid_query", None),
        }
    }
    if err.downcast_ref::<InvalidPathError>().is_some() {
        return ("invalid_path", None);
    }
    if let Some(range) = err.downcast_ref::<InvalidRangeError>() {
        return (
            "invalid_range",
            Some(json!({
                "start_line": range.start_line,
                "end_line": range.end_line,
                "total_lines": range.total_lines,
            })),
        );
    }
    if err.downcast_ref::<PathOutsideRepoError>().is_some() {
        return ("invalid_path", Some(json!({ "kind": "outside_repo" })));
    }
    if err.downcast_ref::<InvalidUriError>().is_some() {
        return ("invalid_params", Some(json!({ "kind": "invalid_uri" })));
    }
<<<<<<< HEAD
    if err.downcast_ref::<MissingSymbolsDependencyError>().is_some() {
        return (
            ERR_MISSING_DEPENDENCY,
            Some(json!({
                "dependency": "DOCDEX_ENABLE_SYMBOL_EXTRACTION",
                "flag": "--enable-symbol-extraction=true"
=======
    if let Some(max_err) = err.downcast_ref::<MaxContentError>() {
        return (
            "max_content_exceeded",
            Some(json!({
                "max_bytes": max_err.max_bytes,
                "actual_bytes": max_err.actual_bytes,
>>>>>>> mcoda/task/bck-05-us-07-t30
            })),
        );
    }
    if let Some(missing) = err.downcast_ref::<MissingSymbolsIndexError>() {
        return (
            ERR_MISSING_INDEX,
            Some(json!({
                "resource": "symbols",
                "path": missing.rel_path,
                "recoverySteps": [
                    "Enable symbol extraction (DOCDEX_ENABLE_SYMBOL_EXTRACTION=1) and rebuild the index with `docdexd index --repo <repo>` or MCP `docdex_index`."
                ]
            })),
        );
    }
    (ERR_INTERNAL_ERROR, None)
}

fn env_flag_enabled(name: &str) -> bool {
    match std::env::var(name) {
        Ok(value) => matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => false,
    }
}

#[derive(Deserialize)]
struct RpcRequest {
    #[serde(default)]
    jsonrpc: Option<String>,
    #[serde(default)]
    id: Option<serde_json::Value>,
    method: String,
    #[serde(default)]
    params: Option<serde_json::Value>,
}

#[derive(Default, Deserialize)]
struct InitializeParams {
    #[serde(default)]
    project_root: Option<PathBuf>,
    #[serde(default)]
    workspace_root: Option<PathBuf>,
    #[serde(default, rename = "protocolVersion")]
    protocol_version: Option<String>,
    #[serde(default)]
    capabilities: Option<serde_json::Value>,
}

#[derive(Serialize)]
struct RpcResponse {
    jsonrpc: &'static str,
    id: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<RpcError>,
}

#[derive(Serialize)]
struct RpcError {
    code: i32,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<serde_json::Value>,
}

#[derive(Serialize)]
struct ToolDefinition {
    name: &'static str,
    description: &'static str,
    #[serde(rename = "inputSchema")]
    input_schema: serde_json::Value,
}

#[derive(Deserialize)]
struct ToolCallParams {
    name: String,
    #[serde(default)]
    arguments: serde_json::Value,
}

#[derive(Deserialize)]
struct SearchArgs {
    query: String,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    project_root: Option<PathBuf>,
    #[serde(default)]
    schema_version: Option<u32>,
}

#[derive(Deserialize)]
struct WebSearchArgs {
    query: String,
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Deserialize)]
struct IndexArgs {
    #[serde(default)]
    paths: Vec<PathBuf>,
    #[serde(default)]
    project_root: Option<PathBuf>,
    #[serde(default)]
    schema_version: Option<u32>,
}

#[derive(Deserialize)]
struct StatsArgs {
    #[serde(default)]
    project_root: Option<PathBuf>,
    #[serde(default)]
<<<<<<< HEAD
    schema_version: Option<u32>,
=======
    runs_limit: Option<usize>,
>>>>>>> mcoda/task/bck-05-us-10-t06
}

#[derive(Deserialize)]
struct RepoInspectArgs {
    #[serde(default)]
    project_root: Option<PathBuf>,
    #[serde(default)]
    schema_version: Option<u32>,
}

#[derive(Deserialize)]
struct FilesArgs {
    #[serde(default)]
    project_root: Option<PathBuf>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    offset: Option<usize>,
    #[serde(default)]
    schema_version: Option<u32>,
}

#[derive(Deserialize)]
struct OpenArgs {
    path: String,
    #[serde(default)]
    project_root: Option<PathBuf>,
    #[serde(default)]
    start_line: Option<usize>,
    #[serde(default)]
    end_line: Option<usize>,
    #[serde(default)]
    schema_version: Option<u32>,
}

#[derive(Deserialize)]
struct SymbolsArgs {
    path: String,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    project_root: Option<PathBuf>,
    #[serde(default)]
<<<<<<< HEAD
    schema_version: Option<u32>,
=======
    limit: Option<usize>,
>>>>>>> mcoda/task/bck-05-us-10-t03
}

#[derive(Deserialize)]
struct MemoryStoreArgs {
    text: String,
    #[serde(default)]
    metadata: Option<serde_json::Value>,
    #[serde(default)]
    project_root: Option<PathBuf>,
    #[serde(default)]
    schema_version: Option<u32>,
}

#[derive(Deserialize)]
struct MemoryRecallArgs {
    query: String,
    #[serde(default)]
    top_k: Option<usize>,
    #[serde(default)]
    max_tokens: Option<usize>,
    #[serde(default)]
    max_items: Option<usize>,
    #[serde(default)]
    project_root: Option<PathBuf>,
}

#[derive(Deserialize)]
struct ExplainabilityRecordArgs {
    record: serde_json::Value,
    #[serde(default)]
    project_root: Option<PathBuf>,
    #[serde(default)]
    schema_version: Option<u32>,
}

#[derive(Deserialize)]
struct ResourceReadParams {
    uri: String,
}

#[derive(Serialize)]
struct ResourceTemplate {
    name: &'static str,
    description: &'static str,
    #[serde(rename = "uriTemplate")]
    uri_template: &'static str,
    variables: &'static [&'static str],
}

pub async fn serve(
    repo_root: PathBuf,
    index_config: IndexConfig,
    max_results: usize,
    rate_limit_per_min: u32,
    rate_limit_burst: u32,
    repo_manager_config: RepoManagerConfig,
) -> Result<()> {
    let repo_root = repo_root
        .canonicalize()
        .context("resolve repo root for MCP server")?;
    // Try to open with a writer; if the index is already locked (another docdexd
    // instance is indexing), fall back to read-only so search/open still work.
    let (indexer, index_writer_available) = match Indexer::with_config(repo_root.clone(), index_config.clone()) {
        Ok(ix) => (ix, true),
        Err(err) if is_lock_busy(&err) => {
            eprintln!(
                "docdex mcp: index writer is busy; opening read-only (disable other docdexd to enable indexing)"
            );
            (
                Indexer::with_config_read_only(repo_root.clone(), index_config)?,
                false,
            )
        }
        Err(err) => return Err(err),
    };
    let memory = if env_flag_enabled("DOCDEX_ENABLE_MEMORY") {
        let base_url = std::env::var("DOCDEX_EMBEDDING_BASE_URL")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .or_else(|| {
                std::env::var("DOCDEX_OLLAMA_BASE_URL")
                    .ok()
                    .filter(|v| !v.trim().is_empty())
            })
            .unwrap_or_else(|| "http://127.0.0.1:11434".to_string());
        let model = std::env::var("DOCDEX_EMBEDDING_MODEL")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| "nomic-embed-text".to_string());
        let timeout_ms = std::env::var("DOCDEX_EMBEDDING_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(5000)
            .max(1);
        Some(McpMemoryState {
            store: MemoryStore::new(indexer.repo_state_dir()),
            embedder: OllamaEmbedder::new(base_url, model, Duration::from_millis(timeout_ms))?,
        })
    } else {
        None
    };
<<<<<<< HEAD
<<<<<<< HEAD
    let explainability = ExplainabilityStore::new(indexer.state_dir());
    let effective_burst = if rate_limit_per_min > 0 && rate_limit_burst == 0 {
        rate_limit_per_min
    } else {
        rate_limit_burst
    };
<<<<<<< HEAD
<<<<<<< HEAD
=======
    let effective_burst = effective_rate_limit_burst(rate_limit_per_min, rate_limit_burst);
>>>>>>> mcoda/task/bck-05-us-09-t41
=======
    let rate_limit_note = mcp_rate_limit_note(rate_limit_per_min, rate_limit_burst, effective_burst);
>>>>>>> mcoda/task/bck-05-us-09-t13
    let tool_rate_limit = if rate_limit_per_min > 0 {
        Some(RateLimiter::<()>::new(rate_limit_per_min, effective_burst))
    } else {
        None
    };
=======
    let tool_rate_limit = RateLimitConfig::for_mcp(rate_limit_per_min, rate_limit_burst)?.limiter();
>>>>>>> mcoda/task/bck-05-us-09-t38
=======
    let tool_rate_limits = ResourceLimiter::new();
    tool_rate_limits.insert_limit("mcp_tools", rate_limit_per_min, effective_burst);
    tool_rate_limits.insert_limit("web_research", rate_limit_per_min, effective_burst);
>>>>>>> mcoda/task/bck-05-us-09-t20
    let libs_indexer = libs::LibsIndexer::open_read_only(libs::libs_state_dir_from_index_state_dir(
        indexer.repo_root(),
        indexer.state_dir(),
    ))
    .ok()
    .flatten();
<<<<<<< HEAD
    let web_config = web::WebConfig::from_env();
    let web_discovery = web::ddg::DdgDiscovery::new(web_config)?;
=======
    let web_gate = policy::web_gate_from_env();
>>>>>>> mcoda/task/bck-05-us-07-t30
    let mut server = McpServer {
        repo_root,
        indexer,
        libs_indexer,
<<<<<<< HEAD
        limits: MaxSizePolicy::for_mcp(max_results),
=======
        size_policy: MaxSizePolicy::new(max_results),
>>>>>>> mcoda/task/bck-05-us-10-t25
        default_project_root: None,
        memory,
<<<<<<< HEAD
<<<<<<< HEAD
        explainability,
=======
        web_gate,
>>>>>>> mcoda/task/bck-05-us-07-t30
        tool_rate_limit,
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
        rate_limit_per_min,
        rate_limit_burst,
        effective_rate_limit_burst: effective_burst,
        index_writer_available,
=======
        tool_rate_limits,
>>>>>>> mcoda/task/bck-05-us-09-t20
=======
        rate_limit_note,
>>>>>>> mcoda/task/bck-05-us-09-t13
=======
        index_state_cache: None,
>>>>>>> mcoda/task/bck-05-us-08-t04
=======
        web_discovery,
>>>>>>> mcoda/task/bck-05-us-07-t16
=======
        repo_manager_config,
>>>>>>> mcoda/task/bck-05-us-07-t02
    };
    server.run().await
}

#[derive(Clone)]
struct McpMemoryState {
    store: MemoryStore,
    embedder: OllamaEmbedder,
}

struct McpServer {
    repo_root: PathBuf,
    indexer: Indexer,
    libs_indexer: Option<libs::LibsIndexer>,
<<<<<<< HEAD
    limits: MaxSizePolicy,
=======
    size_policy: MaxSizePolicy,
>>>>>>> mcoda/task/bck-05-us-10-t25
    default_project_root: Option<PathBuf>,
    memory: Option<McpMemoryState>,
<<<<<<< HEAD
<<<<<<< HEAD
    explainability: ExplainabilityStore,
=======
    web_gate: policy::WebGateDecision,
>>>>>>> mcoda/task/bck-05-us-07-t30
    tool_rate_limit: Option<RateLimiter<()>>,
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
    rate_limit_per_min: u32,
    rate_limit_burst: u32,
    effective_rate_limit_burst: u32,
    index_writer_available: bool,
=======
    rate_limit_note: String,
>>>>>>> mcoda/task/bck-05-us-09-t13
=======
    index_state_cache: Option<IndexStateCache>,
>>>>>>> mcoda/task/bck-05-us-08-t04
=======
    web_discovery: web::ddg::DdgDiscovery,
>>>>>>> mcoda/task/bck-05-us-07-t16
=======
    repo_manager_config: RepoManagerConfig,
>>>>>>> mcoda/task/bck-05-us-07-t02
}

impl McpServer {
    fn policy_snapshot(&self) -> serde_json::Value {
        #[derive(Serialize)]
        struct PolicySnapshot<'a> {
            schema_version: u32,
            rate_limit: RateLimitPolicy<'a>,
            backoff: Vec<BackoffPolicy<'a>>,
        }

        #[derive(Serialize)]
        struct RateLimitPolicy<'a> {
            enabled: bool,
            per_minute: u32,
            burst: u32,
            limit_key: &'a str,
            scope: &'a str,
            shared_across_tools: bool,
            configured_per_minute: u32,
            configured_burst: u32,
            default_per_minute: u32,
            default_burst: u32,
            override_active: bool,
        }

        #[derive(Serialize)]
        struct BackoffPolicy<'a> {
            code: &'a str,
            scope: &'a str,
            reason: &'a str,
            applies_to: &'a [&'a str],
            active: bool,
            retry_hint: BackoffRetryHint<'a>,
        }

        #[derive(Serialize)]
        struct BackoffRetryHint<'a> {
            kind: &'a str,
            message: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            retry_after_ms: Option<u64>,
            #[serde(skip_serializing_if = "Option::is_none")]
            retry_at: Option<String>,
        }

        let enabled = self.rate_limit_per_min > 0;
        let override_active = self.rate_limit_per_min != MCP_RATE_LIMIT_DEFAULT_PER_MIN
            || self.rate_limit_burst != MCP_RATE_LIMIT_DEFAULT_BURST;
        let rate_limit = RateLimitPolicy {
            enabled,
            per_minute: self.rate_limit_per_min,
            burst: if enabled {
                self.effective_rate_limit_burst
            } else {
                0
            },
            limit_key: MCP_RATE_LIMIT_KEY,
            scope: MCP_RATE_LIMIT_SCOPE,
            shared_across_tools: true,
            configured_per_minute: self.rate_limit_per_min,
            configured_burst: self.rate_limit_burst,
            default_per_minute: MCP_RATE_LIMIT_DEFAULT_PER_MIN,
            default_burst: MCP_RATE_LIMIT_DEFAULT_BURST,
            override_active,
        };
        let backoff = vec![BackoffPolicy {
            code: ERR_BACKOFF_REQUIRED,
            scope: "index_writer",
            reason: "index_writer_unavailable",
            applies_to: &["docdex_index"],
            active: !self.index_writer_available,
            retry_hint: BackoffRetryHint {
                kind: "wait_for_lock",
                message: "retry once indexing completes",
                retry_after_ms: None,
                retry_at: None,
            },
        }];

        serde_json::to_value(PolicySnapshot {
            schema_version: 1,
            rate_limit,
            backoff,
        })
        .expect("policy snapshot should serialize")
=======
    tool_rate_limits: ResourceLimiter,
}

impl McpServer {
    fn constrained_limit_key(tool: &str) -> Option<&'static str> {
        match tool {
            "docdex_web_research" | "docdex.web_research" => Some("web_research"),
            _ => None,
        }
>>>>>>> mcoda/task/bck-05-us-09-t20
    }

    async fn run(&mut self) -> Result<()> {
        let stdin = io::stdin();
        let stdout = io::stdout();
        let mut reader = BufReader::new(stdin).lines();
        let mut writer = BufWriter::new(stdout);
        let mut _seen_input = false;

        loop {
            match reader.next_line().await {
                Ok(Some(line)) => {
                    _seen_input = true;
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    let req = match serde_json::from_str::<RpcRequest>(trimmed) {
                        Ok(req) => req,
                        Err(err) => {
                            let resp = RpcResponse {
                                jsonrpc: JSONRPC_VERSION,
                                id: serde_json::Value::Null,
                                result: None,
                                error: Some(rpc_error(
                                    ERR_PARSE,
                                    format!("invalid JSON: {err}"),
                                    "parse_error",
                                    Some(err.to_string()),
                                    None,
                                    None,
                                )),
                            };
                            write_response(&mut writer, &resp).await?;
                            continue;
                        }
                    };
                    if let Some(id) = req.id.as_ref() {
                        eprintln!("docdex mcp: recv method={} id={}", req.method, id);
                    } else {
                        eprintln!("docdex mcp: recv method={}", req.method);
                    }
                    let resp_opt = match self.handle(req).await {
                        Ok(resp) => resp,
                        Err(err) => Some(RpcResponse {
                            jsonrpc: JSONRPC_VERSION,
                            id: serde_json::Value::Null,
                            result: None,
                            error: Some(rpc_error(
                                ERR_INTERNAL,
                                "internal error",
                                "internal_error",
                                Some(err.to_string()),
                                None,
                                None,
                            )),
                        }),
                    };
                    if let Some(resp) = resp_opt {
                        write_response(&mut writer, &resp).await?;
                    }
                }
                Ok(None) => {
                    // Some clients momentarily close stdin; stay alive and keep polling.
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    continue;
                }
                Err(err) => {
                    eprintln!("docdex mcp: stdin read error: {err}");
                    break;
                }
            }
        }
        Ok(())
    }

    async fn handle(&mut self, req: RpcRequest) -> Result<Option<RpcResponse>> {
        // Notifications (no id) do not expect a response.
        if req.id.is_none() {
            if req.method == "notifications/initialized" {
                eprintln!("docdex mcp: client initialized");
            }
            return Ok(None);
        }
        let id = req.id.clone().unwrap();

        if let Some(version) = req.jsonrpc.as_deref() {
            if version != JSONRPC_VERSION {
                return Ok(Some(RpcResponse {
                    jsonrpc: JSONRPC_VERSION,
                    id: id.clone(),
                    result: None,
                    error: Some(rpc_error(
                        ERR_INVALID_REQUEST,
                        format!("unsupported jsonrpc version: {version}"),
                        "invalid_request",
                        None,
                        None,
                        Some(json!({ "expected": JSONRPC_VERSION })),
                    )),
                }));
            }
        }
        match req.method.as_str() {
            "initialize" => {
                let init_params: InitializeParams =
                    serde_json::from_value(req.params.clone().unwrap_or_default())
                        .unwrap_or_default();
                if let Some(client_root) = init_params
                    .workspace_root
                    .or(init_params.project_root)
                    .as_ref()
                {
                    match policy::ensure_repo_match(
                        client_root,
                        &self.repo_root,
                        RepoSurface::Mcp,
                    ) {
                        Ok(canon) => {
                            self.default_project_root = Some(canon);
                        }
                        Err(err) => {
                            return Ok(Some(RpcResponse {
                                jsonrpc: JSONRPC_VERSION,
                                id: id.clone(),
                                result: None,
                                error: Some(rpc_error(
                                    ERR_INVALID_REQUEST,
                                    default_message_for_code(err.code),
                                    err.code,
                                    None,
                                    None,
                                    err.details,
                                )),
                            }));
                        }
                    }
                }
                let protocol_version = init_params
                    .protocol_version
                    .unwrap_or_else(|| "2024-11-05".to_string());
<<<<<<< HEAD
                let instructions = "Use docdex_search to find repo-local docs before changing code.\nUse docdex_index to refresh the index if results seem stale.";
                let policy = self.policy_snapshot();
=======
                let instructions = format!(
                    "Use docdex_search to find repo-local docs before changing code.\nUse docdex_index to refresh the index if results seem stale.\n{}",
                    self.rate_limit_note
                );
>>>>>>> mcoda/task/bck-05-us-09-t13
                let mut caps = json!({
                    "tools": { "listChanged": false },
                    "resources": { "listChanged": false },
                    "resourceTemplates": { "listChanged": false },
                });
                if let Some(req_caps) = init_params.capabilities {
                    if let Some(obj) = caps.as_object_mut() {
                        if let Some(elicitation) = req_caps.get("elicitation") {
                            obj.insert("elicitation".to_string(), elicitation.clone());
                        }
                    }
                }
                let resp = RpcResponse {
                    jsonrpc: JSONRPC_VERSION,
                    id: id.clone(),
                    result: Some(json!({
                        "protocolVersion": protocol_version,
                        "serverInfo": {
                            "name": "docdex-mcp",
                            "version": env!("CARGO_PKG_VERSION"),
                            "docdex": {
                                "policy": policy
                            }
                        },
                        "capabilities": caps,
                        "instructions": instructions,
                    })),
                    error: None,
                };
                eprintln!("docdex mcp: initialize -> ok (id {:?})", id);
                Ok(Some(resp))
            }
            "tools/list" => Ok(Some(RpcResponse {
                jsonrpc: JSONRPC_VERSION,
                id: id.clone(),
                result: Some(json!({ "tools": self.tool_defs() })),
                error: None,
            })),
            "resources/list" => Ok(Some(RpcResponse {
                jsonrpc: JSONRPC_VERSION,
                id: id.clone(),
                result: Some(json!({ "resources": Vec::<serde_json::Value>::new() })),
                error: None,
            })),
            "resources/templates/list" => Ok(Some(RpcResponse {
                jsonrpc: JSONRPC_VERSION,
                id: id.clone(),
                result: Some(json!({ "resourceTemplates": self.resource_templates() })),
                error: None,
            })),
            "resources/read" => {
                let params_res: Result<ResourceReadParams, _> =
                    serde_json::from_value(req.params.clone().unwrap_or_default());
                let params = match params_res {
                    Ok(p) => p,
                    Err(err) => {
                        return Ok(Some(RpcResponse {
                            jsonrpc: JSONRPC_VERSION,
                            id: id.clone(),
                            result: None,
                            error: Some(rpc_invalid_params_for_method("resources/read", err)),
                        }))
                    }
                };
                if let Err(err) = self.check_tool_rate_limit() {
                    return Ok(Some(RpcResponse {
                        jsonrpc: JSONRPC_VERSION,
                        id: id.clone(),
                        result: None,
                        error: Some(rpc_rate_limited(&err)),
                    }));
                }
                match self.handle_resource_read(params).await {
                    Ok(value) => Ok(Some(RpcResponse {
                        jsonrpc: JSONRPC_VERSION,
                        id: id.clone(),
                        result: Some(value),
                        error: None,
                    })),
                    Err(err) => Ok(Some(RpcResponse {
                        jsonrpc: JSONRPC_VERSION,
                        id: id.clone(),
                        result: None,
                        error: Some(rpc_tool_error(&err, None)),
                    })),
                }
            }
            "tools/call" => {
                let params_res: Result<ToolCallParams, _> =
                    serde_json::from_value(req.params.clone().unwrap_or_default());
                let params = match params_res {
                    Ok(p) => p,
                    Err(err) => {
                        return Ok(Some(RpcResponse {
                            jsonrpc: JSONRPC_VERSION,
                            id: id.clone(),
                            result: None,
                            error: Some(rpc_invalid_params_for_method("tools/call", err)),
                        }))
                    }
                };
<<<<<<< HEAD
<<<<<<< HEAD
                if let Some(limiter) = self.tool_rate_limit.as_ref() {
                    if let Err(err) =
<<<<<<< HEAD
                        limiter.check_or_rate_limited((), MCP_RATE_LIMIT_KEY, MCP_RATE_LIMIT_SCOPE)
=======
                if let Err(err) = self
                    .tool_rate_limits
                    .check_or_rate_limited("mcp_tools", "global")
                {
                    return Ok(Some(RpcResponse {
                        jsonrpc: JSONRPC_VERSION,
                        id: id.clone(),
                        result: None,
                        error: Some(rpc_rate_limited(&err)),
                    }));
                }
                if let Some(resource_key) = Self::constrained_limit_key(params.name.as_str()) {
                    if let Err(err) =
                        self.tool_rate_limits
                            .check_or_rate_limited(resource_key, "global")
>>>>>>> mcoda/task/bck-05-us-09-t20
=======
                        limiter.check_or_rate_limited((), "mcp_tools", "global", "global")
>>>>>>> mcoda/task/bck-05-us-09-t05
                    {
                        return Ok(Some(RpcResponse {
                            jsonrpc: JSONRPC_VERSION,
                            id: id.clone(),
                            result: None,
                            error: Some(rpc_rate_limited(&err, Some(params.name.as_str()))),
                        }));
                    }
=======
                if let Err(err) = self.check_tool_rate_limit() {
                    return Ok(Some(RpcResponse {
                        jsonrpc: JSONRPC_VERSION,
                        id: id.clone(),
                        result: None,
                        error: Some(rpc_rate_limited(&err)),
                    }));
>>>>>>> mcoda/task/bck-05-us-09-t33
                }
                let result = match params.name.as_str() {
                    "docdex_search" | "docdex.search" => {
                        let args_res: Result<SearchArgs, _> =
                            serde_json::from_value(params.arguments.clone());
                        let args = match args_res {
                            Ok(args) => args,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_invalid_params_for_tool("docdex_search", err)),
                                }))
                            }
                        };
                        match self.handle_search(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(&err, Some("docdex_search"))),
                                }))
                            }
                        }
                    }
                    "docdex_web_search" | "docdex.web_search" => {
                        let args_res: Result<WebSearchArgs, _> =
                            serde_json::from_value(params.arguments.clone());
                        let args = match args_res {
                            Ok(args) => args,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_error(
                                        ERR_INVALID_PARAMS,
                                        default_message_for_code("invalid_params"),
                                        "invalid_params",
                                        Some(err.to_string()),
                                        Some("docdex_web_search"),
                                        Some(json!({ "validation": "serde", "tool": "docdex_web_search" })),
                                    )),
                                }))
                            }
                        };
                        match self.handle_web_search(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(&err, Some("docdex_web_search"))),
                                }))
                            }
                        }
                    }
                    "docdex_index" | "docdex.index" => {
                        let args_res: Result<IndexArgs, _> =
                            serde_json::from_value(params.arguments.clone());
                        let args = match args_res {
                            Ok(args) => args,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_invalid_params_for_tool("docdex_index", err)),
                                }))
                            }
                        };
                        match self.handle_index(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(&err, Some("docdex_index"))),
                                }))
                            }
                        }
                    }
                    "docdex_files" | "docdex.files" => {
                        let args_res: Result<FilesArgs, _> =
                            serde_json::from_value(params.arguments.clone());
                        let args = match args_res {
                            Ok(args) => args,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_invalid_params_for_tool("docdex_files", err)),
                                }))
                            }
                        };
                        match self.handle_files(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(&err, Some("docdex_files"))),
                                }))
                            }
                        }
                    }
                    "docdex_open" | "docdex.open" => {
                        let args_res: Result<OpenArgs, _> =
                            serde_json::from_value(params.arguments.clone());
                        let args = match args_res {
                            Ok(args) => args,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_invalid_params_for_tool("docdex_open", err)),
                                }))
                            }
                        };
                        match self.handle_open(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(&err, Some("docdex_open"))),
                                }))
                            }
                        }
                    }
                    "docdex_stats" | "docdex.stats" => {
                        let args_res: Result<StatsArgs, _> =
                            serde_json::from_value(params.arguments.clone());
                        let args = match args_res {
                            Ok(args) => args,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_invalid_params_for_tool("docdex_stats", err)),
                                }))
                            }
                        };
                        match self.handle_stats(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(&err, Some("docdex_stats"))),
                                }))
                            }
                        }
                    }
                    "docdex_repo_inspect" | "docdex.repo_inspect" => {
                        let args_res: Result<RepoInspectArgs, _> =
                            serde_json::from_value(params.arguments.clone());
                        let args = match args_res {
                            Ok(args) => args,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_invalid_params_for_tool(
                                        "docdex_repo_inspect",
                                        err,
                                    )),
                                }))
                            }
                        };
                        match self.handle_repo_inspect(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(&err, Some("docdex_repo_inspect"))),
                                }))
                            }
                        }
                    }
                    "docdex_symbols" | "docdex.symbols" => {
                        let args_res: Result<SymbolsArgs, _> =
                            serde_json::from_value(params.arguments.clone());
                        let args = match args_res {
                            Ok(args) => args,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_invalid_params_for_tool("docdex_symbols", err)),
                                }))
                            }
                        };
                        match self.handle_symbols(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(&err, Some("docdex_symbols"))),
                                }))
                            }
                        }
                    }
                    "docdex_memory_store" | "docdex.memory_store" => {
                        let args_res: Result<MemoryStoreArgs, _> =
                            serde_json::from_value(params.arguments.clone());
                        let args = match args_res {
                            Ok(args) => args,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_invalid_params_for_tool(
                                        "docdex_memory_store",
                                        err,
                                    )),
                                }))
                            }
                        };
                        match self.handle_memory_store(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(&err, Some("docdex_memory_store"))),
                                }))
                            }
                        }
                    }
                    "docdex_memory_recall" | "docdex.memory_recall" => {
                        let args_res: Result<MemoryRecallArgs, _> =
                            serde_json::from_value(params.arguments.clone());
                        let args = match args_res {
                            Ok(args) => args,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_invalid_params_for_tool(
                                        "docdex_memory_recall",
                                        err,
                                    )),
                                }))
                            }
                        };
                        match self.handle_memory_recall(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(&err, Some("docdex_memory_recall"))),
                                }))
                            }
                        }
                    }
                    "docdex_explainability_record" | "docdex.explainability_record" => {
                        let args_res: Result<ExplainabilityRecordArgs, _> =
                            serde_json::from_value(params.arguments.clone());
                        let args = match args_res {
                            Ok(args) => args,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_error(
                                        ERR_INVALID_PARAMS,
                                        default_message_for_code("invalid_params"),
                                        "invalid_params",
                                        Some(err.to_string()),
                                        Some("docdex_explainability_record"),
                                        Some(json!({ "validation": "serde", "tool": "docdex_explainability_record" })),
                                    )),
                                }))
                            }
                        };
                        match self.handle_explainability_record(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(&err, Some("docdex_explainability_record"))),
                                }))
                            }
                        }
                    }
                    other => {
                        return Ok(Some(RpcResponse {
                            jsonrpc: JSONRPC_VERSION,
                            id: id.clone(),
                            result: None,
                            error: Some(rpc_error(
                                ERR_METHOD_NOT_FOUND,
                                format!("unknown tool: {other}"),
                                "method_not_found",
                                None,
                                None,
                                Some(json!({
                                    "known_tools": [
                                    "docdex_search",
                                    "docdex_web_search",
                                    "docdex_index",
                                    "docdex_files",
                                    "docdex_open",
                                        "docdex_stats",
                                        "docdex_repo_inspect",
                                        "docdex_symbols",
                                        "docdex_memory_store",
                                        "docdex_memory_recall",
                                        "docdex_explainability_record"
                                    ]
                                })),
                            )),
                        }));
                    }
                };
                let content =
                    serde_json::to_string_pretty(&result).unwrap_or_else(|_| result.to_string());
                Ok(Some(RpcResponse {
                    jsonrpc: JSONRPC_VERSION,
                    id: id.clone(),
                    result: Some(json!({
                        "content": [
                            { "type": "text", "text": content }
                        ],
                        "isError": false
                    })),
                    error: None,
                }))
            }
            other => Ok(Some(RpcResponse {
                jsonrpc: JSONRPC_VERSION,
                id: id.clone(),
                result: None,
                error: Some(rpc_error(
                    ERR_METHOD_NOT_FOUND,
                    format!("unknown method: {other}"),
                    "method_not_found",
                    None,
                    None,
                    None,
                )),
            })),
        }
    }

    fn check_tool_rate_limit(&self) -> Result<(), RateLimited> {
        if let Some(limiter) = self.tool_rate_limit.as_ref() {
            limiter.check_or_rate_limited((), "mcp_tools", "global")?;
        }
        Ok(())
    }

    fn tool_defs(&self) -> Vec<ToolDefinition> {
        vec![
            ToolDefinition {
                name: "docdex_search",
                description:
                    "Search repository docs and return hits with rel_path, summary, snippet, and doc_id.",
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "query": { "type": "string", "minLength": 1, "description": "Concise search query (will be rejected if empty)" },
<<<<<<< HEAD
<<<<<<< HEAD
                        "limit": { "type": "integer", "minimum": 1, "maximum": self.limits.max_search_items as i64, "default": self.limits.max_search_items, "description": "Max results to return (clamped to server max)" },
=======
                        "limit": { "type": "integer", "minimum": 1, "maximum": self.size_policy.max_results as i64, "default": self.size_policy.max_results, "description": "Max results to return (clamped to server max)" },
>>>>>>> mcoda/task/bck-05-us-10-t25
                        "project_root": { "type": "string", "description": "Optional repo root; must match the MCP server repo" }
=======
                        "limit": { "type": "integer", "minimum": 1, "maximum": self.max_results as i64, "default": self.max_results, "description": "Max results to return (clamped to server max)" },
                        "project_root": { "type": "string", "description": "Optional repo root; must match the MCP server repo" },
                        "schema_version": { "type": "integer", "minimum": TOOL_SCHEMA_VERSION_MIN as i64, "maximum": TOOL_SCHEMA_VERSION_MAX as i64, "default": TOOL_SCHEMA_VERSION_MAX as i64, "description": "Optional response schema version to request" }
>>>>>>> mcoda/task/bck-05-us-10-t21
                    },
                    "required": ["query"]
                }),
            },
            ToolDefinition {
                name: "docdex_web_search",
                description:
                    "Perform DuckDuckGo HTML discovery and return a deduplicated URL list.",
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "query": { "type": "string", "minLength": 1, "description": "Search query string" },
                        "limit": { "type": "integer", "minimum": 1, "maximum": self.web_discovery.max_results() as i64, "default": self.web_discovery.max_results() as i64, "description": "Max results to return (clamped)" }
                    },
                    "required": ["query"]
                }),
            },
            ToolDefinition {
                name: "docdex_index",
                description:
                    "Rebuild the index (or ingest specific files) for the current repo root (paths capped).",
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "paths": {
                            "type": "array",
                            "items": { "type": "string" },
                            "maxItems": INDEX_MAX_PATHS,
                            "description": "Optional list of files to ingest; empty => full reindex (max 1000 items)"
                        },
                        "project_root": { "type": "string", "description": "Optional repo root; must match the MCP server repo" },
                        "schema_version": { "type": "integer", "minimum": TOOL_SCHEMA_VERSION_MIN as i64, "maximum": TOOL_SCHEMA_VERSION_MAX as i64, "default": TOOL_SCHEMA_VERSION_MAX as i64, "description": "Optional response schema version to request" }
                    }
                }),
            },
            ToolDefinition {
                name: "docdex_files",
                description:
                    "List indexed documents (rel_path/doc_id/token_estimate) for the current repo.",
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "project_root": { "type": "string", "description": "Optional repo root; must match the MCP server repo" },
<<<<<<< HEAD
                        "limit": { "type": "integer", "minimum": 1, "maximum": self.limits.max_files_limit as i64, "default": limits::MCP_FILES_DEFAULT_LIMIT, "description": "Max documents to return (clamped)" },
                        "offset": { "type": "integer", "minimum": 0, "maximum": self.limits.max_files_offset as i64, "default": 0, "description": "Number of docs to skip before listing (clamped)" }
=======
                        "limit": { "type": "integer", "minimum": 1, "maximum": FILES_MAX_LIMIT as i64, "default": FILES_DEFAULT_LIMIT, "description": "Max documents to return (clamped)" },
                        "offset": { "type": "integer", "minimum": 0, "maximum": FILES_MAX_OFFSET as i64, "default": 0, "description": "Number of docs to skip before listing (clamped)" },
                        "schema_version": { "type": "integer", "minimum": TOOL_SCHEMA_VERSION_MIN as i64, "maximum": TOOL_SCHEMA_VERSION_MAX as i64, "default": TOOL_SCHEMA_VERSION_MAX as i64, "description": "Optional response schema version to request" }
>>>>>>> mcoda/task/bck-05-us-10-t21
                    }
                }),
            },
            ToolDefinition {
                name: "docdex_open",
                description:
                    "Read a file from the repo (optional line window); rejects paths outside the repo and large files (max 512 KiB).",
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "minLength": 1, "description": "Relative path under the repo" },
                        "project_root": { "type": "string", "description": "Optional repo root; must match the MCP server repo" },
                        "start_line": { "type": "integer", "minimum": 1, "description": "Optional start line (1-based, inclusive)" },
                        "end_line": { "type": "integer", "minimum": 1, "description": "Optional end line (1-based, inclusive)" },
                        "schema_version": { "type": "integer", "minimum": TOOL_SCHEMA_VERSION_MIN as i64, "maximum": TOOL_SCHEMA_VERSION_MAX as i64, "default": TOOL_SCHEMA_VERSION_MAX as i64, "description": "Optional response schema version to request" }
                    },
                    "required": ["path"]
                }),
            },
            ToolDefinition {
                name: "docdex_stats",
                description:
                    "Inspect index metadata, symbols enablement, and recent run summaries (max 20 runs; sample lists capped at 25; error summaries truncated to 240 chars).",
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "project_root": { "type": "string", "description": "Optional repo root; must match the MCP server repo" },
<<<<<<< HEAD
                        "schema_version": { "type": "integer", "minimum": TOOL_SCHEMA_VERSION_MIN as i64, "maximum": TOOL_SCHEMA_VERSION_MAX as i64, "default": TOOL_SCHEMA_VERSION_MAX as i64, "description": "Optional response schema version to request" }
=======
                        "runs_limit": { "type": "integer", "minimum": 1, "maximum": crate::index::RUN_SUMMARY_MAX_LIMIT as i64, "default": crate::index::RUN_SUMMARY_DEFAULT_LIMIT, "description": "Max run summaries to return (clamped)" }
>>>>>>> mcoda/task/bck-05-us-10-t06
                    }
                }),
            },
            ToolDefinition {
                name: "docdex_repo_inspect",
                description:
                    "Inspect how Docdex resolves repo identity (normalized path, fingerprint, and any shared-state mapping).",
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "project_root": { "type": "string", "description": "Optional repo root; must match the MCP server repo" },
                        "schema_version": { "type": "integer", "minimum": TOOL_SCHEMA_VERSION_MIN as i64, "maximum": TOOL_SCHEMA_VERSION_MAX as i64, "default": TOOL_SCHEMA_VERSION_MAX as i64, "description": "Optional response schema version to request" }
                    }
                }),
            },
            ToolDefinition {
                name: "docdex_symbols",
                description: "Read the symbol extraction result for a file, including per-file outcome (ok/skipped/failed); payloads capped to 5000 symbols / 512 KiB.",
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "minLength": 1, "description": "Relative path under the repo" },
<<<<<<< HEAD
<<<<<<< HEAD
                        "project_root": { "type": "string", "description": "Optional repo root; must match the MCP server repo" },
                        "schema_version": { "type": "integer", "minimum": TOOL_SCHEMA_VERSION_MIN as i64, "maximum": TOOL_SCHEMA_VERSION_MAX as i64, "default": TOOL_SCHEMA_VERSION_MAX as i64, "description": "Optional response schema version to request" }
=======
                        "limit": { "type": "integer", "minimum": 1, "maximum": SYMBOLS_MAX_LIMIT as i64, "default": SYMBOLS_MAX_LIMIT, "description": "Max symbols to return (clamped)" },
                        "project_root": { "type": "string", "description": "Optional repo root; must match the MCP server repo" }
>>>>>>> mcoda/task/bck-05-us-10-t07
=======
                        "project_root": { "type": "string", "description": "Optional repo root; must match the MCP server repo" },
                        "limit": { "type": "integer", "minimum": 1, "maximum": MAX_SYMBOLS_PER_FILE as i64, "default": MAX_SYMBOLS_PER_FILE, "description": "Max symbols to return (clamped to server max)" }
>>>>>>> mcoda/task/bck-05-us-10-t03
                    },
                    "required": ["path"]
                }),
            },
            ToolDefinition {
                name: "docdex_memory_store",
                description: "Store a memory item (requires DOCDEX_ENABLE_MEMORY=1).",
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "text": { "type": "string", "minLength": 1, "description": "Memory text to store" },
                        "metadata": { "type": "object", "description": "Optional metadata object", "additionalProperties": true },
                        "project_root": { "type": "string", "description": "Optional repo root; must match the MCP server repo" },
                        "schema_version": { "type": "integer", "minimum": TOOL_SCHEMA_VERSION_MIN as i64, "maximum": TOOL_SCHEMA_VERSION_MAX as i64, "default": TOOL_SCHEMA_VERSION_MAX as i64, "description": "Optional response schema version to request" }
                    },
                    "required": ["text"]
                }),
            },
            ToolDefinition {
                name: "docdex_memory_recall",
                description: "Recall memory items by semantic similarity (requires DOCDEX_ENABLE_MEMORY=1).",
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "query": { "type": "string", "minLength": 1, "description": "Query text to embed" },
<<<<<<< HEAD
<<<<<<< HEAD
                        "top_k": { "type": "integer", "minimum": 1, "maximum": self.limits.max_memory_items as i64, "default": 5, "description": "Max results to return" },
=======
                        "top_k": { "type": "integer", "minimum": 1, "maximum": MAX_MEMORY_RECALL as i64, "default": DEFAULT_MEMORY_RECALL, "description": "Max results to return" },
>>>>>>> mcoda/task/bck-05-us-10-t25
                        "project_root": { "type": "string", "description": "Optional repo root; must match the MCP server repo" }
=======
                        "top_k": { "type": "integer", "minimum": 1, "maximum": 50, "default": 5, "description": "Max results to return" },
                        "project_root": { "type": "string", "description": "Optional repo root; must match the MCP server repo" },
                        "schema_version": { "type": "integer", "minimum": TOOL_SCHEMA_VERSION_MIN as i64, "maximum": TOOL_SCHEMA_VERSION_MAX as i64, "default": TOOL_SCHEMA_VERSION_MAX as i64, "description": "Optional response schema version to request" }
>>>>>>> mcoda/task/bck-05-us-10-t21
                    },
                    "required": ["query"]
                }),
            },
            ToolDefinition {
                name: "docdex_explainability_record",
                description: "Persist an explainability record (repo-scoped, deterministically truncated).",
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "record": { "type": "object", "description": "Explainability record JSON (bounded to a server-defined max size)", "additionalProperties": true },
                        "project_root": { "type": "string", "description": "Optional repo root; must match the MCP server repo" }
                    },
                    "required": ["record"]
                }),
            },
        ]
    }

    fn resource_templates(&self) -> Vec<ResourceTemplate> {
        vec![ResourceTemplate {
            name: "docdex_file",
            description:
                "Read a file from the current repo (delegates to docdex_open); vars: {path}.",
            uri_template: "docdex://{path}",
            variables: &["path"],
        }]
    }

    fn index_state_snapshot(&mut self) -> Result<IndexStateSnapshot> {
        if let Some(cache) = self.index_state_cache.as_ref() {
            if cache.checked_at.elapsed() < Duration::from_millis(INDEX_STATE_CACHE_TTL_MS) {
                return Ok(cache.snapshot.clone());
            }
        }

        let stats = self.indexer.stats()?;
        let repo_scan = scan_repo_for_index_state(
            &self.repo_root,
            self.indexer.config(),
            stats.last_updated_epoch_ms,
        )?;
        let state = if !repo_scan.has_indexable {
            IndexState::Fresh
        } else if stats.segments == 0 || stats.last_updated_epoch_ms.is_none() {
            IndexState::Missing
        } else if repo_scan.newer_than_index {
            IndexState::Stale
        } else {
            IndexState::Fresh
        };

        let snapshot = IndexStateSnapshot {
            state,
            index_last_updated_epoch_ms: stats.last_updated_epoch_ms,
            repo_last_modified_epoch_ms: repo_scan.latest_epoch_ms,
        };
        self.index_state_cache = Some(IndexStateCache {
            checked_at: Instant::now(),
            snapshot: snapshot.clone(),
        });
        Ok(snapshot)
    }

    fn ensure_index_fresh(&mut self) -> Result<()> {
        let snapshot = self.index_state_snapshot()?;
        let repo_root = normalize_for_details(&self.repo_root);
        let state_dir = normalize_for_details(self.indexer.config().state_dir());
        let mut recovery_steps = Vec::new();
        recovery_steps.push(format!(
            "Run: `docdexd index --repo {}` to (re)build the index.",
            repo_root
        ));
        recovery_steps.push("From MCP clients, call `docdex_index` before search/files/stats.".to_string());

        match snapshot.state {
            IndexState::Fresh => Ok(()),
            IndexState::Missing => Err(AppError::new(ERR_MISSING_INDEX, "index not built")
                .with_details(json!({
                    "repo_root": repo_root,
                    "state_dir": state_dir,
                    "recoverySteps": recovery_steps,
                }))
                .into()),
            IndexState::Stale => {
                let mut details = serde_json::Map::new();
                details.insert("repo_root".to_string(), json!(repo_root));
                details.insert("state_dir".to_string(), json!(state_dir));
                if let Some(index_last) = snapshot.index_last_updated_epoch_ms {
                    details.insert(
                        "index_last_updated_epoch_ms".to_string(),
                        json!(index_last),
                    );
                }
                if let Some(repo_last) = snapshot.repo_last_modified_epoch_ms {
                    details.insert(
                        "repo_last_modified_epoch_ms".to_string(),
                        json!(repo_last),
                    );
                }
                details.insert(
                    "recoverySteps".to_string(),
                    json!(recovery_steps),
                );
                Err(AppError::new(ERR_STALE_INDEX, "index is stale")
                    .with_details(serde_json::Value::Object(details))
                    .into())
            }
        }
    }

    async fn handle_search(&mut self, args: SearchArgs) -> Result<serde_json::Value> {
        self.ensure_project_root(args.project_root.as_deref())?;
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
        self.ensure_schema_version("docdex_search", args.schema_version)?;
=======
        self.ensure_index_fresh()?;
>>>>>>> mcoda/task/bck-05-us-08-t32
=======
        self.indexer.ensure_index_fresh()?;
>>>>>>> mcoda/task/bck-05-us-08-t31
=======
        self.ensure_index_ready()?;
>>>>>>> mcoda/task/bck-05-us-08-t30
=======
        self.ensure_index_fresh()?;
>>>>>>> mcoda/task/bck-05-us-08-t04
=======
        self.ensure_index_ready()?;
>>>>>>> mcoda/task/bck-05-us-08-t02
=======
        self.ensure_index_ready()?;
>>>>>>> mcoda/task/bck-05-us-08-t05
        let query = args.query.trim();
<<<<<<< HEAD
        let requested_limit = args.limit;
        let limit = args
            .limit
<<<<<<< HEAD
            .unwrap_or(self.limits.max_search_items)
            .clamp(1, self.limits.max_search_items);
        let mut hits =
=======
        let limit = clamp_option(
            args.limit,
            self.size_policy.max_results,
            1,
            self.size_policy.max_results,
        );
        let hits =
>>>>>>> mcoda/task/bck-05-us-10-t25
            search::run_query(&self.indexer, self.libs_indexer.as_ref(), query, limit).await?;
        apply_search_bounds(&self.limits, &mut hits.hits);
=======
            .unwrap_or(self.max_results)
            .clamp(1, self.max_results);
        let mut hits =
            search::run_query(&self.indexer, self.libs_indexer.as_ref(), query, limit).await?;
        if hits.hits.len() > limit {
            hits.hits.truncate(limit);
            let top_score = hits.hits.first().map(|hit| hit.score);
            hits.top_score = top_score;
            hits.top_score_camel = top_score;
        }
>>>>>>> mcoda/task/bck-05-us-08-t32
        let hits_value = serde_json::to_value(&hits.hits)?;
        let project_root_path = self
            .default_project_root
            .as_ref()
            .unwrap_or(&self.repo_root)
            .display()
            .to_string();
        let mut meta = hits.meta.unwrap_or_else(|| search::SearchMeta {
            generated_at_epoch_ms: 0,
            index_last_updated_epoch_ms: None,
            repo_root: self.repo_root.display().to_string(),
            repo_id: crate::symbols::repo_id_for_root(&self.repo_root).ok(),
            query: None,
            context_assembly: None,
        });
        meta.repo_root = project_root_path.clone();
<<<<<<< HEAD
        meta.repo_id = meta
            .repo_id
            .or_else(|| crate::symbols::repo_id_for_root(&self.repo_root).ok());
=======
        let token_estimate_sum_kept: u64 = hits.hits.iter().map(|hit| hit.token_estimate).sum();
        meta.context_assembly = Some(search::ContextAssemblyMeta {
            requested_limit,
            effective_limit: limit,
            snippet_policy: search::SnippetPolicy::Full,
            max_tokens: None,
            token_budget_mode: "per_hit_token_estimate",
            hits_before_pruning: hits.hits.len(),
            hits_after_pruning: hits.hits.len(),
            token_estimate_sum_kept,
            token_estimate_sum_pruned: 0,
            pruned: Vec::new(),
            selected_sources: hits
                .hits
                .iter()
                .map(|hit| search::SelectedSourceMeta {
                    doc_id: hit.doc_id.clone(),
                    rel_path: hit.rel_path.clone(),
                    score: hit.score,
                    token_estimate: hit.token_estimate,
                    snippet_origin: hit.snippet_origin.clone(),
                    snippet_truncated: hit.snippet_truncated,
                })
                .collect(),
        });
>>>>>>> mcoda/task/bck-05-us-10-t12
        Ok(json!({
            "hits": hits_value.clone(),
            "results": hits_value,
            "top_score": hits.top_score,
            "topScore": hits.top_score,
            "repo_root": self.repo_root.display().to_string(),
            "state_dir": self.indexer.config().state_dir().display().to_string(),
            "limit": limit,
            "project_root": project_root_path,
            "meta": meta
        }))
    }

    async fn handle_web_search(&self, args: WebSearchArgs) -> Result<serde_json::Value> {
        let query = args.query.trim();
        if query.is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "query must not be empty").into());
        }
        let limit = args
            .limit
            .unwrap_or_else(|| self.web_discovery.max_results())
            .clamp(1, self.web_discovery.max_results());
        let response = self.web_discovery.discover(query, limit).await?;
        Ok(serde_json::to_value(&response).context("serialize docdex_web_search")?)
    }

    async fn handle_index(&mut self, args: IndexArgs) -> Result<serde_json::Value> {
        self.ensure_project_root(args.project_root.as_deref())?;
        self.ensure_schema_version("docdex_index", args.schema_version)?;
        if args.paths.is_empty() {
<<<<<<< HEAD
            let _ = self.indexer.reindex_all_with_summary().await?;
=======
            self.indexer.reindex_all().await?;
            self.index_state_cache = None;
>>>>>>> mcoda/task/bck-05-us-08-t04
            return Ok(json!({
                "status": "ok",
                "action": "reindex_all",
                "repo_root": self.repo_root.display().to_string(),
                "state_dir": self.indexer.config().state_dir().display().to_string(),
                "project_root": self
                    .default_project_root
                    .as_ref()
                    .unwrap_or(&self.repo_root)
                    .display()
                    .to_string(),
            }));
        }
        if args.paths.len() > INDEX_MAX_PATHS {
            return Err(AppError::new(
                ERR_INVALID_ARGUMENT,
                format!("paths exceeds max of {}", INDEX_MAX_PATHS),
            )
            .into());
        }
        let mut ingested: Vec<String> = Vec::new();
        let mut decisions = Vec::new();
        let mut symbols_budget = SymbolsBudget::new(crate::symbols::MAX_SYMBOLS_PER_RUN);
        for path in args.paths {
            let resolved = if path.is_absolute() {
                path
            } else {
                self.repo_root.join(path)
            };
<<<<<<< HEAD
            let canonical = resolved
                .canonicalize()
                .with_context(|| format!("resolve path {}", resolved.display()))?;
            if !canonical.starts_with(&self.repo_root) {
                return Err(PathOutsideRepoError.into());
            }
            let path_display = canonical
                .strip_prefix(&self.repo_root)
                .map(|rel| rel.to_string_lossy().replace('\\', "/"))
                .unwrap_or_else(|_| canonical.display().to_string());
            let decision = self.indexer.ingest_file(canonical.clone()).await?;
            ingested.push(path_display.clone());
=======
            let path_display = resolved.display().to_string();
<<<<<<< HEAD
            let (decision, _summary) = self.indexer.ingest_file_with_summary(resolved.clone()).await?;
=======
            let decision = self
                .indexer
                .ingest_file_with_budget(resolved.clone(), Some(&mut symbols_budget))
                .await?;
>>>>>>> mcoda/task/bck-05-us-10-t05
            ingested.push(resolved);
>>>>>>> mcoda/task/bck-05-us-10-t06
            decisions.push(json!({
                "path": path_display,
                "decision": decision.decision,
                "reason": decision.reason,
            }));
        }
<<<<<<< HEAD
        if ingested.len() > self.limits.max_index_items {
            ingested.truncate(self.limits.max_index_items);
        }
        if decisions.len() > self.limits.max_index_items {
            decisions.truncate(self.limits.max_index_items);
        }
=======
        self.index_state_cache = None;
>>>>>>> mcoda/task/bck-05-us-08-t04
        Ok(json!({
            "status": "ok",
            "action": "ingest",
            "paths": ingested,
            "decisions": decisions,
            "project_root": self
                .default_project_root
                .as_ref()
                .unwrap_or(&self.repo_root)
                .display()
                .to_string(),
        }))
    }

    async fn handle_files(&mut self, args: FilesArgs) -> Result<serde_json::Value> {
        self.ensure_project_root(args.project_root.as_deref())?;
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
=======
        self.ensure_schema_version("docdex_files", args.schema_version)?;
>>>>>>> mcoda/task/bck-05-us-10-t21
=======
        self.ensure_index_fresh()?;
>>>>>>> mcoda/task/bck-05-us-08-t32
=======
        self.indexer.preflight_index_state()?;
>>>>>>> mcoda/task/bck-05-us-08-t33
=======
        self.indexer.ensure_index_fresh()?;
>>>>>>> mcoda/task/bck-05-us-08-t31
=======
        self.ensure_index_ready()?;
>>>>>>> mcoda/task/bck-05-us-08-t30
=======
        self.ensure_index_fresh()?;
>>>>>>> mcoda/task/bck-05-us-08-t04
=======
        self.ensure_index_ready()?;
>>>>>>> mcoda/task/bck-05-us-08-t02
=======
        self.ensure_index_ready()?;
>>>>>>> mcoda/task/bck-05-us-08-t05
        let limit = args
            .limit
            .unwrap_or(limits::MCP_FILES_DEFAULT_LIMIT)
            .clamp(1, self.limits.max_files_limit);
        let offset = args.offset.unwrap_or(0).min(self.limits.max_files_offset);
=======
        let limit = clamp_option(args.limit, FILES_DEFAULT_LIMIT, 1, FILES_MAX_LIMIT);
        let offset = clamp_option(args.offset, 0, 0, FILES_MAX_OFFSET);
>>>>>>> mcoda/task/bck-05-us-10-t25
        let (docs, total) = self.indexer.list_docs(offset, limit)?;
        Ok(json!({
            "results": docs,
            "total": total,
            "limit": limit,
            "offset": offset,
            "repo_root": self.repo_root.display().to_string(),
            "project_root": self
                .default_project_root
                .as_ref()
                .unwrap_or(&self.repo_root)
                .display()
                .to_string(),
        }))
    }

    async fn handle_stats(&mut self, args: StatsArgs) -> Result<serde_json::Value> {
        self.ensure_project_root(args.project_root.as_deref())?;
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
        self.ensure_schema_version("docdex_stats", args.schema_version)?;
=======
        self.ensure_index_fresh()?;
>>>>>>> mcoda/task/bck-05-us-08-t32
=======
        self.indexer.preflight_index_state()?;
>>>>>>> mcoda/task/bck-05-us-08-t33
=======
        self.indexer.ensure_index_fresh()?;
>>>>>>> mcoda/task/bck-05-us-08-t31
=======
        self.ensure_index_ready()?;
>>>>>>> mcoda/task/bck-05-us-08-t30
=======
        self.ensure_index_fresh()?;
>>>>>>> mcoda/task/bck-05-us-08-t04
=======
        self.ensure_index_ready()?;
>>>>>>> mcoda/task/bck-05-us-08-t02
=======
        self.ensure_index_ready()?;
>>>>>>> mcoda/task/bck-05-us-08-t05
        let stats = self.indexer.stats()?;
        let run_summaries = self.indexer.run_summaries(args.runs_limit)?;
=======
        let stats = self.indexer.stats_checked()?;
>>>>>>> mcoda/task/bck-05-us-08-t01
        Ok(json!({
            "num_docs": stats.num_docs,
            "state_dir": stats.state_dir.display().to_string(),
            "index_size_bytes": stats.index_size_bytes,
            "segments": stats.segments,
            "avg_bytes_per_doc": stats.avg_bytes_per_doc,
            "generated_at_epoch_ms": stats.generated_at_epoch_ms,
            "last_updated_epoch_ms": stats.last_updated_epoch_ms,
<<<<<<< HEAD
            "symbols_enabled": self.indexer.config().symbols_enabled(),
            "symbols_store_ready": self.indexer.symbols_store_ready(),
            "run_summaries": run_summaries,
=======
            "index_status": stats.index_status,
>>>>>>> mcoda/task/bck-05-us-08-t12
            "repo_root": self.repo_root.display().to_string(),
            "project_root": self
                .default_project_root
                .as_ref()
                .unwrap_or(&self.repo_root)
                .display()
                .to_string(),
        }))
    }

    fn ensure_index_ready(&self) -> Result<()> {
        let state_dir = self.indexer.config().state_dir();
        let state_file = self.indexer.index_state_path();
        let state = match self.indexer.read_index_state() {
            Ok(Some(state)) => state,
            Ok(None) => {
                return Err(missing_index_error(&self.repo_root, state_dir, &state_file).into())
            }
            Err(err) => {
                return Err(stale_index_error(
                    &self.repo_root,
                    state_dir,
                    &state_file,
                    None,
                    None,
                    Some(err.to_string()),
                )
                .into())
            }
        };
        let latest_repo_mtime_epoch_ms = self.indexer.latest_repo_mtime_epoch_ms()?;
        if let Some(latest_repo_mtime_epoch_ms) = latest_repo_mtime_epoch_ms {
            if latest_repo_mtime_epoch_ms > state.indexed_at_epoch_ms {
                return Err(stale_index_error(
                    &self.repo_root,
                    state_dir,
                    &state_file,
                    Some(state.indexed_at_epoch_ms),
                    Some(latest_repo_mtime_epoch_ms),
                    None,
                )
                .into());
            }
        }
        Ok(())
    }

    async fn handle_repo_inspect(&self, args: RepoInspectArgs) -> Result<serde_json::Value> {
        self.ensure_project_root(args.project_root.as_deref())?;
        self.ensure_schema_version("docdex_repo_inspect", args.schema_version)?;
        let report = crate::repo_identity::inspect_repo(
            &self.repo_root,
            Some(self.indexer.config().state_dir()),
        )?;
        Ok(serde_json::to_value(&report).context("serialize docdex_repo_inspect")?)
    }

    async fn handle_open(&self, args: OpenArgs) -> Result<serde_json::Value> {
        self.ensure_project_root(args.project_root.as_deref())?;
<<<<<<< HEAD
        self.ensure_schema_version("docdex_open", args.schema_version)?;
=======
        self.ensure_index_ready()?;
>>>>>>> mcoda/task/bck-05-us-08-t02
        let rel_path = normalize_rel_path(&args.path).ok_or(InvalidPathError)?;
        let abs_path = self.repo_root.join(&rel_path);
        let canonical = abs_path
            .canonicalize()
            .with_context(|| format!("resolve path {}", rel_path.display()))?;
        if !canonical.starts_with(&self.repo_root) {
            return Err(PathOutsideRepoError.into());
        }
        let content = fs::read_to_string(&canonical)
            .with_context(|| format!("read {}", rel_path.display()))?;
        let lines: Vec<&str> = content.lines().collect();
        let total_lines = lines.len();
        if total_lines == 0 {
            return Ok(json!({
                "path": rel_path.display().to_string(),
                "start_line": 0,
                "end_line": 0,
                "total_lines": 0,
                "content": "",
                "repo_root": self.repo_root.display().to_string(),
                "project_root": self
                    .default_project_root
                    .as_ref()
                    .unwrap_or(&self.repo_root)
                    .display()
                    .to_string(),
            }));
        }
        let start = args.start_line.unwrap_or(1).max(1);
        let end_raw = args.end_line.unwrap_or(total_lines);
        if end_raw < start || start > total_lines || end_raw > total_lines {
            return Err(InvalidRangeError {
                start_line: start,
                end_line: end_raw,
                total_lines,
            }
            .into());
        }
        let start_idx = start.saturating_sub(1);
        let end_idx = end_raw.saturating_sub(1);
        let slice = lines[start_idx..=end_idx].join("\n");
        let (bounded, _) = limits::truncate_bytes(&slice, self.limits.max_content_bytes);
        Ok(json!({
            "path": rel_path.display().to_string(),
            "start_line": start,
            "end_line": end_raw,
            "total_lines": total_lines,
            "content": bounded,
            "repo_root": self.repo_root.display().to_string(),
            "project_root": self
                .default_project_root
                .as_ref()
                .unwrap_or(&self.repo_root)
                .display()
                .to_string(),
        }))
    }

    async fn handle_symbols(&mut self, args: SymbolsArgs) -> Result<serde_json::Value> {
        self.ensure_project_root(args.project_root.as_deref())?;
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
        self.ensure_schema_version("docdex_symbols", args.schema_version)?;
=======
        self.indexer.preflight_index_state()?;
>>>>>>> mcoda/task/bck-05-us-08-t33
=======
        self.ensure_index_ready()?;
>>>>>>> mcoda/task/bck-05-us-08-t02
        if !self.indexer.config().symbols_enabled() {
            return Err(MissingSymbolsDependencyError.into());
        }
<<<<<<< HEAD
<<<<<<< HEAD
        self.ensure_index_fresh()?;
=======
        self.indexer.ensure_index_state()?;
>>>>>>> mcoda/task/bck-05-us-08-t06
=======
        self.ensure_index_fresh()?;
>>>>>>> mcoda/task/bck-05-us-08-t04
=======
        policy::require_enabled(Dependency::Symbols, self.indexer.config().symbols_enabled())?;
>>>>>>> mcoda/task/bck-05-us-07-t30
        let rel_path = normalize_rel_path(&args.path)
            .ok_or(InvalidPathError)?;
        let rel_str = rel_path.to_string_lossy().replace('\\', "/");
<<<<<<< HEAD
<<<<<<< HEAD
        let store = SymbolsStore::new(
            self.indexer.repo_root(),
            self.indexer.config().repo_state_dir(),
        )
=======
        let store = SymbolsStore::new(self.indexer.repo_root(), self.indexer.repo_state_dir())
>>>>>>> mcoda/task/ops-01-us-03-t02
=======
        let store = SymbolsStore::new(self.indexer.repo_root(), &self.indexer.index_data_dir())
>>>>>>> mcoda/task/bck-05-us-07-t10
            .context("open symbols store")?;
        let mut payload = store
            .read_symbols(&rel_str)?
            .ok_or_else(|| MissingSymbolsIndexError {
                rel_path: rel_str.to_string(),
            })?;
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
        apply_symbols_bounds(&self.limits, &mut payload);
=======
        let limit = args
            .limit
            .unwrap_or(SYMBOLS_MAX_LIMIT)
            .clamp(1, SYMBOLS_MAX_LIMIT);
        clamp_symbols_payload(&mut payload, limit);
>>>>>>> mcoda/task/bck-05-us-10-t07
=======
        let limit = args
            .limit
            .unwrap_or(MAX_SYMBOLS_PER_FILE)
            .clamp(1, MAX_SYMBOLS_PER_FILE);
        if payload.symbols.len() > limit {
            payload.symbols.truncate(limit);
        }
>>>>>>> mcoda/task/bck-05-us-10-t03
        Ok(serde_json::to_value(payload).context("serialize symbols payload")?)
=======
        if payload.symbols.len() > SYMBOLS_MAX_ITEMS {
            payload.symbols.truncate(SYMBOLS_MAX_ITEMS);
        }
        let bytes = serde_json::to_vec(&payload).context("serialize symbols payload")?;
        if bytes.len() > SYMBOLS_MAX_BYTES {
            return Err(MaxContentError {
                actual_bytes: bytes.len(),
                max_bytes: SYMBOLS_MAX_BYTES,
            }
            .into());
        }
        let value = serde_json::from_slice(&bytes).context("deserialize symbols payload")?;
        Ok(value)
>>>>>>> mcoda/task/bck-05-us-10-t14
    }

    async fn handle_memory_store(&self, args: MemoryStoreArgs) -> Result<serde_json::Value> {
        self.ensure_project_root(args.project_root.as_deref())?;
<<<<<<< HEAD
        self.ensure_schema_version("docdex_memory_store", args.schema_version)?;
        let Some(memory) = self.memory.clone() else {
            return Err(AppError::new(
                ERR_MEMORY_DISABLED,
                "memory is disabled; set DOCDEX_ENABLE_MEMORY=1",
            )
            .into());
        };
=======
        let memory = policy::require_option(Dependency::Memory, self.memory.clone())?;
>>>>>>> mcoda/task/bck-05-us-07-t30
        let text = args.text.trim();
        if text.is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "text must not be empty").into());
        }

        let embedding = memory.embedder.embed(text).await?;

        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis() as i64;
        let metadata = inject_embedding_metadata(
            args.metadata,
            memory.embedder.provider(),
            memory.embedder.model(),
        );
        let store = memory.store.clone();
        let text_owned = text.to_string();
        let stored = tokio::task::spawn_blocking(move || {
            store.store(&text_owned, &embedding, metadata, created_at)
        })
        .await??;
        Ok(json!({
            "id": stored.0.to_string(),
            "created_at": stored.1
        }))
    }

    async fn handle_memory_recall(&self, args: MemoryRecallArgs) -> Result<serde_json::Value> {
        self.ensure_project_root(args.project_root.as_deref())?;
<<<<<<< HEAD
        self.ensure_schema_version("docdex_memory_recall", args.schema_version)?;
        let Some(memory) = self.memory.clone() else {
            return Err(AppError::new(
                ERR_MEMORY_DISABLED,
                "memory is disabled; set DOCDEX_ENABLE_MEMORY=1",
            )
            .into());
        };
=======
        let memory = policy::require_option(Dependency::Memory, self.memory.clone())?;
>>>>>>> mcoda/task/bck-05-us-07-t30
        let query = args.query.trim();
        if query.is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "query must not be empty").into());
        }

<<<<<<< HEAD
<<<<<<< HEAD
        let top_k = args.top_k.unwrap_or(5).max(1).min(50);
        let max_items = args.max_items.unwrap_or(top_k).min(50);
        let max_tokens = args.max_tokens;
        let embedding = memory.embedder.embed(query).await?;

        let store = memory.store.clone();
        let items = tokio::task::spawn_blocking(move || {
            let candidates = store.recall_candidates(&embedding, top_k)?;
            let budget = max_tokens.unwrap_or(usize::MAX);
            let (kept, _trace) = crate::memory::prune_and_truncate_memory_context(
                &candidates,
                max_items,
                budget,
            );
            Ok::<_, anyhow::Error>(kept)
        })
        .await??;
=======
        let top_k = args
            .top_k
            .unwrap_or(5)
            .max(1)
            .min(self.limits.max_memory_items);
=======
        let top_k = clamp_option(args.top_k, DEFAULT_MEMORY_RECALL, 1, MAX_MEMORY_RECALL);
>>>>>>> mcoda/task/bck-05-us-10-t25
        let embedding = memory.embedder.embed(query).await?;

        let store = memory.store.clone();
        let items = tokio::task::spawn_blocking(move || store.recall(&embedding, top_k)).await??;
        let max_content_bytes = self.limits.max_content_bytes;
>>>>>>> mcoda/task/bck-05-us-10-t26
        Ok(json!({
            "top_k": top_k,
            "results": items
                .into_iter()
                .map(|item| {
                    let (content, _) = limits::truncate_bytes(&item.content, max_content_bytes);
                    json!({
                        "content": content,
                        "score": item.score,
                        "metadata": item.metadata
                    })
                })
                .collect::<Vec<_>>()
        }))
    }

    async fn handle_explainability_record(
        &self,
        args: ExplainabilityRecordArgs,
    ) -> Result<serde_json::Value> {
        self.ensure_project_root(args.project_root.as_deref())?;
        let store = self.explainability.clone();
        let record = args.record;
        let stored = tokio::task::spawn_blocking(move || store.store(record)).await??;
        Ok(json!({
            "completion_id": stored.completion_id,
            "record_bytes": stored.record_bytes
        }))
    }

    async fn handle_resource_read(&self, params: ResourceReadParams) -> Result<serde_json::Value> {
        // Expect uri like docdex://path
        let uri = params.uri.trim();
        let prefix = "docdex://";
        if !uri.starts_with(prefix) {
            return Err(InvalidUriError.into());
        }
        let raw_path = &uri[prefix.len()..];
        let rel = if raw_path.starts_with('/') {
            &raw_path[1..]
        } else {
            raw_path
        };
        let open_args = OpenArgs {
            path: rel.to_string(),
            project_root: None,
            start_line: None,
            end_line: None,
            schema_version: None,
        };
        self.handle_open(open_args).await
    }

<<<<<<< HEAD
<<<<<<< HEAD
    fn ensure_schema_version(&self, schema_name: &'static str, requested: Option<u32>) -> Result<()> {
        if let Some(version) = requested {
            if version < TOOL_SCHEMA_VERSION_MIN || version > TOOL_SCHEMA_VERSION_MAX {
                return Err(
                    AppError::new(ERR_UNSUPPORTED_VERSION, "unsupported schema version")
                        .with_details(schema_version_details(schema_name, version))
                        .into(),
                );
            }
        }
        Ok(())
=======
    fn ensure_index_fresh(&self) -> Result<()> {
        self.indexer.ensure_index_fresh()
>>>>>>> mcoda/task/bck-05-us-08-t32
    }

    fn ensure_same_repo(&self, candidate: &Path) -> Result<()> {
        let resolution = crate::repo_identity::resolve_repo_root(
            candidate,
            vec![
                "Repo may have moved or been renamed.".to_string(),
                "Pass the current repo path (or omit `project_root` to use the MCP server default)."
                    .to_string(),
                "If the MCP server is pointed at the wrong path, restart it with `docdexd mcp --repo <repo>`."
                    .to_string(),
            ],
        )?;
        if resolution.canonical_path != self.repo_root {
            let attempted_fingerprint = crate::repo_identity::repo_fingerprint_sha256(&resolution.canonical_path).ok();
            let details = repo_resolution_details(
                resolution.normalized_path,
                attempted_fingerprint,
                Some(self.repo_root.to_string_lossy().replace('\\', "/")),
                vec![
                    "Repo may have moved or been renamed.".to_string(),
                    "Restart the MCP server with `docdexd mcp --repo <repo>` matching the repo you want to use."
                        .to_string(),
                    "Alternatively, omit `project_root` in tool arguments to use the MCP server default."
                        .to_string(),
                ],
            );
            return Err(
                AppError::new(ERR_UNKNOWN_REPO, "unknown repo")
                    .with_details(details)
                    .into(),
            );
        }

        Ok(())
=======
    fn ensure_same_repo(&self, candidate: &Path) -> Result<()> {
        policy::ensure_repo_match(candidate, &self.repo_root, RepoSurface::Mcp)
            .map(|_| ())
            .map_err(Into::into)
>>>>>>> mcoda/task/bck-05-us-07-t30
    }

    fn ensure_project_root(&self, candidate: Option<&Path>) -> Result<()> {
        policy::ensure_project_root(
            candidate,
            self.default_project_root.as_deref(),
            &self.repo_root,
            RepoSurface::Mcp,
        )
        .map_err(Into::into)
    }

<<<<<<< HEAD
    fn index_recovery_steps(&self) -> Vec<String> {
        vec![
            "Run `docdex_index` (empty `paths`) to build or refresh the index.".to_string(),
            format!(
                "CLI alternative: `docdexd index --repo {}`",
                self.repo_root.display()
            ),
        ]
    }

    fn index_state_details(
        &self,
        stats: Option<&crate::index::IndexStats>,
        scan: &RepoIndexScan,
    ) -> serde_json::Value {
        let mut details = serde_json::Map::new();
        details.insert(
            "repo_root".to_string(),
            json!(self.repo_root.display().to_string()),
        );
        details.insert(
            "state_dir".to_string(),
            json!(self.indexer.config().state_dir().display().to_string()),
        );
        details.insert(
            "repo_indexable_files".to_string(),
            json!(scan.indexable_files),
        );
        if let Some(mtime) = scan.latest_mtime_epoch_ms {
            details.insert("repo_last_modified_epoch_ms".to_string(), json!(mtime));
        }
        if let Some(stats) = stats {
            details.insert("index_doc_count".to_string(), json!(stats.num_docs));
            details.insert("index_segments".to_string(), json!(stats.segments));
            if let Some(last_updated) = stats.last_updated_epoch_ms {
                details.insert(
                    "index_last_updated_epoch_ms".to_string(),
                    json!(last_updated),
                );
            }
        }
        details.insert(
            "recoverySteps".to_string(),
            serde_json::Value::Array(
                self.index_recovery_steps()
                    .into_iter()
                    .map(serde_json::Value::String)
                    .collect(),
            ),
        );
        serde_json::Value::Object(details)
    }

    fn ensure_index_ready(&self) -> Result<()> {
        let state_dir = self.indexer.config().state_dir();
        let scan = scan_repo_indexable_files(self.indexer.repo_root(), self.indexer.config());
        if !state_dir.exists() {
            return Err(
                AppError::new(
                    ERR_MISSING_INDEX,
                    format!(
                        "index state dir not found at {}; run `docdex_index` or `docdexd index --repo {}`",
                        state_dir.display(),
                        self.repo_root.display()
                    ),
                )
                .with_details(self.index_state_details(None, &scan))
                .into(),
            );
        }
        let stats = self.indexer.stats()?;
        if stats.num_docs == 0 && scan.indexable_files > 0 {
            return Err(
                AppError::new(
                    ERR_MISSING_INDEX,
                    format!(
                        "index has no documents; run `docdex_index` or `docdexd index --repo {}`",
                        self.repo_root.display()
                    ),
                )
                .with_details(self.index_state_details(Some(&stats), &scan))
                .into(),
            );
        }
        if let (Some(index_updated), Some(repo_latest)) =
            (stats.last_updated_epoch_ms, scan.latest_mtime_epoch_ms)
        {
            if repo_latest > index_updated {
                return Err(
                    AppError::new(
                        ERR_STALE_INDEX,
                        format!(
                            "index is stale; run `docdex_index` or `docdexd index --repo {}`",
                            self.repo_root.display()
                        ),
                    )
                    .with_details(self.index_state_details(Some(&stats), &scan))
                    .into(),
                );
            }
        }
        Ok(())
    }
}

fn apply_search_bounds(limits: &MaxSizePolicy, hits: &mut [crate::index::Hit]) {
    for hit in hits {
        let (summary, summary_truncated) =
            limits::truncate_chars(&hit.summary, limits.max_summary_chars);
        if summary_truncated {
            hit.summary = summary;
        }
        let (snippet, snippet_truncated) =
            limits::truncate_chars(&hit.snippet, limits.max_snippet_chars);
        if snippet_truncated {
            hit.snippet = snippet;
            hit.snippet_truncated = Some(true);
        }
    }
}

fn apply_symbols_bounds(limits: &MaxSizePolicy, payload: &mut crate::symbols::SymbolsResponseV1) {
    if payload.symbols.len() > limits.max_symbols_items {
        payload.symbols.truncate(limits.max_symbols_items);
    }
    if let Some(outcome) = payload.outcome.as_mut() {
        if let Some(reason) = outcome.reason.as_mut() {
            let (bounded, _) = limits::truncate_chars(reason, limits.max_summary_chars);
            *reason = bounded;
        }
        if let Some(summary) = outcome.error_summary.as_mut() {
            let (bounded, _) = limits::truncate_chars(summary, limits.max_summary_chars);
            *summary = bounded;
        }
=======
    fn ensure_index_ready(&self) -> Result<()> {
        crate::index::ensure_index_ready(&self.repo_root, self.indexer.config())
>>>>>>> mcoda/task/bck-05-us-08-t05
    }
}

fn is_lock_busy(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        if let Some(app) = cause.downcast_ref::<AppError>() {
            return app.code == ERR_BACKOFF_REQUIRED;
        }
        if let Some(tantivy_err) = cause.downcast_ref::<TantivyError>() {
            if let TantivyError::LockFailure(lock_err, _) = tantivy_err {
                return matches!(lock_err, LockError::LockBusy);
            }
        }
        // Fallback: match on string in case the error is wrapped differently.
        let msg = cause.to_string();
        msg.contains("LockBusy") || msg.contains("Failed to acquire Lockfile")
    })
}

async fn write_response(writer: &mut BufWriter<io::Stdout>, resp: &RpcResponse) -> Result<()> {
    let payload = serde_json::to_vec(resp)?;
    writer.write_all(&payload).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    Ok(())
}

fn normalize_rel_path(input: &str) -> Option<PathBuf> {
    let path = Path::new(input);
    if path.is_absolute() {
        return None;
    }
    let mut clean = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => continue,
            Component::Normal(part) => clean.push(part),
            _ => return None, // rejects ParentDir/Prefix/RootDir
        }
    }
    if clean.as_os_str().is_empty() {
        None
    } else {
        Some(clean)
    }
}

fn normalize_rel_for_prefix(path: &Path) -> Option<String> {
    let mut cleaned = path
        .to_string_lossy()
        .replace('\\', "/")
        .trim_start_matches('/')
        .to_lowercase();
    if cleaned.is_empty() {
        return None;
    }
    Some(cleaned)
}

fn normalize_for_details(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn scan_repo_for_index_state(
    repo_root: &Path,
    config: &IndexConfig,
    index_last_updated_epoch_ms: Option<u128>,
) -> Result<RepoScanResult> {
    let mut has_indexable = false;
    let mut latest_epoch_ms: Option<u128> = None;
    let mut newer_than_index = false;

    let state_dir = config.state_dir();
    let excluded_dir_names = config.excluded_dir_names();
    let excluded_prefixes = config.excluded_relative_prefixes();

    let walker = WalkDir::new(repo_root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| {
            if entry.file_type().is_file() {
                return true;
            }
            let path = entry.path();
            if path == repo_root {
                return true;
            }
            if path.starts_with(state_dir) {
                return false;
            }
            let Ok(rel) = path.strip_prefix(repo_root) else {
                return true;
            };
            let mut normalized = match normalize_rel_for_prefix(rel) {
                Some(value) => value,
                None => return true,
            };
            if entry.file_type().is_dir() {
                normalized.push('/');
            }
            if excluded_prefixes
                .iter()
                .any(|prefix| normalized.starts_with(prefix))
            {
                return false;
            }
            if let Some(name) = path.file_name().and_then(|value| value.to_str()) {
                let name_lower = name.to_lowercase();
                if excluded_dir_names
                    .iter()
                    .any(|excluded| excluded == &name_lower)
                {
                    return false;
                }
            }
            true
        });

    for entry in walker {
        let entry = match entry {
            Ok(value) => value,
            Err(_) => continue,
        };
        if !entry.file_type().is_file() {
            continue;
        }
        if !crate::index::decide_file(entry.path(), repo_root, config).should_index() {
            continue;
        }
        has_indexable = true;
        let meta = match entry.metadata() {
            Ok(value) => value,
            Err(_) => continue,
        };
        let modified = match meta.modified() {
            Ok(value) => value,
            Err(_) => continue,
        };
        let epoch_ms = match modified.duration_since(SystemTime::UNIX_EPOCH) {
            Ok(value) => value.as_millis(),
            Err(_) => continue,
        };
        if let Some(index_last) = index_last_updated_epoch_ms {
            if epoch_ms > index_last {
                newer_than_index = true;
                latest_epoch_ms = Some(epoch_ms.max(latest_epoch_ms.unwrap_or(0)));
                break;
            }
        }
        latest_epoch_ms = Some(latest_epoch_ms.map_or(epoch_ms, |current| current.max(epoch_ms)));
    }

    Ok(RepoScanResult {
        has_indexable,
        latest_epoch_ms,
        newer_than_index,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use crate::error::MAX_RATE_LIMIT_FIELD_BYTES;
    use std::collections::HashSet;
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::Duration;

    fn assert_rate_limit_keys(
        obj: &serde_json::Map<String, serde_json::Value>,
        include_retry_at: bool,
    ) {
        let mut keys: Vec<String> = obj.keys().cloned().collect();
        keys.sort();
        let mut expected = vec![
            "code".to_string(),
            "limit_key".to_string(),
            "retry_after_ms".to_string(),
            "scope".to_string(),
        ];
        if include_retry_at {
            expected.push("retry_at".to_string());
        }
        expected.sort();
        assert_eq!(keys, expected, "rate-limit data keys must remain stable");
    }

    #[test]
    fn rate_limited_rpc_has_stable_data_shape() {
<<<<<<< HEAD
        let err = RateLimited::new(Duration::from_millis(0), "mcp_tools".to_string(), "global".to_string());
        let rpc = rpc_rate_limited(&err, None);
=======
        let err = RateLimited::new(
            Duration::from_millis(0),
            "mcp_tools".to_string(),
            "global".to_string(),
            "global".to_string(),
            60,
            1,
            1,
        );
        let rpc = rpc_rate_limited(&err);
>>>>>>> mcoda/task/bck-05-us-09-t05
        assert_eq!(rpc.code, ERR_RATE_LIMITED_RPC);
        let data = rpc.data.expect("rate limited rpc should include data");
        let obj = data.as_object().expect("rate limited data should be object");
        assert_rate_limit_keys(obj, false);
        assert_eq!(obj.get("code").and_then(|v| v.as_str()), Some(ERR_RATE_LIMITED));
<<<<<<< HEAD
<<<<<<< HEAD
        assert_eq!(obj.get("message").and_then(|v| v.as_str()), Some("rate limited"));
=======
        assert!(obj.get("message").and_then(|v| v.as_str()).is_some());
>>>>>>> mcoda/task/bck-05-us-09-t24
=======
        assert_eq!(obj.get("message").and_then(|v| v.as_str()), Some("rate limited"));
        let envelope = obj
            .get("error")
            .and_then(|value| value.as_object())
            .expect("rate limited data should include error envelope");
        assert_eq!(
            envelope.get("code").and_then(|v| v.as_str()),
            Some(ERR_RATE_LIMITED)
        );
        assert_eq!(
            envelope.get("message").and_then(|v| v.as_str()),
            Some("rate limited")
        );
        let details = envelope
            .get("details")
            .and_then(|value| value.as_object())
            .expect("rate limited data should include details");
        assert_eq!(
            details.get("retry_after_ms").and_then(|v| v.as_u64()),
            Some(0)
        );
>>>>>>> mcoda/task/bck-05-us-09-t37
        assert_eq!(obj.get("retry_after_ms").and_then(|v| v.as_u64()), Some(0));
        assert_eq!(obj.get("limit_key").and_then(|v| v.as_str()), Some("mcp_tools"));
        assert_eq!(obj.get("scope").and_then(|v| v.as_str()), Some("global"));
        assert_eq!(obj.get("resource_key").and_then(|v| v.as_str()), Some("global"));
        assert_eq!(obj.get("limit_per_min").and_then(|v| v.as_u64()), Some(60));
        assert_eq!(obj.get("limit_burst").and_then(|v| v.as_u64()), Some(1));
        assert!(obj.get("denied_total").and_then(|v| v.as_u64()).is_some());
        assert!(obj.get("retry_at").is_none(), "retry_at should be omitted when unset");
<<<<<<< HEAD
=======
        let details = obj
            .get("details")
            .and_then(|v| v.as_object())
            .expect("rate limited data should include details");
        assert_eq!(details.get("retry_after_ms").and_then(|v| v.as_u64()), Some(0));
        assert_eq!(details.get("limit_key").and_then(|v| v.as_str()), Some("mcp_tools"));
        assert_eq!(details.get("scope").and_then(|v| v.as_str()), Some("global"));
        assert!(details.get("retry_at").is_none(), "details.retry_at should be omitted when unset");
>>>>>>> mcoda/task/bck-05-us-09-t24
        let nested = obj
            .get("error")
            .and_then(|v| v.as_object())
            .expect("rate limited data should include error envelope");
<<<<<<< HEAD
        assert_eq!(
            nested.get("code").and_then(|v| v.as_str()),
            Some(ERR_RATE_LIMITED)
        );
        assert_eq!(
            nested.get("message").and_then(|v| v.as_str()),
            Some("rate limited")
        );
        let details = nested
            .get("details")
            .and_then(|v| v.as_object())
            .expect("rate limited error should include details");
        assert_eq!(
            details.get("retry_after_ms").and_then(|v| v.as_u64()),
            Some(0)
        );
        assert_eq!(
            details.get("limit_key").and_then(|v| v.as_str()),
            Some("mcp_tools")
        );
        assert_eq!(details.get("scope").and_then(|v| v.as_str()), Some("global"));
    }

    #[test]
    fn backoff_required_rpc_preserves_code_and_retry_hints() {
        let err = RateLimited::backoff_required(
            Duration::from_millis(500),
            "browser_session".to_string(),
            "global".to_string(),
        );
        let rpc = rpc_rate_limited(&err);
        let data = rpc.data.expect("backoff rpc should include data");
        let obj = data.as_object().expect("backoff data should be object");
        assert_eq!(obj.get("code").and_then(|v| v.as_str()), Some(ERR_BACKOFF_REQUIRED));
        assert_eq!(obj.get("retry_after_ms").and_then(|v| v.as_u64()), Some(500));
        assert_eq!(obj.get("limit_key").and_then(|v| v.as_str()), Some("browser_session"));
        assert_eq!(obj.get("scope").and_then(|v| v.as_str()), Some("global"));
=======
        assert_eq!(nested.get("code").and_then(|v| v.as_str()), Some(ERR_RATE_LIMITED));
>>>>>>> mcoda/task/bck-05-us-09-t24
    }

    #[test]
    fn rate_limited_rpc_truncates_long_message_and_allows_retry_at() {
<<<<<<< HEAD
        let long_key = "k".repeat(2048);
        let long_scope = "s".repeat(2048);
        let err = RateLimited::new(Duration::from_millis(1234), long_key, long_scope)
=======
        let err = RateLimited::new(
            Duration::from_millis(1234),
            "bucket".to_string(),
            "global".to_string(),
            "global".to_string(),
            60,
            1,
            1,
        )
>>>>>>> mcoda/task/bck-05-us-09-t05
            .with_message("x".repeat(10_000))
            .with_retry_at(Utc::now());
        let rpc = rpc_rate_limited(&err, None);
        assert!(
            rpc.message.len() <= MAX_ERROR_MESSAGE_BYTES + "…".len(),
            "rpc error message should be bounded"
        );
        let data = rpc.data.expect("rate limited rpc should include data");
        let obj = data.as_object().expect("rate limited data should be object");
<<<<<<< HEAD
        assert_rate_limit_keys(obj, true);
=======
        let data_message = obj
            .get("message")
            .and_then(|value| value.as_str())
            .expect("rate limited data should include message");
        assert!(
            data_message.len() <= MAX_ERROR_MESSAGE_BYTES + "…".len(),
            "rate limited data message should be bounded"
        );
>>>>>>> mcoda/task/bck-05-us-09-t37
        assert!(obj.get("retry_at").and_then(|v| v.as_str()).is_some());
        assert_eq!(obj.get("retry_after_ms").and_then(|v| v.as_u64()), Some(1234));
<<<<<<< HEAD
<<<<<<< HEAD
        let message = obj
            .get("message")
            .and_then(|v| v.as_str())
            .expect("rate limited data should include message");
        assert!(
            message.len() <= MAX_ERROR_MESSAGE_BYTES + "…".len(),
            "rate limited data message should be bounded"
        );
    }

    #[test]
    fn rate_limited_rpc_truncates_detail_fields_and_bounds_payload() {
        let long = "x".repeat(MAX_RATE_LIMIT_FIELD_BYTES * 8);
        let err = RateLimited::new(Duration::from_millis(1), long.clone(), long);
        let rpc = rpc_rate_limited(&err);
        let data = rpc.data.expect("rate limited rpc should include data");
        let obj = data.as_object().expect("rate limited data should be object");
        let limit_key = obj
            .get("limit_key")
            .and_then(|v| v.as_str())
            .expect("limit_key should be a string");
        let scope = obj
            .get("scope")
            .and_then(|v| v.as_str())
            .expect("scope should be a string");
        assert!(
            limit_key.len() <= MAX_RATE_LIMIT_FIELD_BYTES,
            "limit_key should be truncated"
        );
        assert!(
            scope.len() <= MAX_RATE_LIMIT_FIELD_BYTES,
            "scope should be truncated"
        );
        let payload_bytes = serde_json::to_vec(&rpc).expect("rpc error should serialize");
        assert!(
            payload_bytes.len() <= MCP_RATE_LIMIT_PAYLOAD_MAX_BYTES,
            "rpc rate-limit payload should remain small (got {} bytes)",
            payload_bytes.len()
=======
        let limit_key = obj
            .get("limit_key")
            .and_then(|v| v.as_str())
            .expect("rate-limit data should include limit_key");
        assert!(
            limit_key.len() <= MAX_RATE_LIMIT_FIELD_BYTES + "…".len(),
            "limit_key should be bounded"
        );
        let scope = obj
            .get("scope")
            .and_then(|v| v.as_str())
            .expect("rate-limit data should include scope");
        assert!(
            scope.len() <= MAX_RATE_LIMIT_FIELD_BYTES + "…".len(),
            "scope should be bounded"
>>>>>>> mcoda/task/bck-05-us-09-t30
        );
    }

    #[test]
    fn backoff_required_rpc_has_stable_data_shape() {
        let err = BackoffRequired::new(
            Duration::from_millis(0),
            "index_writer".to_string(),
            "index".to_string(),
        );
        let rpc = rpc_backoff_required(&err);
        assert_eq!(rpc.code, ERR_INVALID_PARAMS);
        let data = rpc.data.expect("backoff rpc should include data");
        let obj = data.as_object().expect("backoff data should be object");
        assert_eq!(
            obj.get("code").and_then(|v| v.as_str()),
            Some(ERR_BACKOFF_REQUIRED)
        );
        assert_eq!(obj.get("retry_after_ms").and_then(|v| v.as_u64()), Some(0));
        assert_eq!(
            obj.get("limit_key").and_then(|v| v.as_str()),
            Some("index_writer")
        );
        assert_eq!(obj.get("scope").and_then(|v| v.as_str()), Some("index"));
        assert!(obj.get("retry_at").is_none(), "retry_at should be omitted when unset");
    }

    #[test]
    fn backoff_required_rpc_truncates_long_message_and_bounds_payload() {
        let err = BackoffRequired::new(
            Duration::from_millis(2500),
            "chrome_concurrency".to_string(),
            "tier2".to_string(),
        )
        .with_message("x".repeat(10_000))
        .with_retry_at(Utc::now());
        let rpc = rpc_backoff_required(&err);
        assert!(
            rpc.message.len() <= MAX_ERROR_MESSAGE_BYTES + "…".len(),
            "rpc error message should be bounded"
        );
        let data = rpc.data.expect("backoff rpc should include data");
        let obj = data.as_object().expect("backoff data should be object");
        assert!(obj.get("retry_at").and_then(|v| v.as_str()).is_some());
        assert_eq!(obj.get("retry_after_ms").and_then(|v| v.as_u64()), Some(2500));
        assert!(
            obj.keys().all(|k| matches!(
                k.as_str(),
                "code" | "retry_after_ms" | "retry_at" | "limit_key" | "scope"
            )),
            "backoff data should only include stable keys"
        );
        let payload_bytes = serde_json::to_vec(&rpc).expect("rpc error should serialize");
        assert!(
            payload_bytes.len() <= 2048,
            "rpc backoff payload should remain small (got {} bytes)",
            payload_bytes.len()
        );
    }

    #[test]
    fn backoff_required_rpc_has_stable_data_shape() {
        let err = BackoffRequired::new(
            "index writer unavailable (another docdexd may be indexing); retry later",
            "index_writer",
            "repo",
        );
        let rpc = rpc_backoff_required(&err);
        assert_eq!(rpc.code, ERR_INVALID_PARAMS);
        let data = rpc
            .data
            .expect("backoff required rpc should include data");
        let obj = data
            .as_object()
            .expect("backoff required data should be object");
        assert_eq!(
            obj.get("code").and_then(|v| v.as_str()),
            Some(ERR_BACKOFF_REQUIRED)
        );
        assert!(
            obj.get("retry_after_ms").and_then(|v| v.as_u64()).is_some(),
            "retry_after_ms must be an integer"
        );
        assert_eq!(
            obj.get("limit_key").and_then(|v| v.as_str()),
            Some("index_writer")
        );
        assert_eq!(obj.get("scope").and_then(|v| v.as_str()), Some("repo"));
        assert!(obj.get("retry_at").is_none(), "retry_at should be omitted when unset");
        assert!(
            obj.keys().all(|k| {
                matches!(
                    k.as_str(),
                    "code" | "retry_after_ms" | "retry_at" | "limit_key" | "scope"
                )
            }),
            "backoff data should only include stable keys"
        );
    }

    #[test]
    fn backoff_required_rpc_truncates_long_message_and_allows_retry_at() {
        let err = BackoffRequired::new("x".repeat(10_000), "index_writer", "repo")
            .with_retry_at(Utc::now());
        let rpc = rpc_backoff_required(&err);
        assert!(
            rpc.message.len() <= MAX_ERROR_MESSAGE_BYTES + "…".len(),
            "rpc error message should be bounded"
        );
        let data = rpc
            .data
            .expect("backoff required rpc should include data");
        let obj = data
            .as_object()
            .expect("backoff required data should be object");
        assert!(obj.get("retry_at").and_then(|v| v.as_str()).is_some());
=======
        let details = obj
            .get("details")
            .and_then(|v| v.as_object())
            .expect("rate limited data should include details");
        assert!(details.get("retry_at").and_then(|v| v.as_str()).is_some());
>>>>>>> mcoda/task/bck-05-us-09-t24
    }

    #[test]
    fn rate_limited_rpc_schema_is_stable_under_concurrency() {
        let limiter = RateLimiter::<()>::new(6, 1);
        let threads = 48usize;
        let barrier = Arc::new(Barrier::new(threads));

        let mut handles = Vec::with_capacity(threads);
        for _ in 0..threads {
            let limiter = limiter.clone();
            let barrier = barrier.clone();
            handles.push(thread::spawn(move || {
                barrier.wait();
                limiter.check_or_rate_limited((), "mcp_tools", "global", "global")
            }));
        }

        let mut rate_limited_count = 0usize;
        let mut schema_variants: HashSet<Vec<String>> = HashSet::new();
        for handle in handles {
            match handle.join().expect("thread panicked") {
                Ok(()) => {}
                Err(err) => {
                    rate_limited_count += 1;
                    let rpc = rpc_rate_limited(&err, None);
                    assert_eq!(rpc.code, ERR_RATE_LIMITED_RPC);
                    assert!(
                        rpc.message.len() <= MAX_ERROR_MESSAGE_BYTES + "…".len(),
                        "rpc error message should remain bounded"
                    );
                    let data = rpc.data.as_ref().expect("rate limited rpc should include data");
                    let obj = data.as_object().expect("rate limited data should be object");
                    assert_rate_limit_keys(obj, false);
                    let mut keys: Vec<String> = obj.keys().cloned().collect();
                    keys.sort();
                    schema_variants.insert(keys);

                    assert_eq!(
                        obj.get("code").and_then(|v| v.as_str()),
                        Some(ERR_RATE_LIMITED)
                    );
<<<<<<< HEAD
                    assert!(obj.get("message").and_then(|v| v.as_str()).is_some());
=======
                    assert!(obj.get("error").is_some(), "error envelope should be present");
>>>>>>> mcoda/task/bck-05-us-09-t24
                    assert!(
                        obj.get("retry_after_ms").and_then(|v| v.as_u64()).is_some(),
                        "retry_after_ms must be an integer"
                    );
                    assert_eq!(
                        obj.get("limit_key").and_then(|v| v.as_str()),
                        Some("mcp_tools")
                    );
                    assert_eq!(obj.get("scope").and_then(|v| v.as_str()), Some("global"));
<<<<<<< HEAD
<<<<<<< HEAD
                    assert!(
                        obj.get("error").and_then(|v| v.as_object()).is_some(),
                        "rate limited data should include error envelope"
                    );
=======
                    let details = obj
                        .get("details")
                        .and_then(|v| v.as_object())
                        .expect("rate limited data should include details");
                    assert!(details
                        .get("retry_after_ms")
                        .and_then(|v| v.as_u64())
                        .is_some());
>>>>>>> mcoda/task/bck-05-us-09-t24
=======
                    assert_eq!(
                        obj.get("resource_key").and_then(|v| v.as_str()),
                        Some("global")
                    );
                    assert_eq!(obj.get("limit_per_min").and_then(|v| v.as_u64()), Some(6));
                    assert_eq!(obj.get("limit_burst").and_then(|v| v.as_u64()), Some(1));
                    assert!(obj.get("denied_total").and_then(|v| v.as_u64()).is_some());
>>>>>>> mcoda/task/bck-05-us-09-t05

                    let payload_bytes = serde_json::to_vec(&rpc).expect("rpc error should serialize");
                    assert!(
<<<<<<< HEAD
                        payload_bytes.len() <= MCP_RATE_LIMIT_PAYLOAD_MAX_BYTES,
=======
                        payload_bytes.len() <= MAX_RATE_LIMIT_PAYLOAD_BYTES,
>>>>>>> mcoda/task/bck-05-us-09-t37
                        "rpc rate-limit payload should remain small (got {} bytes)",
                        payload_bytes.len()
                    );
                }
            }
        }

        assert!(
            rate_limited_count >= threads / 2,
            "expected most concurrent calls to be rate limited (got {rate_limited_count} out of {threads})"
        );
        assert_eq!(
            schema_variants.len(),
            1,
            "rate-limit data schema should not vary under concurrency"
        );
    }

    #[test]
<<<<<<< HEAD
<<<<<<< HEAD
    fn backoff_required_rpc_has_stable_data_shape() {
        let err = BackoffRequired::new(
            Duration::from_millis(500),
            "index_writer".to_string(),
            "repo".to_string(),
        )
        .with_message("x".repeat(10_000))
        .with_retry_at(Utc::now());
        let rpc = rpc_backoff_required(&err);
        assert_eq!(rpc.code, ERR_INVALID_PARAMS);
        assert!(
            rpc.message.len() <= MAX_ERROR_MESSAGE_BYTES + "…".len(),
            "rpc error message should be bounded"
        );
        let data = rpc.data.expect("backoff rpc should include data");
        let obj = data.as_object().expect("backoff data should be object");
=======
    fn backoff_required_rpc_includes_retry_hints() {
        let details = crate::error::backoff_required_details("index_writer", "repo");
        let rpc = rpc_error(
            ERR_INVALID_PARAMS,
            default_message_for_code(ERR_BACKOFF_REQUIRED),
            ERR_BACKOFF_REQUIRED,
            None,
            Some("docdex_index"),
            Some(details),
        );
        let data = rpc.data.expect("backoff required rpc should include data");
        let obj = data.as_object().expect("backoff required data should be object");
>>>>>>> mcoda/task/bck-05-us-09-t37
        assert_eq!(
            obj.get("code").and_then(|v| v.as_str()),
            Some(ERR_BACKOFF_REQUIRED)
        );
<<<<<<< HEAD
        assert_eq!(obj.get("retry_after_ms").and_then(|v| v.as_u64()), Some(500));
        assert_eq!(
            obj.get("limit_key").and_then(|v| v.as_str()),
            Some("index_writer")
        );
        assert_eq!(obj.get("scope").and_then(|v| v.as_str()), Some("repo"));
        assert!(obj.get("retry_at").and_then(|v| v.as_str()).is_some());

        let mut keys: Vec<String> = obj.keys().cloned().collect();
        keys.sort();
        assert_eq!(
            keys,
            vec![
                "code".to_string(),
                "limit_key".to_string(),
                "retry_after_ms".to_string(),
                "retry_at".to_string(),
                "scope".to_string(),
            ]
        );

        let payload_bytes = serde_json::to_vec(&rpc).expect("rpc error should serialize");
        assert!(
            payload_bytes.len() <= 2048,
            "rpc backoff payload should remain small (got {} bytes)",
            payload_bytes.len()
        );
=======
    fn tier2_unavailable_rpc_is_distinct_from_rate_limit() {
        let err = Tier2Unavailable::new(
            crate::tier2::Tier2UnavailableReason::Overload,
            "tier 2 browser capacity exhausted",
        )
        .with_correlation_id("req-123");
        let rpc = rpc_tier2_unavailable(&err, Some("docdex_search"));
        assert_eq!(rpc.code, ERR_INVALID_PARAMS);
        let data = rpc.data.expect("tier2 unavailable rpc should include data");
        let obj = data
            .as_object()
            .expect("tier2 unavailable data should be object");
        assert_eq!(
            obj.get("code").and_then(|v| v.as_str()),
            Some(ERR_TIER2_UNAVAILABLE)
        );
        assert_eq!(
            obj.get("reason").and_then(|v| v.as_str()),
            Some("overload")
        );
        let details = obj
            .get("details")
            .and_then(|v| v.as_object())
            .expect("tier2 unavailable should include details");
        assert_eq!(
            details.get("reason").and_then(|v| v.as_str()),
            Some("overload")
        );
        assert_eq!(
            details.get("correlation_id").and_then(|v| v.as_str()),
            Some("req-123")
        );
        assert!(obj.get("retry_after_ms").is_none());
        assert!(obj.get("retry_at").is_none());
        assert!(obj.get("limit_key").is_none());
        assert!(obj.get("scope").is_none());
>>>>>>> mcoda/task/bck-05-us-09-t21
=======
        assert_eq!(
            obj.get("retry_after_ms").and_then(|v| v.as_u64()),
            Some(crate::error::DEFAULT_BACKOFF_REQUIRED_MS)
        );
        assert_eq!(obj.get("limit_key").and_then(|v| v.as_str()), Some("index_writer"));
        assert_eq!(obj.get("scope").and_then(|v| v.as_str()), Some("repo"));
        assert!(obj.get("retry_at").is_none(), "retry_at should be omitted when unset");

        let payload_bytes = serde_json::to_vec(&rpc).expect("rpc error should serialize");
        assert!(
            payload_bytes.len() <= MAX_RATE_LIMIT_PAYLOAD_BYTES,
            "rpc backoff payload should remain small (got {} bytes)",
            payload_bytes.len()
        );
>>>>>>> mcoda/task/bck-05-us-09-t37
    }
}
