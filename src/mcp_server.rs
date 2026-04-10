use crate::capabilities::{self, BATCH_SEARCH_MAX_QUERIES, RERANK_MAX_CANDIDATES};
use crate::config;
use crate::dag::logging as dag_logging;
use crate::delegation_telemetry;
use crate::diff;
use crate::error::{
    repo_resolution_details, AppError, RateLimited, ERR_BACKOFF_REQUIRED,
    ERR_CONVERSATION_NOT_FOUND, ERR_DELEGATION_LOCAL_REQUIRED, ERR_EMBEDDING_FAILED,
    ERR_EMBEDDING_MODEL_NOT_FOUND, ERR_EMBEDDING_TIMEOUT, ERR_INDEXING_IN_PROGRESS,
    ERR_INTERNAL_ERROR, ERR_INVALID_ARGUMENT, ERR_KNOWLEDGE_EPISODE_NOT_FOUND, ERR_MEMORY_DISABLED,
    ERR_MISSING_DEPENDENCY, ERR_MISSING_INDEX, ERR_MISSING_REPO, ERR_MISSING_REPO_PATH,
    ERR_RATE_LIMITED, ERR_REPO_STATE_MISMATCH, ERR_STALE_INDEX, ERR_UNAUTHORIZED, ERR_UNKNOWN_REPO,
};
use crate::impact::{build_impact_diagnostics_response, ImpactDiagnosticsEntry, ImpactGraphStore};
use crate::index::{IndexConfig, Indexer};
use crate::libs;
use crate::llm::delegation::{
    allowlist_allows, build_local_target_candidates_with_config, build_primary_target_candidates,
    compute_cost_micros, compute_delegation_savings, filter_automatic_local_targets_by_cost,
    local_selection_policy_requires_fresh_library, mode_from_config, parse_local_target_override,
    resolve_explicit_target, resolve_local_cost_per_million, resolve_primary_cost_per_million,
    resolve_task_scoped_delegation_config, run_delegation_flow_with_failure_history,
    update_cached_local_selection_from_completion, DelegationEnforcementError,
    DelegationFailureHistoryContext, DelegationMode, DelegationPricingContext, LocalTarget,
    TaskType,
};
use crate::llm::local_library::{
    delegation_is_enabled, load_local_library, refresh_local_library,
    refresh_local_library_if_stale, refresh_local_library_if_stale_with_web,
    refresh_local_library_with_web, resolve_local_ollama_base_url,
};
use crate::memory::{inject_embedding_metadata, repo_state_root_from_state_dir, MemoryStore};
use crate::metrics::{self, DelegationMetrics, DelegationTelemetrySnapshot};
use crate::ollama::OllamaEmbedder;
use crate::orchestrator::web::{run_web_research, WebResearchResponse};
use crate::orchestrator::{
    memory_budget_from_max_answer_tokens, run_waterfall, ProfileBudget, WaterfallPlan,
    WaterfallRequest, WebGateConfig,
};
use crate::profiles::{ProfileEmbedder, ProfileManager};
use crate::ratelimit::RateLimiter;
use crate::search;
use crate::symbols::SymbolsStore;
use crate::tier2::Tier2Config;
use crate::tree::{render_tree, TreeOptions};
use anyhow::{Context, Result};
use reqwest::{Client, Method};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tantivy::directory::error::LockError;
use tantivy::TantivyError;
use thiserror::Error;
use tracing::{debug, warn};
use uuid::Uuid;

const JSONRPC_VERSION: &str = "2.0";
const ERR_PARSE: i32 = -32700;
const ERR_INVALID_REQUEST: i32 = -32600;
const ERR_METHOD_NOT_FOUND: i32 = -32601;
const ERR_INVALID_PARAMS: i32 = -32602;
const ERR_INTERNAL: i32 = -32000;
const ERR_RATE_LIMITED_RPC: i32 = -32029;
const FILES_DEFAULT_LIMIT: usize = 200;
const FILES_MAX_LIMIT: usize = 1000;
const FILES_MAX_OFFSET: usize = 50_000;
const OPEN_MAX_BYTES: usize = 10 * 1024 * 1024; // guard rail for returning file content
const AST_DEFAULT_MAX_NODES: usize = 20_000;
const AST_MAX_NODES: usize = 100_000;
const DIAGNOSTICS_DEFAULT_LIMIT: usize = 200;
const DIAGNOSTICS_MAX_LIMIT: usize = 1000;
const CONVERSATION_LIST_DEFAULT_LIMIT: usize = 20;
const CONVERSATION_LIST_MAX_LIMIT: usize = 100;
const MAX_ERROR_MESSAGE_BYTES: usize = 256;
const MAX_ERROR_REASON_BYTES: usize = 768;
const DEFAULT_FALLBACK_EMBED_DIM: usize = 768;

#[derive(Error, Debug)]
#[error("path must be relative and not contain parent components")]
struct InvalidPathError;

#[derive(Error, Debug)]
#[error("file too large ({actual_bytes} bytes > {max_bytes} limit)")]
struct MaxContentError {
    actual_bytes: usize,
    max_bytes: usize,
}

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
#[error("symbol extraction is unavailable; reindex the repo to rebuild symbols")]
struct MissingSymbolsDependencyError;

#[derive(Error, Debug)]
#[error("no symbols record found for {rel_path}; run docdex_index")]
struct MissingSymbolsIndexError {
    rel_path: String,
}

#[derive(Error, Debug)]
#[error("no ast record found for {rel_path}; run docdex_index")]
struct MissingAstIndexError {
    rel_path: String,
}

#[derive(Error, Debug)]
#[error("symbols require reindex after parser version change")]
struct StaleSymbolsIndexError;

fn mcp_error_data(
    code: &'static str,
    message: String,
    reason: Option<String>,
    tool: Option<&str>,
    details: Option<serde_json::Value>,
) -> serde_json::Value {
    let message = truncate_bytes(message, MAX_ERROR_MESSAGE_BYTES);
    let message_for_data = message.clone();
    let mut envelope_error = serde_json::Map::new();
    envelope_error.insert("code".to_string(), json!(code));
    envelope_error.insert("message".to_string(), json!(message));
    if let Some(reason) = reason
        .clone()
        .map(|value| truncate_bytes(value, MAX_ERROR_REASON_BYTES))
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
    if let Some(reason) = reason.map(|value| truncate_bytes(value, MAX_ERROR_REASON_BYTES)) {
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

fn mcp_rate_limited_data(err: &RateLimited) -> serde_json::Value {
    #[derive(Serialize)]
    struct RateLimitData<'a> {
        code: &'static str,
        retry_after_ms: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        retry_at: Option<String>,
        limit_key: &'a str,
        scope: &'a str,
    }

    serde_json::to_value(RateLimitData {
        code: ERR_RATE_LIMITED,
        retry_after_ms: err.retry_after_ms,
        retry_at: err.retry_at.as_ref().map(|at| at.to_rfc3339()),
        limit_key: &err.limit_key,
        scope: &err.scope,
    })
    .expect("rate-limit data should serialize")
}

fn truncate_bytes(input: String, max_bytes: usize) -> String {
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

fn format_web_text(response: &WebResearchResponse) -> String {
    let mut text = response.completion.trim().to_string();
    for hit in &response.hits {
        if !hit.summary.trim().is_empty() {
            text.push('\n');
            text.push_str(hit.summary.trim());
        }
        if !hit.snippet.trim().is_empty() {
            text.push('\n');
            text.push_str(hit.snippet.trim());
        }
    }
    text
}

fn rpc_error(
    rpc_code: i32,
    message: impl Into<String>,
    mcp_code: &'static str,
    reason: Option<String>,
    tool: Option<&str>,
    details: Option<serde_json::Value>,
) -> RpcError {
    let message = truncate_bytes(message.into(), MAX_ERROR_MESSAGE_BYTES);
    RpcError {
        code: rpc_code,
        message: message.clone(),
        data: Some(mcp_error_data(mcp_code, message, reason, tool, details)),
    }
}

fn rpc_rate_limited(err: &RateLimited) -> RpcError {
    RpcError {
        code: ERR_RATE_LIMITED_RPC,
        message: truncate_bytes(err.message.clone(), MAX_ERROR_MESSAGE_BYTES),
        data: Some(mcp_rate_limited_data(err)),
    }
}

fn rpc_tool_error(err: &anyhow::Error, tool: Option<&str>) -> RpcError {
    if let Some(rate) = err.downcast_ref::<RateLimited>() {
        return rpc_rate_limited(rate);
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
        ERR_EMBEDDING_TIMEOUT => "embedding timeout",
        ERR_EMBEDDING_MODEL_NOT_FOUND => "embedding model not found",
        ERR_EMBEDDING_FAILED => "embedding failed",
        ERR_MISSING_REPO => "missing repo",
        ERR_MISSING_REPO_PATH => "repo path not found",
        ERR_UNKNOWN_REPO => "unknown repo",
        ERR_MISSING_INDEX => "missing index",
        ERR_INDEXING_IN_PROGRESS => "indexing in progress",
        ERR_STALE_INDEX => "stale index",
        ERR_CONVERSATION_NOT_FOUND => "conversation not found",
        ERR_KNOWLEDGE_EPISODE_NOT_FOUND => "knowledge episode not found",
        ERR_MISSING_DEPENDENCY => "missing dependency",
        ERR_RATE_LIMITED => "rate limited",
        ERR_BACKOFF_REQUIRED => "backoff required",
        ERR_REPO_STATE_MISMATCH => "repo state mismatch",
        ERR_UNAUTHORIZED => "unauthorized",
        ERR_INTERNAL_ERROR => "internal error",
        _ => "error",
    }
}

fn is_legacy_tool_method(method: &str) -> bool {
    method.starts_with("docdex_") || method.starts_with("docdex.")
}

fn normalize_legacy_tool_name(method: &str) -> String {
    match method {
        "docdex.profile"
        | "docdex_profile"
        | "docdex.get_profile"
        | "docdex_get_profile"
        | "docdex.profile.get_profile"
        | "docdex_profile_get_profile" => "docdex_get_profile".to_string(),
        "docdex.profile.save_preference"
        | "docdex_profile_save_preference"
        | "docdex.save_preference"
        | "docdex_save_preference" => "docdex_save_preference".to_string(),
        other => {
            if let Some(stripped) = other.strip_prefix("docdex.") {
                format!("docdex_{}", stripped.replace('.', "_"))
            } else {
                other.to_string()
            }
        }
    }
}

fn normalize_tool_arguments(value: Option<serde_json::Value>) -> serde_json::Value {
    match value.unwrap_or_else(|| json!({})) {
        serde_json::Value::Null => json!({}),
        other => other,
    }
}

fn map_conversation_import_messages(
    messages: Option<Vec<ConversationImportMessageArgs>>,
) -> Option<Vec<crate::conversations::ConversationMessage>> {
    messages.map(|messages| {
        messages
            .into_iter()
            .map(|item| crate::conversations::ConversationMessage {
                role: crate::conversations::ConversationRole::from_str(&item.role),
                content: item.content,
                author: item.author,
                created_at_ms: item.created_at_ms,
                metadata: item.metadata.unwrap_or_else(|| json!({})),
            })
            .collect::<Vec<_>>()
    })
}

fn map_personal_preferences_messages(
    messages: Option<&[crate::conversations::ConversationMessage]>,
) -> Vec<crate::personal_preferences::PersonalPreferencesMessage> {
    messages
        .unwrap_or(&[])
        .iter()
        .map(
            |message| crate::personal_preferences::PersonalPreferencesMessage {
                role: message.role.as_str().to_string(),
                content: message.content.clone(),
                created_at_ms: message.created_at_ms,
                metadata: message.metadata.clone(),
            },
        )
        .collect::<Vec<_>>()
}

fn personal_preferences_scope_details(
    repo_root: &Path,
    scope: &McpConversationScope,
    conversation_namespace: Option<&str>,
) -> (
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
) {
    match scope {
        McpConversationScope::Repo { repo_id, .. } => {
            let repo_root = repo_root.display().to_string();
            (
                Some(repo_id.clone()),
                Some(repo_root.clone()),
                Some(repo_id.clone()),
                Some(repo_root),
            )
        }
        McpConversationScope::Namespace { .. } => {
            let label = conversation_namespace
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or("global")
                .to_string();
            (None, None, Some(format!("namespace:{label}")), Some(label))
        }
    }
}

fn build_personal_preferences_capture_request_from_import(
    repo_root: &Path,
    scope: &McpConversationScope,
    conversation_namespace: Option<&str>,
    payload: &crate::conversations::ConversationImport,
) -> crate::personal_preferences::PersonalPreferencesCaptureRequest {
    let (repo_id, repo_root, scope_id, scope_label) =
        personal_preferences_scope_details(repo_root, scope, conversation_namespace);
    let messages = map_personal_preferences_messages(Some(&payload.messages));
    let transcript_text = if messages.is_empty() {
        None
    } else {
        Some(
            messages
                .iter()
                .filter_map(|message| {
                    let content = message.content.trim();
                    if content.is_empty() {
                        None
                    } else {
                        Some(format!("{}: {}", message.role, content))
                    }
                })
                .collect::<Vec<_>>()
                .join("\n"),
        )
    };
    crate::personal_preferences::PersonalPreferencesCaptureRequest {
        source: payload.source.clone(),
        source_session_id: payload.source_session_id.clone(),
        capture_kind: Some("conversation_import".to_string()),
        title: payload.title.clone(),
        agent_id: payload.agent_id.clone(),
        transport: payload.transport.clone(),
        repo_id,
        repo_root,
        scope_id,
        scope_label,
        started_at_ms: payload.started_at_ms,
        ended_at_ms: payload.ended_at_ms,
        messages,
        transcript_text,
        summary_text: None,
        metadata: payload.metadata.clone(),
    }
}

fn build_personal_preferences_capture_request_from_hook(
    repo_root: &Path,
    scope: &McpConversationScope,
    conversation_namespace: Option<&str>,
    payload: &crate::conversations::ConversationHookPayload,
) -> crate::personal_preferences::PersonalPreferencesCaptureRequest {
    let (repo_id, repo_root, scope_id, scope_label) =
        personal_preferences_scope_details(repo_root, scope, conversation_namespace);
    crate::personal_preferences::PersonalPreferencesCaptureRequest {
        source: payload
            .source
            .clone()
            .unwrap_or_else(|| format!("hook:{}", payload.action.as_str())),
        source_session_id: payload.source_session_id.clone(),
        capture_kind: Some(format!("conversation_hook:{}", payload.action.as_str())),
        title: payload.title.clone(),
        agent_id: payload.agent_id.clone(),
        transport: payload.transport.clone(),
        repo_id,
        repo_root,
        scope_id,
        scope_label,
        started_at_ms: payload.started_at_ms,
        ended_at_ms: payload.ended_at_ms,
        messages: map_personal_preferences_messages(payload.messages.as_deref()),
        transcript_text: payload.transcript_text.clone(),
        summary_text: payload.summary_text.clone(),
        metadata: payload.metadata.clone(),
    }
}

fn classify_tool_error(err: &anyhow::Error) -> (&'static str, Option<serde_json::Value>) {
    if let Some(rate) = err.downcast_ref::<RateLimited>() {
        return (rate.code, Some(mcp_rate_limited_data(rate)));
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
    if let Some(max_err) = err.downcast_ref::<MaxContentError>() {
        return (
            "max_content_exceeded",
            Some(json!({
                "max_bytes": max_err.max_bytes,
                "actual_bytes": max_err.actual_bytes,
            })),
        );
    }
    if err
        .downcast_ref::<MissingSymbolsDependencyError>()
        .is_some()
    {
        return (
            ERR_MISSING_DEPENDENCY,
            Some(json!({
                "dependency": "DOCDEX_ENABLE_SYMBOL_EXTRACTION",
                "flag": "--enable-symbol-extraction=true"
            })),
        );
    }
    if let Some(missing) = err.downcast_ref::<MissingSymbolsIndexError>() {
        return (
            ERR_MISSING_INDEX,
            Some(json!({ "resource": "symbols", "path": missing.rel_path })),
        );
    }
    if let Some(missing) = err.downcast_ref::<MissingAstIndexError>() {
        return (
            ERR_MISSING_INDEX,
            Some(json!({ "resource": "ast", "path": missing.rel_path })),
        );
    }
    if err.downcast_ref::<StaleSymbolsIndexError>().is_some() {
        return (ERR_STALE_INDEX, Some(json!({ "resource": "symbols" })));
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
    #[serde(default, alias = "authToken")]
    auth_token: Option<String>,
    #[serde(default, alias = "agentId")]
    agent_id: Option<String>,
    #[serde(default, alias = "agentModel", alias = "model")]
    agent_model: Option<String>,
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
    title: &'static str,
    description: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    annotations: Option<serde_json::Value>,
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
    force_web: Option<bool>,
    #[serde(default, alias = "asyncWeb")]
    async_web: Option<bool>,
    #[serde(default)]
    diff: Option<diff::DiffOptions>,
    #[serde(default, alias = "dagSessionId", alias = "session_id")]
    dag_session_id: Option<String>,
    #[serde(default)]
    project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    repo_path: Option<PathBuf>,
}

#[derive(Deserialize, Default)]
struct CapabilitiesArgs {}

#[derive(Deserialize)]
struct RerankArgs {
    query: String,
    candidates: Vec<crate::index::Hit>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    repo_path: Option<PathBuf>,
}

#[derive(Deserialize)]
struct BatchSearchArgs {
    queries: Vec<String>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    include_libs: Option<bool>,
    #[serde(default)]
    project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    repo_path: Option<PathBuf>,
}

#[derive(Deserialize)]
struct WebResearchArgs {
    query: String,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default, alias = "webLimit")]
    web_limit: Option<usize>,
    #[serde(default)]
    force_web: Option<bool>,
    #[serde(default, alias = "skipLocalSearch")]
    skip_local_search: Option<bool>,
    #[serde(default, alias = "noCache")]
    no_cache: Option<bool>,
    #[serde(default, alias = "llmFilterLocalResults")]
    llm_filter_local_results: Option<bool>,
    #[serde(default, alias = "repoOnly")]
    repo_only: Option<bool>,
    #[serde(default, alias = "llmModel")]
    llm_model: Option<String>,
    #[serde(default, alias = "llmAgent")]
    llm_agent: Option<String>,
    #[serde(default, alias = "dagSessionId", alias = "session_id")]
    dag_session_id: Option<String>,
    #[serde(default)]
    project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    repo_path: Option<PathBuf>,
}

#[derive(Deserialize)]
struct IndexArgs {
    #[serde(default)]
    paths: Vec<PathBuf>,
    #[serde(default)]
    project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    repo_path: Option<PathBuf>,
}

#[derive(Deserialize)]
struct StatsArgs {
    #[serde(default)]
    project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    repo_path: Option<PathBuf>,
}

#[derive(Deserialize)]
struct RepoInspectArgs {
    #[serde(default)]
    project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    repo_path: Option<PathBuf>,
}

#[derive(Deserialize)]
struct DelegateArgs {
    task_type: String,
    instruction: String,
    context: String,
    #[serde(default)]
    agent: Option<String>,
    #[serde(default, alias = "callerAgentId")]
    caller_agent_id: Option<String>,
    #[serde(default, alias = "callerModel")]
    caller_model: Option<String>,
    #[serde(default, alias = "primaryCostPerMillion")]
    primary_cost_per_million: Option<f64>,
    #[serde(default, alias = "maxTokens")]
    max_tokens: Option<u32>,
    #[serde(default, alias = "timeoutMs")]
    timeout_ms: Option<u64>,
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    max_context_chars: Option<usize>,
    #[serde(default)]
    project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    repo_path: Option<PathBuf>,
}

#[derive(Deserialize)]
struct FilesArgs {
    #[serde(default)]
    project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    repo_path: Option<PathBuf>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    offset: Option<usize>,
}

#[derive(Deserialize)]
struct OpenArgs {
    path: String,
    #[serde(default)]
    project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    repo_path: Option<PathBuf>,
    #[serde(default)]
    start_line: Option<usize>,
    #[serde(default)]
    end_line: Option<usize>,
    #[serde(default)]
    clamp: Option<bool>,
    #[serde(default)]
    head: Option<usize>,
}

#[derive(Deserialize)]
struct TreeArgs {
    #[serde(default)]
    path: Option<String>,
    #[serde(default, alias = "maxDepth")]
    max_depth: Option<usize>,
    #[serde(default, alias = "dirsOnly")]
    dirs_only: Option<bool>,
    #[serde(default, alias = "includeHidden")]
    include_hidden: Option<bool>,
    #[serde(default, alias = "extraExcludes")]
    extra_excludes: Option<Vec<String>>,
    #[serde(default)]
    project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    repo_path: Option<PathBuf>,
}

#[derive(Deserialize)]
struct SymbolsArgs {
    path: String,
    #[serde(default)]
    project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    repo_path: Option<PathBuf>,
}

#[derive(Deserialize)]
struct AstArgs {
    path: String,
    #[serde(default, alias = "maxNodes")]
    max_nodes: Option<usize>,
    #[serde(default)]
    project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    repo_path: Option<PathBuf>,
}

#[derive(Deserialize)]
struct ImpactDiagnosticsArgs {
    #[serde(default)]
    file: Option<String>,
    #[serde(default, alias = "project_root")]
    project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    repo_path: Option<PathBuf>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    offset: Option<usize>,
}

#[derive(Deserialize)]
struct ImpactGraphArgs {
    file: String,
    #[serde(default)]
    max_edges: Option<usize>,
    #[serde(default)]
    max_depth: Option<usize>,
    #[serde(default)]
    edge_types: Option<Vec<String>>,
    #[serde(default)]
    project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    repo_path: Option<PathBuf>,
}

#[derive(Deserialize)]
struct DagExportArgs {
    #[serde(default, alias = "dagSessionId", alias = "dag_session_id")]
    session_id: Option<String>,
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    max_nodes: Option<usize>,
    #[serde(default)]
    project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    repo_path: Option<PathBuf>,
}

#[derive(Deserialize)]
struct MemoryStoreArgs {
    text: String,
    #[serde(default)]
    metadata: Option<serde_json::Value>,
    #[serde(default)]
    project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    repo_path: Option<PathBuf>,
}

#[derive(Deserialize)]
struct MemoryRecallArgs {
    query: String,
    #[serde(default)]
    top_k: Option<usize>,
    #[serde(default)]
    project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    repo_path: Option<PathBuf>,
}

#[derive(Default, Deserialize)]
struct MemoryLayersArgs {
    #[serde(default)]
    project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    repo_path: Option<PathBuf>,
    #[serde(default, alias = "namespace")]
    conversation_namespace: Option<String>,
}

#[derive(Deserialize)]
struct MemoryRouteArgs {
    query: String,
    #[serde(default)]
    intent: Option<String>,
    #[serde(default)]
    project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    repo_path: Option<PathBuf>,
    #[serde(default, alias = "namespace")]
    conversation_namespace: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct ConversationImportMessageArgs {
    role: String,
    content: String,
    #[serde(default)]
    author: Option<String>,
    #[serde(default)]
    created_at_ms: Option<i64>,
    #[serde(default)]
    metadata: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct ConversationImportArgs {
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    source_session_id: Option<String>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    agent_id: Option<String>,
    #[serde(default)]
    transport: Option<String>,
    #[serde(default)]
    started_at_ms: Option<i64>,
    #[serde(default)]
    ended_at_ms: Option<i64>,
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    messages: Option<Vec<ConversationImportMessageArgs>>,
    #[serde(default)]
    transcript_text: Option<String>,
    #[serde(default)]
    metadata: Option<serde_json::Value>,
    #[serde(default)]
    project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    repo_path: Option<PathBuf>,
    #[serde(default, alias = "namespace")]
    conversation_namespace: Option<String>,
}

#[derive(Deserialize)]
struct WakeupArgs {
    #[serde(default)]
    agent_id: Option<String>,
    #[serde(default)]
    query: Option<String>,
    #[serde(default)]
    max_tokens: Option<usize>,
    #[serde(default)]
    project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    repo_path: Option<PathBuf>,
    #[serde(default, alias = "namespace")]
    conversation_namespace: Option<String>,
}

#[derive(Deserialize)]
struct KgQueryArgs {
    query: String,
    #[serde(default)]
    relation: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    offset: Option<usize>,
    #[serde(default)]
    project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    repo_path: Option<PathBuf>,
    #[serde(default, alias = "namespace")]
    conversation_namespace: Option<String>,
}

#[derive(Deserialize)]
struct KgNodeSearchArgs {
    query: String,
    #[serde(default)]
    entity_type: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    offset: Option<usize>,
    #[serde(default)]
    project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    repo_path: Option<PathBuf>,
    #[serde(default, alias = "namespace")]
    conversation_namespace: Option<String>,
}

#[derive(Deserialize)]
struct KgEdgeSearchArgs {
    query: String,
    #[serde(default)]
    relation: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    offset: Option<usize>,
    #[serde(default)]
    project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    repo_path: Option<PathBuf>,
    #[serde(default, alias = "namespace")]
    conversation_namespace: Option<String>,
}

#[derive(Deserialize)]
struct KgTimelineArgs {
    entity: String,
    #[serde(default)]
    relation: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    repo_path: Option<PathBuf>,
    #[serde(default, alias = "namespace")]
    conversation_namespace: Option<String>,
}

#[derive(Deserialize)]
struct KgEpisodeSearchArgs {
    query: String,
    #[serde(default)]
    source_type: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    offset: Option<usize>,
    #[serde(default)]
    project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    repo_path: Option<PathBuf>,
    #[serde(default, alias = "namespace")]
    conversation_namespace: Option<String>,
}

#[derive(Deserialize)]
struct KgNeighborhoodArgs {
    entity: String,
    #[serde(default)]
    relation: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    repo_path: Option<PathBuf>,
    #[serde(default, alias = "namespace")]
    conversation_namespace: Option<String>,
}

#[derive(Deserialize)]
struct KgEntityLinksArgs {
    entity: String,
    #[serde(default)]
    link_type: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    repo_path: Option<PathBuf>,
    #[serde(default, alias = "namespace")]
    conversation_namespace: Option<String>,
}

#[derive(Deserialize)]
struct KgEpisodeArgs {
    #[serde(alias = "id")]
    episode_id: String,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    repo_path: Option<PathBuf>,
    #[serde(default, alias = "namespace")]
    conversation_namespace: Option<String>,
}

#[derive(Deserialize)]
struct KgDeleteEdgeArgs {
    #[serde(alias = "id")]
    edge_id: String,
    #[serde(default)]
    project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    repo_path: Option<PathBuf>,
    #[serde(default, alias = "namespace")]
    conversation_namespace: Option<String>,
}

#[derive(Deserialize)]
struct KgDeleteEpisodeArgs {
    #[serde(alias = "id")]
    episode_id: String,
    #[serde(default)]
    project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    repo_path: Option<PathBuf>,
    #[serde(default, alias = "namespace")]
    conversation_namespace: Option<String>,
}

#[derive(Deserialize)]
struct KgMaintenanceArgs {
    #[serde(default)]
    project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    repo_path: Option<PathBuf>,
    #[serde(default, alias = "namespace")]
    conversation_namespace: Option<String>,
}

#[derive(Deserialize)]
struct ConversationListArgs {
    #[serde(default)]
    agent_id: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    offset: Option<usize>,
    #[serde(default)]
    project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    repo_path: Option<PathBuf>,
    #[serde(default, alias = "namespace")]
    conversation_namespace: Option<String>,
}

#[derive(Deserialize)]
struct ConversationSearchArgs {
    query: String,
    #[serde(default)]
    agent_id: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    offset: Option<usize>,
    #[serde(default)]
    project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    repo_path: Option<PathBuf>,
    #[serde(default, alias = "namespace")]
    conversation_namespace: Option<String>,
}

#[derive(Deserialize)]
struct ConversationReadArgs {
    session_id: String,
    #[serde(default)]
    project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    repo_path: Option<PathBuf>,
    #[serde(default, alias = "namespace")]
    conversation_namespace: Option<String>,
}

#[derive(Deserialize)]
struct ConversationDeleteArgs {
    session_id: String,
    #[serde(default)]
    project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    repo_path: Option<PathBuf>,
    #[serde(default, alias = "namespace")]
    conversation_namespace: Option<String>,
}

#[derive(Deserialize)]
struct ConversationExportArgs {
    session_id: String,
    #[serde(default)]
    project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    repo_path: Option<PathBuf>,
    #[serde(default, alias = "namespace")]
    conversation_namespace: Option<String>,
}

#[derive(Deserialize)]
struct ConversationRedactArgs {
    session_id: String,
    #[serde(default)]
    project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    repo_path: Option<PathBuf>,
    #[serde(default, alias = "namespace")]
    conversation_namespace: Option<String>,
}

#[derive(Deserialize)]
struct ConversationPruneArgs {
    #[serde(default)]
    manual_retention_days: Option<u32>,
    #[serde(default)]
    auto_capture_retention_days: Option<u32>,
    #[serde(default)]
    diary_retention_days: Option<u32>,
    #[serde(default)]
    hook_event_retention_days: Option<u32>,
    #[serde(default)]
    working_memory_retention_days: Option<u32>,
    #[serde(default)]
    episodic_rollup_retention_days: Option<u32>,
    #[serde(default)]
    apply: Option<bool>,
    #[serde(default)]
    project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    repo_path: Option<PathBuf>,
    #[serde(default, alias = "namespace")]
    conversation_namespace: Option<String>,
}

#[derive(Deserialize)]
struct DiaryWriteArgs {
    content: String,
    #[serde(default)]
    agent_id: Option<String>,
    #[serde(default)]
    entry_type: Option<String>,
    #[serde(default)]
    source_session_id: Option<String>,
    #[serde(default)]
    metadata: Option<serde_json::Value>,
    #[serde(default)]
    project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    repo_path: Option<PathBuf>,
    #[serde(default, alias = "namespace")]
    conversation_namespace: Option<String>,
}

#[derive(Deserialize)]
struct DiaryReadArgs {
    #[serde(default)]
    agent_id: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    offset: Option<usize>,
    #[serde(default)]
    project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    repo_path: Option<PathBuf>,
    #[serde(default, alias = "namespace")]
    conversation_namespace: Option<String>,
}

#[derive(Deserialize)]
struct ConversationHookArgs {
    action: crate::conversations::ConversationHookAction,
    #[serde(default)]
    source: Option<String>,
    #[serde(default)]
    source_session_id: Option<String>,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    agent_id: Option<String>,
    #[serde(default)]
    transport: Option<String>,
    #[serde(default)]
    started_at_ms: Option<i64>,
    #[serde(default)]
    ended_at_ms: Option<i64>,
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    messages: Option<Vec<ConversationImportMessageArgs>>,
    #[serde(default)]
    transcript_text: Option<String>,
    #[serde(default)]
    summary_text: Option<String>,
    #[serde(default)]
    metadata: Option<serde_json::Value>,
    #[serde(default)]
    wait_for_processing: Option<bool>,
    #[serde(default)]
    project_root: Option<PathBuf>,
    #[serde(default, alias = "repoPath")]
    repo_path: Option<PathBuf>,
    #[serde(default, alias = "namespace")]
    conversation_namespace: Option<String>,
}

#[derive(Deserialize)]
struct ProfileSaveArgs {
    #[serde(default)]
    agent_id: Option<String>,
    content: String,
    category: String,
    #[serde(default)]
    role: Option<String>,
}

#[derive(Deserialize)]
struct ProfileGetArgs {
    #[serde(default)]
    agent_id: Option<String>,
}

#[derive(Default, Deserialize)]
struct PersonalPreferencesStatusArgs {}

#[derive(Default, Deserialize)]
struct PersonalPreferencesCategoriesArgs {}

#[derive(Deserialize)]
struct PersonalPreferencesListArgs {
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    offset: Option<usize>,
}

#[derive(Deserialize)]
struct PersonalPreferencesReadArgs {
    #[serde(alias = "id")]
    capture_id: String,
}

#[derive(Deserialize)]
struct PersonalPreferencesSearchArgs {
    #[serde(alias = "q")]
    query: String,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    include_sensitive: Option<bool>,
}

#[derive(Deserialize)]
struct PersonalPreferencesReviewQueueArgs {
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    offset: Option<usize>,
}

#[derive(Deserialize)]
struct PersonalPreferencesReviewArgs {
    #[serde(alias = "id")]
    record_id: String,
    verdict: String,
    #[serde(default)]
    notes: Option<String>,
}

#[derive(Deserialize)]
struct PersonalPreferencesProcessArgs {
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Deserialize)]
struct PersonalPreferencesScanArgs {
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Deserialize)]
struct PersonalPreferencesExportArgs {
    #[serde(default)]
    capture_id: Option<String>,
}

#[derive(Deserialize)]
struct PersonalPreferencesDeleteArgs {
    #[serde(alias = "id")]
    capture_id: String,
}

#[derive(Deserialize)]
struct PersonalPreferencesPruneArgs {
    #[serde(default)]
    raw_retention_days: Option<u32>,
    #[serde(default)]
    derived_retention_days: Option<u32>,
    #[serde(default)]
    apply: Option<bool>,
}

#[derive(Deserialize)]
struct PersonalPreferencesPurgeArgs {
    #[serde(default)]
    include_exports: Option<bool>,
}

#[derive(Deserialize)]
struct PersonalPreferencesClaimsArgs {
    #[serde(default, alias = "q")]
    query: Option<String>,
    #[serde(default)]
    truth_status: Option<String>,
    #[serde(default)]
    claim_origin: Option<String>,
    #[serde(default)]
    include_sensitive: Option<bool>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    offset: Option<usize>,
}

#[derive(Deserialize)]
struct PersonalPreferencesClaimReadArgs {
    #[serde(alias = "id")]
    claim_id: String,
}

#[derive(Deserialize)]
struct PersonalPreferencesClaimReviewArgs {
    #[serde(alias = "id")]
    claim_id: String,
    verdict: String,
    #[serde(default)]
    notes: Option<String>,
}

#[derive(Deserialize)]
struct PersonalPreferencesClaimOverrideArgs {
    #[serde(alias = "id")]
    claim_id: String,
    value: String,
    #[serde(default)]
    notes: Option<String>,
}

#[derive(Deserialize)]
struct PersonalPreferencesClaimForgetArgs {
    #[serde(alias = "id")]
    claim_id: String,
    #[serde(default)]
    notes: Option<String>,
}

#[derive(Deserialize)]
struct PersonalPreferencesFeedbackArgs {
    event_type: String,
    #[serde(default)]
    claim_id: Option<String>,
    #[serde(default)]
    capture_id: Option<String>,
    #[serde(default)]
    category: Option<String>,
    #[serde(default)]
    attribute: Option<String>,
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    metadata: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct PersonalPreferencesSnapshotsArgs {
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    offset: Option<usize>,
}

#[derive(Deserialize)]
struct PersonalPreferencesSnapshotReadArgs {
    #[serde(alias = "id")]
    snapshot_id: String,
}

#[derive(Deserialize)]
struct PersonalPreferencesCloneArgs {
    query: String,
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    allow_sensitive: Option<bool>,
    #[serde(default)]
    current_repo_root: Option<String>,
    #[serde(default)]
    max_records: Option<usize>,
    #[serde(default)]
    budget_tokens: Option<usize>,
}

#[derive(Deserialize)]
struct ResourceReadParams {
    uri: String,
}

#[derive(Serialize)]
struct ResourceDefinition {
    uri: String,
    name: String,
    title: String,
    description: String,
    #[serde(rename = "mimeType")]
    mime_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    annotations: Option<serde_json::Value>,
}

#[derive(Serialize)]
struct ResourceTemplate {
    name: &'static str,
    title: &'static str,
    description: &'static str,
    #[serde(rename = "uriTemplate")]
    uri_template: &'static str,
    #[serde(rename = "mimeType")]
    mime_type: &'static str,
    variables: &'static [&'static str],
    #[serde(skip_serializing_if = "Option::is_none")]
    annotations: Option<serde_json::Value>,
}

#[derive(Serialize)]
struct PromptArgument {
    name: &'static str,
    description: &'static str,
    required: bool,
}

#[derive(Serialize)]
struct PromptDefinition {
    name: &'static str,
    title: &'static str,
    description: &'static str,
    arguments: Vec<PromptArgument>,
    #[serde(skip_serializing_if = "Option::is_none")]
    annotations: Option<serde_json::Value>,
}

#[derive(Deserialize)]
struct PromptGetParams {
    name: String,
    #[serde(default)]
    arguments: Option<serde_json::Value>,
}

pub struct McpService {
    server: McpServer,
}

impl McpService {
    pub fn new(
        repo_root: PathBuf,
        index_config: IndexConfig,
        max_results: usize,
        rate_limit_per_min: u32,
        rate_limit_burst: u32,
        auth_token: Option<String>,
        delegation_metrics: Arc<DelegationMetrics>,
    ) -> Result<Self> {
        let repo_root = repo_root
            .canonicalize()
            .context("resolve repo root for MCP server")?;
        // Try to open with a writer; if the index is already locked (another docdexd
        // instance is indexing), fall back to read-only so search/open still work.
        let indexer = match Indexer::with_config(repo_root.clone(), index_config.clone()) {
            Ok(ix) => ix,
            Err(err) if is_lock_busy(&err) => {
                warn!(
                    "docdex mcp: index writer is busy; opening read-only (disable other docdexd to enable indexing)"
                );
                Indexer::with_config_read_only(repo_root.clone(), index_config)?
            }
            Err(err) => return Err(err),
        };
        let indexer = Arc::new(indexer);
        let config = config::AppConfig::load_default().ok();
        let global_state_dir = config
            .as_ref()
            .and_then(|cfg| cfg.core.global_state_dir.clone());
        let memory_enabled = if std::env::var_os("DOCDEX_ENABLE_MEMORY").is_some() {
            env_flag_enabled("DOCDEX_ENABLE_MEMORY")
        } else {
            config
                .as_ref()
                .map(|cfg| cfg.memory.enabled)
                .unwrap_or(false)
        };
        let memory = if memory_enabled {
            let base_url = std::env::var("DOCDEX_EMBEDDING_BASE_URL")
                .ok()
                .filter(|v| !v.trim().is_empty())
                .or_else(|| {
                    std::env::var("DOCDEX_OLLAMA_BASE_URL")
                        .ok()
                        .filter(|v| !v.trim().is_empty())
                })
                .or_else(|| config.as_ref().map(|cfg| cfg.llm.base_url.clone()))
                .unwrap_or_else(|| "http://127.0.0.1:11434".to_string());
            let model = std::env::var("DOCDEX_EMBEDDING_MODEL")
                .ok()
                .filter(|v| !v.trim().is_empty())
                .or_else(|| config.as_ref().map(|cfg| cfg.llm.embedding_model.clone()))
                .unwrap_or_else(|| "nomic-embed-text".to_string());
            let timeout_ms = std::env::var("DOCDEX_EMBEDDING_TIMEOUT_MS")
                .ok()
                .and_then(|v| v.trim().parse::<u64>().ok())
                .unwrap_or(5000);
            let fallback_dim = config
                .as_ref()
                .map(|cfg| cfg.memory.profile.embedding_dim)
                .unwrap_or(DEFAULT_FALLBACK_EMBED_DIM)
                .max(1);
            Some(McpMemoryState {
                store: MemoryStore::new(indexer.state_dir()),
                embedder: OllamaEmbedder::new(base_url, model, Duration::from_millis(timeout_ms))?,
                fallback_dim,
            })
        } else {
            None
        };
        let conversation_config = config
            .as_ref()
            .map(|cfg| cfg.memory.conversations.clone())
            .unwrap_or_default();
        let conversations = if conversation_config.enabled {
            Some(McpConversationState {
                store: crate::conversations::ConversationStore::new(indexer.state_dir()),
                knowledge: crate::knowledge::KnowledgeStore::new(indexer.state_dir()),
                config: conversation_config.clone(),
                max_wakeup_tokens: conversation_config.max_wakeup_tokens,
                max_episodic_summaries: conversation_config.max_episodic_summaries,
                max_knowledge_facts: conversation_config.max_knowledge_facts,
                max_transcript_snippets: conversation_config.max_transcript_snippets,
            })
        } else {
            None
        };
        let max_answer_tokens = config
            .as_ref()
            .map(|cfg| cfg.llm.max_answer_tokens)
            .unwrap_or(1024);
        let llm_config = config
            .as_ref()
            .map(|cfg| cfg.llm.clone())
            .unwrap_or_default();
        let personal_preferences_config = config
            .as_ref()
            .map(|cfg| cfg.memory.personal_preferences.clone())
            .unwrap_or_default();
        let personal_preferences = if personal_preferences_config.enabled {
            let state_dir =
                personal_preferences_config.resolved_storage_root(global_state_dir.as_deref())?;
            Some(search::PersonalPreferencesState {
                store: crate::personal_preferences::PersonalPreferencesStore::new(&state_dir)?,
                config: personal_preferences_config.clone(),
            })
        } else {
            None
        };
        let profile_embedding_base_url = std::env::var("DOCDEX_EMBEDDING_BASE_URL")
            .ok()
            .filter(|v| !v.trim().is_empty())
            .or_else(|| {
                std::env::var("DOCDEX_OLLAMA_BASE_URL")
                    .ok()
                    .filter(|v| !v.trim().is_empty())
            })
            .or_else(|| config.as_ref().map(|cfg| cfg.llm.base_url.clone()))
            .unwrap_or_else(|| "http://127.0.0.1:11434".to_string());
        let profile_embedding_model = config
            .as_ref()
            .map(|cfg| cfg.memory.profile.embedding_model.clone())
            .unwrap_or_else(|| "nomic-embed-text".to_string());
        let profile_embedding_dim = config
            .as_ref()
            .map(|cfg| cfg.memory.profile.embedding_dim)
            .unwrap_or(DEFAULT_FALLBACK_EMBED_DIM)
            .max(1);
        let profile_embedding_timeout_ms = std::env::var("DOCDEX_EMBEDDING_TIMEOUT_MS")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(5000);
        let profile_state = {
            let mut manager = global_state_dir
                .as_ref()
                .and_then(|state_dir| ProfileManager::new(state_dir, profile_embedding_dim).ok());
            if manager.is_none() {
                if let Ok(fallback_dir) = crate::state_paths::default_state_base_dir() {
                    manager = ProfileManager::new(&fallback_dir, profile_embedding_dim).ok();
                }
            }
            if manager.is_none() {
                let temp_dir = std::env::temp_dir().join("docdex").join("state");
                manager = ProfileManager::new(&temp_dir, profile_embedding_dim).ok();
            }
            manager.map(|manager| search::ProfileState {
                manager,
                embedder: ProfileEmbedder::new(
                    profile_embedding_base_url.clone(),
                    profile_embedding_model.clone(),
                    Duration::from_millis(profile_embedding_timeout_ms),
                    profile_embedding_dim,
                )
                .ok(),
            })
        };
        let effective_burst = if rate_limit_per_min > 0 && rate_limit_burst == 0 {
            rate_limit_per_min
        } else {
            rate_limit_burst
        };
        let tool_rate_limit = if rate_limit_per_min > 0 {
            Some(RateLimiter::<()>::new(rate_limit_per_min, effective_burst))
        } else {
            None
        };
        let libs_indexer = libs::LibsIndexer::open_read_only(
            libs::libs_state_dir_from_index_state_dir(indexer.state_dir()),
        )
        .ok()
        .flatten()
        .map(Arc::new);
        let auth_token = auth_token.and_then(|value| {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        });
        let repo_id =
            crate::repo_manager::repo_fingerprint_sha256(&repo_root).unwrap_or_else(|_| {
                crate::repo_manager::fingerprint::legacy_repo_id_for_root(&repo_root)
            });
        let authorized = auth_token.is_none();
        let default_project_root = Some(repo_root.clone());
        let server = McpServer {
            repo_id,
            repo_root,
            indexer,
            libs_indexer,
            max_results: max_results.max(1),
            default_project_root,
            default_agent_id: None,
            default_agent_model: None,
            memory,
            conversations,
            personal_preferences,
            profile_state,
            max_answer_tokens,
            llm_config,
            global_state_dir,
            tool_rate_limit,
            auth_token,
            authorized,
            delegation_metrics,
        };
        Ok(Self { server })
    }

    pub async fn handle_json(&mut self, payload: Value) -> Result<Option<Value>> {
        let req = match serde_json::from_value::<RpcRequest>(payload) {
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
                return Ok(Some(serde_json::to_value(resp)?));
            }
        };
        let resp_opt = match self.server.handle(req).await {
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
        match resp_opt {
            Some(resp) => Ok(Some(serde_json::to_value(resp)?)),
            None => Ok(None),
        }
    }
}

#[derive(Clone)]
struct McpMemoryState {
    store: MemoryStore,
    embedder: OllamaEmbedder,
    fallback_dim: usize,
}

#[derive(Clone)]
struct McpConversationState {
    store: crate::conversations::ConversationStore,
    knowledge: crate::knowledge::KnowledgeStore,
    config: crate::config::MemoryConversationConfig,
    max_wakeup_tokens: usize,
    max_episodic_summaries: usize,
    max_knowledge_facts: usize,
    max_transcript_snippets: usize,
}

#[derive(Clone)]
enum McpConversationScope {
    Repo {
        repo_id: String,
        conversations: McpConversationState,
        memory: Option<McpMemoryState>,
    },
    Namespace {
        conversations: McpConversationState,
    },
}

impl McpConversationScope {
    fn conversations(&self) -> McpConversationState {
        match self {
            Self::Repo { conversations, .. } | Self::Namespace { conversations } => {
                conversations.clone()
            }
        }
    }

    fn repo_memory_target(&self) -> Option<crate::conversations::ConversationRepoMemoryTarget> {
        match self {
            Self::Repo {
                repo_id, memory, ..
            } => memory.as_ref().map(
                |memory| crate::conversations::ConversationRepoMemoryTarget {
                    repo_id: repo_id.clone(),
                    store: memory.store.clone(),
                    embedder: memory.embedder.clone(),
                    fallback_dim: memory.fallback_dim,
                },
            ),
            Self::Namespace { .. } => None,
        }
    }
}

struct MemoryEmbedding {
    embedding: Vec<f32>,
    provider: String,
    model: String,
}

struct McpServer {
    repo_id: String,
    repo_root: PathBuf,
    indexer: Arc<Indexer>,
    libs_indexer: Option<Arc<libs::LibsIndexer>>,
    max_results: usize,
    default_project_root: Option<PathBuf>,
    default_agent_id: Option<String>,
    default_agent_model: Option<String>,
    memory: Option<McpMemoryState>,
    conversations: Option<McpConversationState>,
    personal_preferences: Option<search::PersonalPreferencesState>,
    profile_state: Option<search::ProfileState>,
    max_answer_tokens: u32,
    llm_config: config::LlmConfig,
    global_state_dir: Option<PathBuf>,
    tool_rate_limit: Option<RateLimiter<()>>,
    auth_token: Option<String>,
    authorized: bool,
    delegation_metrics: Arc<DelegationMetrics>,
}

fn annotations_with_priority(priority: f32) -> serde_json::Value {
    json!({
        "audience": ["assistant"],
        "priority": priority
    })
}

impl McpServer {
    async fn handle(&mut self, mut req: RpcRequest) -> Result<Option<RpcResponse>> {
        // Notifications (no id) do not expect a response.
        if req.id.is_none() {
            if req.method == "notifications/initialized" {
                debug!("docdex mcp: client initialized");
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
        if self.auth_token.is_some() && !self.authorized && req.method != "initialize" {
            return Ok(Some(RpcResponse {
                jsonrpc: JSONRPC_VERSION,
                id: id.clone(),
                result: None,
                error: Some(rpc_error(
                    ERR_INVALID_REQUEST,
                    default_message_for_code(ERR_UNAUTHORIZED),
                    ERR_UNAUTHORIZED,
                    None,
                    None,
                    Some(json!({
                        "hint": "Call initialize with auth_token",
                    })),
                )),
            }));
        }
        if is_legacy_tool_method(req.method.as_str()) {
            let method_name = normalize_legacy_tool_name(req.method.as_str());
            req.method = "tools/call".to_string();
            req.params = Some(json!({
                "name": method_name,
                "arguments": normalize_tool_arguments(req.params.take()),
            }));
        }
        match req.method.as_str() {
            "initialize" => {
                let init_params: InitializeParams =
                    serde_json::from_value(req.params.clone().unwrap_or_default())
                        .unwrap_or_default();
                if let Some(expected) = self.auth_token.as_ref() {
                    let provided = init_params
                        .auth_token
                        .as_deref()
                        .map(str::trim)
                        .filter(|value| !value.is_empty());
                    if provided != Some(expected.as_str()) {
                        return Ok(Some(RpcResponse {
                            jsonrpc: JSONRPC_VERSION,
                            id: id.clone(),
                            result: None,
                            error: Some(rpc_error(
                                ERR_INVALID_REQUEST,
                                default_message_for_code(ERR_UNAUTHORIZED),
                                ERR_UNAUTHORIZED,
                                None,
                                None,
                                Some(json!({
                                    "hint": "Call initialize with auth_token",
                                })),
                            )),
                        }));
                    }
                    self.authorized = true;
                }
                if let Some(client_root) = init_params
                    .workspace_root
                    .or(init_params.project_root)
                    .as_ref()
                {
                    match client_root.canonicalize() {
                        Ok(canon) => {
                            if canon != self.repo_root {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_error(
                                        ERR_INVALID_REQUEST,
                                        default_message_for_code(ERR_UNKNOWN_REPO),
                                        ERR_UNKNOWN_REPO,
                                        None,
                                        None,
                                        Some(json!({
                                            "expected": self.repo_root.display().to_string(),
                                            "got": canon.display().to_string()
                                        })),
                                    )),
                                }));
                            }
                            self.default_project_root = Some(canon);
                        }
                        Err(err) => {
                            return Ok(Some(RpcResponse {
                                jsonrpc: JSONRPC_VERSION,
                                id: id.clone(),
                                result: None,
                                error: Some(rpc_error(
                                    ERR_INVALID_REQUEST,
                                    default_message_for_code("invalid_request"),
                                    "invalid_request",
                                    Some(err.to_string()),
                                    None,
                                    None,
                                )),
                            }));
                        }
                    }
                }
                if let Some(agent_id) = init_params
                    .agent_id
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                {
                    self.default_agent_id = Some(agent_id.to_string());
                }
                if let Some(agent_model) = init_params
                    .agent_model
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                {
                    self.default_agent_model = Some(agent_model.to_string());
                }
                let protocol_version = init_params
                    .protocol_version
                    .unwrap_or_else(|| "2025-11-25".to_string());
                let instructions = "Docdex is a local-first repo indexer: use docdex_search for repo docs/code before changing code.\nIf results are weak or the user asks for web context, use docdex_web_research (requires web enabled).\nUse docdex_open for file reads, docdex_files to list indexed docs, docdex_tree for folder structure, and docdex_index to refresh the index when stale.\nFor code intelligence, use docdex_symbols/docdex_ast, docdex_impact_diagnostics for unresolved imports, and docdex_impact_graph for dependency traversal.\nUse docdex_dag_export to export DAG sessions; pass the dag_session_id from docdex_search/docdex_web_research responses (or provide session_id directly).\nUse docdex_local_completion to offload small tasks to a local model or managed mcoda cloud agent. Code-oriented task types use the code lane; lightweight Q&A uses general_question. If mswarm is configured and cloud delegation is enabled, Docdex can discover `mswarm-cloud-*` candidates from `mcoda cloud agent list` and automatically skip usage-limited cloud agents.\nUse docdex_memory_route when you need query-specific guidance about which memory lane to read from or write to. Use docdex_memory_layers when you need the current map of all six memory layers and their scope/storage details.\nThe six layers are: repo memory for repo-specific technical truth; profile memory for global agent/user preferences; conversation memory for archived sessions and wake-up recall; diary memory for per-agent episodic handoff notes; temporal knowledge graph for structured timeline/entity recall; and personal preferences for richer user-specific claims and clone-context flows.\nMemory tools (docdex_memory_store/recall) require memory to be enabled.\nConversation tools: use docdex_conversation_import for ingest, docdex_conversation_search/list/read/export/delete/redact for archive inspection, docdex_conversation_prune for retention cleanup, docdex_diary_write/read for per-agent journals, docdex_conversation_hook for append-only capture events, docdex_kg_* for structured conversation facts, and docdex_wakeup for bounded startup memory.\nProfile tools (docdex_save_preference/docdex_get_profile) use global profile memory and do not require project_root.\nPersonal preferences tools (docdex_personal_preferences_* and docdex_clone_*) are the richer global user-preference lane.\nPass project_root/repo_path to match the MCP server repo (or omit if initialize set a default).";
                let mut caps = json!({
                    "tools": { "listChanged": false },
                    "resources": { "listChanged": false },
                    "resourceTemplates": { "listChanged": false },
                    "prompts": { "listChanged": false },
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
                        },
                        "capabilities": caps,
                        "instructions": instructions,
                    })),
                    error: None,
                };
                debug!(id = ?id, "docdex mcp: initialize ok");
                Ok(Some(resp))
            }
            "tools/list" => Ok(Some(RpcResponse {
                jsonrpc: JSONRPC_VERSION,
                id: id.clone(),
                result: Some(json!({ "tools": self.tool_defs() })),
                error: None,
            })),
            "prompts/list" => Ok(Some(RpcResponse {
                jsonrpc: JSONRPC_VERSION,
                id: id.clone(),
                result: Some(json!({ "prompts": self.prompt_defs() })),
                error: None,
            })),
            "prompts/get" => {
                let params_res: Result<PromptGetParams, _> =
                    serde_json::from_value(req.params.clone().unwrap_or_default());
                let params = match params_res {
                    Ok(p) => p,
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
                                None,
                                Some(json!({ "validation": "serde", "method": "prompts/get" })),
                            )),
                        }))
                    }
                };
                match self.prompt_payload(&params.name, params.arguments.as_ref()) {
                    Some(value) => Ok(Some(RpcResponse {
                        jsonrpc: JSONRPC_VERSION,
                        id: id.clone(),
                        result: Some(value),
                        error: None,
                    })),
                    None => Ok(Some(RpcResponse {
                        jsonrpc: JSONRPC_VERSION,
                        id: id.clone(),
                        result: None,
                        error: Some(rpc_error(
                            ERR_INVALID_PARAMS,
                            "unknown prompt name",
                            "invalid_params",
                            None,
                            None,
                            None,
                        )),
                    })),
                }
            }
            "resources/list" => Ok(Some(RpcResponse {
                jsonrpc: JSONRPC_VERSION,
                id: id.clone(),
                result: Some(json!({ "resources": self.resource_defs() })),
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
                            error: Some(rpc_error(
                                ERR_INVALID_PARAMS,
                                default_message_for_code("invalid_params"),
                                "invalid_params",
                                Some(err.to_string()),
                                None,
                                Some(json!({ "validation": "serde", "method": "resources/read" })),
                            )),
                        }))
                    }
                };
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
                            error: Some(rpc_error(
                                ERR_INVALID_PARAMS,
                                default_message_for_code("invalid_params"),
                                "invalid_params",
                                Some(err.to_string()),
                                None,
                                Some(json!({ "validation": "serde", "method": "tools/call" })),
                            )),
                        }))
                    }
                };
                if let Some(limiter) = self.tool_rate_limit.as_ref() {
                    if let Err(err) = limiter.check_or_rate_limited((), "mcp_tools", "global") {
                        return Ok(Some(RpcResponse {
                            jsonrpc: JSONRPC_VERSION,
                            id: id.clone(),
                            result: None,
                            error: Some(rpc_rate_limited(&err)),
                        }));
                    }
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
                                    error: Some(rpc_error(
                                        ERR_INVALID_PARAMS,
                                        default_message_for_code("invalid_params"),
                                        "invalid_params",
                                        Some(err.to_string()),
                                        Some("docdex_search"),
                                        Some(
                                            json!({ "validation": "serde", "tool": "docdex_search" }),
                                        ),
                                    )),
                                }))
                            }
                        };
                        let request_id = format!("mcp-{}", id.clone());
                        match self.handle_search(request_id, args).await {
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
                    "docdex_capabilities" | "docdex.capabilities" => {
                        let args_res: Result<CapabilitiesArgs, _> =
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
                                        Some("docdex_capabilities"),
                                        Some(json!({
                                            "validation": "serde",
                                            "tool": "docdex_capabilities"
                                        })),
                                    )),
                                }))
                            }
                        };
                        match self.handle_capabilities(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(&err, Some("docdex_capabilities"))),
                                }))
                            }
                        }
                    }
                    "docdex_rerank" | "docdex.rerank" => {
                        let args_res: Result<RerankArgs, _> =
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
                                        Some("docdex_rerank"),
                                        Some(json!({
                                            "validation": "serde",
                                            "tool": "docdex_rerank"
                                        })),
                                    )),
                                }))
                            }
                        };
                        match self.handle_rerank(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(&err, Some("docdex_rerank"))),
                                }))
                            }
                        }
                    }
                    "docdex_batch_search" | "docdex.batch_search" => {
                        let args_res: Result<BatchSearchArgs, _> =
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
                                        Some("docdex_batch_search"),
                                        Some(json!({
                                            "validation": "serde",
                                            "tool": "docdex_batch_search"
                                        })),
                                    )),
                                }))
                            }
                        };
                        let request_id = format!("mcp-batch-{}", id.clone());
                        match self.handle_batch_search(request_id, args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(&err, Some("docdex_batch_search"))),
                                }))
                            }
                        }
                    }
                    "docdex_web_research" | "docdex.web_research" => {
                        let args_res: Result<WebResearchArgs, _> =
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
                                        Some("docdex_web_research"),
                                        Some(json!({
                                            "validation": "serde",
                                            "tool": "docdex_web_research"
                                        })),
                                    )),
                                }))
                            }
                        };
                        let request_id = format!("mcp-web-{}", id.clone());
                        match self.handle_web_research(request_id, args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(&err, Some("docdex_web_research"))),
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
                                    error: Some(rpc_error(
                                        ERR_INVALID_PARAMS,
                                        default_message_for_code("invalid_params"),
                                        "invalid_params",
                                        Some(err.to_string()),
                                        Some("docdex_index"),
                                        Some(
                                            json!({ "validation": "serde", "tool": "docdex_index" }),
                                        ),
                                    )),
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
                                    error: Some(rpc_error(
                                        ERR_INVALID_PARAMS,
                                        default_message_for_code("invalid_params"),
                                        "invalid_params",
                                        Some(err.to_string()),
                                        Some("docdex_files"),
                                        Some(
                                            json!({ "validation": "serde", "tool": "docdex_files" }),
                                        ),
                                    )),
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
                                    error: Some(rpc_error(
                                        ERR_INVALID_PARAMS,
                                        default_message_for_code("invalid_params"),
                                        "invalid_params",
                                        Some(err.to_string()),
                                        Some("docdex_open"),
                                        Some(
                                            json!({ "validation": "serde", "tool": "docdex_open" }),
                                        ),
                                    )),
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
                    "docdex_tree" | "docdex.tree" => {
                        let args_res: Result<TreeArgs, _> =
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
                                        Some("docdex_tree"),
                                        Some(
                                            json!({ "validation": "serde", "tool": "docdex_tree" }),
                                        ),
                                    )),
                                }))
                            }
                        };
                        match self.handle_tree(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(&err, Some("docdex_tree"))),
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
                                    error: Some(rpc_error(
                                        ERR_INVALID_PARAMS,
                                        default_message_for_code("invalid_params"),
                                        "invalid_params",
                                        Some(err.to_string()),
                                        Some("docdex_stats"),
                                        Some(
                                            json!({ "validation": "serde", "tool": "docdex_stats" }),
                                        ),
                                    )),
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
                                    error: Some(rpc_error(
                                        ERR_INVALID_PARAMS,
                                        default_message_for_code("invalid_params"),
                                        "invalid_params",
                                        Some(err.to_string()),
                                        Some("docdex_repo_inspect"),
                                        Some(
                                            json!({ "validation": "serde", "tool": "docdex_repo_inspect" }),
                                        ),
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
                                    error: Some(rpc_error(
                                        ERR_INVALID_PARAMS,
                                        default_message_for_code("invalid_params"),
                                        "invalid_params",
                                        Some(err.to_string()),
                                        Some("docdex_symbols"),
                                        Some(
                                            json!({ "validation": "serde", "tool": "docdex_symbols" }),
                                        ),
                                    )),
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
                    "docdex_ast" | "docdex.ast" => {
                        let args_res: Result<AstArgs, _> =
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
                                        Some("docdex_ast"),
                                        Some(
                                            json!({ "validation": "serde", "tool": "docdex_ast" }),
                                        ),
                                    )),
                                }))
                            }
                        };
                        match self.handle_ast(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(&err, Some("docdex_ast"))),
                                }))
                            }
                        }
                    }
                    "docdex_impact_diagnostics" | "docdex.impact_diagnostics" => {
                        let args_res: Result<ImpactDiagnosticsArgs, _> =
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
                                        Some("docdex_impact_diagnostics"),
                                        Some(json!({
                                            "validation": "serde",
                                            "tool": "docdex_impact_diagnostics"
                                        })),
                                    )),
                                }))
                            }
                        };
                        match self.handle_impact_diagnostics(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(
                                        &err,
                                        Some("docdex_impact_diagnostics"),
                                    )),
                                }))
                            }
                        }
                    }
                    "docdex_impact_graph" | "docdex.impact_graph" => {
                        let args_res: Result<ImpactGraphArgs, _> =
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
                                        Some("docdex_impact_graph"),
                                        Some(json!({
                                            "validation": "serde",
                                            "tool": "docdex_impact_graph"
                                        })),
                                    )),
                                }))
                            }
                        };
                        match self.handle_impact_graph(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(&err, Some("docdex_impact_graph"))),
                                }))
                            }
                        }
                    }
                    "docdex_dag_export" | "docdex.dag_export" => {
                        let args_res: Result<DagExportArgs, _> =
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
                                        Some("docdex_dag_export"),
                                        Some(json!({
                                            "validation": "serde",
                                            "tool": "docdex_dag_export"
                                        })),
                                    )),
                                }))
                            }
                        };
                        match self.handle_dag_export(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(&err, Some("docdex_dag_export"))),
                                }))
                            }
                        }
                    }
                    "docdex_memory_store"
                    | "docdex.memory_store"
                    | "docdex_memory_save"
                    | "docdex.memory_save" => {
                        let tool_name = params.name.as_str();
                        let args_res: Result<MemoryStoreArgs, _> =
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
                                        Some(tool_name),
                                        Some(json!({ "validation": "serde", "tool": tool_name })),
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
                                    error: Some(rpc_tool_error(&err, Some(tool_name))),
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
                                    error: Some(rpc_error(
                                        ERR_INVALID_PARAMS,
                                        default_message_for_code("invalid_params"),
                                        "invalid_params",
                                        Some(err.to_string()),
                                        Some("docdex_memory_recall"),
                                        Some(
                                            json!({ "validation": "serde", "tool": "docdex_memory_recall" }),
                                        ),
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
                    "docdex_conversation_import" | "docdex.conversation_import" => {
                        let args_res: Result<ConversationImportArgs, _> =
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
                                        Some("docdex_conversation_import"),
                                        Some(json!({
                                            "validation": "serde",
                                            "tool": "docdex_conversation_import"
                                        })),
                                    )),
                                }))
                            }
                        };
                        match self.handle_conversation_import(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(
                                        &err,
                                        Some("docdex_conversation_import"),
                                    )),
                                }))
                            }
                        }
                    }
                    "docdex_conversation_search" | "docdex.conversation_search" => {
                        let args_res: Result<ConversationSearchArgs, _> =
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
                                        Some("docdex_conversation_search"),
                                        Some(json!({
                                            "validation": "serde",
                                            "tool": "docdex_conversation_search"
                                        })),
                                    )),
                                }))
                            }
                        };
                        match self.handle_conversation_search(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(
                                        &err,
                                        Some("docdex_conversation_search"),
                                    )),
                                }))
                            }
                        }
                    }
                    "docdex_conversation_list" | "docdex.conversation_list" => {
                        let args_res: Result<ConversationListArgs, _> =
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
                                        Some("docdex_conversation_list"),
                                        Some(json!({
                                            "validation": "serde",
                                            "tool": "docdex_conversation_list"
                                        })),
                                    )),
                                }))
                            }
                        };
                        match self.handle_conversation_list(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(
                                        &err,
                                        Some("docdex_conversation_list"),
                                    )),
                                }))
                            }
                        }
                    }
                    "docdex_conversation_read" | "docdex.conversation_read" => {
                        let args_res: Result<ConversationReadArgs, _> =
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
                                        Some("docdex_conversation_read"),
                                        Some(json!({
                                            "validation": "serde",
                                            "tool": "docdex_conversation_read"
                                        })),
                                    )),
                                }))
                            }
                        };
                        match self.handle_conversation_read(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(
                                        &err,
                                        Some("docdex_conversation_read"),
                                    )),
                                }))
                            }
                        }
                    }
                    "docdex_conversation_delete" | "docdex.conversation_delete" => {
                        let args_res: Result<ConversationDeleteArgs, _> =
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
                                        Some("docdex_conversation_delete"),
                                        Some(json!({
                                            "validation": "serde",
                                            "tool": "docdex_conversation_delete"
                                        })),
                                    )),
                                }))
                            }
                        };
                        match self.handle_conversation_delete(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(
                                        &err,
                                        Some("docdex_conversation_delete"),
                                    )),
                                }))
                            }
                        }
                    }
                    "docdex_conversation_export" | "docdex.conversation_export" => {
                        let args_res: Result<ConversationExportArgs, _> =
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
                                        Some("docdex_conversation_export"),
                                        Some(json!({
                                            "validation": "serde",
                                            "tool": "docdex_conversation_export"
                                        })),
                                    )),
                                }))
                            }
                        };
                        match self.handle_conversation_export(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(
                                        &err,
                                        Some("docdex_conversation_export"),
                                    )),
                                }))
                            }
                        }
                    }
                    "docdex_conversation_redact" | "docdex.conversation_redact" => {
                        let args_res: Result<ConversationRedactArgs, _> =
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
                                        Some("docdex_conversation_redact"),
                                        Some(json!({
                                            "validation": "serde",
                                            "tool": "docdex_conversation_redact"
                                        })),
                                    )),
                                }))
                            }
                        };
                        match self.handle_conversation_redact(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(
                                        &err,
                                        Some("docdex_conversation_redact"),
                                    )),
                                }))
                            }
                        }
                    }
                    "docdex_conversation_prune" | "docdex.conversation_prune" => {
                        let args_res: Result<ConversationPruneArgs, _> =
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
                                        Some("docdex_conversation_prune"),
                                        Some(json!({
                                            "validation": "serde",
                                            "tool": "docdex_conversation_prune"
                                        })),
                                    )),
                                }))
                            }
                        };
                        match self.handle_conversation_prune(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(
                                        &err,
                                        Some("docdex_conversation_prune"),
                                    )),
                                }))
                            }
                        }
                    }
                    "docdex_diary_write" | "docdex.diary_write" => {
                        let args_res: Result<DiaryWriteArgs, _> =
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
                                        Some("docdex_diary_write"),
                                        Some(json!({
                                            "validation": "serde",
                                            "tool": "docdex_diary_write"
                                        })),
                                    )),
                                }))
                            }
                        };
                        match self.handle_diary_write(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(&err, Some("docdex_diary_write"))),
                                }))
                            }
                        }
                    }
                    "docdex_diary_read" | "docdex.diary_read" => {
                        let args_res: Result<DiaryReadArgs, _> =
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
                                        Some("docdex_diary_read"),
                                        Some(json!({
                                            "validation": "serde",
                                            "tool": "docdex_diary_read"
                                        })),
                                    )),
                                }))
                            }
                        };
                        match self.handle_diary_read(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(&err, Some("docdex_diary_read"))),
                                }))
                            }
                        }
                    }
                    "docdex_conversation_hook" | "docdex.conversation_hook" => {
                        let args_res: Result<ConversationHookArgs, _> =
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
                                        Some("docdex_conversation_hook"),
                                        Some(json!({
                                            "validation": "serde",
                                            "tool": "docdex_conversation_hook"
                                        })),
                                    )),
                                }))
                            }
                        };
                        match self.handle_conversation_hook(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(
                                        &err,
                                        Some("docdex_conversation_hook"),
                                    )),
                                }))
                            }
                        }
                    }
                    "docdex_wakeup" | "docdex.wakeup" => {
                        let args_res: Result<WakeupArgs, _> =
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
                                        Some("docdex_wakeup"),
                                        Some(json!({
                                            "validation": "serde",
                                            "tool": "docdex_wakeup"
                                        })),
                                    )),
                                }))
                            }
                        };
                        match self.handle_wakeup(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(&err, Some("docdex_wakeup"))),
                                }))
                            }
                        }
                    }
                    "docdex_kg_query" | "docdex.kg_query" => {
                        let args_res: Result<KgQueryArgs, _> =
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
                                        Some("docdex_kg_query"),
                                        Some(json!({
                                            "validation": "serde",
                                            "tool": "docdex_kg_query"
                                        })),
                                    )),
                                }))
                            }
                        };
                        match self.handle_kg_query(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(&err, Some("docdex_kg_query"))),
                                }))
                            }
                        }
                    }
                    "docdex_kg_search_nodes" | "docdex.kg_search_nodes" => {
                        let args_res: Result<KgNodeSearchArgs, _> =
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
                                        Some("docdex_kg_search_nodes"),
                                        Some(json!({
                                            "validation": "serde",
                                            "tool": "docdex_kg_search_nodes"
                                        })),
                                    )),
                                }))
                            }
                        };
                        match self.handle_kg_search_nodes(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(
                                        &err,
                                        Some("docdex_kg_search_nodes"),
                                    )),
                                }))
                            }
                        }
                    }
                    "docdex_kg_search_edges" | "docdex.kg_search_edges" => {
                        let args_res: Result<KgEdgeSearchArgs, _> =
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
                                        Some("docdex_kg_search_edges"),
                                        Some(json!({
                                            "validation": "serde",
                                            "tool": "docdex_kg_search_edges"
                                        })),
                                    )),
                                }))
                            }
                        };
                        match self.handle_kg_search_edges(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(
                                        &err,
                                        Some("docdex_kg_search_edges"),
                                    )),
                                }))
                            }
                        }
                    }
                    "docdex_kg_timeline" | "docdex.kg_timeline" => {
                        let args_res: Result<KgTimelineArgs, _> =
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
                                        Some("docdex_kg_timeline"),
                                        Some(json!({
                                            "validation": "serde",
                                            "tool": "docdex_kg_timeline"
                                        })),
                                    )),
                                }))
                            }
                        };
                        match self.handle_kg_timeline(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(&err, Some("docdex_kg_timeline"))),
                                }))
                            }
                        }
                    }
                    "docdex_kg_search_episodes" | "docdex.kg_search_episodes" => {
                        let args_res: Result<KgEpisodeSearchArgs, _> =
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
                                        Some("docdex_kg_search_episodes"),
                                        Some(json!({
                                            "validation": "serde",
                                            "tool": "docdex_kg_search_episodes"
                                        })),
                                    )),
                                }))
                            }
                        };
                        match self.handle_kg_search_episodes(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(
                                        &err,
                                        Some("docdex_kg_search_episodes"),
                                    )),
                                }))
                            }
                        }
                    }
                    "docdex_kg_neighborhood" | "docdex.kg_neighborhood" => {
                        let args_res: Result<KgNeighborhoodArgs, _> =
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
                                        Some("docdex_kg_neighborhood"),
                                        Some(json!({
                                            "validation": "serde",
                                            "tool": "docdex_kg_neighborhood"
                                        })),
                                    )),
                                }))
                            }
                        };
                        match self.handle_kg_neighborhood(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(
                                        &err,
                                        Some("docdex_kg_neighborhood"),
                                    )),
                                }))
                            }
                        }
                    }
                    "docdex_kg_entity_links" | "docdex.kg_entity_links" => {
                        let args_res: Result<KgEntityLinksArgs, _> =
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
                                        Some("docdex_kg_entity_links"),
                                        Some(json!({
                                            "validation": "serde",
                                            "tool": "docdex_kg_entity_links"
                                        })),
                                    )),
                                }))
                            }
                        };
                        match self.handle_kg_entity_links(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(
                                        &err,
                                        Some("docdex_kg_entity_links"),
                                    )),
                                }))
                            }
                        }
                    }
                    "docdex_kg_episode" | "docdex.kg_episode" => {
                        let args_res: Result<KgEpisodeArgs, _> =
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
                                        Some("docdex_kg_episode"),
                                        Some(json!({
                                            "validation": "serde",
                                            "tool": "docdex_kg_episode"
                                        })),
                                    )),
                                }))
                            }
                        };
                        match self.handle_kg_episode(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(&err, Some("docdex_kg_episode"))),
                                }))
                            }
                        }
                    }
                    "docdex_kg_delete_edge" | "docdex.kg_delete_edge" => {
                        let args_res: Result<KgDeleteEdgeArgs, _> =
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
                                        Some("docdex_kg_delete_edge"),
                                        Some(json!({
                                            "validation": "serde",
                                            "tool": "docdex_kg_delete_edge"
                                        })),
                                    )),
                                }))
                            }
                        };
                        match self.handle_kg_delete_edge(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(
                                        &err,
                                        Some("docdex_kg_delete_edge"),
                                    )),
                                }))
                            }
                        }
                    }
                    "docdex_kg_delete_episode" | "docdex.kg_delete_episode" => {
                        let args_res: Result<KgDeleteEpisodeArgs, _> =
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
                                        Some("docdex_kg_delete_episode"),
                                        Some(json!({
                                            "validation": "serde",
                                            "tool": "docdex_kg_delete_episode"
                                        })),
                                    )),
                                }))
                            }
                        };
                        match self.handle_kg_delete_episode(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(
                                        &err,
                                        Some("docdex_kg_delete_episode"),
                                    )),
                                }))
                            }
                        }
                    }
                    "docdex_kg_rebuild" | "docdex.kg_rebuild" => {
                        let args_res: Result<KgMaintenanceArgs, _> =
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
                                        Some("docdex_kg_rebuild"),
                                        Some(json!({
                                            "validation": "serde",
                                            "tool": "docdex_kg_rebuild"
                                        })),
                                    )),
                                }))
                            }
                        };
                        match self.handle_kg_rebuild(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(&err, Some("docdex_kg_rebuild"))),
                                }))
                            }
                        }
                    }
                    "docdex_kg_clear" | "docdex.kg_clear" => {
                        let args_res: Result<KgMaintenanceArgs, _> =
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
                                        Some("docdex_kg_clear"),
                                        Some(json!({
                                            "validation": "serde",
                                            "tool": "docdex_kg_clear"
                                        })),
                                    )),
                                }))
                            }
                        };
                        match self.handle_kg_clear(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(&err, Some("docdex_kg_clear"))),
                                }))
                            }
                        }
                    }
                    "docdex_local_completion" | "docdex.local_completion" => {
                        let args_res: Result<DelegateArgs, _> =
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
                                        Some("docdex_local_completion"),
                                        Some(json!({
                                            "validation": "serde",
                                            "tool": "docdex_local_completion"
                                        })),
                                    )),
                                }))
                            }
                        };
                        match self.handle_delegate(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(
                                        &err,
                                        Some("docdex_local_completion"),
                                    )),
                                }))
                            }
                        }
                    }
                    "docdex_memory_layers" | "docdex.memory_layers" => {
                        let args_res: Result<MemoryLayersArgs, _> =
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
                                        Some("docdex_memory_layers"),
                                        Some(
                                            json!({ "validation": "serde", "tool": "docdex_memory_layers" }),
                                        ),
                                    )),
                                }))
                            }
                        };
                        match self.handle_memory_layers(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(&err, Some("docdex_memory_layers"))),
                                }))
                            }
                        }
                    }
                    "docdex_memory_route" | "docdex.memory_route" => {
                        let args_res: Result<MemoryRouteArgs, _> =
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
                                        Some("docdex_memory_route"),
                                        Some(
                                            json!({ "validation": "serde", "tool": "docdex_memory_route" }),
                                        ),
                                    )),
                                }))
                            }
                        };
                        match self.handle_memory_route(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(&err, Some("docdex_memory_route"))),
                                }))
                            }
                        }
                    }
                    "docdex_personal_preferences_status" | "docdex.personal_preferences_status" => {
                        let args_res: Result<PersonalPreferencesStatusArgs, _> =
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
                                        Some("docdex_personal_preferences_status"),
                                        Some(
                                            json!({ "validation": "serde", "tool": "docdex_personal_preferences_status" }),
                                        ),
                                    )),
                                }))
                            }
                        };
                        match self.handle_personal_preferences_status(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(
                                        &err,
                                        Some("docdex_personal_preferences_status"),
                                    )),
                                }))
                            }
                        }
                    }
                    "docdex_personal_preferences_categories"
                    | "docdex.personal_preferences_categories" => {
                        let args_res: Result<PersonalPreferencesCategoriesArgs, _> =
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
                                        Some("docdex_personal_preferences_categories"),
                                        Some(
                                            json!({ "validation": "serde", "tool": "docdex_personal_preferences_categories" }),
                                        ),
                                    )),
                                }))
                            }
                        };
                        match self.handle_personal_preferences_categories(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(
                                        &err,
                                        Some("docdex_personal_preferences_categories"),
                                    )),
                                }))
                            }
                        }
                    }
                    "docdex_personal_preferences_list" | "docdex.personal_preferences_list" => {
                        let args_res: Result<PersonalPreferencesListArgs, _> =
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
                                        Some("docdex_personal_preferences_list"),
                                        Some(
                                            json!({ "validation": "serde", "tool": "docdex_personal_preferences_list" }),
                                        ),
                                    )),
                                }))
                            }
                        };
                        match self.handle_personal_preferences_list(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(
                                        &err,
                                        Some("docdex_personal_preferences_list"),
                                    )),
                                }))
                            }
                        }
                    }
                    "docdex_personal_preferences_read" | "docdex.personal_preferences_read" => {
                        let args_res: Result<PersonalPreferencesReadArgs, _> =
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
                                        Some("docdex_personal_preferences_read"),
                                        Some(
                                            json!({ "validation": "serde", "tool": "docdex_personal_preferences_read" }),
                                        ),
                                    )),
                                }))
                            }
                        };
                        match self.handle_personal_preferences_read(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(
                                        &err,
                                        Some("docdex_personal_preferences_read"),
                                    )),
                                }))
                            }
                        }
                    }
                    "docdex_personal_preferences_search" | "docdex.personal_preferences_search" => {
                        let args_res: Result<PersonalPreferencesSearchArgs, _> =
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
                                        Some("docdex_personal_preferences_search"),
                                        Some(
                                            json!({ "validation": "serde", "tool": "docdex_personal_preferences_search" }),
                                        ),
                                    )),
                                }))
                            }
                        };
                        match self.handle_personal_preferences_search(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(
                                        &err,
                                        Some("docdex_personal_preferences_search"),
                                    )),
                                }))
                            }
                        }
                    }
                    "docdex_personal_preferences_reviews"
                    | "docdex.personal_preferences_reviews" => {
                        let args_res: Result<PersonalPreferencesReviewQueueArgs, _> =
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
                                        Some("docdex_personal_preferences_reviews"),
                                        Some(
                                            json!({ "validation": "serde", "tool": "docdex_personal_preferences_reviews" }),
                                        ),
                                    )),
                                }))
                            }
                        };
                        match self.handle_personal_preferences_reviews(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(
                                        &err,
                                        Some("docdex_personal_preferences_reviews"),
                                    )),
                                }))
                            }
                        }
                    }
                    "docdex_personal_preferences_review" | "docdex.personal_preferences_review" => {
                        let args_res: Result<PersonalPreferencesReviewArgs, _> =
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
                                        Some("docdex_personal_preferences_review"),
                                        Some(
                                            json!({ "validation": "serde", "tool": "docdex_personal_preferences_review" }),
                                        ),
                                    )),
                                }))
                            }
                        };
                        match self.handle_personal_preferences_review(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(
                                        &err,
                                        Some("docdex_personal_preferences_review"),
                                    )),
                                }))
                            }
                        }
                    }
                    "docdex_personal_preferences_process"
                    | "docdex.personal_preferences_process" => {
                        let args_res: Result<PersonalPreferencesProcessArgs, _> =
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
                                        Some("docdex_personal_preferences_process"),
                                        Some(
                                            json!({ "validation": "serde", "tool": "docdex_personal_preferences_process" }),
                                        ),
                                    )),
                                }))
                            }
                        };
                        match self.handle_personal_preferences_process(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(
                                        &err,
                                        Some("docdex_personal_preferences_process"),
                                    )),
                                }))
                            }
                        }
                    }
                    "docdex_personal_preferences_scan" | "docdex.personal_preferences_scan" => {
                        let args_res: Result<PersonalPreferencesScanArgs, _> =
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
                                        Some("docdex_personal_preferences_scan"),
                                        Some(
                                            json!({ "validation": "serde", "tool": "docdex_personal_preferences_scan" }),
                                        ),
                                    )),
                                }))
                            }
                        };
                        match self.handle_personal_preferences_scan(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(
                                        &err,
                                        Some("docdex_personal_preferences_scan"),
                                    )),
                                }))
                            }
                        }
                    }
                    "docdex_personal_preferences_export" | "docdex.personal_preferences_export" => {
                        let args_res: Result<PersonalPreferencesExportArgs, _> =
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
                                        Some("docdex_personal_preferences_export"),
                                        Some(
                                            json!({ "validation": "serde", "tool": "docdex_personal_preferences_export" }),
                                        ),
                                    )),
                                }))
                            }
                        };
                        match self.handle_personal_preferences_export(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(
                                        &err,
                                        Some("docdex_personal_preferences_export"),
                                    )),
                                }))
                            }
                        }
                    }
                    "docdex_personal_preferences_redact" | "docdex.personal_preferences_redact" => {
                        let args_res: Result<PersonalPreferencesDeleteArgs, _> =
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
                                        Some("docdex_personal_preferences_redact"),
                                        Some(
                                            json!({ "validation": "serde", "tool": "docdex_personal_preferences_redact" }),
                                        ),
                                    )),
                                }))
                            }
                        };
                        match self.handle_personal_preferences_redact(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(
                                        &err,
                                        Some("docdex_personal_preferences_redact"),
                                    )),
                                }))
                            }
                        }
                    }
                    "docdex_personal_preferences_delete" | "docdex.personal_preferences_delete" => {
                        let args_res: Result<PersonalPreferencesDeleteArgs, _> =
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
                                        Some("docdex_personal_preferences_delete"),
                                        Some(
                                            json!({ "validation": "serde", "tool": "docdex_personal_preferences_delete" }),
                                        ),
                                    )),
                                }))
                            }
                        };
                        match self.handle_personal_preferences_delete(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(
                                        &err,
                                        Some("docdex_personal_preferences_delete"),
                                    )),
                                }))
                            }
                        }
                    }
                    "docdex_personal_preferences_prune" | "docdex.personal_preferences_prune" => {
                        let args_res: Result<PersonalPreferencesPruneArgs, _> =
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
                                        Some("docdex_personal_preferences_prune"),
                                        Some(
                                            json!({ "validation": "serde", "tool": "docdex_personal_preferences_prune" }),
                                        ),
                                    )),
                                }))
                            }
                        };
                        match self.handle_personal_preferences_prune(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(
                                        &err,
                                        Some("docdex_personal_preferences_prune"),
                                    )),
                                }))
                            }
                        }
                    }
                    "docdex_personal_preferences_purge" | "docdex.personal_preferences_purge" => {
                        let args_res: Result<PersonalPreferencesPurgeArgs, _> =
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
                                        Some("docdex_personal_preferences_purge"),
                                        Some(
                                            json!({ "validation": "serde", "tool": "docdex_personal_preferences_purge" }),
                                        ),
                                    )),
                                }))
                            }
                        };
                        match self.handle_personal_preferences_purge(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(
                                        &err,
                                        Some("docdex_personal_preferences_purge"),
                                    )),
                                }))
                            }
                        }
                    }
                    "docdex_personal_preferences_claims" | "docdex.personal_preferences_claims" => {
                        let args_res: Result<PersonalPreferencesClaimsArgs, _> =
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
                                        Some("docdex_personal_preferences_claims"),
                                        Some(
                                            json!({ "validation": "serde", "tool": "docdex_personal_preferences_claims" }),
                                        ),
                                    )),
                                }))
                            }
                        };
                        match self.handle_personal_preferences_claims(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(
                                        &err,
                                        Some("docdex_personal_preferences_claims"),
                                    )),
                                }))
                            }
                        }
                    }
                    "docdex_personal_preferences_claim_read"
                    | "docdex.personal_preferences_claim_read" => {
                        let args_res: Result<PersonalPreferencesClaimReadArgs, _> =
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
                                        Some("docdex_personal_preferences_claim_read"),
                                        Some(
                                            json!({ "validation": "serde", "tool": "docdex_personal_preferences_claim_read" }),
                                        ),
                                    )),
                                }))
                            }
                        };
                        match self.handle_personal_preferences_claim_read(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(
                                        &err,
                                        Some("docdex_personal_preferences_claim_read"),
                                    )),
                                }))
                            }
                        }
                    }
                    "docdex_personal_preferences_claim_review"
                    | "docdex.personal_preferences_claim_review" => {
                        let args_res: Result<PersonalPreferencesClaimReviewArgs, _> =
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
                                        Some("docdex_personal_preferences_claim_review"),
                                        Some(
                                            json!({ "validation": "serde", "tool": "docdex_personal_preferences_claim_review" }),
                                        ),
                                    )),
                                }))
                            }
                        };
                        match self.handle_personal_preferences_claim_review(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(
                                        &err,
                                        Some("docdex_personal_preferences_claim_review"),
                                    )),
                                }))
                            }
                        }
                    }
                    "docdex_personal_preferences_claim_override"
                    | "docdex.personal_preferences_claim_override" => {
                        let args_res: Result<PersonalPreferencesClaimOverrideArgs, _> =
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
                                        Some("docdex_personal_preferences_claim_override"),
                                        Some(
                                            json!({ "validation": "serde", "tool": "docdex_personal_preferences_claim_override" }),
                                        ),
                                    )),
                                }))
                            }
                        };
                        match self.handle_personal_preferences_claim_override(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(
                                        &err,
                                        Some("docdex_personal_preferences_claim_override"),
                                    )),
                                }))
                            }
                        }
                    }
                    "docdex_personal_preferences_claim_forget"
                    | "docdex.personal_preferences_claim_forget" => {
                        let args_res: Result<PersonalPreferencesClaimForgetArgs, _> =
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
                                        Some("docdex_personal_preferences_claim_forget"),
                                        Some(
                                            json!({ "validation": "serde", "tool": "docdex_personal_preferences_claim_forget" }),
                                        ),
                                    )),
                                }))
                            }
                        };
                        match self.handle_personal_preferences_claim_forget(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(
                                        &err,
                                        Some("docdex_personal_preferences_claim_forget"),
                                    )),
                                }))
                            }
                        }
                    }
                    "docdex_personal_preferences_feedback"
                    | "docdex.personal_preferences_feedback" => {
                        let args_res: Result<PersonalPreferencesFeedbackArgs, _> =
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
                                        Some("docdex_personal_preferences_feedback"),
                                        Some(
                                            json!({ "validation": "serde", "tool": "docdex_personal_preferences_feedback" }),
                                        ),
                                    )),
                                }))
                            }
                        };
                        match self.handle_personal_preferences_feedback(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(
                                        &err,
                                        Some("docdex_personal_preferences_feedback"),
                                    )),
                                }))
                            }
                        }
                    }
                    "docdex_personal_preferences_snapshots"
                    | "docdex.personal_preferences_snapshots" => {
                        let args_res: Result<PersonalPreferencesSnapshotsArgs, _> =
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
                                        Some("docdex_personal_preferences_snapshots"),
                                        Some(
                                            json!({ "validation": "serde", "tool": "docdex_personal_preferences_snapshots" }),
                                        ),
                                    )),
                                }))
                            }
                        };
                        match self.handle_personal_preferences_snapshots(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(
                                        &err,
                                        Some("docdex_personal_preferences_snapshots"),
                                    )),
                                }))
                            }
                        }
                    }
                    "docdex_personal_preferences_snapshot_read"
                    | "docdex.personal_preferences_snapshot_read" => {
                        let args_res: Result<PersonalPreferencesSnapshotReadArgs, _> =
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
                                        Some("docdex_personal_preferences_snapshot_read"),
                                        Some(
                                            json!({ "validation": "serde", "tool": "docdex_personal_preferences_snapshot_read" }),
                                        ),
                                    )),
                                }))
                            }
                        };
                        match self.handle_personal_preferences_snapshot_read(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(
                                        &err,
                                        Some("docdex_personal_preferences_snapshot_read"),
                                    )),
                                }))
                            }
                        }
                    }
                    "docdex_personal_preferences_snapshots_rebuild"
                    | "docdex.personal_preferences_snapshots_rebuild" => {
                        match self.handle_personal_preferences_snapshots_rebuild().await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(
                                        &err,
                                        Some("docdex_personal_preferences_snapshots_rebuild"),
                                    )),
                                }))
                            }
                        }
                    }
                    "docdex_clone_context" | "docdex.clone_context" => {
                        let args_res: Result<PersonalPreferencesCloneArgs, _> =
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
                                        Some("docdex_clone_context"),
                                        Some(
                                            json!({ "validation": "serde", "tool": "docdex_clone_context" }),
                                        ),
                                    )),
                                }))
                            }
                        };
                        match self.handle_clone_context(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(&err, Some("docdex_clone_context"))),
                                }))
                            }
                        }
                    }
                    "docdex_clone_explain" | "docdex.clone_explain" => {
                        let args_res: Result<PersonalPreferencesCloneArgs, _> =
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
                                        Some("docdex_clone_explain"),
                                        Some(
                                            json!({ "validation": "serde", "tool": "docdex_clone_explain" }),
                                        ),
                                    )),
                                }))
                            }
                        };
                        match self.handle_clone_explain(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(&err, Some("docdex_clone_explain"))),
                                }))
                            }
                        }
                    }
                    "docdex_clone_evaluate" | "docdex.clone_evaluate" => {
                        let args_res: Result<PersonalPreferencesCloneArgs, _> =
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
                                        Some("docdex_clone_evaluate"),
                                        Some(
                                            json!({ "validation": "serde", "tool": "docdex_clone_evaluate" }),
                                        ),
                                    )),
                                }))
                            }
                        };
                        match self.handle_clone_evaluate(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(
                                        &err,
                                        Some("docdex_clone_evaluate"),
                                    )),
                                }))
                            }
                        }
                    }
                    "docdex_save_preference" => {
                        let args_res: Result<ProfileSaveArgs, _> =
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
                                        Some("docdex_save_preference"),
                                        Some(
                                            json!({ "validation": "serde", "tool": "docdex_save_preference" }),
                                        ),
                                    )),
                                }))
                            }
                        };
                        match self.handle_profile_save_preference(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(
                                        &err,
                                        Some("docdex_save_preference"),
                                    )),
                                }))
                            }
                        }
                    }
                    "docdex_get_profile" => {
                        let args_res: Result<ProfileGetArgs, _> =
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
                                        Some("docdex_get_profile"),
                                        Some(
                                            json!({ "validation": "serde", "tool": "docdex_get_profile" }),
                                        ),
                                    )),
                                }))
                            }
                        };
                        match self.handle_profile_get_profile(args).await {
                            Ok(value) => value,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(rpc_tool_error(&err, Some("docdex_get_profile"))),
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
                                        "docdex_web_research",
                                        "docdex_capabilities",
                                        "docdex_rerank",
                                        "docdex_batch_search",
                                        "docdex_index",
                                    "docdex_files",
                                    "docdex_open",
                                    "docdex_tree",
                                    "docdex_stats",
                                        "docdex_repo_inspect",
                                        "docdex_symbols",
                                        "docdex_ast",
                                        "docdex_impact_diagnostics",
                                        "docdex_impact_graph",
                                        "docdex_dag_export",
                                        "docdex_memory_save",
                                        "docdex_memory_store",
                                        "docdex_memory_recall",
                                        "docdex_conversation_import",
                                        "docdex_conversation_search",
                                        "docdex_conversation_list",
                                        "docdex_conversation_read",
                                        "docdex_conversation_export",
                                        "docdex_conversation_delete",
                                        "docdex_conversation_redact",
                                        "docdex_conversation_prune",
                                        "docdex_diary_write",
                                        "docdex_diary_read",
                                        "docdex_conversation_hook",
                                        "docdex_wakeup",
                                        "docdex_kg_query",
                                        "docdex_kg_search_nodes",
                                        "docdex_kg_search_edges",
                                        "docdex_kg_timeline",
                                        "docdex_kg_search_episodes",
                                        "docdex_kg_neighborhood",
                                        "docdex_kg_entity_links",
                                        "docdex_kg_episode",
                                        "docdex_kg_delete_edge",
                                        "docdex_kg_delete_episode",
                                        "docdex_kg_rebuild",
                                        "docdex_kg_clear",
                                        "docdex_local_completion",
                                        "docdex_personal_preferences_status",
                                        "docdex_personal_preferences_categories",
                                        "docdex_personal_preferences_list",
                                        "docdex_personal_preferences_read",
                                        "docdex_personal_preferences_search",
                                        "docdex_personal_preferences_reviews",
                                        "docdex_personal_preferences_review",
                                        "docdex_personal_preferences_process",
                                        "docdex_personal_preferences_scan",
                                        "docdex_personal_preferences_export",
                                        "docdex_personal_preferences_redact",
                                        "docdex_personal_preferences_delete",
                                        "docdex_personal_preferences_prune",
                                        "docdex_personal_preferences_purge",
                                        "docdex_personal_preferences_claims",
                                        "docdex_personal_preferences_claim_read",
                                        "docdex_personal_preferences_claim_review",
                                        "docdex_personal_preferences_claim_override",
                                        "docdex_personal_preferences_claim_forget",
                                        "docdex_personal_preferences_feedback",
                                        "docdex_personal_preferences_snapshots",
                                        "docdex_personal_preferences_snapshot_read",
                                        "docdex_personal_preferences_snapshots_rebuild",
                                        "docdex_clone_context",
                                        "docdex_clone_explain",
                                        "docdex_clone_evaluate",
                                        "docdex_save_preference",
                                        "docdex_get_profile"
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

    fn tool_defs(&self) -> Vec<ToolDefinition> {
        vec![
            ToolDefinition {
                name: "docdex_search",
                title: "Search Repo",
                description:
                    "Search repo docs/code and return hits with rel_path/path, summary, snippet, and doc_id.",
                annotations: Some(annotations_with_priority(0.9)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "query": { "type": "string", "minLength": 1, "description": "Concise search query (will be rejected if empty)" },
                        "limit": { "type": "integer", "minimum": 1, "maximum": self.max_results as i64, "default": self.max_results, "description": "Max results to return (clamped to server max)" },
                        "force_web": { "type": "boolean", "description": "When true, bypasses the Tier 2 gate and runs web research" },
                        "async_web": { "type": "boolean", "description": "When true, return local results immediately and defer web research to a background task" },
                        "diff": {
                            "type": "object",
                            "description": "Optional diff-aware context inputs",
                            "properties": {
                                "mode": { "type": "string", "enum": ["working_tree", "working", "staged", "range"], "description": "Diff scope (working tree, staged, or range)" },
                                "base": { "type": "string", "description": "Base ref for range diffs" },
                                "head": { "type": "string", "description": "Head ref for range diffs" },
                                "paths": { "type": "array", "items": { "type": "string" }, "description": "Limit diff to specific paths" }
                            }
                        },
                        "dag_session_id": { "type": "string", "description": "Optional DAG session id for reasoning traces (falls back to request id if omitted)" },
                        "project_root": { "type": "string", "description": "Repo root; must match the MCP server repo (required unless initialize set a default)" },
                        "repo_path": { "type": "string", "description": "Alias for project_root (same rules)" }
                    },
                    "required": ["query"]
                }),
            },
            ToolDefinition {
                name: "docdex_capabilities",
                title: "Docdex Capabilities",
                description:
                    "Return the Docdex optional-feature capability contract for Codali integration.",
                annotations: Some(annotations_with_priority(0.8)),
                input_schema: json!({
                    "type": "object",
                    "properties": {}
                }),
            },
            ToolDefinition {
                name: "docdex_rerank",
                title: "Rerank Candidates",
                description:
                    "Rerank candidate hits with transparent score updates and deterministic fallback behavior.",
                annotations: Some(annotations_with_priority(0.7)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "query": { "type": "string", "minLength": 1, "description": "Search query used for reranking" },
                        "candidates": {
                            "type": "array",
                            "minItems": 1,
                            "maxItems": RERANK_MAX_CANDIDATES as i64,
                            "items": { "type": "object", "additionalProperties": true },
                            "description": "Candidate hit set to rerank"
                        },
                        "limit": { "type": "integer", "minimum": 1, "maximum": self.max_results.min(RERANK_MAX_CANDIDATES) as i64, "description": "Max reranked hits to return" },
                        "project_root": { "type": "string", "description": "Repo root; must match the MCP server repo (required unless initialize set a default)" },
                        "repo_path": { "type": "string", "description": "Alias for project_root (same rules)" }
                    },
                    "required": ["query", "candidates"]
                }),
            },
            ToolDefinition {
                name: "docdex_batch_search",
                title: "Batch Search",
                description:
                    "Run batched search queries with deterministic truncation and per-query responses.",
                annotations: Some(annotations_with_priority(0.7)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "queries": {
                            "type": "array",
                            "minItems": 1,
                            "maxItems": BATCH_SEARCH_MAX_QUERIES as i64,
                            "items": { "type": "string", "minLength": 1 },
                            "description": "List of queries to execute"
                        },
                        "limit": { "type": "integer", "minimum": 1, "maximum": self.max_results as i64, "description": "Max hits per query" },
                        "include_libs": { "type": "boolean", "description": "Include libs index hits when available" },
                        "project_root": { "type": "string", "description": "Repo root; must match the MCP server repo (required unless initialize set a default)" },
                        "repo_path": { "type": "string", "description": "Alias for project_root (same rules)" }
                    },
                    "required": ["queries"]
                }),
            },
            ToolDefinition {
                name: "docdex_web_research",
                title: "Web Research",
                description:
                    "Run local search plus web discovery/fetch and return the combined response (requires web enabled).",
                annotations: Some(annotations_with_priority(0.6)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "query": { "type": "string", "minLength": 1, "description": "Concise search query (will be rejected if empty)" },
                        "limit": { "type": "integer", "minimum": 1, "maximum": self.max_results as i64, "default": self.max_results, "description": "Max local hits to return (clamped to server max)" },
                        "web_limit": { "type": "integer", "minimum": 1, "description": "Optional max web hits to fetch (clamped by DOCDEX_WEB_MAX_HITS)" },
                        "force_web": { "type": "boolean", "description": "When true, bypasses the Tier 2 gate and runs web research" },
                        "skip_local_search": { "type": "boolean", "description": "When true, skip local search and only use web results" },
                        "no_cache": { "type": "boolean", "description": "Disable web cache reads/writes for this query" },
                        "llm_filter_local_results": { "type": "boolean", "description": "Use the LLM to filter local search results before scoring" },
                        "repo_only": { "type": "boolean", "description": "Only search the repo index (ignore repo-scoped libs index, if present)" },
                        "llm_model": { "type": "string", "description": "Override the LLM model for local result filtering" },
                        "llm_agent": { "type": "string", "description": "Override the LLM agent slug for local result filtering" },
                        "dag_session_id": { "type": "string", "description": "Optional DAG session id for reasoning traces (falls back to request id if omitted)" },
                        "project_root": { "type": "string", "description": "Repo root; must match the MCP server repo (required unless initialize set a default)" },
                        "repo_path": { "type": "string", "description": "Alias for project_root (same rules)" }
                    },
                    "required": ["query"]
                }),
            },
            ToolDefinition {
                name: "docdex_index",
                title: "Index Repo",
                description:
                    "Rebuild the index (or ingest specific files) for the current repo root; use after large changes or stale results.",
                annotations: Some(annotations_with_priority(0.7)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "paths": {
                            "type": "array",
                            "items": { "type": "string" },
                            "description": "Optional list of files to ingest; empty => full reindex"
                        },
                        "project_root": { "type": "string", "description": "Repo root; must match the MCP server repo (required unless initialize set a default)" },
                        "repo_path": { "type": "string", "description": "Alias for project_root (same rules)" }
                    }
                }),
            },
            ToolDefinition {
                name: "docdex_files",
                title: "List Files",
                description:
                    "List indexed documents (rel_path/doc_id/token_estimate) for the current repo.",
                annotations: Some(annotations_with_priority(0.6)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "project_root": { "type": "string", "description": "Repo root; must match the MCP server repo (required unless initialize set a default)" },
                        "repo_path": { "type": "string", "description": "Alias for project_root (same rules)" },
                        "limit": { "type": "integer", "minimum": 1, "maximum": FILES_MAX_LIMIT as i64, "default": FILES_DEFAULT_LIMIT, "description": "Max documents to return (clamped)" },
                        "offset": { "type": "integer", "minimum": 0, "maximum": FILES_MAX_OFFSET as i64, "default": 0, "description": "Number of docs to skip before listing (clamped)" }
                    }
                }),
            },
            ToolDefinition {
                name: "docdex_open",
                title: "Open File",
                description:
                    "Read a file from the repo (optional line window); rejects paths outside the repo.",
                annotations: Some(annotations_with_priority(0.6)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "minLength": 1, "description": "Relative path under the repo" },
                        "project_root": { "type": "string", "description": "Repo root; must match the MCP server repo (required unless initialize set a default)" },
                        "repo_path": { "type": "string", "description": "Alias for project_root (same rules)" },
                        "start_line": { "type": "integer", "minimum": 1, "description": "Optional start line (1-based, inclusive)" },
                        "end_line": { "type": "integer", "minimum": 1, "description": "Optional end line (1-based, inclusive)" },
                        "head": { "type": "integer", "minimum": 1, "description": "Optional convenience: read the first N lines (clamped to file length)" },
                        "clamp": { "type": "boolean", "description": "Clamp start/end to file bounds instead of raising invalid_range" }
                    },
                    "required": ["path"]
                }),
            },
            ToolDefinition {
                name: "docdex_tree",
                title: "Render Repo Tree",
                description:
                    "Render a folder tree with standard excludes (git, node_modules, build artifacts).",
                annotations: Some(annotations_with_priority(0.6)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "description": "Repo-relative path to render (defaults to repo root)" },
                        "max_depth": { "type": "integer", "minimum": 0, "description": "Max depth (0 returns only the root label)" },
                        "dirs_only": { "type": "boolean", "description": "When true, only include directories" },
                        "include_hidden": { "type": "boolean", "description": "When true, include dotfiles and dot directories" },
                        "extra_excludes": { "type": "array", "items": { "type": "string" }, "description": "Extra names to exclude (exact basename match)" },
                        "project_root": { "type": "string", "description": "Repo root; must match the MCP server repo (required unless initialize set a default)" },
                        "repo_path": { "type": "string", "description": "Alias for project_root (same rules)" }
                    }
                }),
            },
            ToolDefinition {
                name: "docdex_stats",
                title: "Repo Stats",
                description:
                    "Inspect index metadata: doc count, state dir, size on disk, and last update time.",
                annotations: Some(annotations_with_priority(0.5)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "project_root": { "type": "string", "description": "Repo root; must match the MCP server repo (required unless initialize set a default)" },
                        "repo_path": { "type": "string", "description": "Alias for project_root (same rules)" }
                    }
                }),
            },
            ToolDefinition {
                name: "docdex_repo_inspect",
                title: "Repo Inspect",
                description:
                    "Inspect how Docdex resolves repo identity (normalized path, fingerprint, and any shared-state mapping).",
                annotations: Some(annotations_with_priority(0.5)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "project_root": { "type": "string", "description": "Repo root; must match the MCP server repo (required unless initialize set a default)" },
                        "repo_path": { "type": "string", "description": "Alias for project_root (same rules)" }
                    }
                }),
            },
            ToolDefinition {
                name: "docdex_symbols",
                title: "Symbols",
                description: "Read the symbol extraction result for a file, including per-file outcome (ok/skipped/failed).",
                annotations: Some(annotations_with_priority(0.7)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "minLength": 1, "description": "Relative path under the repo" },
                        "project_root": { "type": "string", "description": "Repo root; must match the MCP server repo (required unless initialize set a default)" },
                        "repo_path": { "type": "string", "description": "Alias for project_root (same rules)" }
                    },
                    "required": ["path"]
                }),
            },
            ToolDefinition {
                name: "docdex_ast",
                title: "AST",
                description: "Read Tree-sitter AST nodes for a file, including per-file outcome (ok/skipped/failed).",
                annotations: Some(annotations_with_priority(0.7)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "minLength": 1, "description": "Relative path under the repo" },
                        "max_nodes": { "type": "integer", "minimum": 1, "description": "Maximum nodes to return (default 20000)" },
                        "project_root": { "type": "string", "description": "Repo root; must match the MCP server repo (required unless initialize set a default)" },
                        "repo_path": { "type": "string", "description": "Alias for project_root (same rules)" }
                    },
                    "required": ["path"]
                }),
            },
            ToolDefinition {
                name: "docdex_impact_diagnostics",
                title: "Impact Diagnostics",
                description: "List unresolved dynamic import diagnostics by file.",
                annotations: Some(annotations_with_priority(0.7)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "file": { "type": "string", "description": "Optional repo-relative file path to filter diagnostics" },
                        "limit": { "type": "integer", "minimum": 1, "description": "Max entries to return (default 200)" },
                        "offset": { "type": "integer", "minimum": 0, "description": "Offset into the diagnostics list (default 0)" },
                        "project_root": { "type": "string", "description": "Repo root; must match the MCP server repo (required unless initialize set a default)" },
                        "repo_path": { "type": "string", "description": "Alias for project_root (same rules)" }
                    }
                }),
            },
            ToolDefinition {
                name: "docdex_impact_graph",
                title: "Impact Graph",
                description: "Fetch impact graph traversal for a repo-relative file.",
                annotations: Some(annotations_with_priority(0.7)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "file": { "type": "string", "minLength": 1, "description": "Repo-relative file path to analyze" },
                        "max_edges": { "type": "integer", "minimum": 0, "description": "Optional max edges to return (default 1000)" },
                        "max_depth": { "type": "integer", "minimum": 0, "description": "Optional max traversal depth (default 10)" },
                        "edge_types": { "type": "array", "items": { "type": "string" }, "description": "Optional list of edge types to include" },
                        "project_root": { "type": "string", "description": "Repo root; must match the MCP server repo (required unless initialize set a default)" },
                        "repo_path": { "type": "string", "description": "Alias for project_root (same rules)" }
                    },
                    "required": ["file"]
                }),
            },
            ToolDefinition {
                name: "docdex_dag_export",
                title: "DAG Export",
                description: "Export a DAG session for a given session_id (json/text/dot).",
                annotations: Some(annotations_with_priority(0.6)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "session_id": { "type": "string", "minLength": 1, "description": "DAG session id to export" },
                        "dag_session_id": { "type": "string", "minLength": 1, "description": "Alias for session_id (use the dag_session_id returned by search/web_research)" },
                        "format": { "type": "string", "description": "Output format: json, text, or dot (default json)" },
                        "max_nodes": { "type": "integer", "minimum": 1, "description": "Optional max nodes to include" },
                        "project_root": { "type": "string", "description": "Repo root; must match the MCP server repo (required unless initialize set a default)" },
                        "repo_path": { "type": "string", "description": "Alias for project_root (same rules)" }
                    }
                }),
            },
            ToolDefinition {
                name: "docdex_memory_save",
                title: "Save Memory",
                description: "Store a memory item (requires DOCDEX_ENABLE_MEMORY=1).",
                annotations: Some(annotations_with_priority(0.5)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "text": { "type": "string", "minLength": 1, "description": "Memory text to store" },
                        "metadata": { "type": "object", "description": "Optional metadata object", "additionalProperties": true },
                        "project_root": { "type": "string", "description": "Repo root; must match the MCP server repo (required unless initialize set a default)" },
                        "repo_path": { "type": "string", "description": "Alias for project_root (same rules)" }
                    },
                    "required": ["text"]
                }),
            },
            ToolDefinition {
                name: "docdex_memory_store",
                title: "Store Memory",
                description: "Store a memory item (requires DOCDEX_ENABLE_MEMORY=1).",
                annotations: Some(annotations_with_priority(0.5)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "text": { "type": "string", "minLength": 1, "description": "Memory text to store" },
                        "metadata": { "type": "object", "description": "Optional metadata object", "additionalProperties": true },
                        "project_root": { "type": "string", "description": "Repo root; must match the MCP server repo (required unless initialize set a default)" },
                        "repo_path": { "type": "string", "description": "Alias for project_root (same rules)" }
                    },
                    "required": ["text"]
                }),
            },
            ToolDefinition {
                name: "docdex_memory_recall",
                title: "Recall Memory",
                description: "Recall memory items by semantic similarity (requires DOCDEX_ENABLE_MEMORY=1).",
                annotations: Some(annotations_with_priority(0.5)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "query": { "type": "string", "minLength": 1, "description": "Query text to embed" },
                        "top_k": { "type": "integer", "minimum": 1, "maximum": 50, "default": 5, "description": "Max results to return" },
                        "project_root": { "type": "string", "description": "Repo root; must match the MCP server repo (required unless initialize set a default)" },
                        "repo_path": { "type": "string", "description": "Alias for project_root (same rules)" }
                    },
                    "required": ["query"]
                }),
            },
            ToolDefinition {
                name: "docdex_conversation_import",
                title: "Import Conversation",
                description: "Import a normalized conversation session, plain-text transcript, or native export format into repo-scoped conversation memory or an explicit global conversation namespace.",
                annotations: Some(annotations_with_priority(0.5)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "source": { "type": "string", "description": "Optional source label (defaults to manual)" },
                        "source_session_id": { "type": "string", "description": "Optional source-side session id for dedupe" },
                        "title": { "type": "string" },
                        "agent_id": { "type": "string" },
                        "transport": { "type": "string" },
                        "started_at_ms": { "type": "integer" },
                        "ended_at_ms": { "type": "integer" },
                        "format": {
                            "type": "string",
                            "enum": ["auto", "plain_text", "generic_json", "codex_jsonl", "claude_jsonl", "chatgpt_export"],
                            "description": "Optional transcript format hint for transcript_text parsing"
                        },
                        "messages": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "role": { "type": "string" },
                                    "content": { "type": "string" },
                                    "author": { "type": "string" },
                                    "created_at_ms": { "type": "integer" },
                                    "metadata": { "type": "object", "additionalProperties": true }
                                },
                                "required": ["role", "content"]
                            }
                        },
                        "transcript_text": { "type": "string", "description": "Alternative transcript payload for auto/plain-text/native import parsing" },
                        "metadata": { "type": "object", "additionalProperties": true },
                        "project_root": { "type": "string", "description": "Repo root; must match the MCP server repo (required unless initialize set a default)" },
                        "repo_path": { "type": "string", "description": "Alias for project_root (same rules)" },
                        "conversation_namespace": { "type": "string", "description": "Explicit global conversation namespace to use instead of project_root/repo_path" }
                    }
                }),
            },
            ToolDefinition {
                name: "docdex_conversation_search",
                title: "Search Conversations",
                description: "Search conversation archive summaries and raw message snippets for a repo or explicit global conversation namespace.",
                annotations: Some(annotations_with_priority(0.5)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "query": { "type": "string", "minLength": 1, "description": "Search query" },
                        "agent_id": { "type": "string", "description": "Optional agent id filter" },
                        "limit": { "type": "integer", "minimum": 1, "maximum": 100, "default": 20 },
                        "offset": { "type": "integer", "minimum": 0, "default": 0 },
                        "project_root": { "type": "string", "description": "Repo root; must match the MCP server repo (required unless initialize set a default)" },
                        "repo_path": { "type": "string", "description": "Alias for project_root (same rules)" },
                        "conversation_namespace": { "type": "string", "description": "Explicit global conversation namespace to use instead of project_root/repo_path" }
                    },
                    "required": ["query"]
                }),
            },
            ToolDefinition {
                name: "docdex_conversation_list",
                title: "List Conversations",
                description: "List conversation sessions with summaries and metadata for a repo or explicit global conversation namespace.",
                annotations: Some(annotations_with_priority(0.5)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "agent_id": { "type": "string", "description": "Optional agent id filter" },
                        "limit": { "type": "integer", "minimum": 1, "maximum": 100, "default": 20 },
                        "offset": { "type": "integer", "minimum": 0, "default": 0 },
                        "project_root": { "type": "string", "description": "Repo root; must match the MCP server repo (required unless initialize set a default)" },
                        "repo_path": { "type": "string", "description": "Alias for project_root (same rules)" },
                        "conversation_namespace": { "type": "string", "description": "Explicit global conversation namespace to use instead of project_root/repo_path" }
                    }
                }),
            },
            ToolDefinition {
                name: "docdex_conversation_read",
                title: "Read Conversation",
                description: "Read a conversation session with ordered messages and derived artifacts from a repo or explicit global conversation namespace.",
                annotations: Some(annotations_with_priority(0.5)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "session_id": { "type": "string", "minLength": 1, "description": "Conversation session id" },
                        "project_root": { "type": "string", "description": "Repo root; must match the MCP server repo (required unless initialize set a default)" },
                        "repo_path": { "type": "string", "description": "Alias for project_root (same rules)" },
                        "conversation_namespace": { "type": "string", "description": "Explicit global conversation namespace to use instead of project_root/repo_path" }
                    },
                    "required": ["session_id"]
                }),
            },
            ToolDefinition {
                name: "docdex_conversation_delete",
                title: "Delete Conversation",
                description: "Delete a conversation session and its derived artifacts from a repo or explicit global conversation namespace.",
                annotations: Some(annotations_with_priority(0.5)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "session_id": { "type": "string", "minLength": 1, "description": "Conversation session id" },
                        "project_root": { "type": "string", "description": "Repo root; must match the MCP server repo (required unless initialize set a default)" },
                        "repo_path": { "type": "string", "description": "Alias for project_root (same rules)" },
                        "conversation_namespace": { "type": "string", "description": "Explicit global conversation namespace to use instead of project_root/repo_path" }
                    },
                    "required": ["session_id"]
                }),
            },
            ToolDefinition {
                name: "docdex_conversation_export",
                title: "Export Conversation",
                description: "Export one conversation session with any linked diary entries from a repo or explicit global conversation namespace.",
                annotations: Some(annotations_with_priority(0.45)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "session_id": { "type": "string", "minLength": 1, "description": "Conversation session id" },
                        "project_root": { "type": "string", "description": "Repo root; must match the MCP server repo (required unless initialize set a default)" },
                        "repo_path": { "type": "string", "description": "Alias for project_root (same rules)" },
                        "conversation_namespace": { "type": "string", "description": "Explicit global conversation namespace to use instead of project_root/repo_path" }
                    },
                    "required": ["session_id"]
                }),
            },
            ToolDefinition {
                name: "docdex_conversation_redact",
                title: "Redact Conversation",
                description: "Redact one conversation session and clear its derived wake-up artifacts in a repo or explicit global conversation namespace.",
                annotations: Some(annotations_with_priority(0.45)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "session_id": { "type": "string", "minLength": 1, "description": "Conversation session id" },
                        "project_root": { "type": "string", "description": "Repo root; must match the MCP server repo (required unless initialize set a default)" },
                        "repo_path": { "type": "string", "description": "Alias for project_root (same rules)" },
                        "conversation_namespace": { "type": "string", "description": "Explicit global conversation namespace to use instead of project_root/repo_path" }
                    },
                    "required": ["session_id"]
                }),
            },
            ToolDefinition {
                name: "docdex_conversation_prune",
                title: "Prune Conversation Retention",
                description: "Preview or apply conversation retention cleanup for a repo or explicit global conversation namespace using current config or explicit overrides.",
                annotations: Some(annotations_with_priority(0.4)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "manual_retention_days": { "type": "integer", "minimum": 0, "description": "Retention window for manual imports; 0 keeps them forever" },
                        "auto_capture_retention_days": { "type": "integer", "minimum": 0, "description": "Retention window for auto-captured sessions; 0 disables pruning" },
                        "diary_retention_days": { "type": "integer", "minimum": 0, "description": "Retention window for diary entries; 0 keeps them forever" },
                        "hook_event_retention_days": { "type": "integer", "minimum": 0, "description": "Retention window for hook event records; 0 disables pruning" },
                        "working_memory_retention_days": { "type": "integer", "minimum": 0, "description": "Retention window for working-memory records; 0 keeps them forever" },
                        "episodic_rollup_retention_days": { "type": "integer", "minimum": 0, "description": "Retention window for stored episodic rollups; 0 keeps them forever" },
                        "apply": { "type": "boolean", "default": false, "description": "When false, return a dry-run count only" },
                        "project_root": { "type": "string", "description": "Repo root; must match the MCP server repo (required unless initialize set a default)" },
                        "repo_path": { "type": "string", "description": "Alias for project_root (same rules)" },
                        "conversation_namespace": { "type": "string", "description": "Explicit global conversation namespace to use instead of project_root/repo_path" }
                    }
                }),
            },
            ToolDefinition {
                name: "docdex_diary_write",
                title: "Write Diary Entry",
                description: "Write one diary entry for an agent in a repo or explicit global conversation namespace.",
                annotations: Some(annotations_with_priority(0.45)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "content": { "type": "string", "minLength": 1, "description": "Diary entry content" },
                        "agent_id": { "type": "string", "description": "Optional agent id filter" },
                        "entry_type": { "type": "string", "description": "Entry type label (defaults to note)" },
                        "source_session_id": { "type": "string", "description": "Optional related conversation session id" },
                        "metadata": { "type": "object", "additionalProperties": true },
                        "project_root": { "type": "string", "description": "Repo root; must match the MCP server repo (required unless initialize set a default)" },
                        "repo_path": { "type": "string", "description": "Alias for project_root (same rules)" },
                        "conversation_namespace": { "type": "string", "description": "Explicit global conversation namespace to use instead of project_root/repo_path" }
                    },
                    "required": ["content"]
                }),
            },
            ToolDefinition {
                name: "docdex_diary_read",
                title: "Read Diary Entries",
                description: "Read diary entries for an optional agent in a repo or explicit global conversation namespace.",
                annotations: Some(annotations_with_priority(0.45)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "agent_id": { "type": "string", "description": "Optional agent id filter" },
                        "limit": { "type": "integer", "minimum": 1, "maximum": 100, "default": 20 },
                        "offset": { "type": "integer", "minimum": 0, "default": 0 },
                        "project_root": { "type": "string", "description": "Repo root; must match the MCP server repo (required unless initialize set a default)" },
                        "repo_path": { "type": "string", "description": "Alias for project_root (same rules)" },
                        "conversation_namespace": { "type": "string", "description": "Explicit global conversation namespace to use instead of project_root/repo_path" }
                    }
                }),
            },
            ToolDefinition {
                name: "docdex_conversation_hook",
                title: "Conversation Hook",
                description: "Enqueue or synchronously process a conversation-memory hook action for a repo or explicit global conversation namespace.",
                annotations: Some(annotations_with_priority(0.45)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "enum": ["periodic_memory_save", "pre_compaction_summarization", "session_close_summarization"]
                        },
                        "source": { "type": "string" },
                        "source_session_id": { "type": "string" },
                        "title": { "type": "string" },
                        "agent_id": { "type": "string" },
                        "transport": { "type": "string" },
                        "started_at_ms": { "type": "integer" },
                        "ended_at_ms": { "type": "integer" },
                        "format": {
                            "type": "string",
                            "enum": ["auto", "plain_text", "generic_json", "codex_jsonl", "claude_jsonl", "chatgpt_export"]
                        },
                        "messages": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "properties": {
                                    "role": { "type": "string" },
                                    "content": { "type": "string" },
                                    "author": { "type": "string" },
                                    "created_at_ms": { "type": "integer" },
                                    "metadata": { "type": "object", "additionalProperties": true }
                                },
                                "required": ["role", "content"]
                            }
                        },
                        "transcript_text": { "type": "string", "description": "Transcript payload for queued import" },
                        "summary_text": { "type": "string", "description": "Optional diary summary/note to persist alongside the hook action" },
                        "metadata": { "type": "object", "additionalProperties": true },
                        "wait_for_processing": { "type": "boolean", "default": false, "description": "When true, wait for async processing before returning" },
                        "project_root": { "type": "string", "description": "Repo root; must match the MCP server repo (required unless initialize set a default)" },
                        "repo_path": { "type": "string", "description": "Alias for project_root (same rules)" },
                        "conversation_namespace": { "type": "string", "description": "Explicit global conversation namespace to use instead of project_root/repo_path" }
                    },
                    "required": ["action"]
                }),
            },
            ToolDefinition {
                name: "docdex_wakeup",
                title: "Wake-up Context",
                description: "Assemble bounded startup memory from conversation history in a repo or explicit global conversation namespace for the active agent/query.",
                annotations: Some(annotations_with_priority(0.5)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "agent_id": { "type": "string", "description": "Optional agent id to scope working memory" },
                        "query": { "type": "string", "description": "Optional current task/query for transcript snippet recall" },
                        "max_tokens": { "type": "integer", "minimum": 1, "description": "Optional render budget; capped by server config" },
                        "project_root": { "type": "string", "description": "Repo root; must match the MCP server repo (required unless initialize set a default)" },
                        "repo_path": { "type": "string", "description": "Alias for project_root (same rules)" },
                        "conversation_namespace": { "type": "string", "description": "Explicit global conversation namespace to use instead of project_root/repo_path" }
                    }
                }),
            },
            ToolDefinition {
                name: "docdex_kg_query",
                title: "Query Knowledge Graph",
                description: "Query temporal knowledge facts extracted from conversation memory in a repo or explicit global conversation namespace.",
                annotations: Some(annotations_with_priority(0.45)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "query": { "type": "string", "minLength": 1, "description": "Entity, decision, or fact query" },
                        "relation": { "type": "string", "description": "Optional relation filter" },
                        "limit": { "type": "integer", "minimum": 1, "maximum": 100, "default": 20 },
                        "offset": { "type": "integer", "minimum": 0, "default": 0 },
                        "project_root": { "type": "string", "description": "Repo root; must match the MCP server repo (required unless initialize set a default)" },
                        "repo_path": { "type": "string", "description": "Alias for project_root (same rules)" },
                        "conversation_namespace": { "type": "string", "description": "Explicit global conversation namespace to use instead of project_root/repo_path" }
                    },
                    "required": ["query"]
                }),
            },
            ToolDefinition {
                name: "docdex_kg_search_nodes",
                title: "Search Knowledge Nodes",
                description: "Search canonical graph entities extracted from conversation memory in a repo or explicit global conversation namespace.",
                annotations: Some(annotations_with_priority(0.45)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "query": { "type": "string", "minLength": 1, "description": "Entity query" },
                        "entity_type": { "type": "string", "description": "Optional entity type filter" },
                        "limit": { "type": "integer", "minimum": 1, "maximum": 100, "default": 20 },
                        "offset": { "type": "integer", "minimum": 0, "default": 0 },
                        "project_root": { "type": "string", "description": "Repo root; must match the MCP server repo (required unless initialize set a default)" },
                        "repo_path": { "type": "string", "description": "Alias for project_root (same rules)" },
                        "conversation_namespace": { "type": "string", "description": "Explicit global conversation namespace to use instead of project_root/repo_path" }
                    },
                    "required": ["query"]
                }),
            },
            ToolDefinition {
                name: "docdex_kg_search_edges",
                title: "Search Knowledge Edges",
                description: "Search graph-native edges extracted from conversation memory in a repo or explicit global conversation namespace.",
                annotations: Some(annotations_with_priority(0.45)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "query": { "type": "string", "minLength": 1, "description": "Edge query across subject, object, and summary text" },
                        "relation": { "type": "string", "description": "Optional relation filter" },
                        "limit": { "type": "integer", "minimum": 1, "maximum": 100, "default": 20 },
                        "offset": { "type": "integer", "minimum": 0, "default": 0 },
                        "project_root": { "type": "string", "description": "Repo root; must match the MCP server repo (required unless initialize set a default)" },
                        "repo_path": { "type": "string", "description": "Alias for project_root (same rules)" },
                        "conversation_namespace": { "type": "string", "description": "Explicit global conversation namespace to use instead of project_root/repo_path" }
                    },
                    "required": ["query"]
                }),
            },
            ToolDefinition {
                name: "docdex_kg_timeline",
                title: "Entity Timeline",
                description: "Read the temporal timeline for one entity or decision topic in a repo or explicit global conversation namespace.",
                annotations: Some(annotations_with_priority(0.45)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "entity": { "type": "string", "minLength": 1, "description": "Entity or topic to inspect" },
                        "relation": { "type": "string", "description": "Optional relation filter" },
                        "limit": { "type": "integer", "minimum": 1, "maximum": 100, "default": 20 },
                        "project_root": { "type": "string", "description": "Repo root; must match the MCP server repo (required unless initialize set a default)" },
                        "repo_path": { "type": "string", "description": "Alias for project_root (same rules)" },
                        "conversation_namespace": { "type": "string", "description": "Explicit global conversation namespace to use instead of project_root/repo_path" }
                    },
                    "required": ["entity"]
                }),
            },
            ToolDefinition {
                name: "docdex_kg_search_episodes",
                title: "Search Knowledge Episodes",
                description: "Search provenance episodes extracted from conversation memory in a repo or explicit global conversation namespace.",
                annotations: Some(annotations_with_priority(0.45)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "query": { "type": "string", "minLength": 1, "description": "Episode query across source ids, summaries, and metadata" },
                        "source_type": { "type": "string", "description": "Optional episode source type filter" },
                        "limit": { "type": "integer", "minimum": 1, "maximum": 100, "default": 20 },
                        "offset": { "type": "integer", "minimum": 0, "default": 0 },
                        "project_root": { "type": "string", "description": "Repo root; must match the MCP server repo (required unless initialize set a default)" },
                        "repo_path": { "type": "string", "description": "Alias for project_root (same rules)" },
                        "conversation_namespace": { "type": "string", "description": "Explicit global conversation namespace to use instead of project_root/repo_path" }
                    },
                    "required": ["query"]
                }),
            },
            ToolDefinition {
                name: "docdex_kg_neighborhood",
                title: "Entity Neighborhood",
                description: "Inspect graph edges adjacent to one entity or topic in a repo or explicit global conversation namespace.",
                annotations: Some(annotations_with_priority(0.45)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "entity": { "type": "string", "minLength": 1, "description": "Entity or topic to inspect" },
                        "relation": { "type": "string", "description": "Optional relation filter" },
                        "limit": { "type": "integer", "minimum": 1, "maximum": 100, "default": 20 },
                        "project_root": { "type": "string", "description": "Repo root; must match the MCP server repo (required unless initialize set a default)" },
                        "repo_path": { "type": "string", "description": "Alias for project_root (same rules)" },
                        "conversation_namespace": { "type": "string", "description": "Explicit global conversation namespace to use instead of project_root/repo_path" }
                    },
                    "required": ["entity"]
                }),
            },
            ToolDefinition {
                name: "docdex_kg_entity_links",
                title: "Entity Code Links",
                description: "Fetch code-facing links recorded for one graph entity in a repo or explicit global conversation namespace.",
                annotations: Some(annotations_with_priority(0.45)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "entity": { "type": "string", "minLength": 1, "description": "Entity or topic to inspect" },
                        "link_type": { "type": "string", "description": "Optional link type filter such as file, symbol, or repo" },
                        "limit": { "type": "integer", "minimum": 1, "maximum": 100, "default": 20 },
                        "project_root": { "type": "string", "description": "Repo root; must match the MCP server repo (required unless initialize set a default)" },
                        "repo_path": { "type": "string", "description": "Alias for project_root (same rules)" },
                        "conversation_namespace": { "type": "string", "description": "Explicit global conversation namespace to use instead of project_root/repo_path" }
                    },
                    "required": ["entity"]
                }),
            },
            ToolDefinition {
                name: "docdex_kg_episode",
                title: "Get Knowledge Episode",
                description: "Fetch one provenance episode together with its graph edges and evidence in a repo or explicit global conversation namespace.",
                annotations: Some(annotations_with_priority(0.45)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "episode_id": { "type": "string", "minLength": 1, "description": "Episode id to fetch" },
                        "id": { "type": "string", "description": "Alias for episode_id" },
                        "limit": { "type": "integer", "minimum": 1, "maximum": 100, "default": 20 },
                        "project_root": { "type": "string", "description": "Repo root; must match the MCP server repo (required unless initialize set a default)" },
                        "repo_path": { "type": "string", "description": "Alias for project_root (same rules)" },
                        "conversation_namespace": { "type": "string", "description": "Explicit global conversation namespace to use instead of project_root/repo_path" }
                    }
                }),
            },
            ToolDefinition {
                name: "docdex_kg_delete_edge",
                title: "Delete Knowledge Edge",
                description: "Delete one graph edge together with its fact projection and evidence in a repo or explicit global conversation namespace.",
                annotations: Some(annotations_with_priority(0.35)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "edge_id": { "type": "string", "minLength": 1, "description": "Edge id to delete" },
                        "id": { "type": "string", "description": "Alias for edge_id" },
                        "project_root": { "type": "string", "description": "Repo root; must match the MCP server repo (required unless initialize set a default)" },
                        "repo_path": { "type": "string", "description": "Alias for project_root (same rules)" },
                        "conversation_namespace": { "type": "string", "description": "Explicit global conversation namespace to use instead of project_root/repo_path" }
                    },
                    "required": ["edge_id"]
                }),
            },
            ToolDefinition {
                name: "docdex_kg_delete_episode",
                title: "Delete Knowledge Episode",
                description: "Delete one provenance episode and its graph edges/facts in a repo or explicit global conversation namespace.",
                annotations: Some(annotations_with_priority(0.35)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "episode_id": { "type": "string", "minLength": 1, "description": "Episode id to delete" },
                        "id": { "type": "string", "description": "Alias for episode_id" },
                        "project_root": { "type": "string", "description": "Repo root; must match the MCP server repo (required unless initialize set a default)" },
                        "repo_path": { "type": "string", "description": "Alias for project_root (same rules)" },
                        "conversation_namespace": { "type": "string", "description": "Explicit global conversation namespace to use instead of project_root/repo_path" }
                    },
                    "required": ["episode_id"]
                }),
            },
            ToolDefinition {
                name: "docdex_kg_rebuild",
                title: "Rebuild Knowledge Graph Projections",
                description: "Rebuild graph-side link projections and reindex SQLite structures for conversation knowledge in a repo or explicit global conversation namespace.",
                annotations: Some(annotations_with_priority(0.35)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "project_root": { "type": "string", "description": "Repo root; must match the MCP server repo (required unless initialize set a default)" },
                        "repo_path": { "type": "string", "description": "Alias for project_root (same rules)" },
                        "conversation_namespace": { "type": "string", "description": "Explicit global conversation namespace to use instead of project_root/repo_path" }
                    }
                }),
            },
            ToolDefinition {
                name: "docdex_kg_clear",
                title: "Clear Knowledge Graph",
                description: "Delete all conversation knowledge graph data in a repo or explicit global conversation namespace.",
                annotations: Some(annotations_with_priority(0.3)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "project_root": { "type": "string", "description": "Repo root; must match the MCP server repo (required unless initialize set a default)" },
                        "repo_path": { "type": "string", "description": "Alias for project_root (same rules)" },
                        "conversation_namespace": { "type": "string", "description": "Explicit global conversation namespace to use instead of project_root/repo_path" }
                    }
                }),
            },
            ToolDefinition {
                name: "docdex_local_completion",
                title: "Local Completion",
                description: "Offload a small local task to a local model and return the draft output.",
                annotations: Some(annotations_with_priority(0.4)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "task_type": {
                            "type": "string",
                            "enum": [
                                "generate_tests",
                                "write_docstring",
                                "scaffold_boilerplate",
                                "refactor_simple",
                                "format_code",
                                "general_question"
                            ]
                        },
                        "instruction": { "type": "string", "minLength": 1 },
                        "context": { "type": "string", "minLength": 1 },
                        "agent": { "type": "string", "description": "Optional mcoda agent id or slug override" },
                        "caller_agent_id": { "type": "string", "description": "Optional calling agent id/slug for avoided-cost attribution; defaults from MCP initialize when available" },
                        "caller_model": { "type": "string", "description": "Optional calling model name for avoided-cost attribution when agent metadata is unavailable" },
                        "primary_cost_per_million": { "type": "number", "minimum": 0, "description": "Optional explicit avoided primary cost per 1M tokens" },
                        "max_tokens": { "type": "integer", "minimum": 1, "description": "Optional max tokens override" },
                        "timeout_ms": { "type": "integer", "minimum": 1, "description": "Optional timeout in milliseconds" },
                        "mode": { "type": "string", "enum": ["draft_only", "draft_then_refine"] },
                        "max_context_chars": { "type": "integer", "minimum": 1 },
                        "project_root": { "type": "string", "description": "Optional repo root (ignored if not provided)" },
                        "repo_path": { "type": "string", "description": "Alias for project_root (optional)" }
                    },
                    "required": ["task_type", "instruction", "context"]
                }),
            },
            ToolDefinition {
                name: "docdex_personal_preferences_status",
                title: "Personal Preferences Status",
                description: "Show personal-preferences storage and queue status.",
                annotations: Some(annotations_with_priority(0.4)),
                input_schema: json!({ "type": "object", "properties": {} }),
            },
            ToolDefinition {
                name: "docdex_personal_preferences_categories",
                title: "Personal Preferences Categories",
                description: "List personal-preferences categories and context policy.",
                annotations: Some(annotations_with_priority(0.4)),
                input_schema: json!({ "type": "object", "properties": {} }),
            },
            ToolDefinition {
                name: "docdex_personal_preferences_list",
                title: "List Personal Preference Captures",
                description: "List captured personal-preferences sessions.",
                annotations: Some(annotations_with_priority(0.4)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "status": { "type": "string" },
                        "limit": { "type": "integer", "minimum": 1, "maximum": 200 },
                        "offset": { "type": "integer", "minimum": 0 }
                    }
                }),
            },
            ToolDefinition {
                name: "docdex_personal_preferences_read",
                title: "Read Personal Preference Capture",
                description: "Read one captured personal-preferences session.",
                annotations: Some(annotations_with_priority(0.4)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "capture_id": { "type": "string", "minLength": 1 },
                        "id": { "type": "string", "minLength": 1 }
                    },
                    "required": ["capture_id"]
                }),
            },
            ToolDefinition {
                name: "docdex_personal_preferences_search",
                title: "Search Personal Preferences",
                description: "Search derived personal-preferences records.",
                annotations: Some(annotations_with_priority(0.4)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "query": { "type": "string", "minLength": 1 },
                        "q": { "type": "string", "minLength": 1 },
                        "limit": { "type": "integer", "minimum": 1, "maximum": 100 },
                        "include_sensitive": { "type": "boolean" }
                    },
                    "required": ["query"]
                }),
            },
            ToolDefinition {
                name: "docdex_personal_preferences_reviews",
                title: "List Personal Preference Reviews",
                description: "List derived personal-preferences records by review status.",
                annotations: Some(annotations_with_priority(0.4)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "status": { "type": "string" },
                        "limit": { "type": "integer", "minimum": 1, "maximum": 200 },
                        "offset": { "type": "integer", "minimum": 0 }
                    }
                }),
            },
            ToolDefinition {
                name: "docdex_personal_preferences_review",
                title: "Review Personal Preference Record",
                description: "Approve, reject, or re-queue one derived personal-preferences record.",
                annotations: Some(annotations_with_priority(0.4)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "record_id": { "type": "string", "minLength": 1 },
                        "id": { "type": "string", "minLength": 1 },
                        "verdict": { "type": "string", "enum": ["approved", "pending_review", "rejected"] },
                        "notes": { "type": "string" }
                    },
                    "required": ["record_id", "verdict"]
                }),
            },
            ToolDefinition {
                name: "docdex_personal_preferences_process",
                title: "Process Personal Preference Captures",
                description: "Manually process queued captures with a local mcoda agent.",
                annotations: Some(annotations_with_priority(0.4)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "limit": { "type": "integer", "minimum": 1 }
                    }
                }),
            },
            ToolDefinition {
                name: "docdex_personal_preferences_scan",
                title: "Scan Personal Preference Transcripts",
                description: "Scan supported local AI-client transcript roots and queue new personal-preferences captures.",
                annotations: Some(annotations_with_priority(0.4)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "limit": { "type": "integer", "minimum": 1 }
                    }
                }),
            },
            ToolDefinition {
                name: "docdex_personal_preferences_export",
                title: "Export Personal Preferences",
                description: "Export one capture or the whole personal-preferences store to JSON.",
                annotations: Some(annotations_with_priority(0.4)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "capture_id": { "type": "string", "minLength": 1 }
                    }
                }),
            },
            ToolDefinition {
                name: "docdex_personal_preferences_redact",
                title: "Redact Personal Preference Capture",
                description: "Redact raw transcript content for one captured session.",
                annotations: Some(annotations_with_priority(0.4)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "capture_id": { "type": "string", "minLength": 1 },
                        "id": { "type": "string", "minLength": 1 }
                    },
                    "required": ["capture_id"]
                }),
            },
            ToolDefinition {
                name: "docdex_personal_preferences_delete",
                title: "Delete Personal Preference Capture",
                description: "Delete one captured personal-preferences session and its derived records.",
                annotations: Some(annotations_with_priority(0.4)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "capture_id": { "type": "string", "minLength": 1 },
                        "id": { "type": "string", "minLength": 1 }
                    },
                    "required": ["capture_id"]
                }),
            },
            ToolDefinition {
                name: "docdex_personal_preferences_prune",
                title: "Prune Personal Preferences",
                description: "Preview or apply personal-preferences retention pruning.",
                annotations: Some(annotations_with_priority(0.4)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "raw_retention_days": { "type": "integer", "minimum": 0 },
                        "derived_retention_days": { "type": "integer", "minimum": 0 },
                        "apply": { "type": "boolean" }
                    }
                }),
            },
            ToolDefinition {
                name: "docdex_personal_preferences_purge",
                title: "Purge Personal Preferences",
                description: "Purge all personal-preferences captures and derived records.",
                annotations: Some(annotations_with_priority(0.4)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "include_exports": { "type": "boolean" }
                    }
                }),
            },
            ToolDefinition {
                name: "docdex_personal_preferences_claims",
                title: "List Personal Preference Claims",
                description: "List extracted personal-preference claims with truth/origin filters.",
                annotations: Some(annotations_with_priority(0.4)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "query": { "type": "string" },
                        "q": { "type": "string" },
                        "truth_status": { "type": "string" },
                        "claim_origin": { "type": "string" },
                        "include_sensitive": { "type": "boolean" },
                        "limit": { "type": "integer", "minimum": 1, "maximum": 200 },
                        "offset": { "type": "integer", "minimum": 0 }
                    }
                }),
            },
            ToolDefinition {
                name: "docdex_personal_preferences_claim_read",
                title: "Read Personal Preference Claim",
                description: "Read one extracted personal-preference claim.",
                annotations: Some(annotations_with_priority(0.4)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "claim_id": { "type": "string", "minLength": 1 },
                        "id": { "type": "string", "minLength": 1 }
                    },
                    "required": ["claim_id"]
                }),
            },
            ToolDefinition {
                name: "docdex_personal_preferences_claim_review",
                title: "Review Personal Preference Claim",
                description: "Approve, reject, or re-queue one extracted claim.",
                annotations: Some(annotations_with_priority(0.4)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "claim_id": { "type": "string", "minLength": 1 },
                        "id": { "type": "string", "minLength": 1 },
                        "verdict": { "type": "string", "enum": ["approved", "pending_review", "rejected"] },
                        "notes": { "type": "string" }
                    },
                    "required": ["claim_id", "verdict"]
                }),
            },
            ToolDefinition {
                name: "docdex_personal_preferences_claim_override",
                title: "Override Personal Preference Claim",
                description: "Override one claim with an explicit corrected value.",
                annotations: Some(annotations_with_priority(0.4)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "claim_id": { "type": "string", "minLength": 1 },
                        "id": { "type": "string", "minLength": 1 },
                        "value": { "type": "string", "minLength": 1 },
                        "notes": { "type": "string" }
                    },
                    "required": ["claim_id", "value"]
                }),
            },
            ToolDefinition {
                name: "docdex_personal_preferences_claim_forget",
                title: "Forget Personal Preference Claim",
                description: "Forget one claim, redact its usable content, and rebuild snapshots.",
                annotations: Some(annotations_with_priority(0.4)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "claim_id": { "type": "string", "minLength": 1 },
                        "id": { "type": "string", "minLength": 1 },
                        "notes": { "type": "string" }
                    },
                    "required": ["claim_id"]
                }),
            },
            ToolDefinition {
                name: "docdex_personal_preferences_feedback",
                title: "Add Personal Preference Feedback",
                description: "Add a feedback event that influences future mind-clone context.",
                annotations: Some(annotations_with_priority(0.4)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "event_type": { "type": "string", "minLength": 1 },
                        "claim_id": { "type": "string" },
                        "capture_id": { "type": "string" },
                        "category": { "type": "string" },
                        "attribute": { "type": "string" },
                        "value": { "type": "string" },
                        "notes": { "type": "string" },
                        "metadata": { "type": "object" }
                    },
                    "required": ["event_type"]
                }),
            },
            ToolDefinition {
                name: "docdex_personal_preferences_snapshots",
                title: "List Personal Preference Snapshots",
                description: "List temporal identity snapshots compiled from claims.",
                annotations: Some(annotations_with_priority(0.4)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "limit": { "type": "integer", "minimum": 1, "maximum": 200 },
                        "offset": { "type": "integer", "minimum": 0 }
                    }
                }),
            },
            ToolDefinition {
                name: "docdex_personal_preferences_snapshot_read",
                title: "Read Personal Preference Snapshot",
                description: "Read one temporal identity snapshot.",
                annotations: Some(annotations_with_priority(0.4)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "snapshot_id": { "type": "string", "minLength": 1 },
                        "id": { "type": "string", "minLength": 1 }
                    },
                    "required": ["snapshot_id"]
                }),
            },
            ToolDefinition {
                name: "docdex_personal_preferences_snapshots_rebuild",
                title: "Rebuild Personal Preference Snapshots",
                description: "Rebuild temporal identity snapshots from the current claim set.",
                annotations: Some(annotations_with_priority(0.4)),
                input_schema: json!({ "type": "object", "properties": {} }),
            },
            ToolDefinition {
                name: "docdex_clone_context",
                title: "Build Mind Clone Context",
                description: "Compile a bounded personal-preferences clone context pack for a query.",
                annotations: Some(annotations_with_priority(0.4)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "query": { "type": "string", "minLength": 1 },
                        "mode": { "type": "string" },
                        "allow_sensitive": { "type": "boolean" },
                        "current_repo_root": { "type": "string" },
                        "max_records": { "type": "integer", "minimum": 1 },
                        "budget_tokens": { "type": "integer", "minimum": 1 }
                    },
                    "required": ["query"]
                }),
            },
            ToolDefinition {
                name: "docdex_clone_explain",
                title: "Explain Mind Clone Context",
                description: "Explain the evidence trace for a bounded clone context pack.",
                annotations: Some(annotations_with_priority(0.4)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "query": { "type": "string", "minLength": 1 },
                        "mode": { "type": "string" },
                        "allow_sensitive": { "type": "boolean" },
                        "current_repo_root": { "type": "string" },
                        "max_records": { "type": "integer", "minimum": 1 },
                        "budget_tokens": { "type": "integer", "minimum": 1 }
                    },
                    "required": ["query"]
                }),
            },
            ToolDefinition {
                name: "docdex_clone_evaluate",
                title: "Evaluate Mind Clone Context",
                description: "Score clone-pack fidelity heuristics for a query.",
                annotations: Some(annotations_with_priority(0.4)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "query": { "type": "string", "minLength": 1 },
                        "mode": { "type": "string" },
                        "allow_sensitive": { "type": "boolean" },
                        "current_repo_root": { "type": "string" },
                        "max_records": { "type": "integer", "minimum": 1 },
                        "budget_tokens": { "type": "integer", "minimum": 1 }
                    },
                    "required": ["query"]
                }),
            },
            ToolDefinition {
                name: "docdex_memory_layers",
                title: "Inspect Memory Layers",
                description: "Describe the six Docdex memory layers, their scope, storage, and recommended agent usage for the current repo or conversation namespace.",
                annotations: Some(annotations_with_priority(0.5)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "project_root": { "type": "string", "description": "Optional repo root for repo-scoped memory layers." },
                        "repo_path": { "type": "string", "description": "Alias for project_root." },
                        "conversation_namespace": { "type": "string", "minLength": 1, "description": "Optional explicit conversation namespace instead of repo scope." }
                    }
                }),
            },
            ToolDefinition {
                name: "docdex_memory_route",
                title: "Route Memory Usage",
                description: "Recommend which Docdex memory lanes to consult first or write to for a specific query, including core versus retrievable memory.",
                annotations: Some(annotations_with_priority(0.6)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "query": { "type": "string", "minLength": 1, "description": "Task or question to route across Docdex memory lanes." },
                        "intent": { "type": "string", "enum": ["read", "write", "auto"], "description": "Optional routing intent override." },
                        "project_root": { "type": "string", "description": "Optional repo root for repo-scoped routing." },
                        "repo_path": { "type": "string", "description": "Alias for project_root." },
                        "conversation_namespace": { "type": "string", "minLength": 1, "description": "Optional explicit conversation namespace instead of repo scope." }
                    },
                    "required": ["query"]
                }),
            },
            ToolDefinition {
                name: "docdex_save_preference",
                title: "Save Preference",
                description: "Store a global profile preference for an agent (profile memory, async evolution).",
                annotations: Some(annotations_with_priority(0.4)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "agent_id": { "type": "string", "minLength": 1, "description": "Profile agent id" },
                        "content": { "type": "string", "minLength": 1, "description": "Preference content" },
                        "category": { "type": "string", "enum": ["style", "tooling", "constraint", "workflow"], "description": "Preference category" },
                        "role": { "type": "string", "description": "Optional agent role (used when creating a new agent)" },
                        "project_root": { "type": "string", "description": "Optional repo root (ignored for global profile tools)" },
                        "repo_path": { "type": "string", "description": "Alias for project_root (ignored)" }
                    },
                    "required": ["content", "category"]
                }),
            },
            ToolDefinition {
                name: "docdex_get_profile",
                title: "Get Profile",
                description: "Fetch profile preferences for an agent (profile memory).",
                annotations: Some(annotations_with_priority(0.4)),
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "agent_id": { "type": "string", "minLength": 1, "description": "Profile agent id" },
                        "project_root": { "type": "string", "description": "Optional repo root (ignored for global profile tools)" },
                        "repo_path": { "type": "string", "description": "Alias for project_root (ignored)" }
                    }
                }),
            },
        ]
    }

    fn prompt_defs(&self) -> Vec<PromptDefinition> {
        vec![
            PromptDefinition {
                name: "docdex_onboarding",
                title: "Onboard a Repo",
                description: "Guide a new contributor through the repo with Docdex tools.",
                arguments: vec![
                    PromptArgument {
                        name: "topic",
                        description: "Area or concept to focus on (e.g., auth, billing)",
                        required: false,
                    },
                    PromptArgument {
                        name: "depth",
                        description: "Depth of the walkthrough (quick or deep)",
                        required: false,
                    },
                ],
                annotations: Some(annotations_with_priority(0.6)),
            },
            PromptDefinition {
                name: "docdex_incident_triage",
                title: "Incident Triage",
                description: "Triage a production issue using Docdex search + impact data.",
                arguments: vec![
                    PromptArgument {
                        name: "symptom",
                        description: "Symptom or error summary",
                        required: true,
                    },
                    PromptArgument {
                        name: "log_snippet",
                        description: "Optional log snippet for context",
                        required: false,
                    },
                ],
                annotations: Some(annotations_with_priority(0.6)),
            },
            PromptDefinition {
                name: "docdex_refactor_plan",
                title: "Refactor Plan",
                description: "Plan a refactor using Docdex symbols and impact graph.",
                arguments: vec![
                    PromptArgument {
                        name: "target",
                        description: "What you want to refactor (module, file, API)",
                        required: true,
                    },
                    PromptArgument {
                        name: "constraints",
                        description: "Optional constraints (performance, compatibility)",
                        required: false,
                    },
                ],
                annotations: Some(annotations_with_priority(0.5)),
            },
        ]
    }

    fn prompt_payload(
        &self,
        name: &str,
        args: Option<&serde_json::Value>,
    ) -> Option<serde_json::Value> {
        let args = args.and_then(|value| value.as_object());
        match name {
            "docdex_onboarding" => {
                let topic = args
                    .and_then(|value| value.get("topic"))
                    .and_then(|value| value.as_str())
                    .unwrap_or("the codebase");
                let depth = args
                    .and_then(|value| value.get("depth"))
                    .and_then(|value| value.as_str())
                    .unwrap_or("quick");
                let text = format!(
                    "You are onboarding a new contributor. Use Docdex tools to map {topic}.\n\
Depth: {depth}.\n\
Steps:\n\
1) Run docdex_search for the entry points.\n\
2) Use docdex_open to read key files.\n\
3) Use docdex_symbols/docdex_ast for structure.\n\
4) Use docdex_impact_graph for dependency traversal and docdex_impact_diagnostics for unresolved imports.\n\
Return a short summary and a next-questions list."
                );
                Some(json!({
                    "name": name,
                    "title": "Onboard a Repo",
                    "description": "Guide a new contributor through the repo with Docdex tools.",
                    "messages": [
                        { "role": "system", "content": [{ "type": "text", "text": text }] }
                    ]
                }))
            }
            "docdex_incident_triage" => {
                let symptom = args
                    .and_then(|value| value.get("symptom"))
                    .and_then(|value| value.as_str())
                    .unwrap_or("unknown incident");
                let log_snippet = args
                    .and_then(|value| value.get("log_snippet"))
                    .and_then(|value| value.as_str());
                let mut text = format!(
                    "Triage the incident: {symptom}.\n\
Use docdex_search to find the code paths, then docdex_open for details. \
Use docdex_impact_graph plus docdex_impact_diagnostics to spot risky dependencies."
                );
                if let Some(snippet) = log_snippet {
                    text.push_str("\nLog snippet:\n");
                    text.push_str(snippet);
                }
                Some(json!({
                    "name": name,
                    "title": "Incident Triage",
                    "description": "Triage a production issue using Docdex search + impact data.",
                    "messages": [
                        { "role": "system", "content": [{ "type": "text", "text": text }] }
                    ]
                }))
            }
            "docdex_refactor_plan" => {
                let target = args
                    .and_then(|value| value.get("target"))
                    .and_then(|value| value.as_str())
                    .unwrap_or("the target area");
                let constraints = args
                    .and_then(|value| value.get("constraints"))
                    .and_then(|value| value.as_str());
                let mut text = format!(
                    "Plan a refactor for {target}.\n\
Use docdex_symbols/docdex_ast to map structure, then docdex_impact_graph and docdex_impact_diagnostics to list affected modules.\n\
Produce a phased plan with risks and tests to run."
                );
                if let Some(extra) = constraints {
                    text.push_str("\nConstraints:\n");
                    text.push_str(extra);
                }
                Some(json!({
                    "name": name,
                    "title": "Refactor Plan",
                    "description": "Plan a refactor using Docdex symbols and impact graph.",
                    "messages": [
                        { "role": "system", "content": [{ "type": "text", "text": text }] }
                    ]
                }))
            }
            _ => None,
        }
    }

    fn resource_defs(&self) -> Vec<ResourceDefinition> {
        let mut resources = Vec::new();
        let candidates = [
            (
                "README.md",
                "repo_readme",
                "Repo README",
                "Primary project README in the repo root.",
                "text/markdown",
            ),
            (
                "docs/overview.md",
                "docs_overview",
                "Docs Overview",
                "High-level documentation overview.",
                "text/markdown",
            ),
            (
                "docs/usage.md",
                "docs_usage",
                "Usage Guide",
                "Docdex usage guide for this repo.",
                "text/markdown",
            ),
        ];
        for (path, name, title, description, mime_type) in candidates {
            if self.repo_root.join(path).is_file() {
                resources.push(ResourceDefinition {
                    uri: format!("docdex://{path}"),
                    name: format!("docdex_{name}"),
                    title: title.to_string(),
                    description: description.to_string(),
                    mime_type: mime_type.to_string(),
                    annotations: Some(annotations_with_priority(0.3)),
                });
            }
        }
        resources
    }

    fn resource_templates(&self) -> Vec<ResourceTemplate> {
        vec![ResourceTemplate {
            name: "docdex_file",
            title: "Docdex File",
            description:
                "Read a file from the current repo (delegates to docdex_open); vars: {path}.",
            uri_template: "docdex://{path}",
            mime_type: "text/plain",
            variables: &["path"],
            annotations: Some(annotations_with_priority(0.3)),
        }]
    }

    async fn handle_search(
        &self,
        request_id: String,
        args: SearchArgs,
    ) -> Result<serde_json::Value> {
        let SearchArgs {
            query,
            limit,
            force_web: force_web_arg,
            async_web: async_web_arg,
            diff,
            dag_session_id,
            project_root,
            repo_path,
        } = args;
        let project_root = self.resolve_project_root_arg(project_root, repo_path)?;
        self.ensure_project_root(project_root.as_deref())?;
        if !self.indexer.index_ready() {
            let indexing_in_progress = self.indexer.indexing_in_progress()?;
            if !indexing_in_progress && !self.indexer.is_read_only() {
                let indexer = self.indexer.clone();
                tokio::spawn(async move {
                    let _ = crate::index::ensure_indexed(indexer).await;
                });
            }
            let details = json!({
                "status": if indexing_in_progress { "indexing" } else { "missing" },
                "indexing_in_progress": indexing_in_progress,
                "status_url": format!("/v1/index/status?repo_id={}", self.repo_id),
                "retry_after_ms": 2000,
                "recovery_steps": [
                    "Wait for indexing to complete, then retry the search.",
                    "Call /v1/index/status to check readiness.",
                    "If indexing is stuck, run POST /v1/index/rebuild."
                ]
            });
            return Err(
                AppError::new(ERR_INDEXING_IN_PROGRESS, "indexing in progress")
                    .with_details(details)
                    .into(),
            );
        }
        self.ensure_index_ready().await?;
        let query_owned = query;
        let query = query_owned.trim();
        let limit = limit.unwrap_or(self.max_results).clamp(1, self.max_results);
        let project_root_path = self
            .default_project_root
            .as_ref()
            .unwrap_or(&self.repo_root)
            .display()
            .to_string();
        let repo_state_root = repo_state_root_from_state_dir(self.indexer.state_dir());
        let force_web = force_web_arg.unwrap_or(false);
        let async_web = async_web_arg.unwrap_or(true);
        let diff_request = diff::resolve_diff_request_from_options(diff.as_ref())?;
        let request_id_ref = request_id.as_str();
        let dag_session_id = dag_session_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(request_id_ref);
        queue_dag_log(
            &repo_state_root,
            dag_session_id,
            "UserRequest",
            json!({
                "query": query,
                "limit": limit,
                "force_web": force_web,
                "project_root": project_root_path.clone(),
                "diff": diff.as_ref().map(|opts| json!(opts)),
            }),
        );
        let plan = WaterfallPlan::new(
            WebGateConfig::from_env(),
            Tier2Config::enabled(),
            memory_budget_from_max_answer_tokens(self.max_answer_tokens),
            ProfileBudget::default(),
        );
        let repo_id =
            crate::repo_manager::repo_fingerprint_sha256(&self.repo_root).unwrap_or_else(|_| {
                crate::repo_manager::fingerprint::legacy_repo_id_for_root(&self.repo_root)
            });
        let memory_state = self.memory.as_ref().map(|state| search::MemoryState {
            store: state.store.clone(),
            embedder: state.embedder.clone(),
            repo_id: repo_id.clone(),
        });
        let waterfall = run_waterfall(WaterfallRequest {
            request_id: request_id_ref,
            dag_session_id: Some(dag_session_id),
            global_state_dir: self.global_state_dir.clone(),
            query,
            limit,
            diff: diff_request,
            web_limit: None,
            force_web,
            skip_local_search: false,
            disable_web_cache: false,
            llm_filter_local_results: false,
            llm_model: None,
            llm_agent: None,
            indexer: self.indexer.clone(),
            libs_indexer: self.libs_indexer.clone(),
            plan,
            tier2_limiter: None,
            memory: memory_state.as_ref(),
            profile_state: None,
            profile_agent_id: None,
            memory_route: None,
            ranking_surface: search::RankingSurface::Search,
            async_web,
        })
        .await?;
        queue_dag_log(
            &repo_state_root,
            dag_session_id,
            "Decision",
            json!({
                "hits": waterfall.search_response.hits.len(),
                "top_score": waterfall.search_response.top_score,
                "web_status": waterfall.tier2.status.status,
            }),
        );
        let mut response = waterfall.search_response;
        response.web_discovery = Some(waterfall.tier2.status.clone());
        response.impact_context = waterfall.impact_context;
        response.memory_context = waterfall.memory_context;
        let hits_value = serde_json::to_value(&response.hits)?;
        let top_score = response.top_score;
        let top_score_camel = response.top_score_camel;
        let web_discovery = response.web_discovery.clone();
        let memory_context = response.memory_context.clone();
        let mut meta = response.meta.unwrap_or_else(|| search::SearchMeta {
            generated_at_epoch_ms: 0,
            index_last_updated_epoch_ms: None,
            dag_session_id: None,
            repo_root: self.repo_root.display().to_string(),
            repo_id: None,
            query: None,
            context_assembly: None,
        });
        meta.repo_root = project_root_path.clone();
        meta.dag_session_id = Some(dag_session_id.to_string());
        if meta.repo_id.is_none() {
            meta.repo_id = crate::repo_manager::repo_fingerprint_sha256(&self.repo_root).ok();
        }
        let mut payload = json!({
            "hits": hits_value.clone(),
            "results": hits_value,
            "top_score": top_score,
            "topScore": top_score_camel,
            "repo_root": self.repo_root.display().to_string(),
            "state_dir": self.indexer.config().state_dir().display().to_string(),
            "limit": limit,
            "project_root": project_root_path,
            "meta": meta
        });
        if let Some(status) = web_discovery {
            payload["webDiscovery"] = json!(status);
        }
        if let Some(context) = memory_context {
            payload["memoryContext"] = json!(context);
        }
        Ok(payload)
    }

    async fn handle_capabilities(&self, _args: CapabilitiesArgs) -> Result<serde_json::Value> {
        Ok(serde_json::to_value(capabilities::current_capabilities())?)
    }

    async fn handle_rerank(&self, args: RerankArgs) -> Result<serde_json::Value> {
        let RerankArgs {
            query,
            candidates,
            limit,
            project_root,
            repo_path,
        } = args;
        let project_root = self.resolve_project_root_arg(project_root, repo_path)?;
        if project_root.is_some() {
            self.ensure_project_root(project_root.as_deref())?;
        }

        let query = query.trim();
        if query.is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "query is required").into());
        }
        if candidates.is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "candidates must not be empty").into());
        }

        let input_count = candidates.len();
        let mut candidates = candidates;
        let truncated = input_count > RERANK_MAX_CANDIDATES;
        if truncated {
            candidates.truncate(RERANK_MAX_CANDIDATES);
        }

        let max_limit = self.max_results.min(RERANK_MAX_CANDIDATES).max(1);
        let limit = limit.unwrap_or(candidates.len()).clamp(1, max_limit);
        let hits = search::rerank_hits(query, candidates, limit);
        let hits_value = serde_json::to_value(&hits)?;

        Ok(json!({
            "hits": hits_value.clone(),
            "results": hits_value,
            "input_count": input_count,
            "returned_count": hits.len(),
            "limit": limit,
            "truncated": truncated,
            "project_root": self.repo_root.display().to_string()
        }))
    }

    async fn handle_batch_search(
        &self,
        _request_id: String,
        args: BatchSearchArgs,
    ) -> Result<serde_json::Value> {
        let BatchSearchArgs {
            queries,
            limit,
            include_libs,
            project_root,
            repo_path,
        } = args;
        let project_root = self.resolve_project_root_arg(project_root, repo_path)?;
        if project_root.is_some() {
            self.ensure_project_root(project_root.as_deref())?;
        }

        if queries.is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "queries must not be empty").into());
        }

        let query_count = queries.len();
        let mut normalized = queries
            .into_iter()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .collect::<Vec<_>>();
        if normalized.is_empty() {
            return Err(AppError::new(
                ERR_INVALID_ARGUMENT,
                "queries must include non-empty values",
            )
            .into());
        }

        let truncated = normalized.len() > BATCH_SEARCH_MAX_QUERIES;
        if truncated {
            normalized.truncate(BATCH_SEARCH_MAX_QUERIES);
        }

        let limit = limit.unwrap_or(self.max_results).clamp(1, self.max_results);
        let include_libs = include_libs.unwrap_or(true);
        let libs_indexer = if include_libs {
            self.libs_indexer.as_deref()
        } else {
            None
        };

        let mut results = Vec::with_capacity(normalized.len());
        for query in normalized {
            let response = search::run_query(
                &self.indexer,
                libs_indexer,
                &query,
                limit,
                search::RankingSurface::Search,
            )
            .await?;
            results.push(json!({
                "query": query,
                "response": response,
            }));
        }

        Ok(json!({
            "results": results,
            "query_count": query_count,
            "effective_query_count": results.len(),
            "limit": limit,
            "truncated": truncated,
            "project_root": self.repo_root.display().to_string(),
        }))
    }

    async fn handle_delegate(&self, args: DelegateArgs) -> Result<serde_json::Value> {
        if args.task_type.trim().is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "task_type is required").into());
        }
        if args.instruction.trim().is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "instruction is required").into());
        }
        if args.context.trim().is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "context is required").into());
        }

        let project_root = self.resolve_project_root_arg(args.project_root, args.repo_path)?;
        if project_root.is_some() {
            self.ensure_project_root(project_root.as_deref())?;
        }

        // Local completion is intentionally local-only; do not fall back to primary models.
        let mut llm_config = self.llm_config.clone();
        llm_config.delegation.enforce_local = true;
        llm_config.delegation.allow_fallback_to_primary = false;

        let task_type = TaskType::parse(&args.task_type)
            .ok_or_else(|| AppError::new(ERR_INVALID_ARGUMENT, "task_type is invalid"))?;
        let mut llm_config = resolve_task_scoped_delegation_config(&llm_config, task_type);
        llm_config.delegation.enforce_local = true;
        llm_config.delegation.allow_fallback_to_primary = false;
        let web_gate = WebGateConfig::from_env();
        let library_result = if web_gate.enabled {
            let indexer = self.indexer.clone();
            let libs_indexer = self.libs_indexer.as_deref();
            let global_state_dir = self.global_state_dir.clone();
            let request_id = Uuid::new_v4().to_string();
            let mut fetcher = move |query: String| {
                let indexer = indexer.clone();
                let request_id = request_id.clone();
                let web_gate = web_gate.clone();
                let libs_indexer = libs_indexer;
                let global_state_dir = global_state_dir.clone();
                async move {
                    let response = run_web_research(
                        &request_id,
                        indexer.as_ref(),
                        libs_indexer,
                        global_state_dir.as_deref(),
                        &query,
                        5,
                        Some(3),
                        true,
                        &web_gate,
                        false,
                        true,
                        false,
                        None,
                        None,
                    )
                    .await?;
                    Ok(format_web_text(&response))
                }
            };
            if local_selection_policy_requires_fresh_library(&llm_config) {
                refresh_local_library_with_web(
                    self.global_state_dir.as_deref(),
                    &llm_config,
                    true,
                    Some(&mut fetcher),
                )
                .await
            } else {
                refresh_local_library_if_stale_with_web(
                    self.global_state_dir.as_deref(),
                    &llm_config,
                    true,
                    Some(&mut fetcher),
                )
                .await
            }
        } else {
            if local_selection_policy_requires_fresh_library(&llm_config) {
                refresh_local_library(self.global_state_dir.as_deref(), &llm_config, true).await
            } else {
                refresh_local_library_if_stale(self.global_state_dir.as_deref(), &llm_config, true)
                    .await
            }
        };
        let mut library = match library_result {
            Ok(library) => Some(library),
            Err(err) => {
                warn!(
                    target: "docdexd",
                    error = ?err,
                    "local model library refresh failed"
                );
                load_local_library(self.global_state_dir.as_deref()).ok()
            }
        };
        if !delegation_is_enabled(&llm_config.delegation, library.as_ref()) {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "delegation is disabled").into());
        }
        if !allowlist_allows(task_type, &llm_config.delegation.task_allowlist) {
            return Err(AppError::new(
                ERR_INVALID_ARGUMENT,
                "task_type not allowed by delegation allowlist",
            )
            .into());
        }
        let mode = match args.mode.as_deref() {
            Some(value) => DelegationMode::parse(value)
                .ok_or_else(|| AppError::new(ERR_INVALID_ARGUMENT, "mode is invalid"))?,
            None => mode_from_config(&llm_config.delegation.mode),
        };
        let max_context_chars = args
            .max_context_chars
            .filter(|value| *value > 0)
            .unwrap_or(llm_config.delegation.max_context_chars);
        let agent_override = args
            .agent
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let override_target =
            agent_override.and_then(|value| parse_local_target_override(value, library.as_ref()));
        let mut local_targets: Vec<LocalTarget> = override_target.clone().into_iter().collect();
        if local_targets.is_empty() {
            if let Some(library) = library.as_ref() {
                let mut library = library.clone();
                local_targets = build_local_target_candidates_with_config(
                    self.global_state_dir.as_deref(),
                    &llm_config,
                    task_type,
                    &mut library,
                );
            }
        }
        if local_targets.is_empty() {
            if let Some(target) =
                resolve_explicit_target(&llm_config.delegation.local_agent_id, library.as_ref())
            {
                local_targets.push(target);
            }
        }
        if local_targets.is_empty() {
            if let Some(target) =
                resolve_explicit_target(&llm_config.delegation.cloud_agent_id, library.as_ref())
            {
                local_targets.push(target);
            }
        }
        if local_targets.is_empty() {
            let model = llm_config.default_model.trim();
            if model.is_empty() {
                local_targets.clear();
            } else if resolve_local_ollama_base_url(&llm_config).is_some() {
                local_targets.push(LocalTarget::OllamaModel(model.to_string()));
            }
        }
        let local_agent_override = match (&override_target, agent_override) {
            (Some(LocalTarget::OllamaModel(model)), _) => Some(format!("model:{model}")),
            (Some(LocalTarget::McodaAgent(_)), Some(value)) => Some(value.to_string()),
            (None, Some(value)) => Some(value.to_string()),
            _ => None,
        };
        let pricing_context = DelegationPricingContext {
            caller_agent_id: args
                .caller_agent_id
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .or_else(|| self.default_agent_id.clone()),
            caller_model: args
                .caller_model
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_string)
                .or_else(|| self.default_agent_model.clone()),
            primary_cost_per_million: args.primary_cost_per_million,
            fallback_primary_cost_per_million: self
                .delegation_metrics
                .snapshot()
                .effective_avoided_primary_usd_per_million_tokens()
                .or_else(|| {
                    DelegationTelemetrySnapshot::from_metrics(metrics::global().as_ref())
                        .effective_avoided_primary_usd_per_million_tokens()
                }),
        };
        let local_override = local_agent_override
            .as_deref()
            .map(|value| !value.trim().is_empty())
            .unwrap_or(false);
        let mut primary_targets = library
            .as_ref()
            .map(|library| {
                build_primary_target_candidates(
                    &llm_config,
                    task_type,
                    library,
                    local_targets.first(),
                )
            })
            .unwrap_or_default();
        if !local_override {
            local_targets = filter_automatic_local_targets_by_cost(
                &llm_config,
                Some(&pricing_context),
                &primary_targets,
                &local_targets,
                library.as_ref(),
            );
            primary_targets = library
                .as_ref()
                .map(|library| {
                    build_primary_target_candidates(
                        &llm_config,
                        task_type,
                        library,
                        local_targets.first(),
                    )
                })
                .unwrap_or_default();
        }
        let metrics = metrics::global();
        let started_at = Instant::now();
        metrics.inc_delegate_request();
        self.delegation_metrics.inc_delegate_request();
        let persist_delegation_metrics = || {
            let repo_state_root = repo_state_root_from_state_dir(self.indexer.state_dir());
            let telemetry_global_state_dir = delegation_telemetry::effective_global_state_dir(
                self.global_state_dir.as_deref(),
                self.indexer.state_dir(),
            );
            delegation_telemetry::persist_metrics(
                telemetry_global_state_dir.as_deref(),
                metrics.as_ref(),
                Some(repo_state_root.as_path()),
                Some(self.delegation_metrics.as_ref()),
            );
        };
        if llm_config.delegation.enforce_local && local_targets.is_empty() && !local_override {
            let elapsed_ms = started_at.elapsed().as_millis();
            metrics.inc_delegate_failed();
            self.delegation_metrics.inc_delegate_failed();
            metrics.inc_delegate_local_enforced_failure();
            self.delegation_metrics
                .inc_delegate_local_enforced_failure();
            metrics.record_delegate_latency(elapsed_ms);
            self.delegation_metrics.record_delegate_latency(elapsed_ms);
            persist_delegation_metrics();
            return Err(AppError::new(
                ERR_DELEGATION_LOCAL_REQUIRED,
                "local delegation required but no local target is configured",
            )
            .into());
        }
        let failure_history = DelegationFailureHistoryContext {
            global_state_dir: self.global_state_dir.clone(),
            repo_id: Some(self.repo_id.clone()),
            repo_root: Some(self.repo_root.display().to_string()),
            source: Some("mcp".to_string()),
        };
        let result = run_delegation_flow_with_failure_history(
            &llm_config,
            local_agent_override.as_deref(),
            &local_targets,
            &primary_targets,
            task_type,
            &args.instruction,
            &args.context,
            max_context_chars,
            args.max_tokens,
            args.timeout_ms,
            mode,
            Some(failure_history),
        )
        .await;
        let result = match result {
            Ok(result) => result,
            Err(err) => {
                let elapsed_ms = started_at.elapsed().as_millis();
                metrics.inc_delegate_failed();
                self.delegation_metrics.inc_delegate_failed();
                metrics.record_delegate_latency(elapsed_ms);
                self.delegation_metrics.record_delegate_latency(elapsed_ms);
                if err.downcast_ref::<DelegationEnforcementError>().is_some() {
                    metrics.inc_delegate_local_enforced_failure();
                    self.delegation_metrics
                        .inc_delegate_local_enforced_failure();
                    persist_delegation_metrics();
                    return Err(
                        AppError::new(ERR_DELEGATION_LOCAL_REQUIRED, err.to_string()).into(),
                    );
                }
                persist_delegation_metrics();
                return Err(err);
            }
        };

        if !result.primary_used {
            if let Some(library) = library.as_mut() {
                update_cached_local_selection_from_completion(
                    self.global_state_dir.as_deref(),
                    &llm_config,
                    library,
                    task_type,
                    &result.completion,
                );
            }
        }

        let elapsed_ms = started_at.elapsed().as_millis();
        metrics.record_delegate_latency(elapsed_ms);
        self.delegation_metrics.record_delegate_latency(elapsed_ms);
        metrics.record_delegate_token_estimate(result.token_estimate);
        self.delegation_metrics
            .record_delegate_token_estimate(result.token_estimate);
        let local_cost_per_million = resolve_local_cost_per_million(
            &llm_config,
            local_agent_override.as_deref(),
            local_targets.first(),
            library.as_ref(),
        );
        let primary_cost_per_million = resolve_primary_cost_per_million(
            &llm_config,
            Some(&pricing_context),
            primary_targets.first(),
            library.as_ref(),
        );
        let local_cost_micros = compute_cost_micros(result.local_tokens, local_cost_per_million);
        let primary_cost_micros =
            compute_cost_micros(result.primary_tokens, primary_cost_per_million);
        if result.local_tokens > 0 {
            metrics.inc_delegate_offloaded();
            self.delegation_metrics.inc_delegate_offloaded();
        }
        metrics.record_delegate_local_tokens(result.local_tokens);
        self.delegation_metrics
            .record_delegate_local_tokens(result.local_tokens);
        metrics.record_delegate_primary_tokens(result.primary_tokens);
        self.delegation_metrics
            .record_delegate_primary_tokens(result.primary_tokens);
        metrics.record_delegate_local_cost_micros(local_cost_micros);
        self.delegation_metrics
            .record_delegate_local_cost_micros(local_cost_micros);
        metrics.record_delegate_primary_cost_micros(primary_cost_micros);
        self.delegation_metrics
            .record_delegate_primary_cost_micros(primary_cost_micros);
        let savings = compute_delegation_savings(
            result.local_tokens,
            local_cost_per_million,
            primary_cost_per_million,
        );
        metrics.record_delegate_token_savings(savings.token_savings);
        self.delegation_metrics
            .record_delegate_token_savings(savings.token_savings);
        metrics.record_delegate_cost_savings_micros(savings.cost_savings_micros);
        self.delegation_metrics
            .record_delegate_cost_savings_micros(savings.cost_savings_micros);
        if result.fallback_used {
            metrics.inc_delegate_fallback();
            self.delegation_metrics.inc_delegate_fallback();
        }
        persist_delegation_metrics();

        Ok(json!({
            "id": Uuid::new_v4().to_string(),
            "task_type": task_type.as_str(),
            "adapter": result.completion.adapter,
            "model": result.completion.model,
            "output": result.completion.output,
            "draft": result.draft,
            "truncated": result.truncated,
            "warnings": result.warnings
        }))
    }

    async fn handle_web_research(
        &self,
        request_id: String,
        args: WebResearchArgs,
    ) -> Result<serde_json::Value> {
        let WebResearchArgs {
            query,
            limit,
            web_limit,
            force_web,
            skip_local_search,
            no_cache,
            llm_filter_local_results,
            repo_only,
            llm_model,
            llm_agent,
            dag_session_id,
            project_root,
            repo_path,
        } = args;
        let project_root = self.resolve_project_root_arg(project_root, repo_path)?;
        self.ensure_project_root(project_root.as_deref())?;
        let query_owned = query;
        let query = query_owned.trim();
        let limit = limit.unwrap_or(self.max_results).clamp(1, self.max_results);
        let web_limit = web_limit.map(|value| value.max(1));
        let project_root_path = self
            .default_project_root
            .as_ref()
            .unwrap_or(&self.repo_root)
            .display()
            .to_string();
        let repo_state_root = repo_state_root_from_state_dir(self.indexer.state_dir());
        let request_id_ref = request_id.as_str();
        let dag_session_id = dag_session_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .unwrap_or(request_id_ref);
        let force_web = force_web.unwrap_or(false);
        let skip_local_search = skip_local_search.unwrap_or(false);
        let disable_web_cache = no_cache.unwrap_or(false);
        let llm_filter_local_results = llm_filter_local_results.unwrap_or(false);
        if !skip_local_search {
            self.ensure_index_ready().await?;
        }
        let libs_indexer = if repo_only.unwrap_or(false) {
            None
        } else {
            self.libs_indexer.as_deref()
        };
        queue_dag_log(
            &repo_state_root,
            dag_session_id,
            "UserRequest",
            json!({
                "query": query,
                "limit": limit,
                "web_limit": web_limit,
                "force_web": force_web,
                "skip_local_search": skip_local_search,
                "disable_web_cache": disable_web_cache,
                "project_root": project_root_path.clone(),
            }),
        );
        let response = run_web_research(
            request_id_ref,
            self.indexer.as_ref(),
            libs_indexer,
            self.global_state_dir.as_deref(),
            query,
            limit,
            web_limit,
            force_web,
            &WebGateConfig::from_env(),
            llm_filter_local_results,
            skip_local_search,
            disable_web_cache,
            llm_model.as_deref(),
            llm_agent.as_deref(),
        )
        .await?;
        queue_dag_log(
            &repo_state_root,
            dag_session_id,
            "Decision",
            json!({
                "hits": response.hits.len(),
                "top_score": response.top_score,
                "web_status": response.web_discovery.status,
            }),
        );
        let mut payload = serde_json::to_value(&response)?;
        if let Some(obj) = payload.as_object_mut() {
            obj.insert(
                "repo_root".to_string(),
                json!(self.repo_root.display().to_string()),
            );
            obj.insert(
                "state_dir".to_string(),
                json!(self.indexer.config().state_dir().display().to_string()),
            );
            obj.insert("limit".to_string(), json!(limit));
            obj.insert("project_root".to_string(), json!(project_root_path));
            obj.insert("dag_session_id".to_string(), json!(dag_session_id));
        }
        Ok(payload)
    }

    async fn handle_index(&mut self, args: IndexArgs) -> Result<serde_json::Value> {
        let project_root =
            self.resolve_project_root_arg(args.project_root.clone(), args.repo_path.clone())?;
        self.ensure_project_root(project_root.as_deref())?;
        if self.indexer.is_read_only() {
            return self.handle_index_via_http(args).await;
        }
        if args.paths.is_empty() {
            self.indexer.reindex_all().await?;
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
        let mut ingested = Vec::new();
        let mut decisions = Vec::new();
        for path in args.paths {
            let resolved = if path.is_absolute() {
                path
            } else {
                self.repo_root.join(path)
            };
            let path_display = resolved.display().to_string();
            let decision = self.indexer.ingest_file(resolved.clone()).await?;
            ingested.push(resolved);
            decisions.push(json!({
                "path": path_display,
                "decision": decision.decision,
                "reason": decision.reason,
            }));
        }
        Ok(json!({
            "status": "ok",
            "action": "ingest",
            "paths": ingested
                .into_iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>(),
            "decisions": decisions,
            "repo_root": self.repo_root.display().to_string(),
            "state_dir": self.indexer.config().state_dir().display().to_string(),
            "project_root": self
                .default_project_root
                .as_ref()
                .unwrap_or(&self.repo_root)
                .display()
                .to_string(),
        }))
    }

    async fn handle_index_via_http(&self, args: IndexArgs) -> Result<serde_json::Value> {
        let repo_id = self.repo_id.as_str();
        if args.paths.is_empty() {
            let report = self
                .call_index_endpoint("/v1/index/rebuild", json!({ "repo_id": repo_id }))
                .await?;
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
                "via": "http",
                "report": report,
            }));
        }
        let mut ingested = Vec::new();
        let mut decisions = Vec::new();
        for path in args.paths {
            let resolved = if path.is_absolute() {
                path
            } else {
                self.repo_root.join(path)
            };
            let path_display = resolved.display().to_string();
            let payload = self
                .call_index_endpoint(
                    "/v1/index/ingest",
                    json!({
                        "file": path_display.as_str(),
                        "repo_id": repo_id,
                    }),
                )
                .await?;
            let (decision, reason) = payload
                .as_object()
                .map(|obj| {
                    (
                        obj.get("decision").cloned().unwrap_or(Value::Null),
                        obj.get("reason").cloned().unwrap_or(Value::Null),
                    )
                })
                .unwrap_or((payload.clone(), Value::Null));
            ingested.push(path_display.clone());
            decisions.push(json!({
                "path": path_display,
                "decision": decision,
                "reason": reason,
            }));
        }
        Ok(json!({
            "status": "ok",
            "action": "ingest",
            "paths": ingested,
            "decisions": decisions,
            "repo_root": self.repo_root.display().to_string(),
            "state_dir": self.indexer.config().state_dir().display().to_string(),
            "project_root": self
                .default_project_root
                .as_ref()
                .unwrap_or(&self.repo_root)
                .display()
                .to_string(),
            "via": "http",
        }))
    }

    async fn handle_files(&self, args: FilesArgs) -> Result<serde_json::Value> {
        let project_root = self.resolve_project_root_arg(args.project_root, args.repo_path)?;
        self.ensure_project_root(project_root.as_deref())?;
        self.ensure_index_ready().await?;
        let limit = args
            .limit
            .unwrap_or(FILES_DEFAULT_LIMIT)
            .clamp(1, FILES_MAX_LIMIT);
        let offset = args.offset.unwrap_or(0).min(FILES_MAX_OFFSET);
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

    async fn handle_stats(&self, args: StatsArgs) -> Result<serde_json::Value> {
        let project_root = self.resolve_project_root_arg(args.project_root, args.repo_path)?;
        self.ensure_project_root(project_root.as_deref())?;
        self.ensure_index_ready().await?;
        let stats = self.indexer.stats()?;
        Ok(json!({
            "num_docs": stats.num_docs,
            "state_dir": stats.state_dir.display().to_string(),
            "index_size_bytes": stats.index_size_bytes,
            "segments": stats.segments,
            "avg_bytes_per_doc": stats.avg_bytes_per_doc,
            "generated_at_epoch_ms": stats.generated_at_epoch_ms,
            "last_updated_epoch_ms": stats.last_updated_epoch_ms,
            "repo_root": self.repo_root.display().to_string(),
            "project_root": self
                .default_project_root
                .as_ref()
                .unwrap_or(&self.repo_root)
                .display()
                .to_string(),
        }))
    }

    async fn handle_repo_inspect(&self, args: RepoInspectArgs) -> Result<serde_json::Value> {
        let project_root = self.resolve_project_root_arg(args.project_root, args.repo_path)?;
        self.ensure_project_root(project_root.as_deref())?;
        let report = crate::repo_manager::inspect_repo(
            &self.repo_root,
            Some(self.indexer.config().state_dir()),
        )?;
        Ok(serde_json::to_value(&report).context("serialize docdex_repo_inspect")?)
    }

    async fn handle_open(&self, args: OpenArgs) -> Result<serde_json::Value> {
        let project_root = self.resolve_project_root_arg(args.project_root, args.repo_path)?;
        self.ensure_project_root(project_root.as_deref())?;
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
        if content.len() > OPEN_MAX_BYTES {
            return Err(MaxContentError {
                actual_bytes: content.len(),
                max_bytes: OPEN_MAX_BYTES,
            }
            .into());
        }
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
        let (start, end_raw) = resolve_open_range(
            total_lines,
            args.start_line,
            args.end_line,
            args.head,
            args.clamp.unwrap_or(false),
        )?;
        let start_idx = start.saturating_sub(1);
        let end_idx = end_raw.saturating_sub(1);
        let slice = lines[start_idx..=end_idx].join("\n");
        Ok(json!({
            "path": rel_path.display().to_string(),
            "start_line": start,
            "end_line": end_raw,
            "total_lines": total_lines,
            "content": slice,
            "repo_root": self.repo_root.display().to_string(),
            "project_root": self
                .default_project_root
                .as_ref()
                .unwrap_or(&self.repo_root)
                .display()
                .to_string(),
        }))
    }

    async fn handle_tree(&self, args: TreeArgs) -> Result<serde_json::Value> {
        let project_root = self.resolve_project_root_arg(args.project_root, args.repo_path)?;
        self.ensure_project_root(project_root.as_deref())?;
        let root = resolve_tree_root(&self.repo_root, args.path.as_deref())?;
        let options = TreeOptions {
            max_depth: args.max_depth,
            dirs_only: args.dirs_only.unwrap_or(false),
            include_hidden: args.include_hidden.unwrap_or(false),
            extra_excludes: args.extra_excludes.unwrap_or_default(),
        };
        let output = render_tree(&root, &options)?;
        Ok(json!({
            "root": output.root.display().to_string(),
            "tree": output.tree,
            "repo_root": self.repo_root.display().to_string(),
            "project_root": self
                .default_project_root
                .as_ref()
                .unwrap_or(&self.repo_root)
                .display()
                .to_string(),
            "max_depth": options.max_depth,
            "dirs_only": options.dirs_only,
            "include_hidden": options.include_hidden,
            "excludes": output.excludes,
        }))
    }

    async fn handle_symbols(&self, args: SymbolsArgs) -> Result<serde_json::Value> {
        let project_root = self.resolve_project_root_arg(args.project_root, args.repo_path)?;
        self.ensure_project_root(project_root.as_deref())?;
        self.ensure_index_ready().await?;
        if !self.indexer.config().symbols_enabled() {
            return Err(MissingSymbolsDependencyError.into());
        }
        let rel_path = normalize_rel_path(&args.path).ok_or(InvalidPathError)?;
        let rel_str = rel_path.to_string_lossy().replace('\\', "/");
        let store = SymbolsStore::new(self.indexer.repo_root(), self.indexer.config().state_dir())
            .context("open symbols store")?;
        if store.requires_reindex()? {
            return Err(StaleSymbolsIndexError.into());
        }
        let payload = store
            .read_symbols(&rel_str)?
            .ok_or_else(|| MissingSymbolsIndexError {
                rel_path: rel_str.to_string(),
            })?;
        Ok(serde_json::to_value(payload).context("serialize symbols payload")?)
    }

    async fn handle_ast(&self, args: AstArgs) -> Result<serde_json::Value> {
        let project_root = self.resolve_project_root_arg(args.project_root, args.repo_path)?;
        self.ensure_project_root(project_root.as_deref())?;
        self.ensure_index_ready().await?;
        if !self.indexer.config().symbols_enabled() {
            return Err(MissingSymbolsDependencyError.into());
        }
        let rel_path = normalize_rel_path(&args.path).ok_or(InvalidPathError)?;
        let rel_str = rel_path.to_string_lossy().replace('\\', "/");
        let store = SymbolsStore::new(self.indexer.repo_root(), self.indexer.config().state_dir())
            .context("open symbols store")?;
        if store.requires_reindex()? {
            return Err(StaleSymbolsIndexError.into());
        }
        let max_nodes = args
            .max_nodes
            .unwrap_or(AST_DEFAULT_MAX_NODES)
            .clamp(1, AST_MAX_NODES);
        let payload = store
            .read_ast(&rel_str, max_nodes)?
            .ok_or_else(|| MissingAstIndexError {
                rel_path: rel_str.to_string(),
            })?;
        Ok(serde_json::to_value(payload).context("serialize ast payload")?)
    }

    async fn handle_impact_diagnostics(
        &self,
        args: ImpactDiagnosticsArgs,
    ) -> Result<serde_json::Value> {
        let project_root = self.resolve_project_root_arg(args.project_root, args.repo_path)?;
        self.ensure_project_root(project_root.as_deref())?;
        self.ensure_index_ready().await?;
        let repo_id = crate::symbols::repo_id_for_root(self.indexer.repo_root())?;
        let store = ImpactGraphStore::new(self.indexer.state_dir());
        let diagnostics_map = store.read_diagnostics_map()?;
        let file = match args.file.as_deref().map(str::trim) {
            None => None,
            Some("") => {
                return Err(AppError::new(ERR_INVALID_ARGUMENT, "file must not be empty").into());
            }
            Some(value) => {
                let rel = normalize_rel_path(value).ok_or_else(|| {
                    AppError::new(ERR_INVALID_ARGUMENT, "file must be repo-relative")
                })?;
                Some(rel.to_string_lossy().replace('\\', "/"))
            }
        };

        let (entries, total, limit, offset) = if let Some(file) = file {
            let entry = diagnostics_map
                .get(&file)
                .cloned()
                .map(|diag| ImpactDiagnosticsEntry {
                    file: file.clone(),
                    diagnostics: diag,
                });
            let diagnostics = entry.into_iter().collect::<Vec<_>>();
            let count = diagnostics.len();
            (diagnostics, count, 1, 0)
        } else {
            let mut entries = diagnostics_map
                .into_iter()
                .map(|(file, diagnostics)| ImpactDiagnosticsEntry { file, diagnostics })
                .collect::<Vec<_>>();
            entries.sort_by(|a, b| a.file.cmp(&b.file));
            let total = entries.len();
            let limit = args
                .limit
                .unwrap_or(DIAGNOSTICS_DEFAULT_LIMIT)
                .min(DIAGNOSTICS_MAX_LIMIT)
                .max(1);
            let offset = args.offset.unwrap_or(0);
            let diagnostics = entries
                .into_iter()
                .skip(offset)
                .take(limit)
                .collect::<Vec<_>>();
            (diagnostics, total, limit, offset)
        };

        let payload = build_impact_diagnostics_response(&repo_id, entries, total, limit, offset);
        Ok(serde_json::to_value(payload).context("serialize impact diagnostics")?)
    }

    async fn handle_impact_graph(&self, args: ImpactGraphArgs) -> Result<serde_json::Value> {
        let project_root = self.resolve_project_root_arg(args.project_root, args.repo_path)?;
        self.ensure_project_root(project_root.as_deref())?;
        self.ensure_index_ready().await?;

        let file = args.file.trim();
        if file.is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "file must not be empty").into());
        }
        let rel = normalize_rel_path(file)
            .ok_or_else(|| AppError::new(ERR_INVALID_ARGUMENT, "file must be repo-relative"))?;
        let file = rel.to_string_lossy().replace('\\', "/");

        let edge_types = args.edge_types.map(|values| {
            values
                .into_iter()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .collect::<Vec<_>>()
        });
        let controls_raw = crate::impact::ImpactQueryControlsRaw {
            max_edges: args.max_edges.map(|value| value as i64),
            max_depth: args.max_depth.map(|value| value as i64),
            edge_types: edge_types.filter(|values| !values.is_empty()),
        };
        let controls = match controls_raw.validate() {
            Ok(value) => value,
            Err(err) => {
                let details = serde_json::to_value(err.details).unwrap_or_else(|_| json!({}));
                return Err(AppError::new(ERR_INVALID_ARGUMENT, "invalid argument")
                    .with_details(details)
                    .into());
            }
        };

        let repo_id = crate::symbols::repo_id_for_root(self.indexer.repo_root())?;
        let store = ImpactGraphStore::new(self.indexer.state_dir());
        let all_edges = store.read_edges()?;
        let traversal = crate::impact::traverse_impact(&file, &all_edges, &controls);
        let diagnostics = store.read_diagnostics(&file).ok().flatten();
        let response = crate::impact::build_impact_response(
            &repo_id,
            &file,
            traversal,
            &controls,
            diagnostics,
        );
        Ok(serde_json::to_value(response).context("serialize impact graph")?)
    }

    async fn handle_dag_export(&self, args: DagExportArgs) -> Result<serde_json::Value> {
        let project_root = self.resolve_project_root_arg(args.project_root, args.repo_path)?;
        self.ensure_project_root(project_root.as_deref())?;

        let session_id = args
            .session_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty());
        let Some(session_id) = session_id else {
            let details = json!({
                "hint": "Pass the dag_session_id from docdex_search/docdex_web_research responses (meta.dag_session_id or top-level dag_session_id).",
                "expected_params": ["session_id", "dag_session_id"]
            });
            return Err(
                AppError::new(ERR_INVALID_ARGUMENT, "session_id is required")
                    .with_details(details)
                    .into(),
            );
        };
        let format = args
            .format
            .as_deref()
            .unwrap_or("json")
            .trim()
            .to_ascii_lowercase();
        let max_nodes = args.max_nodes;

        match format.as_str() {
            "json" => {
                let payload = crate::dag::view::export_session(
                    self.indexer.repo_root(),
                    session_id,
                    Some(self.indexer.state_dir().to_path_buf()),
                    max_nodes,
                )?;
                Ok(serde_json::to_value(payload).context("serialize dag export")?)
            }
            "text" => {
                let output = crate::dag::view::render_session_as_text(
                    self.indexer.repo_root(),
                    session_id,
                    Some(self.indexer.state_dir().to_path_buf()),
                    max_nodes,
                )?;
                Ok(json!({ "format": "text", "content": output }))
            }
            "dot" => {
                let output = crate::dag::view::render_session_as_dot(
                    self.indexer.repo_root(),
                    session_id,
                    Some(self.indexer.state_dir().to_path_buf()),
                    max_nodes,
                )?;
                Ok(json!({ "format": "dot", "content": output }))
            }
            _ => {
                Err(AppError::new(ERR_INVALID_ARGUMENT, "format must be json, text, or dot").into())
            }
        }
    }

    async fn embed_memory_text(
        &self,
        memory: &McpMemoryState,
        text: &str,
    ) -> Result<MemoryEmbedding> {
        let stored_dim = match memory.store.embedding_dim() {
            Ok(dim) => dim,
            Err(err) => {
                warn!(
                    error = ?err,
                    "memory embedding_dim lookup failed; falling back to default"
                );
                None
            }
        };
        match memory.embedder.embed(text).await {
            Ok(embedding) => {
                if let Some(expected) = stored_dim {
                    if embedding.len() != expected {
                        warn!(
                            provider = memory.embedder.provider(),
                            model = memory.embedder.model(),
                            expected,
                            actual = embedding.len(),
                            "memory embedding dimension mismatch; falling back to local hash"
                        );
                        let fallback = ProfileEmbedder::fallback_embedding(text, expected);
                        return Ok(MemoryEmbedding {
                            embedding: fallback,
                            provider: "fallback".to_string(),
                            model: "hash-embed-v1".to_string(),
                        });
                    }
                }
                Ok(MemoryEmbedding {
                    embedding,
                    provider: memory.embedder.provider().to_string(),
                    model: memory.embedder.model().to_string(),
                })
            }
            Err(err) => {
                warn!(
                    error = ?err,
                    "memory embedding failed; falling back to local hash"
                );
                let expected = stored_dim.unwrap_or(memory.fallback_dim).max(1);
                let fallback = ProfileEmbedder::fallback_embedding(text, expected);
                Ok(MemoryEmbedding {
                    embedding: fallback,
                    provider: "fallback".to_string(),
                    model: "hash-embed-v1".to_string(),
                })
            }
        }
    }

    async fn handle_memory_store(&self, args: MemoryStoreArgs) -> Result<serde_json::Value> {
        let project_root = self.resolve_project_root_arg(args.project_root, args.repo_path)?;
        self.ensure_project_root(project_root.as_deref())?;
        let Some(memory) = self.memory.clone() else {
            return Err(AppError::new(
                ERR_MEMORY_DISABLED,
                "memory is disabled; set DOCDEX_ENABLE_MEMORY=1",
            )
            .into());
        };
        let text = args.text.trim();
        if text.is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "text must not be empty").into());
        }

        let repo_state_root = repo_state_root_from_state_dir(self.indexer.state_dir());
        let session_id = format!("mcp-{}", Uuid::new_v4());
        queue_dag_log(
            &repo_state_root,
            &session_id,
            "ToolCall",
            json!({
                "tool": "memory_store",
                "text_len": text.len(),
            }),
        );
        let started = Instant::now();
        let embedding = self.embed_memory_text(&memory, text).await?;

        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis() as i64;
        let metadata =
            inject_embedding_metadata(args.metadata, &embedding.provider, &embedding.model);
        let store = memory.store.clone();
        let text_owned = text.to_string();
        let stored = tokio::task::spawn_blocking(move || {
            store.store(&text_owned, &embedding.embedding, metadata, created_at)
        })
        .await??;
        queue_dag_log(
            &repo_state_root,
            &session_id,
            "Observation",
            json!({
                "tool": "memory_store",
                "id": stored.0.to_string(),
                "latency_ms": started.elapsed().as_millis(),
            }),
        );
        debug!(
            repo = %self.repo_root.display(),
            latency_ms = started.elapsed().as_millis(),
            id = %stored.0,
            "docdex mcp: memory_store"
        );
        Ok(json!({
            "id": stored.0.to_string(),
            "created_at": stored.1
        }))
    }

    async fn handle_memory_recall(&self, args: MemoryRecallArgs) -> Result<serde_json::Value> {
        let project_root = self.resolve_project_root_arg(args.project_root, args.repo_path)?;
        self.ensure_project_root(project_root.as_deref())?;
        let Some(memory) = self.memory.clone() else {
            return Err(AppError::new(
                ERR_MEMORY_DISABLED,
                "memory is disabled; set DOCDEX_ENABLE_MEMORY=1",
            )
            .into());
        };
        let query = args.query.trim();
        if query.is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "query must not be empty").into());
        }

        let top_k = args.top_k.unwrap_or(5).max(1).min(50);
        let repo_state_root = repo_state_root_from_state_dir(self.indexer.state_dir());
        let session_id = format!("mcp-{}", Uuid::new_v4());
        queue_dag_log(
            &repo_state_root,
            &session_id,
            "ToolCall",
            json!({
                "tool": "memory_recall",
                "top_k": top_k,
                "query_len": query.len(),
            }),
        );
        let started = Instant::now();
        let embedding = self.embed_memory_text(&memory, query).await?;

        let store = memory.store.clone();
        let items = tokio::task::spawn_blocking(move || store.recall(&embedding.embedding, top_k))
            .await??;
        queue_dag_log(
            &repo_state_root,
            &session_id,
            "Observation",
            json!({
                "tool": "memory_recall",
                "results": items.len(),
                "latency_ms": started.elapsed().as_millis(),
            }),
        );
        debug!(
            repo = %self.repo_root.display(),
            top_k,
            results = items.len(),
            latency_ms = started.elapsed().as_millis(),
            "docdex mcp: memory_recall"
        );
        Ok(json!({
            "top_k": top_k,
            "results": items.into_iter().map(|item| json!({
                "content": item.content,
                "score": item.score,
                "metadata": item.metadata
            })).collect::<Vec<_>>()
        }))
    }

    async fn handle_memory_layers(&self, args: MemoryLayersArgs) -> Result<serde_json::Value> {
        let namespace = args
            .conversation_namespace
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        let scope =
            self.resolve_conversation_scope(args.project_root, args.repo_path, namespace.clone())?;
        let value = match scope {
            McpConversationScope::Repo {
                repo_id,
                conversations,
                memory,
            } => crate::memory_layers::build_memory_layers_map(
                crate::memory_layers::MemoryLayersInput {
                    scope: crate::memory_layers::MemoryLayerScopeInput::Repo {
                        repo_id: &repo_id,
                        repo_root: self.indexer.repo_root(),
                    },
                    default_agent_id: self.default_agent_id.as_deref(),
                    repo_memory: memory.as_ref().map(|value| &value.store),
                    profile: self.profile_state.as_ref().map(|value| &value.manager),
                    conversations: Some(&conversations.store),
                    knowledge: Some(&conversations.knowledge),
                    conversation_config: Some(&conversations.config),
                    personal_preferences: self
                        .personal_preferences
                        .as_ref()
                        .map(|value| &value.store),
                    personal_preferences_config: self
                        .personal_preferences
                        .as_ref()
                        .map(|value| &value.config),
                },
            ),
            McpConversationScope::Namespace { conversations } => {
                let namespace = namespace.as_deref().ok_or_else(|| {
                    AppError::new(
                        ERR_INTERNAL_ERROR,
                        "conversation namespace context is missing the namespace value",
                    )
                })?;
                crate::memory_layers::build_memory_layers_map(
                    crate::memory_layers::MemoryLayersInput {
                        scope: crate::memory_layers::MemoryLayerScopeInput::Namespace { namespace },
                        default_agent_id: self.default_agent_id.as_deref(),
                        repo_memory: None,
                        profile: self.profile_state.as_ref().map(|value| &value.manager),
                        conversations: Some(&conversations.store),
                        knowledge: Some(&conversations.knowledge),
                        conversation_config: Some(&conversations.config),
                        personal_preferences: self
                            .personal_preferences
                            .as_ref()
                            .map(|value| &value.store),
                        personal_preferences_config: self
                            .personal_preferences
                            .as_ref()
                            .map(|value| &value.config),
                    },
                )
            }
        };
        Ok(serde_json::to_value(value)?)
    }

    async fn handle_memory_route(&self, args: MemoryRouteArgs) -> Result<serde_json::Value> {
        let namespace = args
            .conversation_namespace
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        let scope =
            self.resolve_conversation_scope(args.project_root, args.repo_path, namespace.clone())?;
        let value = match scope {
            McpConversationScope::Repo {
                repo_id,
                conversations,
                memory,
            } => crate::memory_layers::build_memory_route(
                crate::memory_layers::MemoryLayersInput {
                    scope: crate::memory_layers::MemoryLayerScopeInput::Repo {
                        repo_id: &repo_id,
                        repo_root: self.indexer.repo_root(),
                    },
                    default_agent_id: self.default_agent_id.as_deref(),
                    repo_memory: memory.as_ref().map(|value| &value.store),
                    profile: self.profile_state.as_ref().map(|value| &value.manager),
                    conversations: Some(&conversations.store),
                    knowledge: Some(&conversations.knowledge),
                    conversation_config: Some(&conversations.config),
                    personal_preferences: self
                        .personal_preferences
                        .as_ref()
                        .map(|value| &value.store),
                    personal_preferences_config: self
                        .personal_preferences
                        .as_ref()
                        .map(|value| &value.config),
                },
                &args.query,
                args.intent.as_deref(),
            ),
            McpConversationScope::Namespace { conversations } => {
                let namespace = namespace.as_deref().ok_or_else(|| {
                    AppError::new(
                        ERR_INTERNAL_ERROR,
                        "conversation namespace context is missing the namespace value",
                    )
                })?;
                crate::memory_layers::build_memory_route(
                    crate::memory_layers::MemoryLayersInput {
                        scope: crate::memory_layers::MemoryLayerScopeInput::Namespace { namespace },
                        default_agent_id: self.default_agent_id.as_deref(),
                        repo_memory: None,
                        profile: self.profile_state.as_ref().map(|value| &value.manager),
                        conversations: Some(&conversations.store),
                        knowledge: Some(&conversations.knowledge),
                        conversation_config: Some(&conversations.config),
                        personal_preferences: self
                            .personal_preferences
                            .as_ref()
                            .map(|value| &value.store),
                        personal_preferences_config: self
                            .personal_preferences
                            .as_ref()
                            .map(|value| &value.config),
                    },
                    &args.query,
                    args.intent.as_deref(),
                )
            }
        };
        Ok(serde_json::to_value(value)?)
    }

    async fn handle_conversation_import(
        &self,
        args: ConversationImportArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences_namespace = args.conversation_namespace.clone();
        let scope = self.resolve_conversation_scope(
            args.project_root.clone(),
            args.repo_path.clone(),
            args.conversation_namespace.clone(),
        )?;
        let conversations = scope.conversations();
        let payload = crate::conversations::normalize_import_request(
            crate::conversations::ConversationImportEnvelope {
                source: args.source,
                source_session_id: args.source_session_id,
                title: args.title,
                agent_id: args.agent_id.or_else(|| self.default_agent_id.clone()),
                transport: args.transport,
                started_at_ms: args.started_at_ms,
                ended_at_ms: args.ended_at_ms,
                format: args.format,
                messages: map_conversation_import_messages(args.messages),
                transcript_text: args.transcript_text,
                metadata: args.metadata.unwrap_or_else(|| json!({})),
            },
        )
        .map_err(|message| AppError::new(ERR_INVALID_ARGUMENT, message))?;
        if !conversations.config.allows_source(&payload.source) {
            return Err(AppError::new(
                ERR_INVALID_ARGUMENT,
                "conversation source is blocked by memory.conversations source policy",
            )
            .into());
        }
        let personal_preferences_capture = self
            .personal_preferences
            .as_ref()
            .filter(|personal_preferences| {
                crate::personal_preferences::should_capture_external_source(
                    &personal_preferences.config,
                    &payload.source,
                    personal_preferences.config.capture_imported_conversations,
                )
            })
            .map(|personal_preferences| {
                (
                    personal_preferences.clone(),
                    build_personal_preferences_capture_request_from_import(
                        &self.repo_root,
                        &scope,
                        personal_preferences_namespace.as_deref(),
                        &payload,
                    ),
                )
            });
        let route_targets = crate::conversations::build_conversation_route_targets(
            scope.repo_memory_target(),
            self.profile_state.as_ref().map(|profile| {
                crate::conversations::build_conversation_profile_target(
                    profile.manager.clone(),
                    profile.embedder.clone(),
                    "conversation_import",
                )
            }),
            conversations.knowledge.clone(),
            conversations.config.graph.clone(),
            self.default_agent_id.clone(),
        );
        let store = conversations.store.clone();
        let imported = crate::conversations::import_conversation_with_routing_options(
            store,
            payload,
            crate::conversations::ConversationImportOptions {
                capture_kind: crate::conversations::ConversationCaptureKind::Manual,
                store_raw_messages: conversations.config.archive_raw_transcripts,
            },
            route_targets,
        )
        .await?;
        if let Some((personal_preferences, capture_request)) = personal_preferences_capture {
            personal_preferences.store.capture_conversation(
                capture_request,
                personal_preferences.config.digest_enabled,
                personal_preferences.config.archive_raw_conversations,
            )?;
        }
        self.update_conversation_archive_metric(&conversations);
        Ok(json!({
            "session_id": imported.session_id,
            "deduplicated": imported.deduplicated,
            "message_count": imported.message_count,
            "capture_kind": imported.capture_kind,
            "raw_messages_stored": imported.raw_messages_stored,
            "summary": imported.summary,
            "working_memory": imported.working_memory,
            "durable_memories": imported.durable_memories,
            "knowledge_facts": imported.knowledge_facts,
        }))
    }

    async fn handle_conversation_search(
        &self,
        args: ConversationSearchArgs,
    ) -> Result<serde_json::Value> {
        let scope = self.resolve_conversation_scope(
            args.project_root.clone(),
            args.repo_path.clone(),
            args.conversation_namespace.clone(),
        )?;
        let conversations = scope.conversations();
        let query = args.query.trim().to_string();
        if query.is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "query must not be empty").into());
        }
        if matches!(args.limit, Some(0)) {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "limit must be greater than 0").into());
        }
        let limit = args
            .limit
            .unwrap_or(CONVERSATION_LIST_DEFAULT_LIMIT)
            .clamp(1, CONVERSATION_LIST_MAX_LIMIT);
        let offset = args.offset.unwrap_or(0);
        let agent_id = args
            .agent_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        let store = conversations.store.clone();
        let query_for_task = query.clone();
        let result = tokio::task::spawn_blocking(move || {
            store.search_sessions(&query_for_task, agent_id.as_deref(), limit, offset)
        })
        .await??;
        Ok(serde_json::to_value(result)?)
    }

    async fn handle_conversation_list(
        &self,
        args: ConversationListArgs,
    ) -> Result<serde_json::Value> {
        let scope = self.resolve_conversation_scope(
            args.project_root.clone(),
            args.repo_path.clone(),
            args.conversation_namespace.clone(),
        )?;
        let conversations = scope.conversations();
        if matches!(args.limit, Some(0)) {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "limit must be greater than 0").into());
        }
        let limit = args
            .limit
            .unwrap_or(CONVERSATION_LIST_DEFAULT_LIMIT)
            .clamp(1, CONVERSATION_LIST_MAX_LIMIT);
        let offset = args.offset.unwrap_or(0);
        let agent_id = args
            .agent_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        let store = conversations.store.clone();
        let list = tokio::task::spawn_blocking(move || {
            store.list_sessions(agent_id.as_deref(), limit, offset)
        })
        .await??;
        Ok(serde_json::to_value(list)?)
    }

    async fn handle_conversation_read(
        &self,
        args: ConversationReadArgs,
    ) -> Result<serde_json::Value> {
        let scope = self.resolve_conversation_scope(
            args.project_root.clone(),
            args.repo_path.clone(),
            args.conversation_namespace.clone(),
        )?;
        let conversations = scope.conversations();
        let session_id = args.session_id.trim().to_string();
        if session_id.is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "session_id must not be empty").into());
        }
        let store = conversations.store.clone();
        let session_id_for_task = session_id.clone();
        let session =
            tokio::task::spawn_blocking(move || store.read_session(&session_id_for_task)).await??;
        let Some(session) = session else {
            return Err(AppError::new(
                ERR_CONVERSATION_NOT_FOUND,
                "conversation session not found",
            )
            .with_details(json!({ "session_id": session_id }))
            .into());
        };
        Ok(json!({ "session": session }))
    }

    async fn handle_conversation_delete(
        &self,
        args: ConversationDeleteArgs,
    ) -> Result<serde_json::Value> {
        let scope = self.resolve_conversation_scope(
            args.project_root.clone(),
            args.repo_path.clone(),
            args.conversation_namespace.clone(),
        )?;
        let conversations = scope.conversations();
        let session_id = args.session_id.trim().to_string();
        if session_id.is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "session_id must not be empty").into());
        }
        let store = conversations.store.clone();
        let session_id_for_task = session_id.clone();
        let knowledge = conversations.knowledge.clone();
        let deleted = tokio::task::spawn_blocking(move || -> anyhow::Result<bool> {
            let deleted = store.delete_session(&session_id_for_task)?;
            if deleted {
                let _ = knowledge.delete_facts_for_session(&session_id_for_task)?;
            }
            Ok(deleted)
        })
        .await??;
        if !deleted {
            return Err(AppError::new(
                ERR_CONVERSATION_NOT_FOUND,
                "conversation session not found",
            )
            .with_details(json!({ "session_id": session_id }))
            .into());
        }
        self.update_conversation_archive_metric(&conversations);
        Ok(json!({
            "session_id": session_id,
            "deleted": true,
        }))
    }

    async fn handle_conversation_export(
        &self,
        args: ConversationExportArgs,
    ) -> Result<serde_json::Value> {
        let scope = self.resolve_conversation_scope(
            args.project_root.clone(),
            args.repo_path.clone(),
            args.conversation_namespace.clone(),
        )?;
        let conversations = scope.conversations();
        let session_id = args.session_id.trim().to_string();
        if session_id.is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "session_id must not be empty").into());
        }
        let store = conversations.store.clone();
        let session_id_for_task = session_id.clone();
        let knowledge = conversations.knowledge.clone();
        let export = tokio::task::spawn_blocking(
            move || -> anyhow::Result<Option<crate::conversations::ConversationExportRecord>> {
                let Some(mut export) = store.export_session(&session_id_for_task)? else {
                    return Ok(None);
                };
                export.knowledge_facts = knowledge.facts_for_session(&session_id_for_task)?;
                Ok(Some(export))
            },
        )
        .await??;
        let Some(export) = export else {
            return Err(AppError::new(
                ERR_CONVERSATION_NOT_FOUND,
                "conversation session not found",
            )
            .with_details(json!({ "session_id": session_id }))
            .into());
        };
        Ok(json!({ "export": export }))
    }

    async fn handle_conversation_redact(
        &self,
        args: ConversationRedactArgs,
    ) -> Result<serde_json::Value> {
        let scope = self.resolve_conversation_scope(
            args.project_root.clone(),
            args.repo_path.clone(),
            args.conversation_namespace.clone(),
        )?;
        let conversations = scope.conversations();
        let session_id = args.session_id.trim().to_string();
        if session_id.is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "session_id must not be empty").into());
        }
        let store = conversations.store.clone();
        let session_id_for_task = session_id.clone();
        let knowledge = conversations.knowledge.clone();
        let result = tokio::task::spawn_blocking(
            move || -> anyhow::Result<Option<crate::conversations::ConversationRedactResult>> {
                let result = store.redact_session(&session_id_for_task)?;
                if result.as_ref().map(|item| item.redacted).unwrap_or(false) {
                    let _ = knowledge.delete_facts_for_session(&session_id_for_task)?;
                }
                Ok(result)
            },
        )
        .await??;
        let Some(result) = result else {
            return Err(AppError::new(
                ERR_CONVERSATION_NOT_FOUND,
                "conversation session not found",
            )
            .with_details(json!({ "session_id": session_id }))
            .into());
        };
        self.update_conversation_archive_metric(&conversations);
        Ok(json!({ "result": result }))
    }

    async fn handle_conversation_prune(
        &self,
        args: ConversationPruneArgs,
    ) -> Result<serde_json::Value> {
        let scope = self.resolve_conversation_scope(
            args.project_root.clone(),
            args.repo_path.clone(),
            args.conversation_namespace.clone(),
        )?;
        let conversations = scope.conversations();
        let policy = crate::conversations::ConversationRetentionPolicy {
            manual_retention_days: args
                .manual_retention_days
                .unwrap_or(conversations.config.manual_retention_days),
            auto_capture_retention_days: args
                .auto_capture_retention_days
                .unwrap_or(conversations.config.auto_capture_retention_days),
            diary_retention_days: args
                .diary_retention_days
                .unwrap_or(conversations.config.diary_retention_days),
            hook_event_retention_days: args
                .hook_event_retention_days
                .unwrap_or(conversations.config.hook_event_retention_days),
            working_memory_retention_days: args
                .working_memory_retention_days
                .unwrap_or(conversations.config.working_memory_retention_days),
            episodic_rollup_retention_days: args
                .episodic_rollup_retention_days
                .unwrap_or(conversations.config.episodic_rollup_retention_days),
        };
        let apply = args.apply.unwrap_or(false);
        let store = conversations.store.clone();
        let knowledge = conversations.knowledge.clone();
        let result = tokio::task::spawn_blocking(
            move || -> anyhow::Result<(crate::conversations::ConversationPruneResult, u64, u64)> {
                let before = crate::conversations::combined_archive_size_bytes(&store, &knowledge);
                let result = crate::conversations::prune_with_knowledge(
                    &store, &knowledge, &policy, apply, true,
                )?;
                let after = crate::conversations::combined_archive_size_bytes(&store, &knowledge);
                Ok((result, before, after))
            },
        )
        .await??;
        let (result, before_size, after_size) = result;
        if result.applied && result.has_deletions() {
            metrics::global().record_conversation_compaction(
                result.deleted_sessions_total(),
                result.deleted_diary_entries,
                result.deleted_hook_events,
                result.deleted_knowledge_facts,
                before_size.saturating_sub(after_size),
            );
        }
        self.update_conversation_archive_metric(&conversations);
        Ok(json!({ "result": result }))
    }

    async fn handle_kg_query(&self, args: KgQueryArgs) -> Result<serde_json::Value> {
        let scope = self.resolve_conversation_scope(
            args.project_root.clone(),
            args.repo_path.clone(),
            args.conversation_namespace.clone(),
        )?;
        let conversations = scope.conversations();
        let query = args.query.trim().to_string();
        if query.is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "query must not be empty").into());
        }
        if matches!(args.limit, Some(0)) {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "limit must be greater than 0").into());
        }
        let knowledge = conversations.knowledge.clone();
        let relation = args.relation.clone();
        let limit = args
            .limit
            .unwrap_or(CONVERSATION_LIST_DEFAULT_LIMIT)
            .clamp(1, CONVERSATION_LIST_MAX_LIMIT);
        let offset = args.offset.unwrap_or(0);
        let result = tokio::task::spawn_blocking(move || {
            knowledge.query_facts(&query, relation.as_deref(), limit, offset)
        })
        .await??;
        Ok(serde_json::to_value(result)?)
    }

    async fn handle_kg_search_nodes(&self, args: KgNodeSearchArgs) -> Result<serde_json::Value> {
        let scope = self.resolve_conversation_scope(
            args.project_root.clone(),
            args.repo_path.clone(),
            args.conversation_namespace.clone(),
        )?;
        let conversations = scope.conversations();
        let query = args.query.trim().to_string();
        if query.is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "query must not be empty").into());
        }
        if matches!(args.limit, Some(0)) {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "limit must be greater than 0").into());
        }
        let knowledge = conversations.knowledge.clone();
        let entity_type = args.entity_type.clone();
        let limit = args
            .limit
            .unwrap_or(CONVERSATION_LIST_DEFAULT_LIMIT)
            .clamp(1, CONVERSATION_LIST_MAX_LIMIT);
        let offset = args.offset.unwrap_or(0);
        let result = tokio::task::spawn_blocking(move || {
            knowledge.search_nodes(&query, entity_type.as_deref(), limit, offset)
        })
        .await??;
        Ok(serde_json::to_value(result)?)
    }

    async fn handle_kg_search_edges(&self, args: KgEdgeSearchArgs) -> Result<serde_json::Value> {
        let scope = self.resolve_conversation_scope(
            args.project_root.clone(),
            args.repo_path.clone(),
            args.conversation_namespace.clone(),
        )?;
        let conversations = scope.conversations();
        let query = args.query.trim().to_string();
        if query.is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "query must not be empty").into());
        }
        if matches!(args.limit, Some(0)) {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "limit must be greater than 0").into());
        }
        let knowledge = conversations.knowledge.clone();
        let relation = args.relation.clone();
        let limit = args
            .limit
            .unwrap_or(CONVERSATION_LIST_DEFAULT_LIMIT)
            .clamp(1, CONVERSATION_LIST_MAX_LIMIT);
        let offset = args.offset.unwrap_or(0);
        let result = tokio::task::spawn_blocking(move || {
            knowledge.search_edges(&query, relation.as_deref(), limit, offset)
        })
        .await??;
        Ok(serde_json::to_value(result)?)
    }

    async fn handle_kg_timeline(&self, args: KgTimelineArgs) -> Result<serde_json::Value> {
        let scope = self.resolve_conversation_scope(
            args.project_root.clone(),
            args.repo_path.clone(),
            args.conversation_namespace.clone(),
        )?;
        let conversations = scope.conversations();
        let entity = args.entity.trim().to_string();
        if entity.is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "entity must not be empty").into());
        }
        if matches!(args.limit, Some(0)) {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "limit must be greater than 0").into());
        }
        let knowledge = conversations.knowledge.clone();
        let relation = args.relation.clone();
        let limit = args
            .limit
            .unwrap_or(CONVERSATION_LIST_DEFAULT_LIMIT)
            .clamp(1, CONVERSATION_LIST_MAX_LIMIT);
        let result = tokio::task::spawn_blocking(move || {
            knowledge.timeline_for_entity(&entity, relation.as_deref(), limit)
        })
        .await??;
        Ok(serde_json::to_value(result)?)
    }

    async fn handle_kg_search_episodes(
        &self,
        args: KgEpisodeSearchArgs,
    ) -> Result<serde_json::Value> {
        let scope = self.resolve_conversation_scope(
            args.project_root.clone(),
            args.repo_path.clone(),
            args.conversation_namespace.clone(),
        )?;
        let conversations = scope.conversations();
        let query = args.query.trim().to_string();
        if query.is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "query must not be empty").into());
        }
        if matches!(args.limit, Some(0)) {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "limit must be greater than 0").into());
        }
        let knowledge = conversations.knowledge.clone();
        let source_type = args.source_type.clone();
        let limit = args
            .limit
            .unwrap_or(CONVERSATION_LIST_DEFAULT_LIMIT)
            .clamp(1, CONVERSATION_LIST_MAX_LIMIT);
        let offset = args.offset.unwrap_or(0);
        let result = tokio::task::spawn_blocking(move || {
            knowledge.search_episodes(&query, source_type.as_deref(), limit, offset)
        })
        .await??;
        Ok(serde_json::to_value(result)?)
    }

    async fn handle_kg_neighborhood(&self, args: KgNeighborhoodArgs) -> Result<serde_json::Value> {
        let scope = self.resolve_conversation_scope(
            args.project_root.clone(),
            args.repo_path.clone(),
            args.conversation_namespace.clone(),
        )?;
        let conversations = scope.conversations();
        let entity = args.entity.trim().to_string();
        if entity.is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "entity must not be empty").into());
        }
        if matches!(args.limit, Some(0)) {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "limit must be greater than 0").into());
        }
        let knowledge = conversations.knowledge.clone();
        let relation = args.relation.clone();
        let limit = args
            .limit
            .unwrap_or(CONVERSATION_LIST_DEFAULT_LIMIT)
            .clamp(1, CONVERSATION_LIST_MAX_LIMIT);
        let result = tokio::task::spawn_blocking(move || {
            knowledge.neighborhood_for_entity(&entity, relation.as_deref(), limit)
        })
        .await??;
        Ok(serde_json::to_value(result)?)
    }

    async fn handle_kg_entity_links(&self, args: KgEntityLinksArgs) -> Result<serde_json::Value> {
        let scope = self.resolve_conversation_scope(
            args.project_root.clone(),
            args.repo_path.clone(),
            args.conversation_namespace.clone(),
        )?;
        let conversations = scope.conversations();
        let entity = args.entity.trim().to_string();
        if entity.is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "entity must not be empty").into());
        }
        if matches!(args.limit, Some(0)) {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "limit must be greater than 0").into());
        }
        let knowledge = conversations.knowledge.clone();
        let link_type = args.link_type.clone();
        let limit = args
            .limit
            .unwrap_or(CONVERSATION_LIST_DEFAULT_LIMIT)
            .clamp(1, CONVERSATION_LIST_MAX_LIMIT);
        let result = tokio::task::spawn_blocking(move || {
            knowledge.entity_links_for_entity(&entity, link_type.as_deref(), limit)
        })
        .await??;
        Ok(serde_json::to_value(result)?)
    }

    async fn handle_kg_episode(&self, args: KgEpisodeArgs) -> Result<serde_json::Value> {
        let scope = self.resolve_conversation_scope(
            args.project_root.clone(),
            args.repo_path.clone(),
            args.conversation_namespace.clone(),
        )?;
        let conversations = scope.conversations();
        let episode_id = args.episode_id.trim().to_string();
        if episode_id.is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "episode_id must not be empty").into());
        }
        if matches!(args.limit, Some(0)) {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "limit must be greater than 0").into());
        }
        let knowledge = conversations.knowledge.clone();
        let limit = args
            .limit
            .unwrap_or(CONVERSATION_LIST_DEFAULT_LIMIT)
            .clamp(1, CONVERSATION_LIST_MAX_LIMIT);
        let result =
            tokio::task::spawn_blocking(move || knowledge.episode_details(&episode_id, limit))
                .await??;
        let Some(result) = result else {
            return Err(AppError::new(
                ERR_KNOWLEDGE_EPISODE_NOT_FOUND,
                "knowledge episode not found",
            )
            .into());
        };
        Ok(serde_json::to_value(result)?)
    }

    async fn handle_kg_delete_edge(&self, args: KgDeleteEdgeArgs) -> Result<serde_json::Value> {
        let scope = self.resolve_conversation_scope(
            args.project_root.clone(),
            args.repo_path.clone(),
            args.conversation_namespace.clone(),
        )?;
        let conversations = scope.conversations();
        let edge_id = args.edge_id.trim().to_string();
        if edge_id.is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "edge_id must not be empty").into());
        }
        let knowledge = conversations.knowledge.clone();
        let result = tokio::task::spawn_blocking(move || knowledge.delete_edge(&edge_id)).await??;
        Ok(serde_json::to_value(result)?)
    }

    async fn handle_kg_delete_episode(
        &self,
        args: KgDeleteEpisodeArgs,
    ) -> Result<serde_json::Value> {
        let scope = self.resolve_conversation_scope(
            args.project_root.clone(),
            args.repo_path.clone(),
            args.conversation_namespace.clone(),
        )?;
        let conversations = scope.conversations();
        let episode_id = args.episode_id.trim().to_string();
        if episode_id.is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "episode_id must not be empty").into());
        }
        let knowledge = conversations.knowledge.clone();
        let result =
            tokio::task::spawn_blocking(move || knowledge.delete_episode(&episode_id)).await??;
        Ok(serde_json::to_value(result)?)
    }

    async fn handle_kg_rebuild(&self, args: KgMaintenanceArgs) -> Result<serde_json::Value> {
        let scope = self.resolve_conversation_scope(
            args.project_root.clone(),
            args.repo_path.clone(),
            args.conversation_namespace.clone(),
        )?;
        let conversations = scope.conversations();
        let knowledge = conversations.knowledge.clone();
        let result = tokio::task::spawn_blocking(move || knowledge.rebuild()).await??;
        Ok(serde_json::to_value(result)?)
    }

    async fn handle_kg_clear(&self, args: KgMaintenanceArgs) -> Result<serde_json::Value> {
        let scope = self.resolve_conversation_scope(
            args.project_root.clone(),
            args.repo_path.clone(),
            args.conversation_namespace.clone(),
        )?;
        let conversations = scope.conversations();
        let knowledge = conversations.knowledge.clone();
        let result = tokio::task::spawn_blocking(move || knowledge.clear()).await??;
        Ok(serde_json::to_value(result)?)
    }

    async fn handle_diary_write(&self, args: DiaryWriteArgs) -> Result<serde_json::Value> {
        let scope = self.resolve_conversation_scope(
            args.project_root.clone(),
            args.repo_path.clone(),
            args.conversation_namespace.clone(),
        )?;
        let conversations = scope.conversations();
        let content = args.content.trim().to_string();
        if content.is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "content must not be empty").into());
        }
        let entry = crate::conversations::write_diary_entry(
            conversations.store.clone(),
            args.agent_id.or_else(|| self.default_agent_id.clone()),
            args.entry_type
                .unwrap_or_else(|| "note".to_string())
                .trim()
                .to_string(),
            content,
            args.source_session_id,
            args.metadata.unwrap_or_else(|| json!({})),
        )
        .await?;
        crate::conversations::record_diary_entry_episode(
            conversations.knowledge.clone(),
            entry.clone(),
        )
        .await?;
        Ok(serde_json::to_value(entry)?)
    }

    async fn handle_diary_read(&self, args: DiaryReadArgs) -> Result<serde_json::Value> {
        let scope = self.resolve_conversation_scope(
            args.project_root.clone(),
            args.repo_path.clone(),
            args.conversation_namespace.clone(),
        )?;
        let conversations = scope.conversations();
        if matches!(args.limit, Some(0)) {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "limit must be greater than 0").into());
        }
        let limit = args
            .limit
            .unwrap_or(CONVERSATION_LIST_DEFAULT_LIMIT)
            .clamp(1, CONVERSATION_LIST_MAX_LIMIT);
        let offset = args.offset.unwrap_or(0);
        let entries = crate::conversations::read_diary_entries(
            conversations.store.clone(),
            args.agent_id,
            limit,
            offset,
        )
        .await?;
        Ok(serde_json::to_value(entries)?)
    }

    async fn handle_conversation_hook(
        &self,
        args: ConversationHookArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences_namespace = args.conversation_namespace.clone();
        let scope = self.resolve_conversation_scope(
            args.project_root.clone(),
            args.repo_path.clone(),
            args.conversation_namespace.clone(),
        )?;
        let conversations = scope.conversations();
        let has_messages = args
            .messages
            .as_ref()
            .map(|items| !items.is_empty())
            .unwrap_or(false);
        let has_transcript = args
            .transcript_text
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_some();
        let has_summary = args
            .summary_text
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .is_some();
        if !has_messages && !has_transcript && !has_summary {
            return Err(AppError::new(
                ERR_INVALID_ARGUMENT,
                "conversation hook requires transcript/messages or summary_text",
            )
            .into());
        }
        let source = args
            .source
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| format!("hook:{}", args.action.as_str()));
        if !conversations.config.allows_source(&source) {
            return Err(AppError::new(
                ERR_INVALID_ARGUMENT,
                "conversation source is blocked by memory.conversations source policy",
            )
            .into());
        }
        let wait_for_processing = args.wait_for_processing.unwrap_or(false);
        let payload = crate::conversations::ConversationHookPayload {
            action: args.action.clone(),
            source: Some(source),
            source_session_id: args.source_session_id,
            title: args.title,
            agent_id: args.agent_id.or_else(|| self.default_agent_id.clone()),
            transport: args.transport,
            started_at_ms: args.started_at_ms,
            ended_at_ms: args.ended_at_ms,
            format: args.format,
            messages: map_conversation_import_messages(args.messages),
            transcript_text: args.transcript_text,
            summary_text: args.summary_text,
            metadata: args.metadata.unwrap_or_else(|| json!({})),
        };
        let personal_preferences_capture = self
            .personal_preferences
            .as_ref()
            .filter(|personal_preferences| {
                crate::personal_preferences::should_capture_external_source(
                    &personal_preferences.config,
                    payload.source.as_deref().unwrap_or_default(),
                    personal_preferences.config.capture_conversation_hooks,
                )
            })
            .map(|personal_preferences| {
                (
                    personal_preferences.clone(),
                    build_personal_preferences_capture_request_from_hook(
                        &self.repo_root,
                        &scope,
                        personal_preferences_namespace.as_deref(),
                        &payload,
                    ),
                )
            });
        let route_targets = crate::conversations::build_conversation_route_targets(
            scope.repo_memory_target(),
            self.profile_state.as_ref().map(|profile| {
                crate::conversations::build_conversation_profile_target(
                    profile.manager.clone(),
                    profile.embedder.clone(),
                    "conversation_hook",
                )
            }),
            conversations.knowledge.clone(),
            conversations.config.graph.clone(),
            self.default_agent_id.clone(),
        );
        let result = crate::conversations::enqueue_conversation_hook(
            conversations.store.clone(),
            payload,
            crate::conversations::ConversationImportOptions {
                capture_kind: crate::conversations::ConversationCaptureKind::Auto,
                store_raw_messages: conversations.config.archive_raw_transcripts,
            },
            route_targets,
            wait_for_processing,
        )
        .await?;
        if let Some((personal_preferences, capture_request)) = personal_preferences_capture {
            personal_preferences.store.capture_conversation(
                capture_request,
                personal_preferences.config.digest_enabled,
                personal_preferences.config.archive_raw_conversations,
            )?;
        }
        Ok(serde_json::to_value(result)?)
    }

    async fn handle_wakeup(&self, args: WakeupArgs) -> Result<serde_json::Value> {
        let scope = self.resolve_conversation_scope(
            args.project_root.clone(),
            args.repo_path.clone(),
            args.conversation_namespace.clone(),
        )?;
        let conversations = scope.conversations();
        if matches!(args.max_tokens, Some(0)) {
            return Err(
                AppError::new(ERR_INVALID_ARGUMENT, "max_tokens must be greater than 0").into(),
            );
        }
        let max_tokens = args
            .max_tokens
            .unwrap_or(conversations.max_wakeup_tokens)
            .min(conversations.max_wakeup_tokens)
            .max(1);
        let agent_id = args
            .agent_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        let query = args
            .query
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        let store = conversations.store.clone();
        let knowledge = conversations.knowledge.clone();
        let conversation_config = conversations.config.clone();
        let summary_limit = conversations.max_episodic_summaries;
        let knowledge_limit = conversations.max_knowledge_facts;
        let snippet_limit = conversations.max_transcript_snippets;
        let bundle = tokio::task::spawn_blocking(move || {
            crate::conversations::assemble_wakeup_bundle(
                &store,
                &knowledge,
                &conversation_config,
                agent_id.as_deref(),
                query.as_deref(),
                summary_limit,
                knowledge_limit,
                snippet_limit,
            )
        })
        .await??;
        let (text, render_trace) = crate::conversations::render_wakeup_bundle(&bundle, max_tokens);
        metrics::global().record_conversation_wakeup(
            render_trace.selected > 0,
            render_trace.saved_tokens,
            render_trace.working_memory_tokens,
            render_trace.summary_tokens,
            render_trace.knowledge_tokens,
            render_trace.snippet_tokens,
        );
        Ok(json!({
            "text": text,
            "trace": {
                "budget_tokens": max_tokens,
                "available_items": render_trace.available,
                "selected_items": render_trace.selected,
                "truncated_items": render_trace.truncated,
                "summary_candidates": bundle.trace.summary_candidates,
                "kg_candidates": bundle.trace.kg_candidates,
                "graph_edge_candidates": bundle.trace.graph_edge_candidates,
                "graph_episode_candidates": bundle.trace.graph_episode_candidates,
                "graph_link_candidates": bundle.trace.graph_link_candidates,
                "snippet_candidates": bundle.trace.snippet_candidates,
                "startup_diary_candidates": bundle.trace.startup_diary_candidates,
                "startup_diary_selected": bundle.trace.startup_diary_selected,
                "available_tokens": render_trace.available_tokens,
                "selected_tokens": render_trace.selected_tokens,
                "saved_tokens": render_trace.saved_tokens,
                "working_memory_tokens": render_trace.working_memory_tokens,
                "summary_tokens": render_trace.summary_tokens,
                "knowledge_tokens": render_trace.knowledge_tokens,
                "snippet_tokens": render_trace.snippet_tokens,
            },
            "working_memory": bundle.working_memory,
            "episodic_summaries": bundle.episodic_summaries,
            "knowledge_facts": bundle.knowledge_facts,
            "knowledge_edges": bundle.knowledge_edges,
            "knowledge_episodes": bundle.knowledge_episodes,
            "knowledge_entity_links": bundle.knowledge_entity_links,
            "transcript_snippets": bundle.transcript_snippets,
        }))
    }

    fn update_conversation_archive_metric(&self, conversations: &McpConversationState) {
        let repo_total = crate::conversations::combined_archive_size_bytes(
            &conversations.store,
            &conversations.knowledge,
        );
        metrics::global().set_conversation_archive_size_bytes(
            crate::conversations::archive_size_bytes_total(
                repo_total,
                self.global_state_dir.as_deref(),
            ),
        );
    }

    fn personal_preferences_state(&self) -> Result<search::PersonalPreferencesState> {
        self.personal_preferences.clone().ok_or_else(|| {
            AppError::new(
                ERR_MEMORY_DISABLED,
                "personal preferences memory is disabled; enable [personal_preferences].enabled",
            )
            .into()
        })
    }

    async fn handle_personal_preferences_status(
        &self,
        _args: PersonalPreferencesStatusArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        Ok(serde_json::to_value(personal_preferences.store.status()?)?)
    }

    async fn handle_personal_preferences_categories(
        &self,
        _args: PersonalPreferencesCategoriesArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        Ok(serde_json::to_value(
            personal_preferences.store.list_categories()?,
        )?)
    }

    async fn handle_personal_preferences_list(
        &self,
        args: PersonalPreferencesListArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        Ok(serde_json::to_value(
            personal_preferences.store.list_captures(
                args.status.as_deref(),
                args.limit.unwrap_or(20).clamp(1, 200),
                args.offset.unwrap_or(0),
            )?,
        )?)
    }

    async fn handle_personal_preferences_read(
        &self,
        args: PersonalPreferencesReadArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        let capture_id = args.capture_id.trim().to_string();
        if capture_id.is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "capture_id must not be empty").into());
        }
        let Some(capture) = personal_preferences.store.read_capture(&capture_id)? else {
            return Err(AppError::new(
                ERR_INVALID_ARGUMENT,
                "personal preferences capture not found",
            )
            .into());
        };
        Ok(serde_json::to_value(capture)?)
    }

    async fn handle_personal_preferences_search(
        &self,
        args: PersonalPreferencesSearchArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        let query = args.query.trim().to_string();
        Ok(serde_json::to_value(
            personal_preferences.store.search_records_with_policy(
                &query,
                args.limit.unwrap_or(10).clamp(1, 100),
                args.include_sensitive.unwrap_or(true),
            )?,
        )?)
    }

    async fn handle_personal_preferences_reviews(
        &self,
        args: PersonalPreferencesReviewQueueArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        Ok(serde_json::to_value(
            personal_preferences.store.list_review_records(
                args.status.as_deref(),
                args.limit.unwrap_or(20).clamp(1, 200),
                args.offset.unwrap_or(0),
            )?,
        )?)
    }

    async fn handle_personal_preferences_review(
        &self,
        args: PersonalPreferencesReviewArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        Ok(serde_json::to_value(
            personal_preferences.store.review_record(
                args.record_id.trim(),
                args.verdict.trim(),
                args.notes.as_deref(),
            )?,
        )?)
    }

    async fn handle_personal_preferences_process(
        &self,
        args: PersonalPreferencesProcessArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        if !personal_preferences.config.digest_enabled {
            return Err(AppError::new(
                ERR_MEMORY_DISABLED,
                "personal preferences digest is disabled; enable [personal_preferences].digest_enabled",
            )
            .into());
        }
        let mut summary = crate::personal_preferences::process_pending_with_local_agents(
            &personal_preferences.store,
            self.global_state_dir.as_deref(),
            &self.llm_config,
            &personal_preferences.config,
            args.limit,
        )
        .await?;
        if let Some(profile_state) = self.profile_state.as_ref() {
            summary.projected_profile_preferences =
                crate::personal_preferences::project_safe_preferences_to_profile(
                    &personal_preferences.store,
                    &profile_state.manager,
                    profile_state.embedder.as_ref(),
                    &personal_preferences.config,
                    self.default_agent_id.as_deref(),
                )
                .await?;
        }
        Ok(serde_json::to_value(summary)?)
    }

    async fn handle_personal_preferences_scan(
        &self,
        args: PersonalPreferencesScanArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        if !personal_preferences
            .config
            .capture_supported_client_transcripts
        {
            return Err(AppError::new(
                ERR_MEMORY_DISABLED,
                "supported client transcript capture is disabled; enable [personal_preferences].capture_supported_client_transcripts",
            )
            .into());
        }
        if matches!(args.limit, Some(0)) {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "limit must be > 0").into());
        }
        Ok(serde_json::to_value(
            personal_preferences
                .store
                .scan_supported_client_transcripts(&personal_preferences.config, args.limit)?,
        )?)
    }

    async fn handle_personal_preferences_export(
        &self,
        args: PersonalPreferencesExportArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        if !personal_preferences.config.export_enabled {
            return Err(AppError::new(
                ERR_MEMORY_DISABLED,
                "personal preferences export is disabled; enable [personal_preferences].export_enabled",
            )
            .into());
        }
        Ok(serde_json::to_value(
            personal_preferences
                .store
                .export_bundle(args.capture_id.as_deref())?,
        )?)
    }

    async fn handle_personal_preferences_redact(
        &self,
        args: PersonalPreferencesDeleteArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        Ok(serde_json::to_value(
            personal_preferences
                .store
                .redact_capture(args.capture_id.trim())?,
        )?)
    }

    async fn handle_personal_preferences_delete(
        &self,
        args: PersonalPreferencesDeleteArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        Ok(serde_json::to_value(
            personal_preferences
                .store
                .delete_capture(args.capture_id.trim())?,
        )?)
    }

    async fn handle_personal_preferences_prune(
        &self,
        args: PersonalPreferencesPruneArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        Ok(serde_json::to_value(
            personal_preferences.store.prune_retention(
                args.raw_retention_days
                    .unwrap_or(personal_preferences.config.raw_retention_days),
                args.derived_retention_days
                    .unwrap_or(personal_preferences.config.derived_retention_days),
                args.apply.unwrap_or(false),
            )?,
        )?)
    }

    async fn handle_personal_preferences_purge(
        &self,
        args: PersonalPreferencesPurgeArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        if !personal_preferences.config.purge_enabled {
            return Err(AppError::new(
                ERR_MEMORY_DISABLED,
                "personal preferences purge is disabled; enable [personal_preferences].purge_enabled",
            )
            .into());
        }
        Ok(serde_json::to_value(
            personal_preferences
                .store
                .purge_all(args.include_exports.unwrap_or(false))?,
        )?)
    }

    async fn handle_personal_preferences_claims(
        &self,
        args: PersonalPreferencesClaimsArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        Ok(serde_json::to_value(
            personal_preferences.store.list_claims(
                crate::personal_preferences::PersonalPreferencesClaimsQuery {
                    query: args
                        .query
                        .map(|value| value.trim().to_string())
                        .filter(|value| !value.is_empty()),
                    truth_status: args
                        .truth_status
                        .map(|value| value.trim().to_string())
                        .filter(|value| !value.is_empty()),
                    claim_origin: args
                        .claim_origin
                        .map(|value| value.trim().to_string())
                        .filter(|value| !value.is_empty()),
                    include_sensitive: args.include_sensitive.unwrap_or(false),
                    limit: args.limit,
                    offset: args.offset,
                },
            )?,
        )?)
    }

    async fn handle_personal_preferences_claim_read(
        &self,
        args: PersonalPreferencesClaimReadArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        let claim_id = args.claim_id.trim().to_string();
        if claim_id.is_empty() {
            return Err(AppError::new(ERR_INVALID_ARGUMENT, "claim_id must not be empty").into());
        }
        let Some(claim) = personal_preferences.store.read_claim(&claim_id)? else {
            return Err(
                AppError::new(ERR_INVALID_ARGUMENT, "personal preference claim not found").into(),
            );
        };
        Ok(serde_json::to_value(claim)?)
    }

    async fn handle_personal_preferences_claim_review(
        &self,
        args: PersonalPreferencesClaimReviewArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        Ok(serde_json::to_value(
            personal_preferences.store.review_claim(
                args.claim_id.trim(),
                args.verdict.trim(),
                args.notes.as_deref(),
            )?,
        )?)
    }

    async fn handle_personal_preferences_claim_override(
        &self,
        args: PersonalPreferencesClaimOverrideArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        Ok(serde_json::to_value(
            personal_preferences.store.override_claim(
                args.claim_id.trim(),
                args.value.trim(),
                args.notes.as_deref(),
            )?,
        )?)
    }

    async fn handle_personal_preferences_claim_forget(
        &self,
        args: PersonalPreferencesClaimForgetArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        Ok(serde_json::to_value(
            personal_preferences
                .store
                .forget_claim(args.claim_id.trim(), args.notes.as_deref())?,
        )?)
    }

    async fn handle_personal_preferences_feedback(
        &self,
        args: PersonalPreferencesFeedbackArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        Ok(serde_json::to_value(
            personal_preferences.store.add_feedback_event(
                args.event_type.trim(),
                args.claim_id
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty()),
                args.capture_id
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty()),
                args.category
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty()),
                args.attribute
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty()),
                args.value
                    .as_deref()
                    .map(str::trim)
                    .filter(|value| !value.is_empty()),
                args.notes.as_deref(),
                args.metadata.unwrap_or(serde_json::Value::Null),
            )?,
        )?)
    }

    async fn handle_personal_preferences_snapshots(
        &self,
        args: PersonalPreferencesSnapshotsArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        Ok(serde_json::to_value(
            personal_preferences.store.list_snapshots(
                args.limit.unwrap_or(20).clamp(1, 200),
                args.offset.unwrap_or(0),
            )?,
        )?)
    }

    async fn handle_personal_preferences_snapshot_read(
        &self,
        args: PersonalPreferencesSnapshotReadArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        let snapshot_id = args.snapshot_id.trim().to_string();
        if snapshot_id.is_empty() {
            return Err(
                AppError::new(ERR_INVALID_ARGUMENT, "snapshot_id must not be empty").into(),
            );
        }
        let Some(snapshot) = personal_preferences.store.read_snapshot(&snapshot_id)? else {
            return Err(AppError::new(
                ERR_INVALID_ARGUMENT,
                "personal preference snapshot not found",
            )
            .into());
        };
        Ok(serde_json::to_value(snapshot)?)
    }

    async fn handle_personal_preferences_snapshots_rebuild(&self) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        Ok(serde_json::to_value(
            personal_preferences.store.rebuild_snapshots()?,
        )?)
    }

    async fn handle_clone_context(
        &self,
        args: PersonalPreferencesCloneArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        Ok(serde_json::to_value(
            personal_preferences.store.build_clone_context_pack(
                args.query.trim(),
                crate::personal_preferences::PersonalPreferencesCloneOptions {
                    mode: args
                        .mode
                        .map(|value| value.trim().to_string())
                        .filter(|value| !value.is_empty()),
                    allow_sensitive: args.allow_sensitive.unwrap_or(false),
                    current_repo_root: args
                        .current_repo_root
                        .map(|value| value.trim().to_string())
                        .filter(|value| !value.is_empty()),
                    max_records: args.max_records,
                    budget_tokens: args.budget_tokens,
                },
            )?,
        )?)
    }

    async fn handle_clone_explain(
        &self,
        args: PersonalPreferencesCloneArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        Ok(serde_json::to_value(
            personal_preferences.store.explain_clone_context(
                args.query.trim(),
                crate::personal_preferences::PersonalPreferencesCloneOptions {
                    mode: args
                        .mode
                        .map(|value| value.trim().to_string())
                        .filter(|value| !value.is_empty()),
                    allow_sensitive: args.allow_sensitive.unwrap_or(false),
                    current_repo_root: args
                        .current_repo_root
                        .map(|value| value.trim().to_string())
                        .filter(|value| !value.is_empty()),
                    max_records: args.max_records,
                    budget_tokens: args.budget_tokens,
                },
            )?,
        )?)
    }

    async fn handle_clone_evaluate(
        &self,
        args: PersonalPreferencesCloneArgs,
    ) -> Result<serde_json::Value> {
        let personal_preferences = self.personal_preferences_state()?;
        Ok(serde_json::to_value(
            personal_preferences.store.evaluate_clone_context(
                args.query.trim(),
                crate::personal_preferences::PersonalPreferencesCloneOptions {
                    mode: args
                        .mode
                        .map(|value| value.trim().to_string())
                        .filter(|value| !value.is_empty()),
                    allow_sensitive: args.allow_sensitive.unwrap_or(false),
                    current_repo_root: args
                        .current_repo_root
                        .map(|value| value.trim().to_string())
                        .filter(|value| !value.is_empty()),
                    max_records: args.max_records,
                    budget_tokens: args.budget_tokens,
                },
            )?,
        )?)
    }

    async fn handle_profile_save_preference(
        &self,
        args: ProfileSaveArgs,
    ) -> Result<serde_json::Value> {
        let agent_id = args
            .agent_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .or_else(|| self.default_agent_id.as_deref());
        let content = args.content.trim();
        let category = args.category.trim().to_ascii_lowercase();
        if agent_id.is_none() || content.is_empty() || category.is_empty() {
            return Err(AppError::new(
                ERR_INVALID_ARGUMENT,
                "agent_id, content, and category are required",
            )
            .into());
        }
        if !matches!(
            category.as_str(),
            "style" | "tooling" | "constraint" | "workflow"
        ) {
            return Err(AppError::new(
                ERR_INVALID_ARGUMENT,
                "category must be one of: style, tooling, constraint, workflow",
            )
            .into());
        }
        let payload = json!({
            "agent_id": agent_id.unwrap(),
            "content": content,
            "category": category,
            "role": args.role,
        });
        self.call_profile_endpoint(Method::POST, "/v1/profile/save", None, Some(payload))
            .await
    }

    async fn handle_profile_get_profile(&self, args: ProfileGetArgs) -> Result<serde_json::Value> {
        let agent_id = args
            .agent_id
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .or_else(|| self.default_agent_id.as_deref());
        let query = agent_id.map(|value| vec![("agent_id", value.to_string())]);
        self.call_profile_endpoint(Method::GET, "/v1/profile/list", query, None)
            .await
    }

    async fn call_profile_endpoint(
        &self,
        method: Method,
        path: &str,
        query: Option<Vec<(&str, String)>>,
        body: Option<Value>,
    ) -> Result<Value> {
        let base_url = resolve_docdexd_base_url()?;
        let client = docdexd_http_client()?;
        let url = format!(
            "{}/{}",
            base_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        );
        let mut req = client.request(method, url);
        let token = self
            .auth_token
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| value.to_string())
            .or_else(|| env_non_empty("DOCDEX_AUTH_TOKEN"));
        if let Some(token) = token {
            req = req.header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"));
        }
        if let Some(query) = query.as_ref() {
            req = req.query(query);
        }
        if let Some(body) = body {
            req = req.json(&body);
        }
        let resp = req.send().await.context("profile HTTP request failed")?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(AppError::new(
                ERR_INTERNAL_ERROR,
                format!("profile request failed ({status}): {text}"),
            )
            .into());
        }
        let payload = serde_json::from_str(&text).context("parse profile response")?;
        Ok(payload)
    }

    async fn call_index_endpoint(&self, path: &str, body: Value) -> Result<Value> {
        let base_url = resolve_docdexd_base_url()?;
        let client = docdexd_http_client()?;
        let url = format!(
            "{}/{}",
            base_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        );
        let mut req = client.request(Method::POST, url).json(&body);
        let token = self
            .auth_token
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| value.to_string())
            .or_else(|| env_non_empty("DOCDEX_AUTH_TOKEN"));
        if let Some(token) = token {
            req = req.header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let resp = req.send().await.context("index HTTP request failed")?;
        let status = resp.status();
        let text = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(AppError::new(
                ERR_INTERNAL_ERROR,
                format!("index request failed ({status}): {text}"),
            )
            .into());
        }
        let payload = serde_json::from_str(&text).context("parse index response")?;
        Ok(payload)
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
            project_root: self.default_project_root.clone(),
            repo_path: None,
            start_line: None,
            end_line: None,
            clamp: None,
            head: None,
        };
        self.handle_open(open_args).await
    }

    fn ensure_same_repo(&self, candidate: &Path) -> Result<()> {
        if !candidate.exists() {
            let normalized_path = candidate.to_string_lossy().replace('\\', "/");
            let details = repo_resolution_details(
                normalized_path,
                None,
                Some(self.repo_root.to_string_lossy().replace('\\', "/")),
                vec![
                    "Repo may have moved or been renamed.".to_string(),
                    "Pass the current repo path in `project_root` (or `repo_path`).".to_string(),
                    "Ensure your MCP client is pointing at the daemon serving the repo you want."
                        .to_string(),
                ],
            );
            return Err(AppError::new(ERR_MISSING_REPO_PATH, "repo path not found")
                .with_details(details)
                .into());
        }

        let normalized = candidate
            .canonicalize()
            .unwrap_or_else(|_| candidate.to_path_buf());
        if normalized != self.repo_root {
            let attempted_fingerprint =
                crate::repo_manager::repo_fingerprint_sha256(&normalized).ok();
            let details = repo_resolution_details(
                normalized.to_string_lossy().replace('\\', "/"),
                attempted_fingerprint,
                Some(self.repo_root.to_string_lossy().replace('\\', "/")),
                vec![
                    "Repo may have moved or been renamed.".to_string(),
                    "Ensure your MCP client is connected to the daemon serving the repo you want to use."
                        .to_string(),
                    "Pass `project_root` (or `repo_path`) matching the repo the MCP session is bound to.".to_string(),
                ],
            );
            return Err(AppError::new(ERR_UNKNOWN_REPO, "unknown repo")
                .with_details(details)
                .into());
        }

        Ok(())
    }

    fn resolve_project_root_arg(
        &self,
        project_root: Option<PathBuf>,
        repo_path: Option<PathBuf>,
    ) -> Result<Option<PathBuf>> {
        match (project_root, repo_path) {
            (Some(project_root), Some(repo_path)) => {
                let normalized_project = project_root
                    .canonicalize()
                    .unwrap_or_else(|_| project_root.clone());
                let normalized_repo = repo_path
                    .canonicalize()
                    .unwrap_or_else(|_| repo_path.clone());
                if normalized_project != normalized_repo {
                    let details = json!({
                        "project_root": project_root.to_string_lossy().replace('\\', "/"),
                        "repo_path": repo_path.to_string_lossy().replace('\\', "/"),
                    });
                    return Err(AppError::new(
                        ERR_INVALID_ARGUMENT,
                        "project_root and repo_path must match",
                    )
                    .with_details(details)
                    .into());
                }
                Ok(Some(project_root))
            }
            (Some(project_root), None) => Ok(Some(project_root)),
            (None, Some(repo_path)) => Ok(Some(repo_path)),
            (None, None) => Ok(None),
        }
    }

    fn resolve_conversation_scope(
        &self,
        project_root: Option<PathBuf>,
        repo_path: Option<PathBuf>,
        conversation_namespace: Option<String>,
    ) -> Result<McpConversationScope> {
        let project_root = self.resolve_project_root_arg(project_root, repo_path)?;
        let namespace = conversation_namespace
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        if project_root.is_some() && namespace.is_some() {
            return Err(AppError::new(
                ERR_INVALID_ARGUMENT,
                "project_root/repo_path and conversation_namespace are mutually exclusive",
            )
            .with_details(json!({
                "hint": "Use project_root/repo_path for repo-scoped conversation memory or conversation_namespace for the explicit global namespace.",
            }))
            .into());
        }
        if let Some(namespace) = namespace {
            return Ok(McpConversationScope::Namespace {
                conversations: self.build_namespace_conversation_state(&namespace)?,
            });
        }
        self.ensure_project_root(project_root.as_deref())?;
        let Some(conversations) = self.conversations.clone() else {
            return Err(AppError::new(
                ERR_MEMORY_DISABLED,
                "conversation memory is disabled; enable [memory.conversations].enabled",
            )
            .into());
        };
        Ok(McpConversationScope::Repo {
            repo_id: self.repo_id.clone(),
            conversations,
            memory: self.memory.clone(),
        })
    }

    fn build_namespace_conversation_state(&self, namespace: &str) -> Result<McpConversationState> {
        let trimmed = namespace.trim();
        if trimmed.is_empty() {
            return Err(AppError::new(
                ERR_INVALID_ARGUMENT,
                "conversation_namespace must not be empty",
            )
            .into());
        }
        let Some(template) = self.conversations.as_ref() else {
            return Err(AppError::new(
                ERR_MEMORY_DISABLED,
                "conversation memory is disabled; enable [memory.conversations].enabled",
            )
            .into());
        };
        let base_state_dir = self
            .global_state_dir
            .clone()
            .or_else(|| {
                crate::repo_manager::split_scoped_state_dir(self.indexer.state_dir())
                    .map(|(base_dir, _, _)| base_dir)
            })
            .ok_or_else(|| {
                AppError::new(
                    ERR_INTERNAL_ERROR,
                    "conversation namespace requires a shared global state directory",
                )
                .with_details(json!({
                    "conversation_namespace": trimmed,
                    "hint": "Start the daemon with a shared global state dir so repo-less conversation namespaces have an isolated home.",
                }))
            })?;
        let config = template.config.clone();
        Ok(McpConversationState {
            store: crate::conversations::ConversationStore::for_namespace(&base_state_dir, trimmed),
            knowledge: crate::knowledge::KnowledgeStore::for_namespace(&base_state_dir, trimmed),
            max_wakeup_tokens: config.max_wakeup_tokens,
            max_episodic_summaries: config.max_episodic_summaries,
            max_knowledge_facts: config.max_knowledge_facts,
            max_transcript_snippets: config.max_transcript_snippets,
            config,
        })
    }

    fn ensure_project_root(&self, candidate: Option<&Path>) -> Result<()> {
        let path = match candidate {
            Some(path) => path,
            None => {
                let Some(default_root) = self.default_project_root.as_deref() else {
                    let details = json!({
                        "recoverySteps": [
                            "Pass the repo path as `project_root` (or `repo_path`) in tool arguments.",
                            "Call initialize with `workspace_root` to set a default project_root.",
                            "Ensure your MCP client is pointing at the daemon serving the repo you want."
                        ]
                    });
                    return Err(AppError::new(ERR_MISSING_REPO, "missing repo")
                        .with_details(details)
                        .into());
                };
                default_root
            }
        };
        self.ensure_same_repo(path)
    }

    async fn ensure_index_ready(&self) -> Result<()> {
        crate::index::ensure_indexed(self.indexer.clone()).await?;
        Ok(())
    }
}

fn resolve_open_range(
    total_lines: usize,
    start_line: Option<usize>,
    end_line: Option<usize>,
    head: Option<usize>,
    clamp: bool,
) -> Result<(usize, usize), InvalidRangeError> {
    let mut start = start_line.unwrap_or(1).max(1);
    let mut end = end_line.unwrap_or(total_lines);
    let mut clamp = clamp;

    if let Some(head) = head {
        start = 1;
        end = head.max(1);
        clamp = true;
    }

    if clamp {
        if total_lines == 0 {
            return Ok((0, 0));
        }
        if start > total_lines {
            start = total_lines;
        }
        if end > total_lines {
            end = total_lines;
        }
        if end < start {
            end = start;
        }
        return Ok((start, end));
    }

    if end < start || start > total_lines || end > total_lines {
        return Err(InvalidRangeError {
            start_line: start,
            end_line: end,
            total_lines,
        });
    }
    Ok((start, end))
}

fn docdexd_http_client() -> Result<Client> {
    let timeout_ms = env_u64("DOCDEX_HTTP_TIMEOUT_MS").unwrap_or(30_000);
    let client = Client::builder()
        .timeout(Duration::from_millis(timeout_ms.max(1)))
        .build()
        .context("build docdexd http client")?;
    Ok(client)
}

fn resolve_docdexd_base_url() -> Result<String> {
    if let Some(raw) = env_non_empty("DOCDEX_HTTP_BASE_URL") {
        return Ok(normalize_base_url(&raw));
    }
    let config = config::AppConfig::load_default()?;
    let bind_addr = config.server.http_bind_addr.trim();
    if bind_addr.is_empty() {
        return Err(anyhow::anyhow!(
            "server.http_bind_addr is empty; set it in ~/.docdex/config.toml"
        ));
    }
    Ok(normalize_base_url(bind_addr))
}

fn normalize_base_url(raw: &str) -> String {
    let trimmed = raw.trim_end_matches('/');
    if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("http://{trimmed}")
    }
}

fn env_non_empty(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn env_u64(key: &str) -> Option<u64> {
    env_non_empty(key)?.parse::<u64>().ok()
}

fn is_lock_busy(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
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

fn resolve_tree_root(repo_root: &Path, path: Option<&str>) -> Result<PathBuf> {
    let root = repo_root
        .canonicalize()
        .with_context(|| format!("resolve repo root {}", repo_root.display()))?;
    let candidate = match path.map(str::trim) {
        None | Some("") | Some(".") => root.clone(),
        Some(value) => {
            let rel = normalize_rel_path(value).ok_or(InvalidPathError)?;
            root.join(rel)
        }
    };
    let canonical = candidate
        .canonicalize()
        .with_context(|| format!("resolve tree path {}", candidate.display()))?;
    if !canonical.starts_with(&root) {
        return Err(PathOutsideRepoError.into());
    }
    Ok(canonical)
}

fn queue_dag_log(
    repo_state_root: &Path,
    session_id: &str,
    node_type: &'static str,
    payload: serde_json::Value,
) {
    let repo_state_root = repo_state_root.to_path_buf();
    let session_id = session_id.to_string();
    tokio::spawn(async move {
        let session_id_log = session_id.clone();
        let result = tokio::task::spawn_blocking(move || {
            dag_logging::log_node(&repo_state_root, &session_id, node_type, &payload)
        })
        .await;
        if let Err(err) = result {
            warn!(
                session_id = %session_id_log,
                error = %err,
                "docdex mcp: dag log task failed"
            );
        } else if let Ok(Err(err)) = result {
            warn!(
                session_id = %session_id_log,
                error = %err,
                "docdex mcp: dag log failed"
            );
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::collections::HashSet;
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::Duration;

    #[test]
    fn rate_limited_rpc_has_stable_data_shape() {
        let err = RateLimited::new(
            Duration::from_millis(0),
            "mcp_tools".to_string(),
            "global".to_string(),
        );
        let rpc = rpc_rate_limited(&err);
        assert_eq!(rpc.code, ERR_RATE_LIMITED_RPC);
        let data = rpc.data.expect("rate limited rpc should include data");
        let obj = data
            .as_object()
            .expect("rate limited data should be object");
        assert_eq!(
            obj.get("code").and_then(|v| v.as_str()),
            Some(ERR_RATE_LIMITED)
        );
        assert_eq!(obj.get("retry_after_ms").and_then(|v| v.as_u64()), Some(0));
        assert_eq!(
            obj.get("limit_key").and_then(|v| v.as_str()),
            Some("mcp_tools")
        );
        assert_eq!(obj.get("scope").and_then(|v| v.as_str()), Some("global"));
        assert!(
            obj.get("retry_at").is_none(),
            "retry_at should be omitted when unset"
        );
    }

    #[test]
    fn rate_limited_rpc_truncates_long_message_and_allows_retry_at() {
        let err = RateLimited::new(
            Duration::from_millis(1234),
            "bucket".to_string(),
            "global".to_string(),
        )
        .with_message("x".repeat(10_000))
        .with_retry_at(Utc::now());
        let rpc = rpc_rate_limited(&err);
        assert!(
            rpc.message.len() <= MAX_ERROR_MESSAGE_BYTES + "…".len(),
            "rpc error message should be bounded"
        );
        let data = rpc.data.expect("rate limited rpc should include data");
        let obj = data
            .as_object()
            .expect("rate limited data should be object");
        assert!(obj.get("retry_at").and_then(|v| v.as_str()).is_some());
        assert_eq!(
            obj.get("retry_after_ms").and_then(|v| v.as_u64()),
            Some(1234)
        );
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
                limiter.check_or_rate_limited((), "mcp_tools", "global")
            }));
        }

        let mut rate_limited_count = 0usize;
        let mut schema_variants: HashSet<Vec<String>> = HashSet::new();
        for handle in handles {
            match handle.join().expect("thread panicked") {
                Ok(()) => {}
                Err(err) => {
                    rate_limited_count += 1;
                    let rpc = rpc_rate_limited(&err);
                    assert_eq!(rpc.code, ERR_RATE_LIMITED_RPC);
                    assert!(
                        rpc.message.len() <= MAX_ERROR_MESSAGE_BYTES + "…".len(),
                        "rpc error message should remain bounded"
                    );
                    let data = rpc
                        .data
                        .as_ref()
                        .expect("rate limited rpc should include data");
                    let obj = data
                        .as_object()
                        .expect("rate limited data should be object");
                    let mut keys: Vec<String> = obj.keys().cloned().collect();
                    keys.sort();
                    schema_variants.insert(keys);

                    assert_eq!(
                        obj.get("code").and_then(|v| v.as_str()),
                        Some(ERR_RATE_LIMITED)
                    );
                    assert!(
                        obj.get("retry_after_ms").and_then(|v| v.as_u64()).is_some(),
                        "retry_after_ms must be an integer"
                    );
                    assert_eq!(
                        obj.get("limit_key").and_then(|v| v.as_str()),
                        Some("mcp_tools")
                    );
                    assert_eq!(obj.get("scope").and_then(|v| v.as_str()), Some("global"));

                    let payload_bytes =
                        serde_json::to_vec(&rpc).expect("rpc error should serialize");
                    assert!(
                        payload_bytes.len() <= 2048,
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
    fn open_range_clamps_end_when_enabled() {
        let (start, end) =
            resolve_open_range(10, Some(1), Some(25), None, true).expect("clamped range");
        assert_eq!(start, 1);
        assert_eq!(end, 10);
    }

    #[test]
    fn open_range_head_clamps_to_file() {
        let (start, end) = resolve_open_range(5, None, None, Some(20), false).expect("head range");
        assert_eq!(start, 1);
        assert_eq!(end, 5);
    }

    #[test]
    fn open_range_errors_without_clamp() {
        let err = resolve_open_range(5, Some(1), Some(10), None, false)
            .expect_err("expected invalid range");
        assert_eq!(err.start_line, 1);
        assert_eq!(err.end_line, 10);
        assert_eq!(err.total_lines, 5);
    }

    #[test]
    fn initialize_params_accept_agent_model_aliases() {
        let params: InitializeParams = serde_json::from_value(serde_json::json!({
            "agentId": "codex",
            "agentModel": "gpt-5.2-codex"
        }))
        .expect("initialize params should parse");
        assert_eq!(params.agent_id.as_deref(), Some("codex"));
        assert_eq!(params.agent_model.as_deref(), Some("gpt-5.2-codex"));

        let snake_case: InitializeParams = serde_json::from_value(serde_json::json!({
            "agent_id": "codex",
            "agent_model": "gpt-5.2-codex"
        }))
        .expect("snake_case initialize params should parse");
        assert_eq!(snake_case.agent_model.as_deref(), Some("gpt-5.2-codex"));
    }
}
