use crate::error::{
    AppError, RateLimited, ERR_BACKOFF_REQUIRED, ERR_EMBEDDING_FAILED, ERR_EMBEDDING_MODEL_NOT_FOUND,
    ERR_EMBEDDING_TIMEOUT, ERR_INTERNAL_ERROR, ERR_INVALID_ARGUMENT, ERR_MEMORY_DISABLED,
    repo_resolution_details, ERR_MISSING_DEPENDENCY, ERR_MISSING_INDEX, ERR_MISSING_REPO,
    ERR_MISSING_REPO_PATH, ERR_RATE_LIMITED, ERR_REPO_STATE_MISMATCH, ERR_STALE_INDEX, ERR_UNKNOWN_REPO,
};
use crate::index::{IndexConfig, Indexer};
use crate::libs;
use crate::memory::{inject_embedding_metadata, MemoryStore};
use crate::ollama::OllamaEmbedder;
use crate::ratelimit::RateLimiter;
use crate::search;
use crate::symbols::SymbolsStore;
use anyhow::{Context, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::json;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;
use tantivy::directory::error::LockError;
use tantivy::TantivyError;
use thiserror::Error;
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};

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
const OPEN_MAX_BYTES: usize = 512 * 1024; // guard rail for returning file content
const MAX_ERROR_MESSAGE_BYTES: usize = 256;
const MAX_ERROR_REASON_BYTES: usize = 768;

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
#[error("symbol extraction is disabled; re-run with --enable-symbol-extraction=true (or set DOCDEX_ENABLE_SYMBOL_EXTRACTION=1) and reindex")]
struct MissingSymbolsDependencyError;

#[derive(Error, Debug)]
#[error("no symbols record found for {rel_path}; run docdex_index")]
struct MissingSymbolsIndexError {
    rel_path: String,
}

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
    if let Some(reason) = reason.clone().map(|value| truncate_bytes(value, MAX_ERROR_REASON_BYTES)) {
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

fn mcp_rate_limited_details(err: &RateLimited) -> serde_json::Value {
    #[derive(Serialize)]
    struct RateLimitData<'a> {
        retry_after_ms: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        retry_at: Option<String>,
        limit_key: &'a str,
        scope: &'a str,
    }

    serde_json::to_value(RateLimitData {
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

fn rpc_rate_limited(err: &RateLimited, tool: Option<&str>) -> RpcError {
    let message = default_message_for_code(ERR_RATE_LIMITED);
    let reason = if err.message.trim() == message {
        None
    } else {
        Some(err.message.clone())
    };
    rpc_error(
        ERR_RATE_LIMITED_RPC,
        message,
        ERR_RATE_LIMITED,
        reason,
        tool,
        Some(mcp_rate_limited_details(err)),
    )
}

fn rpc_tool_error(err: &anyhow::Error, tool: Option<&str>) -> RpcError {
    if let Some(rate) = err.downcast_ref::<RateLimited>() {
        return rpc_rate_limited(rate, tool);
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
        ERR_STALE_INDEX => "stale index",
        ERR_MISSING_DEPENDENCY => "missing dependency",
        ERR_RATE_LIMITED => "rate limited",
        ERR_BACKOFF_REQUIRED => "backoff required",
        ERR_REPO_STATE_MISMATCH => "repo state mismatch",
        ERR_INTERNAL_ERROR => "internal error",
        _ => "error",
    }
}

fn classify_tool_error(err: &anyhow::Error) -> (&'static str, Option<serde_json::Value>) {
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
    if err.downcast_ref::<MissingSymbolsDependencyError>().is_some() {
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

fn invalid_params_error(
    err: serde_json::Error,
    tool: Option<&str>,
    details: serde_json::Value,
) -> RpcError {
    rpc_error(
        ERR_INVALID_PARAMS,
        default_message_for_code("invalid_params"),
        "invalid_params",
        Some(err.to_string()),
        tool,
        Some(details),
    )
}

fn parse_method_params<T: DeserializeOwned>(
    params: serde_json::Value,
    method: &'static str,
) -> Result<T, RpcError> {
    serde_json::from_value(params).map_err(|err| {
        invalid_params_error(err, None, json!({ "validation": "serde", "method": method }))
    })
}

fn parse_tool_args<T: DeserializeOwned>(
    args: serde_json::Value,
    tool: &'static str,
) -> Result<T, RpcError> {
    serde_json::from_value(args).map_err(|err| {
        invalid_params_error(err, Some(tool), json!({ "validation": "serde", "tool": tool }))
    })
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
}

#[derive(Deserialize)]
struct IndexArgs {
    #[serde(default)]
    paths: Vec<PathBuf>,
    #[serde(default)]
    project_root: Option<PathBuf>,
}

#[derive(Deserialize)]
struct StatsArgs {
    #[serde(default)]
    project_root: Option<PathBuf>,
}

#[derive(Deserialize)]
struct RepoInspectArgs {
    #[serde(default)]
    project_root: Option<PathBuf>,
}

#[derive(Deserialize)]
struct FilesArgs {
    #[serde(default)]
    project_root: Option<PathBuf>,
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
    #[serde(default)]
    start_line: Option<usize>,
    #[serde(default)]
    end_line: Option<usize>,
}

#[derive(Deserialize)]
struct SymbolsArgs {
    path: String,
    #[serde(default)]
    project_root: Option<PathBuf>,
}

#[derive(Deserialize)]
struct MemoryStoreArgs {
    text: String,
    #[serde(default)]
    metadata: Option<serde_json::Value>,
    #[serde(default)]
    project_root: Option<PathBuf>,
}

#[derive(Deserialize)]
struct MemoryRecallArgs {
    query: String,
    #[serde(default)]
    top_k: Option<usize>,
    #[serde(default)]
    project_root: Option<PathBuf>,
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
) -> Result<()> {
    let repo_root = repo_root
        .canonicalize()
        .context("resolve repo root for MCP server")?;
    // Try to open with a writer; if the index is already locked (another docdexd
    // instance is indexing), fall back to read-only so search/open still work.
    let indexer = match Indexer::with_config(repo_root.clone(), index_config.clone()) {
        Ok(ix) => ix,
        Err(err) if is_lock_busy(&err) => {
            eprintln!(
                "docdex mcp: index writer is busy; opening read-only (disable other docdexd to enable indexing)"
            );
            Indexer::with_config_read_only(repo_root.clone(), index_config)?
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
            store: MemoryStore::new(indexer.state_dir()),
            embedder: OllamaEmbedder::new(base_url, model, Duration::from_millis(timeout_ms))?,
        })
    } else {
        None
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
    let libs_indexer = libs::LibsIndexer::open_read_only(libs::libs_state_dir_from_index_state_dir(
        indexer.state_dir(),
    ))
    .ok()
    .flatten();
    let mut server = McpServer {
        repo_root,
        indexer,
        libs_indexer,
        max_results: max_results.max(1),
        default_project_root: None,
        memory,
        tool_rate_limit,
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
    max_results: usize,
    default_project_root: Option<PathBuf>,
    memory: Option<McpMemoryState>,
    tool_rate_limit: Option<RateLimiter<()>>,
}

impl McpServer {
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
                let protocol_version = init_params
                    .protocol_version
                    .unwrap_or_else(|| "2024-11-05".to_string());
                let instructions = "Use docdex_search to find repo-local docs before changing code.\nUse docdex_index to refresh the index if results seem stale.";
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
                let params =
                    match parse_method_params::<ResourceReadParams>(
                        req.params.clone().unwrap_or_default(),
                        "resources/read",
                    ) {
                        Ok(params) => params,
                        Err(err) => {
                            return Ok(Some(RpcResponse {
                                jsonrpc: JSONRPC_VERSION,
                                id: id.clone(),
                                result: None,
                                error: Some(err),
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
                let params = match parse_method_params::<ToolCallParams>(
                    req.params.clone().unwrap_or_default(),
                    "tools/call",
                ) {
                    Ok(params) => params,
                    Err(err) => {
                        return Ok(Some(RpcResponse {
                            jsonrpc: JSONRPC_VERSION,
                            id: id.clone(),
                            result: None,
                            error: Some(err),
                        }))
                    }
                };
                if let Some(limiter) = self.tool_rate_limit.as_ref() {
                    if let Err(err) = limiter.check_or_rate_limited((), "mcp_tools", "global") {
                        return Ok(Some(RpcResponse {
                            jsonrpc: JSONRPC_VERSION,
                            id: id.clone(),
                            result: None,
                            error: Some(rpc_rate_limited(&err, Some(params.name.as_str()))),
                        }));
                    }
                }
                let result = match params.name.as_str() {
                    "docdex_search" | "docdex.search" => {
                        let args = match parse_tool_args::<SearchArgs>(
                            params.arguments.clone(),
                            "docdex_search",
                        ) {
                            Ok(args) => args,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(err),
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
                    "docdex_index" | "docdex.index" => {
                        let args = match parse_tool_args::<IndexArgs>(
                            params.arguments.clone(),
                            "docdex_index",
                        ) {
                            Ok(args) => args,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(err),
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
                        let args = match parse_tool_args::<FilesArgs>(
                            params.arguments.clone(),
                            "docdex_files",
                        ) {
                            Ok(args) => args,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(err),
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
                        let args = match parse_tool_args::<OpenArgs>(
                            params.arguments.clone(),
                            "docdex_open",
                        ) {
                            Ok(args) => args,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(err),
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
                        let args = match parse_tool_args::<StatsArgs>(
                            params.arguments.clone(),
                            "docdex_stats",
                        ) {
                            Ok(args) => args,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(err),
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
                        let args = match parse_tool_args::<RepoInspectArgs>(
                            params.arguments.clone(),
                            "docdex_repo_inspect",
                        ) {
                            Ok(args) => args,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(err),
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
                        let args = match parse_tool_args::<SymbolsArgs>(
                            params.arguments.clone(),
                            "docdex_symbols",
                        ) {
                            Ok(args) => args,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(err),
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
                        let args = match parse_tool_args::<MemoryStoreArgs>(
                            params.arguments.clone(),
                            "docdex_memory_store",
                        ) {
                            Ok(args) => args,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(err),
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
                        let args = match parse_tool_args::<MemoryRecallArgs>(
                            params.arguments.clone(),
                            "docdex_memory_recall",
                        ) {
                            Ok(args) => args,
                            Err(err) => {
                                return Ok(Some(RpcResponse {
                                    jsonrpc: JSONRPC_VERSION,
                                    id: id.clone(),
                                    result: None,
                                    error: Some(err),
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
                                        "docdex_index",
                                        "docdex_files",
                                    "docdex_open",
                                    "docdex_stats",
                                    "docdex_repo_inspect",
                                    "docdex_symbols",
                                    "docdex_memory_store",
                                    "docdex_memory_recall"
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
                description:
                    "Search repository docs and return hits with rel_path, summary, snippet, and doc_id.",
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "query": { "type": "string", "minLength": 1, "description": "Concise search query (will be rejected if empty)" },
                        "limit": { "type": "integer", "minimum": 1, "maximum": self.max_results as i64, "default": self.max_results, "description": "Max results to return (clamped to server max)" },
                        "project_root": { "type": "string", "description": "Optional repo root; must match the MCP server repo" }
                    },
                    "required": ["query"]
                }),
            },
            ToolDefinition {
                name: "docdex_index",
                description:
                    "Rebuild the index (or ingest specific files) for the current repo root.",
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "paths": {
                            "type": "array",
                            "items": { "type": "string" },
                            "description": "Optional list of files to ingest; empty => full reindex"
                        },
                        "project_root": { "type": "string", "description": "Optional repo root; must match the MCP server repo" }
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
                        "limit": { "type": "integer", "minimum": 1, "maximum": FILES_MAX_LIMIT as i64, "default": FILES_DEFAULT_LIMIT, "description": "Max documents to return (clamped)" },
                        "offset": { "type": "integer", "minimum": 0, "maximum": FILES_MAX_OFFSET as i64, "default": 0, "description": "Number of docs to skip before listing (clamped)" }
                    }
                }),
            },
            ToolDefinition {
                name: "docdex_open",
                description:
                    "Read a file from the repo (optional line window); rejects paths outside the repo.",
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "minLength": 1, "description": "Relative path under the repo" },
                        "project_root": { "type": "string", "description": "Optional repo root; must match the MCP server repo" },
                        "start_line": { "type": "integer", "minimum": 1, "description": "Optional start line (1-based, inclusive)" },
                        "end_line": { "type": "integer", "minimum": 1, "description": "Optional end line (1-based, inclusive)" }
                    },
                    "required": ["path"]
                }),
            },
            ToolDefinition {
                name: "docdex_stats",
                description:
                    "Inspect index metadata: doc count, state dir, size on disk, and last update time.",
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "project_root": { "type": "string", "description": "Optional repo root; must match the MCP server repo" }
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
                        "project_root": { "type": "string", "description": "Optional repo root; must match the MCP server repo" }
                    }
                }),
            },
            ToolDefinition {
                name: "docdex_symbols",
                description: "Read the symbol extraction result for a file, including per-file outcome (ok/skipped/failed).",
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string", "minLength": 1, "description": "Relative path under the repo" },
                        "project_root": { "type": "string", "description": "Optional repo root; must match the MCP server repo" }
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
                        "project_root": { "type": "string", "description": "Optional repo root; must match the MCP server repo" }
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
                        "top_k": { "type": "integer", "minimum": 1, "maximum": 50, "default": 5, "description": "Max results to return" },
                        "project_root": { "type": "string", "description": "Optional repo root; must match the MCP server repo" }
                    },
                    "required": ["query"]
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

    async fn handle_search(&self, args: SearchArgs) -> Result<serde_json::Value> {
        self.ensure_project_root(args.project_root.as_deref())?;
        let query = args.query.trim();
        let limit = args
            .limit
            .unwrap_or(self.max_results)
            .clamp(1, self.max_results);
        let hits =
            search::run_query(&self.indexer, self.libs_indexer.as_ref(), query, limit).await?;
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
            query: None,
            context_assembly: None,
        });
        meta.repo_root = project_root_path.clone();
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

    async fn handle_index(&mut self, args: IndexArgs) -> Result<serde_json::Value> {
        self.ensure_project_root(args.project_root.as_deref())?;
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
            "paths": ingested.into_iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
            "decisions": decisions,
            "project_root": self
                .default_project_root
                .as_ref()
                .unwrap_or(&self.repo_root)
                .display()
                .to_string(),
        }))
    }

    async fn handle_files(&self, args: FilesArgs) -> Result<serde_json::Value> {
        self.ensure_project_root(args.project_root.as_deref())?;
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
        self.ensure_project_root(args.project_root.as_deref())?;
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
        self.ensure_project_root(args.project_root.as_deref())?;
        let report = crate::repo_identity::inspect_repo(
            &self.repo_root,
            Some(self.indexer.config().state_dir()),
        )?;
        Ok(serde_json::to_value(&report).context("serialize docdex_repo_inspect")?)
    }

    async fn handle_open(&self, args: OpenArgs) -> Result<serde_json::Value> {
        self.ensure_project_root(args.project_root.as_deref())?;
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

    async fn handle_symbols(&self, args: SymbolsArgs) -> Result<serde_json::Value> {
        self.ensure_project_root(args.project_root.as_deref())?;
        if !self.indexer.config().symbols_enabled() {
            return Err(MissingSymbolsDependencyError.into());
        }
        let rel_path = normalize_rel_path(&args.path)
            .ok_or(InvalidPathError)?;
        let rel_str = rel_path.to_string_lossy().replace('\\', "/");
        let store = SymbolsStore::new(self.indexer.repo_root(), self.indexer.config().state_dir())
            .context("open symbols store")?;
        let payload = store
            .read_symbols(&rel_str)?
            .ok_or_else(|| MissingSymbolsIndexError {
                rel_path: rel_str.to_string(),
            })?;
        Ok(serde_json::to_value(payload).context("serialize symbols payload")?)
    }

    async fn handle_memory_store(&self, args: MemoryStoreArgs) -> Result<serde_json::Value> {
        self.ensure_project_root(args.project_root.as_deref())?;
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
        let embedding = memory.embedder.embed(query).await?;

        let store = memory.store.clone();
        let items = tokio::task::spawn_blocking(move || store.recall(&embedding, top_k)).await??;
        Ok(json!({
            "top_k": top_k,
            "results": items.into_iter().map(|item| json!({
                "content": item.content,
                "score": item.score,
                "metadata": item.metadata
            })).collect::<Vec<_>>()
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
                    "Pass the current repo path (or omit `project_root` to use the MCP server default)."
                        .to_string(),
                    "If the MCP server is pointed at the wrong path, restart it with `docdexd mcp --repo <repo>`."
                        .to_string(),
                ],
            );
            return Err(
                AppError::new(ERR_MISSING_REPO_PATH, "repo path not found")
                    .with_details(details)
                    .into(),
            );
        }

        let normalized = candidate.canonicalize().unwrap_or_else(|_| candidate.to_path_buf());
        if normalized != self.repo_root {
            let attempted_fingerprint = crate::repo_identity::repo_fingerprint_sha256(&normalized).ok();
            let details = repo_resolution_details(
                normalized.to_string_lossy().replace('\\', "/"),
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
    }

    fn ensure_project_root(&self, candidate: Option<&Path>) -> Result<()> {
        if let Some(path) = candidate {
            return self.ensure_same_repo(path);
        }
        if let Some(default_root) = self.default_project_root.as_ref() {
            return self.ensure_same_repo(default_root);
        }
        Ok(())
    }
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
        let err = RateLimited::new(Duration::from_millis(0), "mcp_tools".to_string(), "global".to_string());
        let rpc = rpc_rate_limited(&err, None);
        assert_eq!(rpc.code, ERR_RATE_LIMITED_RPC);
        let data = rpc.data.expect("rate limited rpc should include data");
        let obj = data.as_object().expect("rate limited data should be object");
        assert_eq!(obj.get("code").and_then(|v| v.as_str()), Some(ERR_RATE_LIMITED));
        assert_eq!(
            obj.get("message").and_then(|v| v.as_str()),
            Some(default_message_for_code(ERR_RATE_LIMITED))
        );
        let details = obj
            .get("details")
            .and_then(|v| v.as_object())
            .expect("rate limited data should include details");
        assert_eq!(details.get("retry_after_ms").and_then(|v| v.as_u64()), Some(0));
        assert_eq!(details.get("limit_key").and_then(|v| v.as_str()), Some("mcp_tools"));
        assert_eq!(details.get("scope").and_then(|v| v.as_str()), Some("global"));
        assert!(details.get("retry_at").is_none(), "retry_at should be omitted when unset");
        let nested = obj
            .get("error")
            .and_then(|v| v.as_object())
            .expect("rate limited data should include nested error");
        assert_eq!(nested.get("code").and_then(|v| v.as_str()), Some(ERR_RATE_LIMITED));
    }

    #[test]
    fn rate_limited_rpc_truncates_long_message_and_allows_retry_at() {
        let err = RateLimited::new(Duration::from_millis(1234), "bucket".to_string(), "global".to_string())
            .with_message("x".repeat(10_000))
            .with_retry_at(Utc::now());
        let rpc = rpc_rate_limited(&err, None);
        assert_eq!(
            rpc.message,
            default_message_for_code(ERR_RATE_LIMITED),
            "rpc error message should be stable for rate limits"
        );
        let data = rpc.data.expect("rate limited rpc should include data");
        let obj = data.as_object().expect("rate limited data should be object");
        let reason = obj
            .get("reason")
            .and_then(|v| v.as_str())
            .expect("rate limited error should include reason when message is customized");
        assert!(
            reason.len() <= MAX_ERROR_REASON_BYTES + "…".len(),
            "rpc error reason should be bounded"
        );
        let details = obj
            .get("details")
            .and_then(|v| v.as_object())
            .expect("rate limited data should include details");
        assert!(details.get("retry_at").and_then(|v| v.as_str()).is_some());
        assert_eq!(details.get("retry_after_ms").and_then(|v| v.as_u64()), Some(1234));
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
                    let rpc = rpc_rate_limited(&err, None);
                    assert_eq!(rpc.code, ERR_RATE_LIMITED_RPC);
                    assert!(
                        rpc.message == default_message_for_code(ERR_RATE_LIMITED),
                        "rpc error message should remain stable"
                    );
                    let data = rpc.data.as_ref().expect("rate limited rpc should include data");
                    let obj = data.as_object().expect("rate limited data should be object");
                    let details = obj
                        .get("details")
                        .and_then(|v| v.as_object())
                        .expect("rate limited data should include details");
                    let mut keys: Vec<String> = details.keys().cloned().collect();
                    keys.sort();
                    schema_variants.insert(keys);

                    assert_eq!(
                        obj.get("code").and_then(|v| v.as_str()),
                        Some(ERR_RATE_LIMITED)
                    );
                    assert_eq!(
                        obj.get("message").and_then(|v| v.as_str()),
                        Some(default_message_for_code(ERR_RATE_LIMITED))
                    );
                    assert_eq!(
                        details.get("limit_key").and_then(|v| v.as_str()),
                        Some("mcp_tools")
                    );
                    assert!(
                        details.get("retry_after_ms").and_then(|v| v.as_u64()).is_some(),
                        "retry_after_ms must be an integer"
                    );
                    assert_eq!(details.get("scope").and_then(|v| v.as_str()), Some("global"));

                    let payload_bytes = serde_json::to_vec(&rpc).expect("rpc error should serialize");
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
}
