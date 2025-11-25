use crate::index::{IndexConfig, Indexer};
use crate::search;
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fs;
use std::path::{Component, Path, PathBuf};
use tantivy::directory::error::LockError;
use tantivy::TantivyError;
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};

const JSONRPC_VERSION: &str = "2.0";
const ERR_PARSE: i32 = -32700;
const ERR_INVALID_REQUEST: i32 = -32600;
const ERR_METHOD_NOT_FOUND: i32 = -32601;
const ERR_INVALID_PARAMS: i32 = -32602;
const ERR_INTERNAL: i32 = -32000;
const FILES_DEFAULT_LIMIT: usize = 200;
const FILES_MAX_LIMIT: usize = 1000;
const FILES_MAX_OFFSET: usize = 50_000;
const OPEN_MAX_BYTES: usize = 512 * 1024; // guard rail for returning file content

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
    let mut server = McpServer {
        repo_root,
        indexer,
        max_results: max_results.max(1),
        default_project_root: None,
    };
    server.run().await
}

struct McpServer {
    repo_root: PathBuf,
    indexer: Indexer,
    max_results: usize,
    default_project_root: Option<PathBuf>,
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
                    if !trimmed.is_empty() {
                        eprintln!("docdex mcp: recv -> {}", trimmed);
                    }
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
                                error: Some(RpcError {
                                    code: ERR_PARSE,
                                    message: format!("invalid JSON: {err}"),
                                    data: None,
                                }),
                            };
                            write_response(&mut writer, &resp).await?;
                            continue;
                        }
                    };
                    let resp_opt = match self.handle(req).await {
                        Ok(resp) => resp,
                        Err(err) => Some(RpcResponse {
                            jsonrpc: JSONRPC_VERSION,
                            id: serde_json::Value::Null,
                            result: None,
                            error: Some(RpcError {
                                code: ERR_INTERNAL,
                                message: format!("internal error"),
                                data: Some(json!({ "reason": err.to_string() })),
                            }),
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
                    error: Some(RpcError {
                        code: ERR_INVALID_REQUEST,
                        message: format!("unsupported jsonrpc version: {version}"),
                        data: Some(json!({ "expected": JSONRPC_VERSION })),
                    }),
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
                            if canon == self.repo_root {
                                self.default_project_root = Some(canon);
                            } else {
                                eprintln!(
                                    "docdex mcp: workspace root mismatch; expected {}, got {} (continuing with server repo)",
                                    self.repo_root.display(),
                                    canon.display()
                                );
                            }
                        }
                        Err(err) => {
                            eprintln!("docdex mcp: workspace root not usable: {err} (continuing with server repo)");
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
                let params_res: Result<ResourceReadParams, _> =
                    serde_json::from_value(req.params.clone().unwrap_or_default());
                let params = match params_res {
                    Ok(p) => p,
                    Err(err) => {
                        return Ok(Some(RpcResponse {
                            jsonrpc: JSONRPC_VERSION,
                            id: id.clone(),
                            result: None,
                            error: Some(RpcError {
                                code: ERR_INVALID_PARAMS,
                                message: "invalid resources/read params".to_string(),
                                data: Some(json!({ "reason": err.to_string() })),
                            }),
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
                        error: Some(RpcError {
                            code: ERR_INVALID_PARAMS,
                            message: "resources/read failed".to_string(),
                            data: Some(json!({ "reason": err.to_string() })),
                        }),
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
                            error: Some(RpcError {
                                code: ERR_INVALID_PARAMS,
                                message: "invalid tool call params".to_string(),
                                data: Some(json!({ "reason": err.to_string() })),
                            }),
                        }))
                    }
                };
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
                                    error: Some(RpcError {
                                        code: ERR_INVALID_PARAMS,
                                        message: "invalid docdex_search args".to_string(),
                                        data: Some(json!({ "reason": err.to_string() })),
                                    }),
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
                                    error: Some(RpcError {
                                        code: ERR_INVALID_PARAMS,
                                        message: "docdex_search failed".to_string(),
                                        data: Some(json!({ "reason": err.to_string() })),
                                    }),
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
                                    error: Some(RpcError {
                                        code: ERR_INVALID_PARAMS,
                                        message: "invalid docdex_index args".to_string(),
                                        data: Some(json!({ "reason": err.to_string() })),
                                    }),
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
                                    error: Some(RpcError {
                                        code: ERR_INVALID_PARAMS,
                                        message: "docdex_index failed".to_string(),
                                        data: Some(json!({ "reason": err.to_string() })),
                                    }),
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
                                    error: Some(RpcError {
                                        code: ERR_INVALID_PARAMS,
                                        message: "invalid docdex_files args".to_string(),
                                        data: Some(json!({ "reason": err.to_string() })),
                                    }),
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
                                    error: Some(RpcError {
                                        code: ERR_INVALID_PARAMS,
                                        message: "docdex_files failed".to_string(),
                                        data: Some(json!({ "reason": err.to_string() })),
                                    }),
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
                                    error: Some(RpcError {
                                        code: ERR_INVALID_PARAMS,
                                        message: "invalid docdex_open args".to_string(),
                                        data: Some(json!({ "reason": err.to_string() })),
                                    }),
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
                                    error: Some(RpcError {
                                        code: ERR_INVALID_PARAMS,
                                        message: "docdex_open failed".to_string(),
                                        data: Some(json!({ "reason": err.to_string() })),
                                    }),
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
                                    error: Some(RpcError {
                                        code: ERR_INVALID_PARAMS,
                                        message: "invalid docdex_stats args".to_string(),
                                        data: Some(json!({ "reason": err.to_string() })),
                                    }),
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
                                    error: Some(RpcError {
                                        code: ERR_INTERNAL,
                                        message: "docdex_stats failed".to_string(),
                                        data: Some(json!({ "reason": err.to_string() })),
                                    }),
                                }))
                            }
                        }
                    }
                    other => {
                        return Ok(Some(RpcResponse {
                            jsonrpc: JSONRPC_VERSION,
                            id: id.clone(),
                            result: None,
                            error: Some(RpcError {
                                code: ERR_METHOD_NOT_FOUND,
                                message: format!("unknown tool: {other}"),
                                data: Some(
                                    json!({ "known_tools": ["docdex_search", "docdex_index", "docdex_files", "docdex_open", "docdex_stats"] }),
                                ),
                            }),
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
                error: Some(RpcError {
                    code: ERR_METHOD_NOT_FOUND,
                    message: format!("unknown method: {other}"),
                    data: None,
                }),
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
        if query.is_empty() {
            return Err(anyhow!("query must not be empty"));
        }
        let limit = args
            .limit
            .unwrap_or(self.max_results)
            .clamp(1, self.max_results);
        let hits = search::run_query(&self.indexer, query, limit).await?;
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
        });
        meta.repo_root = project_root_path.clone();
        Ok(json!({
            "results": hits.hits,
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
        for path in args.paths {
            let resolved = if path.is_absolute() {
                path
            } else {
                self.repo_root.join(path)
            };
            self.indexer.ingest_file(resolved.clone()).await?;
            ingested.push(resolved);
        }
        Ok(json!({
            "status": "ok",
            "action": "ingest",
            "paths": ingested.into_iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
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

    async fn handle_open(&self, args: OpenArgs) -> Result<serde_json::Value> {
        self.ensure_project_root(args.project_root.as_deref())?;
        let rel_path = normalize_rel_path(&args.path)
            .ok_or_else(|| anyhow!("path must be relative and not contain parent components"))?;
        let abs_path = self.repo_root.join(&rel_path);
        let canonical = abs_path
            .canonicalize()
            .with_context(|| format!("resolve path {}", rel_path.display()))?;
        if !canonical.starts_with(&self.repo_root) {
            return Err(anyhow!("path must be under repo root"));
        }
        let content = fs::read_to_string(&canonical)
            .with_context(|| format!("read {}", rel_path.display()))?;
        if content.len() > OPEN_MAX_BYTES {
            return Err(anyhow!(
                "file too large ({} bytes > {} limit)",
                content.len(),
                OPEN_MAX_BYTES
            ));
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
        if end_raw < start {
            return Err(anyhow!("end_line must be >= start_line"));
        }
        if start > total_lines {
            return Err(anyhow!("start_line beyond file length"));
        }
        if end_raw > total_lines {
            return Err(anyhow!("end_line beyond file length"));
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

    async fn handle_resource_read(&self, params: ResourceReadParams) -> Result<serde_json::Value> {
        // Expect uri like docdex://path
        let uri = params.uri.trim();
        let prefix = "docdex://";
        if !uri.starts_with(prefix) {
            return Err(anyhow!("unsupported uri scheme"));
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
        let normalized = candidate.canonicalize().context("resolve project_root")?;
        if normalized != self.repo_root {
            return Err(anyhow!(
                "project_root mismatch (started for {}; got {})",
                self.repo_root.display(),
                normalized.display()
            ));
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
