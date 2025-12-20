use crate::index::{
    DocSnapshot, Hit, Indexer, SearchError, SearchQueryMeta, SnippetOrigin, SnippetResult,
};
use crate::error::{
    AppError, RateLimited, StartupError, ERR_EMBEDDING_FAILED, ERR_EMBEDDING_MODEL_NOT_FOUND,
    ERR_EMBEDDING_TIMEOUT, ERR_INTERNAL_ERROR, ERR_INVALID_ARGUMENT, ERR_MEMORY_DISABLED,
    ERR_RATE_LIMITED,
};
use crate::libs::LibsIndexer;
use crate::memory::{inject_embedding_metadata, MemoryStore};
use crate::ollama::OllamaEmbedder;
use crate::repo_manager::RepoManagerConfig;
use crate::ratelimit::RateLimiter;
use anyhow::Result;
use axum::body::HttpBody;
use axum::{
    extract::{ConnectInfo, Path, Query, RawQuery, State},
    http::{header::CONTENT_LENGTH, HeaderMap, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;
use tracing::warn;
use uuid::Uuid;

const DEFAULT_SNIPPET_WINDOW: usize = 40;
const MIN_SNIPPET_WINDOW: usize = 10;
const MAX_SNIPPET_WINDOW: usize = 400;
const MAX_RATE_LIMIT_MESSAGE_BYTES: usize = 256;

// Rate limiting is shared with MCP and other surfaces via crate::ratelimit.

#[derive(Clone)]
pub struct SecurityConfig {
    pub auth_token: Option<String>,
    pub allow_nets: Vec<ipnet::IpNet>,
    pub max_limit: usize,
    pub max_query_bytes: usize,
    pub max_request_bytes: usize,
    pub rate_limit: Option<RateLimiter<IpAddr>>,
    pub strip_snippet_html: bool,
    pub disable_snippet_text: bool,
}

impl SecurityConfig {
    pub fn from_options(
        token: Option<String>,
        allow_ips: &[String],
        max_limit: usize,
        max_query_bytes: usize,
        max_request_bytes: usize,
        rate_limit_per_min: u32,
        rate_limit_burst: u32,
        strip_snippet_html: bool,
        secure_mode: bool,
        disable_snippet_text: bool,
    ) -> Result<Self> {
        let mut allow_nets: Vec<ipnet::IpNet> = Vec::new();
        for raw in allow_ips.iter().map(|raw| raw.trim()).filter(|raw| !raw.is_empty()) {
            match raw.parse::<ipnet::IpNet>() {
                Ok(net) => allow_nets.push(net),
                Err(err) => {
                    return Err(StartupError::new(
                        "startup_config_invalid",
                        format!("invalid --allow-ip value `{raw}`: {err}"),
                    )
                    .with_hint("Expected an IP or CIDR, e.g. `127.0.0.1/32` or `10.0.0.0/8`.")
                    .into());
                }
            }
        }
        if secure_mode && allow_nets.is_empty() {
            allow_nets.push("127.0.0.0/8".parse()?);
            if let Ok(ipv6) = "::1/128".parse() {
                allow_nets.push(ipv6);
            }
        }
        let auth_token = token.filter(|value| !value.is_empty());
        if secure_mode && auth_token.is_none() {
            return Err(StartupError::new(
                "startup_auth_required",
                "secure mode requires an auth token",
            )
            .with_hint("Provide `--auth-token <token>` or disable with `--secure-mode=false` for local-only use.")
            .with_remediation(vec![
                "docdexd serve --repo . --host 127.0.0.1 --port 46137 --auth-token <token>".to_string(),
                "docdexd serve --repo . --host 127.0.0.1 --port 46137 --secure-mode=false".to_string(),
            ])
            .into());
        }
        let effective_per_min = if secure_mode && rate_limit_per_min == 0 {
            60
        } else {
            rate_limit_per_min
        };
        let effective_burst = if secure_mode && rate_limit_burst == 0 {
            effective_per_min
        } else {
            rate_limit_burst
        };
        let rate_limit = if effective_per_min > 0 {
            Some(RateLimiter::new(
                effective_per_min,
                if effective_burst == 0 {
                    effective_per_min
                } else {
                    effective_burst
                },
            ))
        } else {
            None
        };
        Ok(Self {
            auth_token,
            allow_nets,
            max_limit: max_limit.max(1),
            max_query_bytes,
            max_request_bytes,
            rate_limit,
            strip_snippet_html,
            disable_snippet_text,
        })
    }

    fn ip_allowed(&self, ip: IpAddr) -> bool {
        if self.allow_nets.is_empty() {
            return true;
        }
        self.allow_nets.iter().any(|net| net.contains(&ip))
    }

    fn auth_matches(&self, headers: &HeaderMap) -> bool {
        let Some(expected) = self.auth_token.as_ref() else {
            return true;
        };
        let Some(value) = headers.get(axum::http::header::AUTHORIZATION) else {
            return false;
        };
        let Ok(text) = value.to_str() else {
            return false;
        };
        let token = text
            .strip_prefix("Bearer ")
            .or_else(|| text.strip_prefix("bearer "))
            .unwrap_or(text);
        token == expected
    }
}

#[derive(Clone)]
pub struct AppState {
    pub indexer: Arc<Indexer>,
    pub libs_indexer: Option<Arc<LibsIndexer>>,
    pub security: SecurityConfig,
    pub access_log: bool,
    pub audit: Option<crate::audit::AuditLogger>,
    pub metrics: Arc<crate::metrics::Metrics>,
    pub memory: Option<MemoryState>,
    pub repo_manager_config: RepoManagerConfig,
}

#[derive(Clone)]
pub struct RequestId(pub String);

#[derive(Clone)]
pub struct MemoryState {
    pub store: MemoryStore,
    pub embedder: OllamaEmbedder,
}

pub fn router(state: AppState) -> Router {
    let mut router = Router::new()
        .route("/healthz", get(healthz))
        .route("/search", get(search_handler))
        .route("/snippet/*doc_id", get(snippet_handler))
        .route("/v1/graph/impact", get(impact_graph_handler))
        .route("/v1/memory/store", post(memory_store_handler))
        .route("/v1/memory/recall", post(memory_recall_handler))
        .route("/ai-help", get(ai_help_handler))
        .route("/metrics", get(metrics_handler))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            security_middleware,
        ));
    if state.access_log {
        router = router.layer(middleware::from_fn_with_state(
            state.clone(),
            access_log_middleware,
        ));
    }
    router.with_state(state)
}

async fn healthz() -> &'static str {
    "ok"
}

#[derive(Serialize)]
struct ImpactErrorResponse {
    error: ImpactErrorDetail,
}

#[derive(Serialize)]
struct ImpactErrorDetail {
    code: &'static str,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<serde_json::Value>,
}

fn invalid_argument_details(
    issues: Vec<crate::impact::InvalidFieldIssue>,
) -> crate::impact::InvalidArgumentDetails {
    crate::impact::InvalidArgumentDetails::new(issues)
}

fn invalid_argument_response(message: impl Into<String>, details: crate::impact::InvalidArgumentDetails) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(ImpactErrorResponse {
            error: ImpactErrorDetail {
                code: "invalid_argument",
                message: message.into(),
                details: Some(serde_json::to_value(details).unwrap_or_else(|_| json!({}))),
            },
        }),
    )
        .into_response()
}

fn push_issue(
    issues: &mut Vec<crate::impact::InvalidFieldIssue>,
    field: &'static str,
    code: &'static str,
    message: impl Into<String>,
) {
    issues.push(crate::impact::InvalidFieldIssue {
        field,
        code,
        message: message.into(),
    });
}

fn parse_i64_param(
    issues: &mut Vec<crate::impact::InvalidFieldIssue>,
    field: &'static str,
    raw: &str,
) -> Option<i64> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        push_issue(issues, field, "must_be_integer", format!("{field} must be an integer"));
        return None;
    }
    match trimmed.parse::<i64>() {
        Ok(value) => Some(value),
        Err(_) => {
            push_issue(issues, field, "must_be_integer", format!("{field} must be an integer"));
            None
        }
    }
}

fn parse_impact_graph_query(
    raw_query: Option<&str>,
) -> std::result::Result<(String, crate::impact::ImpactQueryControls), crate::impact::InvalidArgumentError>
{
    let mut issues: Vec<crate::impact::InvalidFieldIssue> = Vec::new();
    let mut file: Option<String> = None;
    let mut max_edges: Option<i64> = None;
    let mut max_depth: Option<i64> = None;
    let mut edge_types: Vec<String> = Vec::new();
    let mut edge_types_seen = false;

    let pairs = match raw_query {
        None => Vec::new(),
        Some(raw) if raw.is_empty() => Vec::new(),
        Some(raw) => match serde_urlencoded::from_str::<Vec<(String, String)>>(raw) {
            Ok(pairs) => pairs,
            Err(_) => {
                push_issue(
                    &mut issues,
                    "query",
                    "invalid_encoding",
                    "invalid query string encoding",
                );
                return Err(crate::impact::InvalidArgumentError {
                    details: invalid_argument_details(issues),
                });
            }
        },
    };

    for (key, value) in pairs {
        match key.as_str() {
            "file" => file = Some(value),
            "maxEdges" => max_edges = parse_i64_param(&mut issues, "maxEdges", &value),
            "maxDepth" => max_depth = parse_i64_param(&mut issues, "maxDepth", &value),
            "edgeTypes" => {
                edge_types_seen = true;
                for item in value.split(',') {
                    let trimmed = item.trim();
                    if trimmed.is_empty() {
                        push_issue(
                            &mut issues,
                            "edgeTypes",
                            "must_be_non_empty_string",
                            "edgeTypes entries must be non-empty strings",
                        );
                    } else {
                        edge_types.push(trimmed.to_string());
                    }
                }
            }
            _ => {}
        }
    }

    let source = file.unwrap_or_default();
    let source_trimmed = source.trim();
    if source_trimmed.is_empty() {
        push_issue(
            &mut issues,
            "file",
            "must_be_non_empty",
            "file must not be empty",
        );
    }

    if !issues.is_empty() {
        return Err(crate::impact::InvalidArgumentError {
            details: invalid_argument_details(issues),
        });
    }

    let raw_controls = crate::impact::ImpactQueryControlsRaw {
        max_edges,
        max_depth,
        edge_types: if edge_types_seen { Some(edge_types) } else { None },
    };
    let controls = raw_controls.validate()?;

    Ok((source_trimmed.to_string(), controls))
}

async fn impact_graph_handler(
    State(state): State<AppState>,
    RawQuery(raw): RawQuery,
) -> impl IntoResponse {
    let (source, controls) = match parse_impact_graph_query(raw.as_deref()) {
        Ok(value) => value,
        Err(err) => {
            let message = if err.details.issues.len() == 1 && err.details.field_errors.contains_key("file")
            {
                "file must not be empty"
            } else {
                "invalid query parameters"
            };
            return invalid_argument_response(message, err.details);
        }
    };

    let repo_id = crate::symbols::repo_id_for_root(state.indexer.repo_root())
        .unwrap_or_else(|_| String::new());
    let store = crate::impact::ImpactGraphStore::new(state.indexer.state_dir());
    let all_edges = match store.read_edges() {
        Ok(edges) => edges,
        Err(err) => {
            state.metrics.inc_error();
            warn!(target: "docdexd", error = ?err, "impact graph read failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ImpactErrorResponse {
                    error: ImpactErrorDetail {
                        code: "internal_error",
                        message: "impact graph unavailable".to_string(),
                        details: None,
                    },
                }),
            )
                .into_response();
        }
    };

    let traversal = crate::impact::traverse_impact(&source, &all_edges, &controls);
    let response = crate::impact::build_impact_response(&repo_id, &source, traversal, &controls);
    Json(response).into_response()
}

#[derive(Deserialize)]
struct MemoryStoreRequest {
    text: String,
    #[serde(default)]
    metadata: Option<serde_json::Value>,
}

#[derive(Serialize)]
struct MemoryStoreResponse {
    id: String,
    created_at: i64,
}

#[derive(Deserialize)]
struct MemoryRecallRequest {
    query: String,
    #[serde(default)]
    top_k: Option<usize>,
}

#[derive(Serialize)]
struct MemoryRecallResponse {
    results: Vec<MemoryRecallItem>,
}

#[derive(Serialize)]
struct MemoryRecallItem {
    content: String,
    score: f32,
    metadata: serde_json::Value,
}

fn status_for_app_error(code: &str) -> StatusCode {
    match code {
        ERR_EMBEDDING_TIMEOUT => StatusCode::GATEWAY_TIMEOUT,
        ERR_EMBEDDING_MODEL_NOT_FOUND => StatusCode::BAD_REQUEST,
        ERR_EMBEDDING_FAILED => StatusCode::BAD_GATEWAY,
        ERR_INVALID_ARGUMENT => StatusCode::BAD_REQUEST,
        ERR_MEMORY_DISABLED => StatusCode::CONFLICT,
        ERR_INTERNAL_ERROR => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn json_error(status: StatusCode, code: &'static str, message: impl Into<String>) -> Response {
    (
        status,
        Json(ErrorBody {
            error: ErrorDetail::new(code, message),
        }),
    )
        .into_response()
}

async fn memory_store_handler(
    State(state): State<AppState>,
    axum::extract::Extension(request_id): axum::extract::Extension<RequestId>,
    Json(req): Json<MemoryStoreRequest>,
) -> impl IntoResponse {
    let Some(memory) = state.memory.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            "memory is disabled; start the daemon with --enable-memory=true",
        );
    };
    let text = req.text.trim();
    if text.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, ERR_INVALID_ARGUMENT, "text must not be empty");
    }

    let embedding = match memory
        .embedder
        .embed(text)
        .await
    {
        Ok(value) => value,
        Err(err) => {
            let (code, status, message) = if let Some(app) = err.downcast_ref::<AppError>() {
                (app.code, status_for_app_error(app.code), app.message.clone())
            } else {
                (ERR_INTERNAL_ERROR, StatusCode::INTERNAL_SERVER_ERROR, "embedding failed".to_string())
            };
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                request_id = %request_id.0,
                error_code = %code,
                "memory_store embedding failed"
            );
            return json_error(status, code, message);
        }
    };

    let created_at = now_epoch_ms()
        .ok()
        .and_then(|ms| i64::try_from(ms).ok())
        .unwrap_or(0);
    let metadata = inject_embedding_metadata(
        req.metadata,
        memory.embedder.provider(),
        memory.embedder.model(),
    );
    let store = memory.store.clone();
    let text_owned = text.to_string();

    let write = tokio::task::spawn_blocking(move || store.store(&text_owned, &embedding, metadata, created_at))
        .await;
    match write {
        Ok(Ok((id, created_at))) => Json(MemoryStoreResponse {
            id: id.to_string(),
            created_at,
        })
        .into_response(),
        Ok(Err(err)) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                request_id = %request_id.0,
                error = ?err,
                "memory_store persistence failed"
            );
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "memory persistence failed",
            )
        }
        Err(err) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                request_id = %request_id.0,
                error = ?err,
                "memory_store task join failed"
            );
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "memory persistence failed",
            )
        }
    }
}

async fn memory_recall_handler(
    State(state): State<AppState>,
    axum::extract::Extension(request_id): axum::extract::Extension<RequestId>,
    Json(req): Json<MemoryRecallRequest>,
) -> impl IntoResponse {
    let Some(memory) = state.memory.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            "memory is disabled; start the daemon with --enable-memory=true",
        );
    };
    let query = req.query.trim();
    if query.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "query must not be empty",
        );
    }
    let top_k = req.top_k.unwrap_or(5).max(1).min(50);

    let query_embedding = match memory
        .embedder
        .embed(query)
        .await
    {
        Ok(value) => value,
        Err(err) => {
            let (code, status, message) = if let Some(app) = err.downcast_ref::<AppError>() {
                (app.code, status_for_app_error(app.code), app.message.clone())
            } else {
                (ERR_INTERNAL_ERROR, StatusCode::INTERNAL_SERVER_ERROR, "embedding failed".to_string())
            };
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                request_id = %request_id.0,
                error_code = %code,
                "memory_recall embedding failed"
            );
            return json_error(status, code, message);
        }
    };

    let store = memory.store.clone();
    let read = tokio::task::spawn_blocking(move || store.recall(&query_embedding, top_k)).await;
    match read {
        Ok(Ok(items)) => {
            let results = items
                .into_iter()
                .map(|item| MemoryRecallItem {
                    content: item.content,
                    score: item.score,
                    metadata: item.metadata,
                })
                .collect();
            Json(MemoryRecallResponse { results }).into_response()
        }
        Ok(Err(err)) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                request_id = %request_id.0,
                error = ?err,
                "memory_recall persistence failed"
            );
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "memory recall failed",
            )
        }
        Err(err) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                request_id = %request_id.0,
                error = ?err,
                "memory_recall task join failed"
            );
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "memory recall failed",
            )
        }
    }
}

async fn metrics_handler(State(state): State<AppState>) -> impl IntoResponse {
    state.metrics.render_prometheus()
}

#[derive(Serialize)]
struct AiHelpEndpoint {
    method: &'static str,
    path: &'static str,
    description: &'static str,
    params: &'static [&'static str],
}

#[derive(Serialize)]
struct AiHelpCli {
    command: &'static str,
    description: &'static str,
    example: &'static str,
}

#[derive(Serialize)]
struct AiHelpLimits {
    max_limit: usize,
    max_query_bytes: usize,
    max_request_bytes: usize,
    rate_limit_per_min: Option<u32>,
    auth_required: bool,
    snippet_html_disabled: bool,
}

#[derive(Serialize)]
struct AiHelpMcpTool {
    name: &'static str,
    description: &'static str,
    args: &'static [&'static str],
    returns: &'static [&'static str],
}

#[derive(Serialize)]
struct AiHelpPayload {
    product: &'static str,
    version: &'static str,
    purpose: &'static str,
    http_endpoints: Vec<AiHelpEndpoint>,
    cli_commands: Vec<AiHelpCli>,
    mcp_tools: Vec<AiHelpMcpTool>,
    best_practices: Vec<&'static str>,
    limits: AiHelpLimits,
    index_stats_fields: Vec<&'static str>,
}

fn rate_limit_hint(security: &SecurityConfig) -> Option<u32> {
    security.rate_limit.as_ref().map(|lim| lim.per_minute())
}

async fn ai_help_handler(State(state): State<AppState>) -> impl IntoResponse {
    let payload = AiHelpPayload {
        product: "Docdex",
        version: env!("CARGO_PKG_VERSION"),
        purpose: "Index local Markdown/text docs per-repo and serve search/snippets over HTTP or CLI for coding assistants.",
        http_endpoints: vec![
            AiHelpEndpoint {
                method: "GET",
                path: "/search",
                description: "Search docs; returns hits with summary/snippet.",
                params: &[
                    "q=<query>",
                    "limit=<n optional, defaults 8, clamped>",
                    "snippets=false (summary-only to save tokens)",
                    "max_tokens=<u64 optional, drop hits above token_estimate>",
                ],
            },
            AiHelpEndpoint {
                method: "GET",
                path: "/snippet/:doc_id",
                description: "Fetch a snippet for a given doc_id; optional highlighting.",
                params: &[
                    "window=<lines optional>",
                    "q=<query optional>",
                    "text_only=true (omit HTML to save tokens)",
                    "max_tokens=<u64 optional, omit snippet if doc exceeds budget>",
                ],
            },
            AiHelpEndpoint {
                method: "GET",
                path: "/v1/graph/impact",
                description: "Read per-file impact graph (inbound/outbound dependency edges).",
                params: &[
                    "file=<repo-relative path>",
                    "maxEdges=<int optional>",
                    "maxDepth=<int optional>",
                    "edgeTypes=<comma-separated optional>",
                ],
            },
            AiHelpEndpoint {
                method: "POST",
                path: "/v1/memory/store",
                description: "Store a memory item (requires --enable-memory=true).",
                params: &[],
            },
            AiHelpEndpoint {
                method: "POST",
                path: "/v1/memory/recall",
                description: "Recall memory items by semantic similarity (requires --enable-memory=true).",
                params: &[],
            },
            AiHelpEndpoint {
                method: "GET",
                path: "/healthz",
                description: "Liveness check (200 OK => ready).",
                params: &[],
            },
        ],
        cli_commands: vec![
            AiHelpCli {
                command: "docdexd index --repo <path>",
                description: "Build or rebuild the index for a repo.",
                example: "docdexd index --repo /workspace",
            },
            AiHelpCli {
                command: "docdexd serve --repo <path> [--host 127.0.0.1] [--port 46137]",
                description: "Serve HTTP API with watcher for incremental ingest.",
                example: "docdexd serve --repo /workspace --host 127.0.0.1 --port 46137",
            },
            AiHelpCli {
                command: "docdexd query --repo <path> --query \"text\" [--limit 8]",
                description: "Ad-hoc search via CLI (JSON to stdout).",
                example: "docdexd query --repo /workspace --query \"payment flow\" --limit 5",
            },
            AiHelpCli {
                command: "docdexd ingest --repo <path> --file <file>",
                description: "Reindex a single file (honors exclude flags).",
                example: "docdexd ingest --repo /workspace --file docs/new.md",
            },
            AiHelpCli {
                command: "docdexd self-check --repo <path> --terms \"foo,bar\"",
                description: "Scan index for sensitive terms; exits non-zero if found.",
                example: "docdexd self-check --repo /workspace --terms \"SECRET,API_KEY\"",
            },
        ],
        mcp_tools: vec![
            AiHelpMcpTool {
                name: "docdex_search",
                description: "Search docs; returns rel_path, summary, snippet, doc_id, token_estimate.",
                args: &["query (string, required)", "limit (int, optional, clamped)", "project_root (string, optional)"],
                returns: &["results[]", "repo_root", "state_dir", "limit"],
            },
            AiHelpMcpTool {
                name: "docdex_index",
                description: "Rebuild index or ingest specific files for the repo.",
                args: &["paths (array of file paths, empty => full reindex)", "project_root (string, optional)"],
                returns: &["status", "action", "paths?"],
            },
            AiHelpMcpTool {
                name: "docdex_files",
                description: "List indexed docs (rel_path/doc_id/summary/token_estimate) with pagination.",
                args: &["limit (int, optional, default 200, max 1000)", "offset (int, optional, default 0)", "project_root (string, optional)"],
                returns: &["results[]", "total", "limit", "offset", "repo_root"],
            },
            AiHelpMcpTool {
                name: "docdex_open",
                description: "Read a file from the repo; optional line range; rejects paths outside the repo.",
                args: &["path (string, required, relative)", "start_line (int, optional)", "end_line (int, optional)", "project_root (string, optional)"],
                returns: &["path", "start_line", "end_line", "total_lines", "content", "repo_root"],
            },
            AiHelpMcpTool {
                name: "docdex_stats",
                description: "Report index metadata.",
                args: &["project_root (string, optional)"],
                returns: &["num_docs", "state_dir", "index_size_bytes", "segments", "avg_bytes_per_doc", "generated_at_epoch_ms", "last_updated_epoch_ms", "repo_root"],
            },
            AiHelpMcpTool {
                name: "docdex_memory_store",
                description: "Store a memory item (requires DOCDEX_ENABLE_MEMORY=1).",
                args: &["text (string, required)", "metadata (object, optional)", "project_root (string, optional)"],
                returns: &["id", "created_at"],
            },
            AiHelpMcpTool {
                name: "docdex_memory_recall",
                description: "Recall memory items by semantic similarity (requires DOCDEX_ENABLE_MEMORY=1).",
                args: &["query (string, required)", "top_k (int, optional)", "project_root (string, optional)"],
                returns: &["results[]"],
            },
        ],
        best_practices: vec![
            "Prefer narrow queries (file names, headings, concepts) to keep snippets focused.",
            "Use /search to get doc_id, then /snippet/:doc_id for a larger window when needed.",
            "Use /search with snippets=false to read summaries first; only fetch 1-2 snippets you need.",
            "Keep q short; long query strings are rejected by max_query_bytes to save bandwidth/tokens.",
            "Respect the reported `token_estimate` to avoid oversized prompts.",
            "When running remote, set --auth-token and TLS (certbot or manual cert/key).",
            "Keep server logging minimal for agent pipelines (e.g., --log warn --access-log=false).",
            "Use state_dir per project to keep indexes isolated; run separate serve instances per repo.",
            "Use text_only=true on /snippet or --strip-snippet-html/--disable-snippet-text to trim payloads.",
            "When building prompts, keep rel_path + summary + trimmed snippet; drop score/token_estimate/doc_id and normalize whitespace.",
            "Trim noisy content up front with --exclude-dir/--exclude-prefix so snippets stay relevant and short.",
            "Cache doc_id/rel_path/summary client-side to avoid repeat snippet fetches; only call /snippet for new doc_ids.",
            "For MCP-aware agents, register a server named docdex that runs `docdexd mcp --repo <repo> --log warn --max-results 8`, then use docdex_search before edits and docdex_index when results look stale.",
        ],
        limits: AiHelpLimits {
            max_limit: state.security.max_limit,
            max_query_bytes: state.security.max_query_bytes,
            max_request_bytes: state.security.max_request_bytes,
            rate_limit_per_min: rate_limit_hint(&state.security),
            auth_required: state.security.auth_token.is_some(),
            snippet_html_disabled: state.security.disable_snippet_text || state.security.strip_snippet_html,
        },
        index_stats_fields: vec![
            "num_docs",
            "state_dir",
            "index_size_bytes",
            "segments",
            "avg_bytes_per_doc",
            "generated_at_epoch_ms",
            "last_updated_epoch_ms",
            "repo_root",
        ],
    };
    Json(payload)
}

#[derive(Deserialize)]
struct SearchParams {
    q: Option<String>,
    limit: Option<usize>,
    snippets: Option<bool>,
    max_tokens: Option<u64>,
    include_libs: Option<bool>,
}

#[derive(Serialize)]
pub struct SearchResponse {
    pub hits: Vec<Hit>,
    pub top_score: Option<f32>,
    #[serde(rename = "topScore")]
    pub top_score_camel: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<SearchMeta>,
}

#[derive(Serialize)]
pub struct SearchMeta {
    pub generated_at_epoch_ms: u128,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index_last_updated_epoch_ms: Option<u128>,
    pub repo_root: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<SearchQueryMeta>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context_assembly: Option<ContextAssemblyMeta>,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SnippetPolicy {
    Full,
    SummaryOnly,
    Disabled,
}

#[derive(Serialize)]
pub struct SelectedSourceMeta {
    pub doc_id: String,
    pub rel_path: String,
    pub score: f32,
    pub token_estimate: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet_origin: Option<crate::index::SearchSnippetOrigin>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet_truncated: Option<bool>,
}

#[derive(Serialize)]
pub struct PrunedHitMeta {
    pub doc_id: String,
    pub rel_path: String,
    pub score: f32,
    pub token_estimate: u64,
    pub reason: String,
}

#[derive(Serialize)]
pub struct ContextAssemblyMeta {
    pub requested_limit: Option<usize>,
    pub effective_limit: usize,
    pub snippet_policy: SnippetPolicy,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<u64>,
    pub token_budget_mode: &'static str,
    pub hits_before_pruning: usize,
    pub hits_after_pruning: usize,
    pub token_estimate_sum_kept: u64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub pruned: Vec<PrunedHitMeta>,
    pub selected_sources: Vec<SelectedSourceMeta>,
}

#[derive(Serialize)]
struct ErrorBody {
    error: ErrorDetail,
}

fn truncate_bytes(input: &str, max_bytes: usize) -> String {
    if input.len() <= max_bytes {
        return input.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !input.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = input[..end].to_string();
    out.push_str("…");
    out
}

#[derive(Serialize)]
struct ErrorDetail {
    code: &'static str,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_after_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    retry_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    limit_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scope: Option<String>,
}

impl ErrorDetail {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            retry_after_ms: None,
            retry_at: None,
            limit_key: None,
            scope: None,
        }
    }

    fn rate_limited(err: &RateLimited) -> Self {
        Self {
            code: ERR_RATE_LIMITED,
            message: truncate_bytes(&err.message, MAX_RATE_LIMIT_MESSAGE_BYTES),
            retry_after_ms: Some(err.retry_after_ms),
            retry_at: err.retry_at.as_ref().map(|at| at.to_rfc3339()),
            limit_key: Some(err.limit_key.clone()),
            scope: Some(err.scope.clone()),
        }
    }
}

#[cfg(test)]
mod rate_limit_contract_tests {
    use super::*;
    use chrono::Utc;
    use serde_json::Value;
    use std::time::Duration;

    #[test]
    fn http_rate_limited_error_truncates_message_and_bounds_payload() {
        let err = RateLimited::new(
            Duration::from_millis(1234),
            "http_ip".to_string(),
            "ip".to_string(),
        )
        .with_message("x".repeat(10_000))
        .with_retry_at(Utc::now());

        let body = ErrorBody {
            error: ErrorDetail::rate_limited(&err),
        };

        assert!(
            body.error.message.len() <= MAX_RATE_LIMIT_MESSAGE_BYTES + "…".len(),
            "rate-limit error message should be bounded"
        );

        let bytes = serde_json::to_vec(&body).expect("rate-limit error body should serialize");
        assert!(
            bytes.len() <= 1024,
            "rate-limit payload should remain small (got {} bytes)",
            bytes.len()
        );

        let json: Value = serde_json::from_slice(&bytes).expect("rate-limit body should parse");
        let error = json
            .get("error")
            .and_then(|v| v.as_object())
            .expect("rate-limit response should contain error object");

        assert_eq!(
            error.get("code").and_then(|v| v.as_str()),
            Some("rate_limited")
        );
        assert!(error
            .get("retry_after_ms")
            .and_then(|v| v.as_u64())
            .is_some());
        assert!(error.get("limit_key").and_then(|v| v.as_str()).is_some());
        assert!(error.get("scope").and_then(|v| v.as_str()).is_some());
    }
}

#[cfg(test)]
mod latency_perf_tests {
    use crate::{index, libs};
    use std::fs;
    use std::time::Instant;
    use tempfile::TempDir;

    fn percentile(sorted: &[u128], p: f64) -> u128 {
        if sorted.is_empty() {
            return 0;
        }
        let p = p.clamp(0.0, 1.0);
        let idx = ((p * ((sorted.len() - 1) as f64)).ceil() as usize).min(sorted.len() - 1);
        sorted[idx]
    }

    fn summarize(mut samples_us: Vec<u128>) -> (u128, u128, u128) {
        samples_us.sort_unstable();
        let p50 = percentile(&samples_us, 0.50);
        let p95 = percentile(&samples_us, 0.95);
        let max = *samples_us.last().unwrap_or(&0);
        (p50, p95, max)
    }

    /// NFR check: repo-only search p95 should remain under 50ms even when a libs index exists.
    /// See `docs/sds/sds.md` (latency: local search p95 < 50ms, < 20ms typical).
    #[tokio::test]
    #[ignore]
    async fn repo_only_search_p95_under_50ms_with_libs_index_present() -> anyhow::Result<()> {
        let repo = TempDir::new()?;
        let repo_root = repo.path();

        fs::write(
            repo_root.join("readme.md"),
            "# Repo\n\nThis repo contains REPO_NEEDLE_ABC.\n",
        )?;

        let docs_dir = repo_root.join("docs");
        fs::create_dir_all(&docs_dir)?;
        for i in 0..250usize {
            let body = if i % 9 == 0 {
                format!(
                    "# Doc {i}\n\nREPO_NEEDLE_ABC appears in this document.\n\nMore text.\n"
                )
            } else {
                format!("# Doc {i}\n\nFiller content for indexing.\n")
            };
            fs::write(docs_dir.join(format!("doc_{i}.md")), body)?;
        }

        let index_config =
            index::IndexConfig::with_overrides(repo_root, None, Vec::new(), Vec::new(), false)?;
        let indexer = index::Indexer::with_config(repo_root.to_path_buf(), index_config)?;
        indexer.reindex_all().await?;

        let libs_doc_path = repo_root.join("vendor").join("serde").join("README.md");
        fs::create_dir_all(libs_doc_path.parent().expect("libs doc parent"))?;
        fs::write(
            &libs_doc_path,
            "# Serde\n\nLIBS_ONLY_TERM_123 appears only in library docs.\n",
        )?;

        let libs_dir = libs::libs_state_dir_from_index_state_dir(indexer.state_dir());
        let libs_writer = libs::LibsIndexer::open_or_create(libs_dir.clone())?;
        let sources = [libs::LibSource {
            library: "serde".to_string(),
            version: Some("1.0.0".to_string()),
            source: "local_file".to_string(),
            path: libs_doc_path,
            title: Some("Serde".to_string()),
        }];
        let report = libs_writer.ingest_sources(&sources)?;
        drop(libs_writer);
        assert!(
            report.succeeded_sources >= 1,
            "expected libs ingestion to succeed (report: {})",
            serde_json::to_string(&report).unwrap_or_default()
        );
        let libs_indexer = libs::LibsIndexer::open_read_only(libs_dir)?.expect("libs indexer");

        let query = "REPO_NEEDLE_ABC";
        let limit = 8usize;
        for _ in 0..20usize {
            let _ = indexer.search_with_query_meta(query, limit)?;
            let _ = super::search_with_optional_libs(&indexer, Some(&libs_indexer), query, limit)?;
        }

        let iterations = 250usize;
        let mut repo_only_us = Vec::with_capacity(iterations);
        for _ in 0..iterations {
            let start = Instant::now();
            let _ = indexer.search_with_query_meta(query, limit)?;
            repo_only_us.push(start.elapsed().as_micros());
        }

        let mut combined_us = Vec::with_capacity(iterations);
        for _ in 0..iterations {
            let start = Instant::now();
            let _ = super::search_with_optional_libs(&indexer, Some(&libs_indexer), query, limit)?;
            combined_us.push(start.elapsed().as_micros());
        }

        let (repo_p50, repo_p95, repo_max) = summarize(repo_only_us);
        let (combined_p50, combined_p95, combined_max) = summarize(combined_us);

        eprintln!(
            "repo-only search: p50={}us p95={}us max={}us (libs index exists)",
            repo_p50, repo_p95, repo_max
        );
        eprintln!(
            "combined search:  p50={}us p95={}us max={}us (repo + libs)",
            combined_p50, combined_p95, combined_max
        );

        if cfg!(debug_assertions) {
            eprintln!(
                "note: perf assertions are enforced in release builds; re-run with `cargo test --release ... -- --ignored --nocapture`"
            );
            return Ok(());
        }

        assert!(
            repo_p95 < 50_000,
            "repo-only search p95 {}us exceeds 50ms (see docs/sds/sds.md)",
            repo_p95
        );

        Ok(())
    }
}

pub async fn run_query(
    indexer: &Indexer,
    libs_indexer: Option<&LibsIndexer>,
    query: &str,
    limit: usize,
) -> Result<SearchResponse> {
    let (hits, query_meta) = search_with_optional_libs(indexer, libs_indexer, query, limit)?;
    let top_score = hits.first().map(|hit| hit.score);
    Ok(SearchResponse {
        hits,
        top_score,
        top_score_camel: top_score,
        meta: Some(build_search_meta(indexer, Some(query_meta), None)?),
    })
}

fn search_with_optional_libs(
    indexer: &Indexer,
    libs_indexer: Option<&LibsIndexer>,
    query: &str,
    limit: usize,
) -> Result<(Vec<Hit>, SearchQueryMeta)> {
    let (repo_hits, query_meta) = indexer.search_with_query_meta(query, limit)?;
    let Some(libs) = libs_indexer else {
        return Ok((repo_hits, query_meta));
    };
    let libs_hits = match libs.search_with_query_meta(query, limit) {
        Ok((hits, _meta)) => hits,
        Err(err) => {
            warn!(target: "docdexd", error = ?err, "libs search failed; continuing with repo-only hits");
            Vec::new()
        }
    };
    Ok((merge_hits(repo_hits, libs_hits, limit), query_meta))
}

fn merge_hits(repo_hits: Vec<Hit>, libs_hits: Vec<Hit>, limit: usize) -> Vec<Hit> {
    if libs_hits.is_empty() {
        return repo_hits;
    }
    let repo_max = repo_hits.first().map(|h| h.score).unwrap_or(0.0).max(0.0001);
    let libs_max = libs_hits.first().map(|h| h.score).unwrap_or(0.0).max(0.0001);

    struct Ranked {
        rank: f32,
        hit: Hit,
    }

    let mut ranked: Vec<Ranked> = Vec::with_capacity(repo_hits.len() + libs_hits.len());
    for hit in repo_hits {
        ranked.push(Ranked {
            rank: (hit.score / repo_max) * 1.0,
            hit,
        });
    }
    for hit in libs_hits {
        ranked.push(Ranked {
            rank: (hit.score / libs_max) * 0.95,
            hit,
        });
    }
    ranked.sort_by(|a, b| {
        b.rank
            .partial_cmp(&a.rank)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.hit.doc_id.cmp(&b.hit.doc_id))
    });
    ranked.into_iter().take(limit).map(|r| r.hit).collect()
}

fn now_epoch_ms() -> Result<u128> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis())
}

fn build_search_meta(
    indexer: &Indexer,
    query: Option<SearchQueryMeta>,
    context_assembly: Option<ContextAssemblyMeta>,
) -> Result<SearchMeta> {
    let generated_at_epoch_ms = now_epoch_ms()?;
    let last_updated = indexer.stats().ok().and_then(|s| s.last_updated_epoch_ms);
    Ok(SearchMeta {
        generated_at_epoch_ms,
        index_last_updated_epoch_ms: last_updated,
        repo_root: indexer.repo_root().display().to_string(),
        query,
        context_assembly,
    })
}

async fn search_handler(
    State(state): State<AppState>,
    axum::extract::Extension(request_id): axum::extract::Extension<RequestId>,
    Query(params): Query<SearchParams>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(8).min(state.security.max_limit);
    let raw = match params.q.as_deref() {
        Some(value) => value,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorBody {
                    error: ErrorDetail::new("missing_query", "q is required"),
                }),
            )
                .into_response();
        }
    };
    let query = raw.trim();
    if query.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: ErrorDetail::new("invalid_query", "q must not be empty"),
            }),
        )
            .into_response();
    }

    let include_libs = params.include_libs.unwrap_or(true);
    let libs_indexer = if include_libs {
        state.libs_indexer.as_deref()
    } else {
        None
    };

    match search_with_optional_libs(state.indexer.as_ref(), libs_indexer, query, limit) {
        Ok((mut hits, query_meta)) => {
            let max_tokens = params.max_tokens;
            let snippet_policy = if state.security.disable_snippet_text {
                SnippetPolicy::Disabled
            } else if params.snippets == Some(false) {
                SnippetPolicy::SummaryOnly
            } else {
                SnippetPolicy::Full
            };

            let hits_before_pruning = hits.len();
            let mut pruned: Vec<PrunedHitMeta> = Vec::new();
            if let Some(budget) = max_tokens {
                hits.retain(|hit| {
                    if hit.token_estimate <= budget {
                        true
                    } else {
                        pruned.push(PrunedHitMeta {
                            doc_id: hit.doc_id.clone(),
                            rel_path: hit.rel_path.clone(),
                            score: hit.score,
                            token_estimate: hit.token_estimate,
                            reason: format!("token_estimate {}/{} exceeds max_tokens", hit.token_estimate, budget),
                        });
                        false
                    }
                });
            }

            if !matches!(snippet_policy, SnippetPolicy::Full) {
                for hit in hits.iter_mut() {
                    hit.snippet.clear();
                }
            }

            let top_score = hits.first().map(|hit| hit.score);
            let token_estimate_sum_kept = hits.iter().map(|hit| hit.token_estimate).sum();
            let selected_sources = hits
                .iter()
                .map(|hit| SelectedSourceMeta {
                    doc_id: hit.doc_id.clone(),
                    rel_path: hit.rel_path.clone(),
                    score: hit.score,
                    token_estimate: hit.token_estimate,
                    snippet_origin: hit.snippet_origin.clone(),
                    snippet_truncated: hit.snippet_truncated,
                })
                .collect::<Vec<_>>();

            let context_assembly = ContextAssemblyMeta {
                requested_limit: params.limit,
                effective_limit: limit,
                snippet_policy,
                max_tokens,
                token_budget_mode: "per_hit_token_estimate",
                hits_before_pruning,
                hits_after_pruning: hits.len(),
                token_estimate_sum_kept,
                pruned,
                selected_sources,
            };
            let meta =
                build_search_meta(&state.indexer, Some(query_meta), Some(context_assembly)).ok();
            Json(SearchResponse {
                hits,
                top_score,
                top_score_camel: top_score,
                meta,
            })
            .into_response()
        }
        Err(err) => {
            if let Some(SearchError::InvalidQuery { reason }) = err.downcast_ref::<SearchError>() {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(ErrorBody {
                        error: ErrorDetail::new("invalid_query", reason.clone()),
                    }),
                )
                    .into_response();
            }
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                error = ?err,
                request_id = %request_id.0,
                limit,
                "search handler failed"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("internal error (request id: {})", request_id.0),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
struct SnippetParams {
    window: Option<usize>,
    q: Option<String>,
    text_only: Option<bool>,
    max_tokens: Option<u64>,
    strip_html: Option<bool>,
}

#[derive(Serialize)]
struct SnippetPayload {
    text: String,
    html: Option<String>,
    truncated: bool,
    origin: SnippetOrigin,
    #[serde(skip_serializing_if = "Option::is_none")]
    line_start: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    line_end: Option<usize>,
}

#[derive(Serialize)]
struct SnippetResponse {
    doc: Option<DocSnapshot>,
    snippet: Option<SnippetPayload>,
}

async fn snippet_handler(
    State(state): State<AppState>,
    Path(doc_id): Path<String>,
    axum::extract::Extension(request_id): axum::extract::Extension<RequestId>,
    Query(params): Query<SnippetParams>,
) -> impl IntoResponse {
    let window = params
        .window
        .unwrap_or(DEFAULT_SNIPPET_WINDOW)
        .clamp(MIN_SNIPPET_WINDOW, MAX_SNIPPET_WINDOW);
    let strip_html_flag = params.strip_html.unwrap_or(false)
        | params.text_only.unwrap_or(false)
        | state.security.strip_snippet_html;
    let snapshot = if doc_id.starts_with("libs:") {
        match state.libs_indexer.as_deref() {
            Some(libs) => libs.snapshot_with_snippet(&doc_id, params.q.as_deref(), window),
            None => Ok(None),
        }
    } else {
        state
            .indexer
            .snapshot_with_snippet(&doc_id, params.q.as_deref(), window)
    };
    match snapshot {
        Ok(Some((doc, snippet))) => {
            let payload = if let Some(max_tokens) = params.max_tokens {
                if doc.token_estimate > max_tokens {
                    None
                } else {
                    render_snippet(snippet, &state, strip_html_flag)
                }
            } else {
                render_snippet(snippet, &state, strip_html_flag)
            };
            Json(SnippetResponse {
                doc: Some(doc),
                snippet: payload,
            })
            .into_response()
        }
        Ok(None) => Json(SnippetResponse {
            doc: None,
            snippet: None,
        })
        .into_response(),
        Err(err) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                error = ?err,
                request_id = %request_id.0,
                window,
                "snippet handler failed"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("internal error (request id: {})", request_id.0),
            )
                .into_response()
        }
    }
}

fn render_snippet(
    snippet: Option<SnippetResult>,
    state: &AppState,
    strip_html: bool,
) -> Option<SnippetPayload> {
    if state.security.disable_snippet_text {
        return None;
    }
    snippet.map(|snippet| {
        let html = if strip_html {
            None
        } else {
            snippet
                .html
                .as_ref()
                .map(|html| sanitize_snippet_html(html))
        };
        SnippetPayload {
            text: snippet.text,
            html,
            truncated: snippet.truncated,
            origin: snippet.origin,
            line_start: snippet.line_start,
            line_end: snippet.line_end,
        }
    })
}

async fn security_middleware(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    axum::extract::Extension(request_id): axum::extract::Extension<RequestId>,
    request: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Result<Response, Response> {
    let path = request.uri().path().to_string();
    let size_hint = request.body().size_hint();
    if !state.security.ip_allowed(addr.ip()) {
        if let Some(audit) = state.audit.as_ref() {
            audit.log(
                "ip_allow",
                "deny",
                Some(&request_id.0),
                Some(&path_template(&path)),
                Some(request.method().as_str()),
                Some(StatusCode::FORBIDDEN.as_u16()),
                Some(&addr.ip().to_string()),
                None,
            );
        }
        return Err((StatusCode::FORBIDDEN, HeaderMap::new()).into_response());
    }
    if path != "/healthz" {
        if let Some(limiter) = state.security.rate_limit.as_ref() {
            if let Err(err) =
                limiter.check_or_rate_limited(addr.ip(), "http_ip", "ip")
            {
                state.metrics.inc_rate_limit();
                let mut headers = HeaderMap::new();
                let retry_after_seconds = err.retry_after_ms.saturating_add(999) / 1000;
                if let Ok(value) = HeaderValue::from_str(&retry_after_seconds.to_string()) {
                    headers.insert(axum::http::header::RETRY_AFTER, value);
                }
                if let Some(audit) = state.audit.as_ref() {
                    audit.log(
                        "rate_limit",
                        "deny",
                        Some(&request_id.0),
                        Some(&path_template(&path)),
                        Some(request.method().as_str()),
                        Some(StatusCode::TOO_MANY_REQUESTS.as_u16()),
                        Some(&addr.ip().to_string()),
                        None,
                    );
                }
                return Err((
                    StatusCode::TOO_MANY_REQUESTS,
                    headers,
                    Json(ErrorBody {
                        error: ErrorDetail::rate_limited(&err),
                    }),
                )
                    .into_response());
            }
        }
        if state.security.max_request_bytes > 0 {
            if let Some(len) = request
                .headers()
                .get(CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<u64>().ok())
            {
                if len as usize > state.security.max_request_bytes {
                    return Err((StatusCode::PAYLOAD_TOO_LARGE, HeaderMap::new()).into_response());
                }
            }
            if let Some(upper) = size_hint.upper() {
                if upper as usize > state.security.max_request_bytes {
                    return Err((StatusCode::PAYLOAD_TOO_LARGE, HeaderMap::new()).into_response());
                }
            }
        }
        if state.security.max_query_bytes > 0 {
            if let Some(query) = request.uri().query() {
                if query.len() > state.security.max_query_bytes {
                    return Err((StatusCode::PAYLOAD_TOO_LARGE, HeaderMap::new()).into_response());
                }
            }
        }
        if !state.security.auth_matches(request.headers()) {
            state.metrics.inc_auth_deny();
            if let Some(audit) = state.audit.as_ref() {
                audit.log(
                    "auth",
                    "deny",
                    Some(&request_id.0),
                    Some(&path_template(&path)),
                    Some(request.method().as_str()),
                    Some(StatusCode::UNAUTHORIZED.as_u16()),
                    Some(&addr.ip().to_string()),
                    None,
                );
            }
            let mut hdrs = HeaderMap::new();
            let _ = hdrs.insert(
                axum::http::header::WWW_AUTHENTICATE,
                HeaderValue::from_static("Bearer"),
            );
            return Err((StatusCode::UNAUTHORIZED, hdrs).into_response());
        }
        if let Some(audit) = state.audit.as_ref() {
            audit.log(
                "auth",
                "allow",
                Some(&request_id.0),
                Some(&path_template(&path)),
                Some(request.method().as_str()),
                Some(StatusCode::OK.as_u16()),
                Some(&addr.ip().to_string()),
                None,
            );
        }
    }
    Ok(next.run(request).await)
}

async fn access_log_middleware(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    mut request: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Result<Response, (StatusCode, HeaderMap)> {
    let request_id = RequestId(Uuid::new_v4().to_string());
    let method = request.method().clone();
    let path = path_template(request.uri().path());
    let start = Instant::now();
    request
        .extensions_mut()
        .insert::<RequestId>(request_id.clone());
    let mut response = next.run(request).await;
    let status = response.status().as_u16();
    let duration_ms = start.elapsed().as_millis();
    let _ = response.headers_mut().insert(
        "x-request-id",
        HeaderValue::from_str(&request_id.0)
            .unwrap_or_else(|_| HeaderValue::from_static("invalid-request-id")),
    );
    tracing::info!(
        target: "docdexd_access",
        client = %addr.ip(),
        method = %method,
        path = %path,
        status,
        duration_ms,
        request_id = %request_id.0,
        "http_access"
    );
    if let Some(audit) = state.audit.as_ref() {
        audit.log(
            "access",
            "observe",
            Some(&request_id.0),
            Some(&path),
            Some(method.as_str()),
            Some(status),
            Some(&addr.ip().to_string()),
            None,
        );
    }
    Ok(response)
}

fn sanitize_snippet_html(html: &str) -> String {
    let mut tags = HashSet::new();
    tags.insert("b");
    ammonia::Builder::default()
        .tags(tags)
        .clean(html)
        .to_string()
}

fn path_template(path: &str) -> String {
    if path.starts_with("/snippet/") {
        "/snippet/:doc_id".to_string()
    } else {
        path.to_string()
    }
}
