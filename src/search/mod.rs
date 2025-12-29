use crate::config;
use crate::diff;
use crate::error::{
    AppError, RateLimited, StartupError, ERR_EMBEDDING_FAILED, ERR_EMBEDDING_MODEL_NOT_FOUND,
    ERR_EMBEDDING_TIMEOUT, ERR_INTERNAL_ERROR, ERR_INVALID_ARGUMENT, ERR_MEMORY_DISABLED,
    ERR_MISSING_REPO, ERR_RATE_LIMITED, ERR_UNKNOWN_REPO,
};
use crate::index::{
    DocSnapshot, Hit, Indexer, SearchError, SearchQueryMeta, SearchSnippetOrigin, SnippetOrigin,
    SnippetResult,
};
use crate::libs::LibsIndexer;
use crate::memory::{inject_embedding_metadata, MemoryStore};
use crate::ollama::OllamaEmbedder;
use crate::orchestrator::web::{web_context_from_status, WebDiscoveryStatus, WebFetchResult};
use crate::orchestrator::{
    memory_budget_from_max_answer_tokens, run_waterfall, MemoryContextAssembly, ProfileBudget,
    SymbolContextAssembly, WaterfallPlan, WaterfallRequest, WebGateConfig,
};
use crate::profiles::{ProfileEmbedder, ProfileManager};
use crate::repo_manager;
use crate::ratelimit::RateLimiter;
use crate::tier2::Tier2Config;
use crate::symbols::SymbolSearchMatch;
use anyhow::Result;
use axum::body::HttpBody;
use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::{header::CONTENT_LENGTH, HeaderMap, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;
use tracing::{info, warn};
use uuid::Uuid;

const DEFAULT_SNIPPET_WINDOW: usize = 40;
const MIN_SNIPPET_WINDOW: usize = 10;
const MAX_SNIPPET_WINDOW: usize = 400;
const MAX_RATE_LIMIT_MESSAGE_BYTES: usize = 256;
const REPO_ID_HEADER: &str = "x-docdex-repo-id";
const TOP_SCORE_NORMALIZATION_K: f32 = 8.0;
const SYMBOL_MATCH_MAX_FILES: usize = 6;
const SYMBOL_MATCH_MAX_PER_FILE: usize = 8;
const SYMBOL_SCORE_BASE: f32 = 0.1;
const SYMBOL_SCORE_SCALE: f32 = 0.05;
const SYMBOL_SCORE_PER_MATCH: f32 = 0.02;
const SYMBOL_SCORE_MAX_BOOST: f32 = 0.2;
const SYMBOL_NAME_MATCH_BONUS: f32 = 0.03;
const SYMBOL_NAME_MATCH_MAX_BOOST: f32 = 0.12;
const SYMBOL_SNIPPET_FALLBACK_LINES: usize = 60;
const AST_MATCH_MAX_FILES: usize = 6;
const AST_SCORE_BASE: f32 = 0.08;
const AST_SCORE_SCALE: f32 = 0.03;
const AST_SCORE_PER_MATCH: f32 = 0.015;
const AST_SCORE_MAX_BOOST: f32 = 0.15;
const RANKING_QUERY_TOKEN_LIMIT: usize = 6;

// Rate limiting is shared with MCP and other surfaces via crate::ratelimit.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RankingSurface {
    Search,
    Chat,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RankingMode {
    IncludeNewHits,
    BoostOnly,
}

#[derive(Clone, Copy, Debug)]
struct RankingConfig {
    symbol_enabled: bool,
    ast_enabled: bool,
    mode: RankingMode,
}

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
        default_loopback_only: bool,
        require_auth_token: bool,
    ) -> Result<Self> {
        let mut allow_nets: Vec<ipnet::IpNet> = Vec::new();
        for raw in allow_ips
            .iter()
            .map(|raw| raw.trim())
            .filter(|raw| !raw.is_empty())
        {
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
        if default_loopback_only && allow_nets.is_empty() {
            allow_nets.push("127.0.0.0/8".parse()?);
            if let Ok(ipv6) = "::1/128".parse() {
                allow_nets.push(ipv6);
            }
        }
        let auth_token = token.and_then(|value| {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        });
        if require_auth_token && auth_token.is_none() {
            return Err(StartupError::new(
                "startup_auth_required",
                "exposed mode requires an auth token",
            )
            .with_hint(
                "Provide `--auth-token <token>` when binding to non-loopback addresses (or bind to 127.0.0.1).",
            )
            .with_remediation(vec![
                "docdexd serve --repo . --host 0.0.0.0 --port 3210 --expose --auth-token <token> --require-tls=false".to_string(),
                "docdexd serve --repo . --host 127.0.0.1 --port 3210".to_string(),
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
    pub profile_state: Option<ProfileState>,
    pub features: crate::config::FeatureFlagsConfig,
    pub default_agent_id: Option<String>,
    pub max_answer_tokens: u32,
    pub llm_base_url: String,
    pub llm_default_model: String,
}

#[derive(Clone)]
pub struct RequestId(pub String);

#[derive(Clone)]
pub struct MemoryState {
    pub store: MemoryStore,
    pub embedder: OllamaEmbedder,
}

#[derive(Clone)]
pub struct ProfileState {
    pub manager: ProfileManager,
    pub embedder: Option<ProfileEmbedder>,
}

pub fn router(state: AppState) -> Router {
    let mut router = Router::new()
        .route("/healthz", get(healthz))
        .route("/search", get(search_handler))
        .route("/snippet/*doc_id", get(snippet_handler))
        .route(
            "/v1/chat/completions",
            post(crate::api::v1::chat::chat_completions_handler),
        )
        .route(
            "/v1/profile/list",
            get(crate::api::v1::profile::profile_list_handler),
        )
        .route(
            "/v1/profile/add",
            post(crate::api::v1::profile::profile_add_handler),
        )
        .route(
            "/v1/profile/search",
            post(crate::api::v1::profile::profile_search_handler),
        )
        .route(
            "/v1/profile/export",
            get(crate::api::v1::profile::profile_export_handler),
        )
        .route(
            "/v1/profile/save",
            post(crate::api::v1::profile::profile_save_handler),
        )
        .route(
            "/v1/profile/import",
            post(crate::api::v1::profile::profile_import_handler),
        )
        .route(
            "/v1/hooks/validate",
            post(crate::api::v1::hooks::hook_validate_handler),
        )
        .route(
            "/v1/graph/impact",
            get(crate::api::v1::graph::impact_graph_handler),
        )
        .route(
            "/v1/graph/impact/diagnostics",
            get(crate::api::v1::graph::impact_diagnostics_handler),
        )
        .route(
            "/v1/symbols",
            get(crate::api::v1::symbols::symbols_handler),
        )
        .route("/v1/ast", get(crate::api::v1::ast::ast_handler))
        .route(
            "/v1/ast/search",
            get(crate::api::v1::ast::ast_search_handler),
        )
        .route(
            "/v1/ast/query",
            post(crate::api::v1::ast::ast_query_handler),
        )
        .route(
            "/v1/symbols/status",
            get(crate::api::v1::symbols::symbols_status_handler),
        )
        .route(
            "/v1/dag/export",
            get(crate::api::v1::dag::dag_export_handler),
        )
        .route(
            "/v1/index/rebuild",
            post(crate::api::v1::index::index_rebuild_handler),
        )
        .route(
            "/v1/index/ingest",
            post(crate::api::v1::index::index_ingest_handler),
        )
        .route(
            "/v1/libs/discover",
            post(crate::api::v1::libs::libs_discover_handler),
        )
        .route(
            "/v1/libs/ingest",
            post(crate::api::v1::libs::libs_ingest_handler),
        )
        .route(
            "/v1/libs/fetch",
            post(crate::api::v1::libs::libs_fetch_handler),
        )
        .route(
            "/v1/web/search",
            post(crate::api::v1::web::web_search_handler),
        )
        .route(
            "/v1/web/fetch",
            post(crate::api::v1::web::web_fetch_handler),
        )
        .route(
            "/v1/web/cache/flush",
            post(crate::api::v1::web::web_cache_flush_handler),
        )
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

#[derive(Deserialize)]
struct RepoIdQuery {
    #[serde(default)]
    repo_id: Option<String>,
}


#[derive(Deserialize)]
struct MemoryStoreRequest {
    text: String,
    #[serde(default)]
    metadata: Option<serde_json::Value>,
    #[serde(default)]
    repo_id: Option<String>,
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
    #[serde(default)]
    repo_id: Option<String>,
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

pub(crate) fn json_error(
    status: StatusCode,
    code: &'static str,
    message: impl Into<String>,
) -> Response {
    (
        status,
        Json(ErrorBody {
            error: ErrorDetail::new(code, message),
        }),
    )
        .into_response()
}

pub(crate) struct RepoIdError {
    pub status: StatusCode,
    pub code: &'static str,
    pub message: String,
}

pub(crate) fn resolve_repo_id(
    headers: &HeaderMap,
    query_repo_id: Option<&str>,
    body_repo_id: Option<&str>,
    indexer: &Indexer,
    require: bool,
) -> Result<Option<String>, RepoIdError> {
    let mut selected: Option<String> = None;
    if let Some(value) = headers.get(REPO_ID_HEADER) {
        let header_value = value.to_str().map_err(|_| RepoIdError {
            status: StatusCode::BAD_REQUEST,
            code: ERR_INVALID_ARGUMENT,
            message: format!("{REPO_ID_HEADER} must be valid UTF-8"),
        })?;
        let trimmed = header_value.trim();
        if trimmed.is_empty() {
            return Err(RepoIdError {
                status: StatusCode::BAD_REQUEST,
                code: ERR_INVALID_ARGUMENT,
                message: format!("{REPO_ID_HEADER} must not be empty"),
            });
        }
        selected = Some(trimmed.to_string());
    }

    for value in [query_repo_id, body_repo_id] {
        let Some(raw) = value else {
            continue;
        };
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(RepoIdError {
                status: StatusCode::BAD_REQUEST,
                code: ERR_INVALID_ARGUMENT,
                message: "repo_id must not be empty".to_string(),
            });
        }
        match selected.as_deref() {
            None => selected = Some(trimmed.to_string()),
            Some(existing) if existing != trimmed => {
                return Err(RepoIdError {
                    status: StatusCode::BAD_REQUEST,
                    code: ERR_INVALID_ARGUMENT,
                    message: "repo_id values must match across header, query, and body".to_string(),
                });
            }
            _ => {}
        }
    }

    let Some(candidate) = selected else {
        return if require {
            Err(RepoIdError {
                status: StatusCode::BAD_REQUEST,
                code: ERR_MISSING_REPO,
                message: "repo_id is required".to_string(),
            })
        } else {
            Ok(None)
        };
    };

    let repo_root = indexer.repo_root();
    let fingerprint =
        repo_manager::repo_fingerprint_sha256(repo_root).map_err(|_| RepoIdError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            code: ERR_INTERNAL_ERROR,
            message: "repo identity unavailable".to_string(),
        })?;
    let legacy = repo_manager::fingerprint::legacy_repo_id_for_root(repo_root);
    let mut expected = HashSet::new();
    expected.insert(fingerprint);
    expected.insert(legacy);

    if !expected.contains(&candidate) {
        return Err(RepoIdError {
            status: StatusCode::NOT_FOUND,
            code: ERR_UNKNOWN_REPO,
            message: "unknown repo".to_string(),
        });
    }

    Ok(Some(candidate))
}

async fn memory_store_handler(
    State(state): State<AppState>,
    axum::extract::Extension(request_id): axum::extract::Extension<RequestId>,
    headers: HeaderMap,
    Query(repo_id): Query<RepoIdQuery>,
    Json(req): Json<MemoryStoreRequest>,
) -> impl IntoResponse {
    let Some(memory) = state.memory.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            "memory is disabled; start the daemon with --enable-memory=true",
        );
    };
    if let Err(err) = resolve_repo_id(
        &headers,
        repo_id.repo_id.as_deref(),
        req.repo_id.as_deref(),
        state.indexer.as_ref(),
        false,
    ) {
        return json_error(err.status, err.code, err.message);
    }

    let text = req.text.trim();
    if text.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "text must not be empty",
        );
    }

    let started = Instant::now();
    let repo_root = state.indexer.repo_root().display().to_string();
    let embedding = match memory.embedder.embed(text).await {
        Ok(value) => value,
        Err(err) => {
            let (code, status, message) = if let Some(app) = err.downcast_ref::<AppError>() {
                (
                    app.code,
                    status_for_app_error(app.code),
                    app.message.clone(),
                )
            } else {
                (
                    ERR_INTERNAL_ERROR,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "embedding failed".to_string(),
                )
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

    let write = tokio::task::spawn_blocking(move || {
        store.store(&text_owned, &embedding, metadata, created_at)
    })
    .await;
    match write {
        Ok(Ok((id, created_at))) => {
            info!(
                target: "docdexd",
                request_id = %request_id.0,
                repo_root = %repo_root,
                latency_ms = started.elapsed().as_millis(),
                "memory_store succeeded"
            );
            Json(MemoryStoreResponse {
                id: id.to_string(),
                created_at,
            })
            .into_response()
        }
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
    headers: HeaderMap,
    Query(repo_id): Query<RepoIdQuery>,
    Json(req): Json<MemoryRecallRequest>,
) -> impl IntoResponse {
    let Some(memory) = state.memory.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            "memory is disabled; start the daemon with --enable-memory=true",
        );
    };
    if let Err(err) = resolve_repo_id(
        &headers,
        repo_id.repo_id.as_deref(),
        req.repo_id.as_deref(),
        state.indexer.as_ref(),
        false,
    ) {
        return json_error(err.status, err.code, err.message);
    }

    let query = req.query.trim();
    if query.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "query must not be empty",
        );
    }
    let top_k = req.top_k.unwrap_or(5).max(1).min(50);

    let started = Instant::now();
    let repo_root = state.indexer.repo_root().display().to_string();
    let query_embedding = match memory.embedder.embed(query).await {
        Ok(value) => value,
        Err(err) => {
            let (code, status, message) = if let Some(app) = err.downcast_ref::<AppError>() {
                (
                    app.code,
                    status_for_app_error(app.code),
                    app.message.clone(),
                )
            } else {
                (
                    ERR_INTERNAL_ERROR,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "embedding failed".to_string(),
                )
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
            let results_len = items.len();
            let results = items
                .into_iter()
                .map(|item| MemoryRecallItem {
                    content: item.content,
                    score: item.score,
                    metadata: item.metadata,
                })
                .collect();
            info!(
                target: "docdexd",
                request_id = %request_id.0,
                repo_root = %repo_root,
                top_k,
                results = results_len,
                latency_ms = started.elapsed().as_millis(),
                "memory_recall succeeded"
            );
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
        purpose: "Index local docs and source code per-repo and serve search/chat + AST/symbol/impact context over HTTP, CLI, or MCP.",
        http_endpoints: vec![
            AiHelpEndpoint {
                method: "GET",
                path: "/search",
                description: "Search repo docs/code; returns hits with rel_path/path, summary, snippet.",
                params: &[
                    "q=<query>",
                    "limit=<n optional, defaults 8, clamped>",
                    "snippets=false (summary-only to save tokens)",
                    "max_tokens=<u64 optional, drop hits above token_estimate>",
                    "include_libs=<bool optional>",
                    "force_web=<bool optional>",
                    "skip_local_search=<bool optional>",
                    "no_cache=<bool optional>",
                    "max_web_results=<int optional>",
                    "llm_filter_local_results=<bool optional>",
                    "diff_mode=<working_tree|staged|range>",
                    "diff_base=<rev optional>",
                    "diff_head=<rev optional>",
                    "diff_path=<path optional, repeatable>",
                    "repo_id=<optional>",
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
                method: "POST",
                path: "/v1/chat/completions",
                description: "OpenAI-compatible chat completions with docdex context.",
                params: &[
                    "model=<string optional>",
                    "messages=[{role,content}...]",
                    "docdex.limit=<int optional>",
                    "docdex.force_web=<bool optional>",
                    "docdex.skip_local_search=<bool optional>",
                    "docdex.no_cache=<bool optional>",
                    "docdex.include_libs=<bool optional>",
                    "docdex.max_web_results=<int optional>",
                    "docdex.llm_filter_local_results=<bool optional>",
                    "docdex.compress_results=<bool optional>",
                    "docdex.agent_id=<string optional>",
                    "docdex.diff=<{mode,base,head,paths}>",
                    "repo_id=<optional (query or body)>",
                    "x-docdex-agent-id=<header optional>",
                ],
            },
            AiHelpEndpoint {
                method: "POST",
                path: "/v1/index/rebuild",
                description: "Rebuild the repo index (optionally ingest libs sources).",
                params: &[
                    "libs_sources=<path optional>",
                    "repo_id=<optional>",
                ],
            },
            AiHelpEndpoint {
                method: "POST",
                path: "/v1/index/ingest",
                description: "Ingest a single file into the index.",
                params: &[
                    "file=<path>",
                    "repo_id=<optional>",
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
                    "repo_id=<optional>",
                ],
            },
            AiHelpEndpoint {
                method: "GET",
                path: "/v1/graph/impact/diagnostics",
                description: "List unresolved dynamic import diagnostics.",
                params: &[
                    "file=<repo-relative path optional>",
                    "limit=<int optional>",
                    "offset=<int optional>",
                    "repo_id=<optional>",
                ],
            },
            AiHelpEndpoint {
                method: "GET",
                path: "/v1/symbols",
                description: "Read per-file symbol extraction output.",
                params: &["path=<repo-relative path>", "repo_id=<optional>"],
            },
            AiHelpEndpoint {
                method: "GET",
                path: "/v1/symbols/status",
                description: "Tree-sitter parser drift status for the repo.",
                params: &["repo_id=<optional>"],
            },
            AiHelpEndpoint {
                method: "GET",
                path: "/v1/ast",
                description: "Read Tree-sitter AST nodes for a file.",
                params: &["path=<repo-relative path>", "maxNodes=<int optional>", "repo_id=<optional>"],
            },
            AiHelpEndpoint {
                method: "GET",
                path: "/v1/ast/search",
                description: "Search AST nodes by kind across the repo.",
                params: &["kinds=<comma-separated>", "mode=<any|all optional>", "limit=<int optional>", "repo_id=<optional>"],
            },
            AiHelpEndpoint {
                method: "POST",
                path: "/v1/ast/query",
                description: "Query AST nodes by kind/name/field and return sample nodes.",
                params: &[
                    "kinds=[...]",
                    "name=<string optional>",
                    "field=<string optional>",
                    "pathPrefix=<string optional>",
                    "mode=<any|all optional>",
                    "limit=<int optional>",
                    "sampleLimit=<int optional>",
                    "repo_id=<optional>",
                ],
            },
            AiHelpEndpoint {
                method: "POST",
                path: "/v1/memory/store",
                description: "Store a memory item (requires memory enabled).",
                params: &["text=<string>", "metadata=<object optional>", "repo_id=<optional>"],
            },
            AiHelpEndpoint {
                method: "POST",
                path: "/v1/memory/recall",
                description: "Recall memory items by semantic similarity (requires memory enabled).",
                params: &["query=<string>", "top_k=<int optional>", "repo_id=<optional>"],
            },
            AiHelpEndpoint {
                method: "GET",
                path: "/v1/profile/list",
                description: "List profile agents and preferences (global memory).",
                params: &["agent_id=<optional>"],
            },
            AiHelpEndpoint {
                method: "POST",
                path: "/v1/profile/add",
                description: "Add a profile preference (immediate write).",
                params: &[
                    "agent_id=<string>",
                    "content=<string>",
                    "category=<style|tooling|constraint|workflow>",
                    "role=<string optional>",
                ],
            },
            AiHelpEndpoint {
                method: "POST",
                path: "/v1/profile/save",
                description: "Add a profile preference and trigger evolution.",
                params: &[
                    "agent_id=<string>",
                    "content=<string>",
                    "category=<style|tooling|constraint|workflow>",
                    "role=<string optional>",
                ],
            },
            AiHelpEndpoint {
                method: "POST",
                path: "/v1/profile/search",
                description: "Search profile preferences by semantic similarity.",
                params: &["agent_id=<string>", "query=<string>", "top_k=<int optional>"],
            },
            AiHelpEndpoint {
                method: "POST",
                path: "/v1/profile/export",
                description: "Export profile preferences to a JSON manifest.",
                params: &[],
            },
            AiHelpEndpoint {
                method: "POST",
                path: "/v1/profile/import",
                description: "Import profile preferences from a JSON manifest.",
                params: &["manifest=<json body>"],
            },
            AiHelpEndpoint {
                method: "POST",
                path: "/v1/hooks/validate",
                description: "Validate staged files against profile constraints.",
                params: &["files=[\"<repo-relative>\", ...]"],
            },
            AiHelpEndpoint {
                method: "GET",
                path: "/v1/dag/export",
                description: "Export a reasoning DAG trace.",
                params: &[
                    "session_id=<id>",
                    "format=<json|text|dot optional>",
                    "max_nodes=<int optional>",
                    "repo_id=<optional>",
                ],
            },
            AiHelpEndpoint {
                method: "POST",
                path: "/v1/web/search",
                description: "Run a web discovery query (requires DOCDEX_WEB_ENABLED=1).",
                params: &["query=<string>", "limit=<int optional>"],
            },
            AiHelpEndpoint {
                method: "POST",
                path: "/v1/web/fetch",
                description: "Fetch a URL via headless Chrome.",
                params: &["url=<string>"],
            },
            AiHelpEndpoint {
                method: "POST",
                path: "/v1/web/cache/flush",
                description: "Clear cached web discovery/fetch entries.",
                params: &[],
            },
            AiHelpEndpoint {
                method: "POST",
                path: "/v1/libs/discover",
                description: "Discover library documentation sources for the repo.",
                params: &["sources_path=<path optional>", "repo_id=<optional>"],
            },
            AiHelpEndpoint {
                method: "POST",
                path: "/v1/libs/ingest",
                description: "Ingest library documentation sources for the repo.",
                params: &["sources_path=<path>", "repo_id=<optional>"],
            },
            AiHelpEndpoint {
                method: "POST",
                path: "/v1/libs/fetch",
                description: "Discover + ingest library documentation sources for the repo.",
                params: &["sources_path=<path optional>", "repo_id=<optional>"],
            },
            AiHelpEndpoint {
                method: "GET",
                path: "/healthz",
                description: "Liveness check (200 OK => ready).",
                params: &[],
            },
            AiHelpEndpoint {
                method: "GET",
                path: "/metrics",
                description: "Prometheus-style metrics for rate-limit/auth/error counts.",
                params: &[],
            },
            AiHelpEndpoint {
                method: "GET",
                path: "/ai-help",
                description: "This help payload (feature-aware endpoints, limits, and tips).",
                params: &[],
            },
        ],
        cli_commands: vec![
            AiHelpCli {
                command: "docdexd check",
                description: "Validate config/state, bind availability, and dependency readiness.",
                example: "docdexd check",
            },
            AiHelpCli {
                command: "docdexd index --repo <path>",
                description: "Build or rebuild the index for a repo.",
                example: "docdexd index --repo /workspace",
            },
            AiHelpCli {
                command: "docdexd serve --repo <path> [--host 127.0.0.1] [--port 3210]",
                description: "Serve HTTP API with watcher for incremental ingest.",
                example: "docdexd serve --repo /workspace --host 127.0.0.1 --port 3210",
            },
            AiHelpCli {
                command: "docdexd chat --repo <path> --query \"text\" [--limit 8]",
                description: "Ad-hoc search/chat via CLI (JSON to stdout).",
                example: "docdexd chat --repo /workspace --query \"payment flow\" --limit 5",
            },
            AiHelpCli {
                command: "docdexd ingest --repo <path> --file <file>",
                description: "Reindex a single file (honors exclude flags).",
                example: "docdexd ingest --repo /workspace --file docs/new.md",
            },
            AiHelpCli {
                command: "docdexd symbols-status --repo <path>",
                description: "Check Tree-sitter parser drift for symbols/AST.",
                example: "docdexd symbols-status --repo /workspace",
            },
            AiHelpCli {
                command: "docdexd impact-diagnostics --repo <path>",
                description: "List unresolved dynamic import diagnostics.",
                example: "docdexd impact-diagnostics --repo /workspace",
            },
            AiHelpCli {
                command: "docdexd memory-store --repo <path> --text \"...\"",
                description: "Store a memory item (requires embeddings).",
                example: "docdexd memory-store --repo /workspace --text \"release notes\"",
            },
            AiHelpCli {
                command: "docdexd memory-recall --repo <path> --query \"...\"",
                description: "Recall memory items by semantic similarity.",
                example: "docdexd memory-recall --repo /workspace --query \"release notes\"",
            },
            AiHelpCli {
                command: "docdexd profile list [--agent-id <id>]",
                description: "List profile agents/preferences (global memory).",
                example: "docdexd profile list --agent-id agent-default",
            },
            AiHelpCli {
                command: "docdexd profile add --agent-id <id> --category style --content \"...\"",
                description: "Add a profile preference for an agent.",
                example: "docdexd profile add --agent-id agent-default --category style --content \"Prefer ripgrep\"",
            },
            AiHelpCli {
                command: "docdexd hook pre-commit --repo <path>",
                description: "Run semantic gatekeeper checks for staged files.",
                example: "docdexd hook pre-commit --repo /workspace",
            },
            AiHelpCli {
                command: "docdexd web-search --query \"...\" [--limit 8]",
                description: "Run a web discovery query (requires DOCDEX_WEB_ENABLED=1).",
                example: "docdexd web-search --query \"rust async cancel\" --limit 5",
            },
            AiHelpCli {
                command: "docdexd web-fetch --url <url>",
                description: "Fetch a URL via headless Chrome.",
                example: "docdexd web-fetch --url https://example.com",
            },
            AiHelpCli {
                command: "docdexd web-rag --repo <path> --query \"...\"",
                description: "Run a web-assisted query (forces Tier 2 behavior).",
                example: "docdexd web-rag --repo /workspace --query \"rust async cancel\"",
            },
            AiHelpCli {
                command: "docdexd web-cache-flush",
                description: "Clear cached web discovery/fetch entries.",
                example: "docdexd web-cache-flush",
            },
            AiHelpCli {
                command: "docdexd libs discover --repo <path>",
                description: "Discover library documentation sources for a repo.",
                example: "docdexd libs discover --repo /workspace",
            },
            AiHelpCli {
                command: "docdexd libs fetch --repo <path>",
                description: "Fetch + ingest library docs for a repo.",
                example: "docdexd libs fetch --repo /workspace",
            },
            AiHelpCli {
                command: "docdexd libs ingest --repo <path> --sources <file>",
                description: "Ingest library docs from a sources file.",
                example: "docdexd libs ingest --repo /workspace --sources /tmp/libs.json",
            },
            AiHelpCli {
                command: "docdexd run-tests --repo <path> [--target <path>]",
                description: "Run repo-specific test commands from .docdex/run-tests.json or env.",
                example: "docdexd run-tests --repo /workspace",
            },
            AiHelpCli {
                command: "docdexd tui [--repo <path>]",
                description: "Launch the local TUI client (requires docdex-tui binary).",
                example: "docdexd tui --repo /workspace",
            },
            AiHelpCli {
                command: "docdexd mcp --repo <path>",
                description: "Run the MCP server over stdio for MCP-aware agents.",
                example: "docdexd mcp --repo /workspace --log warn --max-results 8",
            },
            AiHelpCli {
                command: "docdexd mcp-add --repo <path>",
                description: "Register Docdex MCP in supported agent CLIs.",
                example: "docdexd mcp-add --repo /workspace --log warn --max-results 8",
            },
            AiHelpCli {
                command: "docdexd repo inspect --repo <path>",
                description: "Inspect repo identity and shared-state mapping.",
                example: "docdexd repo inspect --repo /workspace",
            },
            AiHelpCli {
                command: "docdexd repo reassociate --repo <new_path> --state-dir <dir> --old-path <old_path>",
                description: "Reassociate a moved repo to existing shared state.",
                example: "docdexd repo reassociate --repo /workspace --state-dir /shared/state --old-path /old/path",
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
                args: &[
                    "query (string, required)",
                    "limit (int, optional, clamped)",
                    "force_web (bool, optional)",
                    "diff (object, optional)",
                    "project_root or repo_path (string, optional; must match server repo)",
                ],
                returns: &["results[]", "repo_root", "state_dir", "limit"],
            },
            AiHelpMcpTool {
                name: "docdex_web_research",
                description: "Run local search + web discovery/fetch and return combined response.",
                args: &[
                    "query (string, required)",
                    "limit (int, optional, clamped)",
                    "web_limit (int, optional)",
                    "force_web (bool, optional)",
                    "skip_local_search (bool, optional)",
                    "no_cache (bool, optional)",
                    "llm_filter_local_results (bool, optional)",
                    "repo_only (bool, optional)",
                    "llm_model (string, optional)",
                    "llm_agent (string, optional)",
                    "project_root or repo_path (string, optional; must match server repo)",
                ],
                returns: &["results[]", "web_context[]", "web_discovery", "repo_root", "state_dir"],
            },
            AiHelpMcpTool {
                name: "docdex_index",
                description: "Rebuild index or ingest specific files for the repo.",
                args: &[
                    "paths (array of file paths, empty => full reindex)",
                    "project_root or repo_path (string, optional)",
                ],
                returns: &["status", "action", "paths?"],
            },
            AiHelpMcpTool {
                name: "docdex_files",
                description: "List indexed docs (rel_path/doc_id/summary/token_estimate) with pagination.",
                args: &[
                    "limit (int, optional, default 200, max 1000)",
                    "offset (int, optional, default 0)",
                    "project_root or repo_path (string, optional)",
                ],
                returns: &["results[]", "total", "limit", "offset", "repo_root"],
            },
            AiHelpMcpTool {
                name: "docdex_open",
                description: "Read a file from the repo; optional line range; rejects paths outside the repo.",
                args: &[
                    "path (string, required, relative)",
                    "start_line (int, optional)",
                    "end_line (int, optional)",
                    "project_root or repo_path (string, optional)",
                ],
                returns: &["path", "start_line", "end_line", "total_lines", "content", "repo_root"],
            },
            AiHelpMcpTool {
                name: "docdex_stats",
                description: "Report index metadata.",
                args: &["project_root or repo_path (string, optional)"],
                returns: &["num_docs", "state_dir", "index_size_bytes", "segments", "avg_bytes_per_doc", "generated_at_epoch_ms", "last_updated_epoch_ms", "repo_root"],
            },
            AiHelpMcpTool {
                name: "docdex_repo_inspect",
                description: "Inspect repo identity (normalized path, fingerprint, shared-state mapping).",
                args: &["project_root or repo_path (string, optional)"],
                returns: &["repo_root", "fingerprint", "state_key", "state_dir", "aliases[]"],
            },
            AiHelpMcpTool {
                name: "docdex_symbols",
                description: "Read per-file symbols from the repo.",
                args: &["path (string, required, relative)", "project_root or repo_path (string, optional)"],
                returns: &["schema", "repo_id", "file", "symbols[]", "outcome?"],
            },
            AiHelpMcpTool {
                name: "docdex_ast",
                description: "Read Tree-sitter AST nodes for a file.",
                args: &[
                    "path (string, required, relative)",
                    "max_nodes (int, optional)",
                    "project_root or repo_path (string, optional)",
                ],
                returns: &["schema", "repo_id", "file", "nodes[]", "total_nodes", "truncated", "outcome?"],
            },
            AiHelpMcpTool {
                name: "docdex_impact_diagnostics",
                description: "List unresolved dynamic import diagnostics.",
                args: &[
                    "file (string, optional, relative)",
                    "limit (int, optional)",
                    "offset (int, optional)",
                    "project_root or repo_path (string, optional)",
                ],
                returns: &["schema", "repo_id", "diagnostics[]", "total", "limit", "offset", "truncated"],
            },
            AiHelpMcpTool {
                name: "docdex_memory_save",
                description: "Store a memory item (requires DOCDEX_ENABLE_MEMORY=1).",
                args: &["text (string, required)", "metadata (object, optional)", "project_root or repo_path (string, optional)"],
                returns: &["id", "created_at"],
            },
            AiHelpMcpTool {
                name: "docdex_memory_store",
                description: "Alias for docdex_memory_save (requires DOCDEX_ENABLE_MEMORY=1).",
                args: &["text (string, required)", "metadata (object, optional)", "project_root or repo_path (string, optional)"],
                returns: &["id", "created_at"],
            },
            AiHelpMcpTool {
                name: "docdex_memory_recall",
                description: "Recall memory items by semantic similarity (requires DOCDEX_ENABLE_MEMORY=1).",
                args: &["query (string, required)", "top_k (int, optional)", "project_root or repo_path (string, optional)"],
                returns: &["results[]"],
            },
            AiHelpMcpTool {
                name: "docdex_save_preference",
                description: "Save a profile preference and trigger evolution.",
                args: &[
                    "agent_id (string, optional; defaults from initialize)",
                    "content (string, required)",
                    "category (style|tooling|constraint|workflow)",
                    "role (string, optional)",
                ],
                returns: &["status", "request_id"],
            },
            AiHelpMcpTool {
                name: "docdex_get_profile",
                description: "Fetch profile agents and preferences.",
                args: &["agent_id (string, optional; defaults from initialize)"],
                returns: &["agents[]", "preferences[]"],
            },
        ],
        best_practices: vec![
            "Prefer narrow queries (file names, headings, concepts) to keep snippets focused.",
            "Use /search to get doc_id, then /snippet/:doc_id for a larger window when needed.",
            "Use /search with snippets=false to read summaries first; only fetch 1-2 snippets you need.",
            "Keep q short; long query strings are rejected by max_query_bytes to save bandwidth/tokens.",
            "Respect the reported `token_estimate` to avoid oversized prompts.",
            "Web discovery is disabled by default; set DOCDEX_WEB_ENABLED=1 to allow web search.",
            "When running remote, set --auth-token and TLS (certbot or manual cert/key).",
            "Keep server logging minimal for agent pipelines (e.g., --log warn --access-log=false).",
            "Use state_dir per project to keep indexes isolated; run separate serve instances per repo.",
            "When targeting a specific repo over HTTP, pass repo_id (or x-docdex-repo-id header); mismatches are rejected.",
            "Use text_only=true on /snippet or --strip-snippet-html/--disable-snippet-text to trim payloads.",
            "When building prompts, keep rel_path + summary + trimmed snippet; drop score/token_estimate/doc_id and normalize whitespace.",
            "Trim noisy content up front with --exclude-dir/--exclude-prefix so snippets stay relevant and short.",
            "Cache doc_id/rel_path/summary client-side to avoid repeat snippet fetches; only call /snippet for new doc_ids.",
            "For MCP-aware agents, register a server named docdex that runs `docdexd mcp --repo <repo> --log warn --max-results 8`, then use docdex_search or docdex_web_research and docdex_index when results look stale.",
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
    #[serde(default)]
    force_web: Option<bool>,
    #[serde(default)]
    max_web_results: Option<usize>,
    #[serde(default)]
    skip_local_search: Option<bool>,
    #[serde(default)]
    no_cache: Option<bool>,
    #[serde(default)]
    llm_filter_local_results: Option<bool>,
    #[serde(default)]
    llm_model: Option<String>,
    #[serde(default)]
    llm_agent: Option<String>,
    #[serde(default)]
    diff_mode: Option<diff::DiffMode>,
    #[serde(default)]
    diff_base: Option<String>,
    #[serde(default)]
    diff_head: Option<String>,
    #[serde(default)]
    diff_path: Vec<String>,
    #[serde(default)]
    repo_id: Option<String>,
}

#[derive(Serialize)]
pub struct SearchResponse {
    pub hits: Vec<Hit>,
    pub top_score: Option<f32>,
    #[serde(rename = "topScore")]
    pub top_score_camel: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_score_normalized: Option<f32>,
    #[serde(rename = "topScoreNormalized", skip_serializing_if = "Option::is_none")]
    pub top_score_normalized_camel: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub web_context: Option<Vec<WebFetchResult>>,
    #[serde(rename = "webDiscovery", skip_serializing_if = "Option::is_none")]
    pub web_discovery: Option<WebDiscoveryStatus>,
    #[serde(rename = "impactContext", skip_serializing_if = "Option::is_none")]
    pub impact_context: Option<crate::impact::ImpactContextAssembly>,
    #[serde(rename = "profileContext", skip_serializing_if = "Option::is_none")]
    pub profile_context: Option<crate::orchestrator::ProfileContextAssembly>,
    #[serde(rename = "memoryContext", skip_serializing_if = "Option::is_none")]
    pub memory_context: Option<MemoryContextAssembly>,
    #[serde(rename = "symbolsContext", skip_serializing_if = "Option::is_none")]
    pub symbols_context: Option<SymbolContextAssembly>,
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
    use super::RankingSurface;
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
                format!("# Doc {i}\n\nREPO_NEEDLE_ABC appears in this document.\n\nMore text.\n")
            } else {
                format!("# Doc {i}\n\nFiller content for indexing.\n")
            };
            fs::write(docs_dir.join(format!("doc_{i}.md")), body)?;
        }

        let index_config =
            index::IndexConfig::with_overrides(repo_root, None, Vec::new(), Vec::new(), true)?;
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
        let report = libs_writer.ingest_sources(&repo_root, &sources)?;
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
            let _ = super::search_with_optional_libs(
                &indexer,
                Some(&libs_indexer),
                query,
                limit,
                RankingSurface::Search,
            )?;
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
            let _ = super::search_with_optional_libs(
                &indexer,
                Some(&libs_indexer),
                query,
                limit,
                RankingSurface::Search,
            )?;
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
    surface: RankingSurface,
) -> Result<SearchResponse> {
    let (hits, query_meta) =
        search_with_optional_libs(indexer, libs_indexer, query, limit, surface)?;
    let top_score = hits.first().map(|hit| hit.score);
    let top_score_normalized = top_score.map(normalize_score);
    Ok(SearchResponse {
        hits,
        top_score,
        top_score_camel: top_score,
        top_score_normalized,
        top_score_normalized_camel: top_score_normalized,
        web_context: None,
        web_discovery: None,
        impact_context: None,
        profile_context: None,
        memory_context: None,
        symbols_context: None,
        meta: Some(build_search_meta(indexer, Some(query_meta), None)?),
    })
}

fn search_with_optional_libs(
    indexer: &Indexer,
    libs_indexer: Option<&LibsIndexer>,
    query: &str,
    limit: usize,
    surface: RankingSurface,
) -> Result<(Vec<Hit>, SearchQueryMeta)> {
    let (mut repo_hits, query_meta) = indexer.search_with_query_meta(query, limit)?;
    if surface == RankingSurface::Search {
        apply_ranking_deltas(indexer, &mut repo_hits, query, limit, surface)?;
    }
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

pub(crate) fn apply_ranking_deltas(
    indexer: &Indexer,
    hits: &mut Vec<Hit>,
    query: &str,
    limit: usize,
    surface: RankingSurface,
) -> Result<()> {
    let config = ranking_config_for_surface(surface);
    if config.symbol_enabled {
        apply_symbol_matches(indexer, hits, query, limit, config.mode)?;
    }
    if config.ast_enabled {
        apply_ast_matches(indexer, hits, query, limit, config.mode)?;
    }
    Ok(())
}

fn ranking_config_for_surface(surface: RankingSurface) -> RankingConfig {
    let mode = match surface {
        RankingSurface::Search => RankingMode::IncludeNewHits,
        RankingSurface::Chat => RankingMode::BoostOnly,
    };
    RankingConfig {
        symbol_enabled: resolve_symbol_ranking_enabled(surface),
        ast_enabled: resolve_ast_ranking_enabled(surface),
        mode,
    }
}

fn apply_symbol_matches(
    indexer: &Indexer,
    hits: &mut Vec<Hit>,
    query: &str,
    limit: usize,
    mode: RankingMode,
) -> Result<()> {
    if !indexer.symbols_enabled() {
        return Ok(());
    }
    if indexer.symbols_reindex_required().unwrap_or(false) {
        warn!(
            target: "docdexd",
            "symbols reindex required; skipping symbol matches"
        );
        return Ok(());
    }
    let max_files = SYMBOL_MATCH_MAX_FILES.min(limit.max(1));
    let matches = indexer.search_symbols(query, max_files, SYMBOL_MATCH_MAX_PER_FILE)?;
    if matches.is_empty() {
        return Ok(());
    }

    let mut by_path: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let query_tokens = extract_query_tokens(query);
    for (idx, hit) in hits.iter().enumerate() {
        by_path.insert(hit.rel_path.clone(), idx);
    }

    for symbol_match in matches {
        let (weighted_count, name_matches) = symbol_match_score_details(&symbol_match, &query_tokens);
        let base_boost = (weighted_count.max(1.0) * SYMBOL_SCORE_PER_MATCH).min(SYMBOL_SCORE_MAX_BOOST);
        let name_boost = (name_matches as f32 * SYMBOL_NAME_MATCH_BONUS).min(SYMBOL_NAME_MATCH_MAX_BOOST);
        let boost = base_boost + name_boost;
        if let Some(idx) = by_path.get(&symbol_match.file).copied() {
            let hit = &mut hits[idx];
            hit.score += hit.score * SYMBOL_SCORE_SCALE + boost;
            continue;
        }
        if mode == RankingMode::IncludeNewHits {
            if let Some(hit) = build_symbol_hit(indexer, &symbol_match, query, boost)? {
                by_path.insert(hit.rel_path.clone(), hits.len());
                hits.push(hit);
            }
        }
    }

    sort_hits_deterministically(hits);
    if hits.len() > limit {
        hits.truncate(limit);
    }
    Ok(())
}

fn apply_ast_matches(
    indexer: &Indexer,
    hits: &mut Vec<Hit>,
    query: &str,
    limit: usize,
    mode: RankingMode,
) -> Result<()> {
    if !indexer.symbols_enabled() {
        return Ok(());
    }
    if indexer.symbols_reindex_required().unwrap_or(false) {
        warn!(
            target: "docdexd",
            "symbols reindex required; skipping AST matches"
        );
        return Ok(());
    }

    let ast_query = extract_ast_query_kinds(query);
    if ast_query.kinds.is_empty() {
        return Ok(());
    }

    let max_files = AST_MATCH_MAX_FILES.min(limit.max(1));
    let matches = indexer.search_ast_kinds(&ast_query.kinds, max_files)?;
    if matches.is_empty() {
        return Ok(());
    }

    let mut by_path: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for (idx, hit) in hits.iter().enumerate() {
        by_path.insert(hit.rel_path.clone(), idx);
    }

    for ast_match in matches {
        let weighted_count =
            ast_weighted_match_count(indexer, &ast_match.file, &ast_query.kinds)
                .unwrap_or_else(|_| ast_match.match_count.max(1) as f32);
        let boost = (weighted_count.max(1.0) * AST_SCORE_PER_MATCH).min(AST_SCORE_MAX_BOOST);
        if let Some(idx) = by_path.get(&ast_match.file).copied() {
            let hit = &mut hits[idx];
            hit.score += hit.score * AST_SCORE_SCALE + boost;
            continue;
        }
        if mode == RankingMode::IncludeNewHits {
            if let Some(hit) = build_ast_hit(indexer, &ast_match, query, &ast_query.labels, boost)? {
                by_path.insert(hit.rel_path.clone(), hits.len());
                hits.push(hit);
            }
        }
    }

    sort_hits_deterministically(hits);
    if hits.len() > limit {
        hits.truncate(limit);
    }
    Ok(())
}

fn symbol_match_score_details(
    symbol_match: &SymbolSearchMatch,
    query_tokens: &[String],
) -> (f32, usize) {
    if symbol_match.symbols.is_empty() {
        return (0.0, 0);
    }
    let mut weighted_count = 0.0;
    let mut matched_names = HashSet::new();
    for symbol in &symbol_match.symbols {
        weighted_count += symbol_kind_weight(&symbol.kind);
        if !query_tokens.is_empty() && symbol_name_matches_query(&symbol.name, query_tokens) {
            matched_names.insert(symbol.name.to_lowercase());
        }
    }
    (weighted_count, matched_names.len())
}

fn symbol_name_matches_query(name: &str, tokens: &[String]) -> bool {
    if tokens.is_empty() {
        return false;
    }
    let lowered = name.to_lowercase();
    if tokens.iter().any(|token| token == &lowered) {
        return true;
    }
    for part in lowered.split(|ch: char| !ch.is_alphanumeric() && ch != '_') {
        if part.len() < 2 {
            continue;
        }
        if tokens.iter().any(|token| token == part) {
            return true;
        }
    }
    for token in tokens {
        if token.len() < 3 {
            continue;
        }
        if lowered.contains(token) {
            return true;
        }
    }
    false
}

fn symbol_kind_weight(kind: &str) -> f32 {
    match kind.to_lowercase().as_str() {
        "function" | "method" => 1.2,
        "class" | "struct" | "trait" | "enum" | "interface" => 1.1,
        "type" => 1.0,
        "module" => 0.9,
        "const" | "constant" => 0.7,
        "variable" | "var" => 0.6,
        _ => 1.0,
    }
}

fn ast_kind_weight(kind: &str) -> f32 {
    match kind {
        "function_item"
        | "function_definition"
        | "function_declaration"
        | "method_definition"
        | "method_declaration"
        | "arrow_function" => 1.2,
        "class_definition" | "class_declaration" | "class_item" => 1.1,
        "struct_item" | "struct_declaration" => 1.1,
        "trait_item" => 1.1,
        "enum_item" | "enum_declaration" => 1.0,
        "interface_declaration" => 1.0,
        "mod_item" | "module" => 0.9,
        "import_statement"
        | "import_declaration"
        | "import_clause"
        | "use_declaration"
        | "include_macro_invocation" => 0.6,
        _ => 1.0,
    }
}

fn ast_weighted_match_count(
    indexer: &Indexer,
    rel_path: &str,
    kinds: &[String],
) -> Result<f32> {
    let counts = indexer.ast_kind_counts_for_file(rel_path, kinds)?;
    if counts.is_empty() {
        return Ok(0.0);
    }
    let mut weighted = 0.0;
    for (kind, count) in counts {
        weighted += (count as f32) * ast_kind_weight(&kind);
    }
    Ok(weighted)
}

fn extract_query_tokens(query: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for raw in query.split_whitespace() {
        for part in raw.split(|ch: char| !ch.is_alphanumeric() && ch != '_') {
            let trimmed = part.trim();
            if trimmed.len() < 2 {
                continue;
            }
            let lowered = trimmed.to_lowercase();
            if seen.insert(lowered.clone()) {
                out.push(lowered);
                if out.len() >= RANKING_QUERY_TOKEN_LIMIT {
                    return out;
                }
            }
        }
    }
    out
}

fn build_symbol_hit(
    indexer: &Indexer,
    symbol_match: &SymbolSearchMatch,
    query: &str,
    boost: f32,
) -> Result<Option<Hit>> {
    let rel_path = symbol_match.file.as_str();
    let Some((snapshot, snippet)) =
        indexer.snapshot_with_snippet(rel_path, Some(query), SYMBOL_SNIPPET_FALLBACK_LINES)?
    else {
        return Ok(None);
    };
    let symbol_snippet = symbol_match_snippet(symbol_match);
    let (snippet_text, snippet_origin, snippet_truncated, line_start, line_end) =
        if !symbol_snippet.is_empty() {
            (
                symbol_snippet,
                SearchSnippetOrigin::Summary,
                false,
                None,
                None,
            )
        } else if let Some(snippet) = snippet {
            (
                snippet.text,
                map_snippet_origin(snippet.origin),
                snippet.truncated,
                snippet.line_start,
                snippet.line_end,
            )
        } else {
            (
                snapshot.summary.clone(),
                SearchSnippetOrigin::Summary,
                false,
                None,
                None,
            )
        };
    Ok(Some(Hit {
        doc_id: snapshot.doc_id.clone(),
        rel_path: snapshot.rel_path.clone(),
        path: snapshot.rel_path.clone(),
        kind: snapshot.kind,
        score: SYMBOL_SCORE_BASE + boost,
        summary: snapshot.summary,
        snippet: snippet_text,
        token_estimate: snapshot.token_estimate,
        snippet_origin: Some(snippet_origin),
        snippet_truncated: Some(snippet_truncated),
        line_start,
        line_end,
    }))
}

fn build_ast_hit(
    indexer: &Indexer,
    ast_match: &crate::symbols::AstSearchMatch,
    query: &str,
    labels: &[String],
    boost: f32,
) -> Result<Option<Hit>> {
    let rel_path = ast_match.file.as_str();
    let Some((snapshot, snippet)) =
        indexer.snapshot_with_snippet(rel_path, Some(query), SYMBOL_SNIPPET_FALLBACK_LINES)?
    else {
        return Ok(None);
    };
    let ast_snippet = if labels.is_empty() {
        "AST: query match".to_string()
    } else {
        format!("AST: {}", labels.join(", "))
    };
    let (snippet_text, snippet_origin, snippet_truncated, line_start, line_end) =
        if !ast_snippet.is_empty() {
            (
                ast_snippet,
                SearchSnippetOrigin::Summary,
                false,
                None,
                None,
            )
        } else if let Some(snippet) = snippet {
            (
                snippet.text,
                map_snippet_origin(snippet.origin),
                snippet.truncated,
                snippet.line_start,
                snippet.line_end,
            )
        } else {
            (
                snapshot.summary.clone(),
                SearchSnippetOrigin::Summary,
                false,
                None,
                None,
            )
        };
    Ok(Some(Hit {
        doc_id: snapshot.doc_id.clone(),
        rel_path: snapshot.rel_path.clone(),
        path: snapshot.rel_path.clone(),
        kind: snapshot.kind,
        score: AST_SCORE_BASE + boost,
        summary: snapshot.summary,
        snippet: snippet_text,
        token_estimate: snapshot.token_estimate,
        snippet_origin: Some(snippet_origin),
        snippet_truncated: Some(snippet_truncated),
        line_start,
        line_end,
    }))
}

fn map_snippet_origin(origin: SnippetOrigin) -> SearchSnippetOrigin {
    match origin {
        SnippetOrigin::Query => SearchSnippetOrigin::Query,
        SnippetOrigin::Preview => SearchSnippetOrigin::Preview,
    }
}

fn symbol_match_snippet(symbol_match: &SymbolSearchMatch) -> String {
    const MAX_SYMBOLS: usize = 6;
    let mut labels = Vec::new();
    for symbol in symbol_match.symbols.iter().take(MAX_SYMBOLS) {
        let label = if let Some(signature) = symbol.signature.as_ref() {
            let trimmed = signature.trim();
            if trimmed.is_empty() {
                format!("{} {}", symbol.kind, symbol.name)
            } else {
                trimmed.to_string()
            }
        } else {
            format!("{} {}", symbol.kind, symbol.name)
        };
        labels.push(label);
    }
    if labels.is_empty() {
        return String::new();
    }
    format!("Symbols: {}", labels.join(", "))
}

struct AstQueryKinds {
    kinds: Vec<String>,
    labels: Vec<String>,
}

fn extract_ast_query_kinds(query: &str) -> AstQueryKinds {
    const MAX_TOKENS: usize = 6;
    let mut labels = Vec::new();
    let mut kinds = Vec::new();
    let mut seen_labels = std::collections::HashSet::new();
    let mut seen_kinds = std::collections::HashSet::new();

    for raw in query.split_whitespace() {
        for part in raw.split(|ch: char| !ch.is_alphanumeric() && ch != '_') {
            let trimmed = part.trim();
            if trimmed.len() < 2 {
                continue;
            }
            let token = trimmed.to_lowercase();
            if seen_labels.len() >= MAX_TOKENS {
                break;
            }
            if !seen_labels.contains(&token) {
                if let Some(kinds_for_token) = ast_kinds_for_token(&token) {
                    seen_labels.insert(token.clone());
                    labels.push(token.clone());
                    for kind in kinds_for_token {
                        if seen_kinds.insert(kind.to_string()) {
                            kinds.push(kind.to_string());
                        }
                    }
                }
            }
        }
        if seen_labels.len() >= MAX_TOKENS {
            break;
        }
    }

    AstQueryKinds { kinds, labels }
}

fn ast_kinds_for_token(token: &str) -> Option<&'static [&'static str]> {
    match token {
        "function" | "fn" | "method" => Some(&[
            "function_item",
            "function_definition",
            "function_declaration",
            "method_definition",
            "method_declaration",
            "arrow_function",
        ]),
        "class" => Some(&[
            "class_definition",
            "class_declaration",
            "class_item",
        ]),
        "struct" => Some(&["struct_item", "struct_declaration"]),
        "enum" => Some(&["enum_item", "enum_declaration"]),
        "interface" => Some(&["interface_declaration"]),
        "trait" => Some(&["trait_item"]),
        "module" | "mod" => Some(&["mod_item", "module"]),
        "import" | "require" | "include" | "use" => Some(&[
            "import_statement",
            "import_declaration",
            "import_clause",
            "use_declaration",
            "include_macro_invocation",
        ]),
        "const" => Some(&["const_item", "const_declaration", "constant_declaration"]),
        "type" => Some(&["type_alias_declaration", "type_item", "type_definition"]),
        _ => None,
    }
}

fn sort_hits_deterministically(hits: &mut [Hit]) {
    hits.sort_by(|a, b| {
        let score_cmp = b.score.total_cmp(&a.score);
        if score_cmp != std::cmp::Ordering::Equal {
            return score_cmp;
        }
        let path_cmp = a.rel_path.cmp(&b.rel_path);
        if path_cmp != std::cmp::Ordering::Equal {
            return path_cmp;
        }
        a.doc_id.cmp(&b.doc_id)
    });
}

fn resolve_symbol_ranking_enabled(surface: RankingSurface) -> bool {
    let env_key = match surface {
        RankingSurface::Search => "DOCDEX_ENABLE_SYMBOL_RANKING",
        RankingSurface::Chat => "DOCDEX_ENABLE_CHAT_SYMBOL_RANKING",
    };
    env_boolish(env_key)
        .or_else(|| config_symbol_ranking_enabled(surface))
        .unwrap_or(true)
}

fn resolve_ast_ranking_enabled(surface: RankingSurface) -> bool {
    let env_key = match surface {
        RankingSurface::Search => "DOCDEX_ENABLE_AST_RANKING",
        RankingSurface::Chat => "DOCDEX_ENABLE_CHAT_AST_RANKING",
    };
    env_boolish(env_key)
        .or_else(|| config_ast_ranking_enabled(surface))
        .unwrap_or(true)
}

fn config_symbol_ranking_enabled(surface: RankingSurface) -> Option<bool> {
    let search = load_search_config()?;
    Some(match surface {
        RankingSurface::Search => search.symbol_ranking_enabled,
        RankingSurface::Chat => search.chat_symbol_ranking_enabled,
    })
}

fn config_ast_ranking_enabled(surface: RankingSurface) -> Option<bool> {
    let search = load_search_config()?;
    Some(match surface {
        RankingSurface::Search => search.ast_ranking_enabled,
        RankingSurface::Chat => search.chat_ast_ranking_enabled,
    })
}

fn load_search_config() -> Option<config::SearchConfig> {
    let path = config::default_config_path().ok()?;
    if !path.exists() {
        return None;
    }
    let config = config::load_config_from_path(&path).ok()?;
    Some(config.search)
}

fn env_boolish(key: &str) -> Option<bool> {
    let raw = std::env::var(key).ok()?;
    let trimmed = raw.trim().to_lowercase();
    if trimmed.is_empty() {
        return None;
    }
    match trimmed.as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

pub(crate) fn normalize_score(score: f32) -> f32 {
    if !score.is_finite() {
        return 0.0;
    }
    if score <= 0.0 {
        return 0.0;
    }
    (score / (score + TOP_SCORE_NORMALIZATION_K)).clamp(0.0, 1.0)
}

fn merge_hits(repo_hits: Vec<Hit>, libs_hits: Vec<Hit>, limit: usize) -> Vec<Hit> {
    if libs_hits.is_empty() {
        return repo_hits;
    }
    if repo_hits.is_empty() {
        return libs_hits.into_iter().take(limit).collect();
    }
    let repo_max = repo_hits
        .first()
        .map(|h| h.score)
        .unwrap_or(0.0)
        .max(0.0001);
    let libs_max = libs_hits
        .first()
        .map(|h| h.score)
        .unwrap_or(0.0)
        .max(0.0001);

    struct Ranked {
        rank: f32,
        hit: Hit,
    }

    let mut repo_ranked: Vec<Ranked> = repo_hits
        .into_iter()
        .map(|hit| Ranked {
            rank: (hit.score / repo_max) * 1.0,
            hit,
        })
        .collect();
    repo_ranked.sort_by(|a, b| {
        b.rank
            .partial_cmp(&a.rank)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.hit.doc_id.cmp(&b.hit.doc_id))
    });
    let mut libs_ranked: Vec<Ranked> = libs_hits
        .into_iter()
        .map(|hit| Ranked {
            rank: (hit.score / libs_max) * 0.95,
            hit,
        })
        .collect();
    libs_ranked.sort_by(|a, b| {
        b.rank
            .partial_cmp(&a.rank)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.hit.doc_id.cmp(&b.hit.doc_id))
    });

    let mut ordered: Vec<Hit> = Vec::with_capacity(limit);
    for ranked in repo_ranked {
        if ordered.len() >= limit {
            return ordered;
        }
        ordered.push(ranked.hit);
    }
    for ranked in libs_ranked {
        if ordered.len() >= limit {
            break;
        }
        ordered.push(ranked.hit);
    }
    ordered
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
    headers: HeaderMap,
    Query(params): Query<SearchParams>,
) -> impl IntoResponse {
    if let Err(err) = resolve_repo_id(
        &headers,
        params.repo_id.as_deref(),
        None,
        state.indexer.as_ref(),
        false,
    ) {
        return json_error(err.status, err.code, err.message).into_response();
    }
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
    let diff_paths = params
        .diff_path
        .iter()
        .map(|path| std::path::PathBuf::from(path))
        .collect::<Vec<_>>();
    let diff_request = match diff::resolve_diff_request(
        params.diff_mode,
        params.diff_base.clone(),
        params.diff_head.clone(),
        diff_paths,
    ) {
        Ok(value) => value,
        Err(err) => {
            return json_error(
                StatusCode::BAD_REQUEST,
                ERR_INVALID_ARGUMENT,
                err.to_string(),
            )
            .into_response();
        }
    };

    let request_id_value = request_id.0;
    let request_id_str = request_id_value.as_str();
    let plan = WaterfallPlan::new(
        WebGateConfig::from_env(),
        Tier2Config::enabled(),
        memory_budget_from_max_answer_tokens(state.max_answer_tokens),
        ProfileBudget::default(),
    );
    let force_web = params.force_web.unwrap_or(false);
    let skip_local_search = params.skip_local_search.unwrap_or(false);
    let disable_web_cache = params.no_cache.unwrap_or(false);
    let llm_filter_local_results = params.llm_filter_local_results.unwrap_or(false);

    match run_waterfall(WaterfallRequest {
        request_id: request_id_str,
        query,
        limit,
        diff: diff_request,
        web_limit: params.max_web_results,
        force_web,
        skip_local_search,
        disable_web_cache,
        llm_filter_local_results,
        llm_model: params.llm_model.as_deref(),
        llm_agent: params.llm_agent.as_deref(),
        indexer: state.indexer.as_ref(),
        libs_indexer,
        plan,
        tier2_limiter: None,
        memory: state.memory.as_ref(),
        profile_state: state.profile_state.as_ref(),
        profile_agent_id: None,
        ranking_surface: RankingSurface::Search,
    })
    .await
    {
        Ok(waterfall_result) => {
            let mut response = waterfall_result.search_response;
            let mut hits = std::mem::take(&mut response.hits);
            let query_meta = response
                .meta
                .as_ref()
                .and_then(|meta| meta.query.clone());
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
                            reason: format!(
                                "token_estimate {}/{} exceeds max_tokens",
                                hit.token_estimate, budget
                            ),
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
            let meta = build_search_meta(&state.indexer, query_meta, Some(context_assembly)).ok();
            let top_score_normalized = top_score.map(normalize_score);
            let web_context = web_context_from_status(&waterfall_result.tier2.status);
            response.hits = hits;
            response.top_score = top_score;
            response.top_score_camel = top_score;
            response.top_score_normalized = top_score_normalized;
            response.top_score_normalized_camel = top_score_normalized;
            response.web_context = web_context;
            response.web_discovery = Some(waterfall_result.tier2.status);
            response.impact_context = waterfall_result.impact_context;
            response.memory_context = waterfall_result.memory_context;
            response.meta = meta;
            Json(response)
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
                request_id = %request_id_value,
                limit,
                "search handler failed"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("internal error (request id: {})", request_id_value),
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
    #[serde(default)]
    repo_id: Option<String>,
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
    headers: HeaderMap,
    Query(params): Query<SnippetParams>,
) -> impl IntoResponse {
    if let Err(err) = resolve_repo_id(
        &headers,
        params.repo_id.as_deref(),
        None,
        state.indexer.as_ref(),
        false,
    ) {
        return json_error(err.status, err.code, err.message).into_response();
    }
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
            if let Err(err) = limiter.check_or_rate_limited(addr.ip(), "http_ip", "ip") {
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
