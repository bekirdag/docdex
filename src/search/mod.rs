use crate::index::{DocSnapshot, Hit, Indexer, SnippetOrigin, SnippetResult};
use anyhow::{anyhow, Result};
use axum::body::HttpBody;
use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::{header::CONTENT_LENGTH, HeaderMap, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Json, Response},
    routing::get,
    Router,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tracing::warn;
use uuid::Uuid;

const DEFAULT_SNIPPET_WINDOW: usize = 40;
const MIN_SNIPPET_WINDOW: usize = 10;
const MAX_SNIPPET_WINDOW: usize = 400;

#[derive(Clone)]
pub struct RateLimiter {
    inner: Arc<parking_lot::Mutex<HashMap<IpAddr, RateBucket>>>,
    refill_per_sec: f64,
    capacity: f64,
}

#[derive(Clone, Copy)]
struct RateBucket {
    tokens: f64,
    last: Instant,
}

impl RateLimiter {
    pub fn new(per_minute: u32, burst: u32) -> Self {
        let capacity = if burst == 0 {
            per_minute as f64
        } else {
            burst as f64
        }
        .max(1.0);
        let refill_per_sec = per_minute as f64 / 60.0;
        Self {
            inner: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            refill_per_sec,
            capacity,
        }
    }

    pub fn allow(&self, ip: IpAddr) -> bool {
        let mut guard = self.inner.lock();
        let now = Instant::now();
        let bucket = guard.entry(ip).or_insert(RateBucket {
            tokens: self.capacity,
            last: now,
        });
        let elapsed = now.duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        bucket.last = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[derive(Clone)]
pub struct SecurityConfig {
    pub auth_token: Option<String>,
    pub allow_nets: Vec<ipnet::IpNet>,
    pub max_limit: usize,
    pub max_query_bytes: usize,
    pub max_request_bytes: usize,
    pub rate_limit: Option<RateLimiter>,
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
        let mut allow_nets: Vec<ipnet::IpNet> = allow_ips
            .iter()
            .map(|raw| raw.trim())
            .filter(|raw| !raw.is_empty())
            .map(|raw| raw.parse::<ipnet::IpNet>().map_err(|err| anyhow!(err)))
            .collect::<Result<Vec<_>>>()?;
        if secure_mode && allow_nets.is_empty() {
            allow_nets.push("127.0.0.0/8".parse()?);
            if let Ok(ipv6) = "::1/128".parse() {
                allow_nets.push(ipv6);
            }
        }
        let auth_token = token.filter(|value| !value.is_empty());
        if secure_mode && auth_token.is_none() {
            return Err(anyhow!(
                "secure mode requires an auth token; provide --auth-token or disable with --secure-mode=false"
            ));
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
    pub security: SecurityConfig,
    pub access_log: bool,
    pub audit: Option<crate::audit::AuditLogger>,
    pub metrics: Arc<Metrics>,
}

#[derive(Clone)]
pub struct RequestId(pub String);

#[derive(Default)]
pub struct Metrics {
    pub rate_limit_denies: AtomicU64,
    pub auth_denies: AtomicU64,
    pub error_count: AtomicU64,
}

impl Metrics {
    fn inc_rate_limit(&self) {
        self.rate_limit_denies.fetch_add(1, Ordering::Relaxed);
    }
    fn inc_auth_deny(&self) {
        self.auth_denies.fetch_add(1, Ordering::Relaxed);
    }
    fn inc_error(&self) {
        self.error_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn render_prometheus(&self) -> String {
        format!(
            concat!(
                "# HELP docdex_rate_limit_denies_total Rate limit denials\n",
                "# TYPE docdex_rate_limit_denies_total counter\n",
                "docdex_rate_limit_denies_total {}\n",
                "# HELP docdex_auth_denies_total Auth denials\n",
                "# TYPE docdex_auth_denies_total counter\n",
                "docdex_auth_denies_total {}\n",
                "# HELP docdex_errors_total Handler errors\n",
                "# TYPE docdex_errors_total counter\n",
                "docdex_errors_total {}\n",
            ),
            self.rate_limit_denies.load(Ordering::Relaxed),
            self.auth_denies.load(Ordering::Relaxed),
            self.error_count.load(Ordering::Relaxed)
        )
    }
}

pub fn router(state: AppState) -> Router {
    let mut router = Router::new()
        .route("/healthz", get(healthz))
        .route("/search", get(search_handler))
        .route("/snippet/*doc_id", get(snippet_handler))
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
struct AiHelpPayload {
    product: &'static str,
    version: &'static str,
    purpose: &'static str,
    http_endpoints: Vec<AiHelpEndpoint>,
    cli_commands: Vec<AiHelpCli>,
    best_practices: Vec<&'static str>,
    limits: AiHelpLimits,
}

fn rate_limit_hint(security: &SecurityConfig) -> Option<u32> {
    security.rate_limit.as_ref().map(|lim| {
        // refill_per_sec is tokens/min / 60
        (lim.refill_per_sec * 60.0).round() as u32
    })
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
        ],
        limits: AiHelpLimits {
            max_limit: state.security.max_limit,
            max_query_bytes: state.security.max_query_bytes,
            max_request_bytes: state.security.max_request_bytes,
            rate_limit_per_min: rate_limit_hint(&state.security),
            auth_required: state.security.auth_token.is_some(),
            snippet_html_disabled: state.security.disable_snippet_text || state.security.strip_snippet_html,
        },
    };
    Json(payload)
}

#[derive(Deserialize)]
struct SearchParams {
    q: String,
    limit: Option<usize>,
    snippets: Option<bool>,
    max_tokens: Option<u64>,
}

#[derive(Serialize)]
pub struct SearchResponse {
    pub hits: Vec<Hit>,
}

pub async fn run_query(indexer: &Indexer, query: &str, limit: usize) -> Result<SearchResponse> {
    let hits = indexer.search(query, limit)?;
    Ok(SearchResponse { hits })
}

async fn search_handler(
    State(state): State<AppState>,
    axum::extract::Extension(request_id): axum::extract::Extension<RequestId>,
    Query(params): Query<SearchParams>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(8).min(state.security.max_limit);
    match state.indexer.search(&params.q, limit) {
        Ok(mut hits) => {
            if params.snippets == Some(false) || state.security.disable_snippet_text {
                for hit in hits.iter_mut() {
                    hit.snippet.clear();
                }
            }
            if let Some(max_tokens) = params.max_tokens {
                hits.retain(|hit| hit.token_estimate <= max_tokens);
            }
            if state.security.disable_snippet_text {
                for hit in hits.iter_mut() {
                    hit.snippet.clear();
                }
            }
            Json(SearchResponse { hits }).into_response()
        }
        Err(err) => {
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
    match state
        .indexer
        .snapshot_with_snippet(&doc_id, params.q.as_deref(), window)
    {
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
        }
    })
}

async fn security_middleware(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    axum::extract::Extension(request_id): axum::extract::Extension<RequestId>,
    request: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Result<Response, (StatusCode, HeaderMap)> {
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
        return Err((StatusCode::FORBIDDEN, HeaderMap::new()));
    }
    if path != "/healthz" {
        if let Some(limiter) = state.security.rate_limit.as_ref() {
            if !limiter.allow(addr.ip()) {
                state.metrics.inc_rate_limit();
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
                return Err((StatusCode::TOO_MANY_REQUESTS, HeaderMap::new()));
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
                    return Err((StatusCode::PAYLOAD_TOO_LARGE, HeaderMap::new()));
                }
            }
            if let Some(upper) = size_hint.upper() {
                if upper as usize > state.security.max_request_bytes {
                    return Err((StatusCode::PAYLOAD_TOO_LARGE, HeaderMap::new()));
                }
            }
        }
        if state.security.max_query_bytes > 0 {
            if let Some(query) = request.uri().query() {
                if query.len() > state.security.max_query_bytes {
                    return Err((StatusCode::PAYLOAD_TOO_LARGE, HeaderMap::new()));
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
            return Err((StatusCode::UNAUTHORIZED, hdrs));
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
