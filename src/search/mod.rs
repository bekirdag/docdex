use crate::auth::{AuthRuntime, RepoOperation};
use crate::capabilities::{self, BATCH_SEARCH_MAX_QUERIES, RERANK_MAX_CANDIDATES};
use crate::config;
use crate::diff;
use crate::error::{
    status_for_app_error, AppError, StartupError, ERR_INDEXING_IN_PROGRESS, ERR_INTERNAL_ERROR,
    ERR_INVALID_ARGUMENT, ERR_MEMORY_DISABLED,
};
use crate::http_api::{
    json_error, json_error_with_details, repo_error_response, resolve_repo_context, ErrorBody,
    ErrorDetail,
};
use crate::index::{
    build_hit_provenance, build_hit_score_breakdown, build_retrieval_explanation, DocSnapshot, Hit,
    Indexer, QueryRewrite, SearchError, SearchQueryMeta, SearchSnippetOrigin, SnippetOrigin,
    SnippetResult,
};
use crate::libs::LibsIndexer;
use crate::mcp::McpProxyRouter;
use crate::memory::{
    filter_memory_items_by_repo, inject_embedding_metadata, inject_repo_metadata, MemoryStore,
};
use crate::ollama::OllamaEmbedder;
use crate::orchestrator::web::{web_context_from_status, WebDiscoveryStatus, WebFetchResult};
use crate::orchestrator::{
    memory_budget_from_max_answer_tokens, run_waterfall, MemoryContextAssembly, ProfileBudget,
    SymbolContextAssembly, WaterfallPlan, WaterfallRequest, WebGateConfig,
};
use crate::personal_preferences::PersonalPreferencesStore;
use crate::profiles::{ProfileEmbedder, ProfileManager};
use crate::ratelimit::RateLimiter;
use crate::repo_manager;
use crate::symbols::SymbolSearchMatch;
use crate::tier2::Tier2Config;
use anyhow::Result;
use axum::body::HttpBody;
use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::{header::CONTENT_LENGTH, HeaderMap, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Json, Response},
    routing::{delete, get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::path::{Component, Path as FsPath, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use tracing::{info, warn};
use uuid::Uuid;

#[cfg(test)]
#[path = "tests.rs"]
mod tests;

const DEFAULT_SNIPPET_WINDOW: usize = 40;
const MIN_SNIPPET_WINDOW: usize = 10;
const MAX_SNIPPET_WINDOW: usize = 400;
const DAG_SESSION_HEADER: &str = "x-docdex-dag-session";
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
const AST_SCORE_PER_MATCH: f32 = 0.15;
const AST_SCORE_MAX_BOOST: f32 = 0.3;
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
        if !secure_mode && rate_limit_per_min == 0 && rate_limit_burst > 0 {
            return Err(StartupError::new(
                "startup_config_invalid",
                "rate limit burst requires a non-zero rate limit per minute",
            )
            .with_hint(
                "Set --rate-limit-per-min (or omit --rate-limit-burst) when secure mode is disabled.",
            )
            .into());
        }
        if require_auth_token && auth_token.is_none() {
            return Err(StartupError::new(
                "startup_auth_required",
                "exposed mode requires an auth token",
            )
            .with_hint(
                "Provide `--auth-token <token>` when binding to non-loopback addresses (or bind to 127.0.0.1).",
            )
            .with_remediation(vec![
                "docdexd serve --repo . --host 0.0.0.0 --port 28491 --expose --auth-token <token> --require-tls=false".to_string(),
                "docdexd serve --repo . --host 127.0.0.1 --port 28491".to_string(),
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
    pub repo_id: String,
    pub legacy_repo_id: String,
    pub indexer: Arc<Indexer>,
    pub libs_indexer: Option<Arc<LibsIndexer>>,
    pub security: SecurityConfig,
    pub access_log: bool,
    pub audit: Option<crate::audit::AuditLogger>,
    pub metrics: Arc<crate::metrics::Metrics>,
    pub delegation_metrics: Arc<crate::metrics::DelegationMetrics>,
    pub memory: Option<MemoryState>,
    pub conversations: Option<ConversationState>,
    pub personal_preferences: Option<PersonalPreferencesState>,
    pub profile_state: Option<ProfileState>,
    pub features: crate::config::FeatureFlagsConfig,
    pub auth: AuthRuntime,
    pub repo_encryption: crate::repo_encryption::RepoEncryptionConfig,
    pub default_agent_id: Option<String>,
    pub max_answer_tokens: u32,
    pub llm_config: config::LlmConfig,
    pub llm_base_url: String,
    pub llm_default_model: String,
    pub global_state_dir: Option<PathBuf>,
    pub repos: Option<Arc<crate::daemon::multi_repo::RepoManager>>,
    pub multi_repo: bool,
    pub require_repo_id: bool,
    pub mcp_router: Option<Arc<McpProxyRouter>>,
}

#[derive(Clone)]
pub(crate) struct RepoContext {
    pub repo_id: String,
    pub legacy_repo_id: String,
    pub indexer: Arc<Indexer>,
    pub libs_indexer: Option<Arc<LibsIndexer>>,
    pub memory: Option<MemoryState>,
    pub conversations: Option<ConversationState>,
    pub delegation_metrics: Arc<crate::metrics::DelegationMetrics>,
}

impl RepoContext {
    pub(crate) fn matches_id(&self, candidate: &str) -> bool {
        candidate == self.repo_id || candidate == self.legacy_repo_id
    }
}

#[derive(Clone)]
pub(crate) struct ConversationNamespaceContext {
    pub namespace: String,
    pub conversations: Option<ConversationState>,
}

#[derive(Clone)]
pub(crate) enum ConversationRequestContext {
    Repo(RepoContext),
    Namespace(ConversationNamespaceContext),
}

impl ConversationRequestContext {
    pub(crate) fn conversations(&self) -> Option<ConversationState> {
        match self {
            Self::Repo(repo) => repo.conversations.clone(),
            Self::Namespace(namespace) => namespace.conversations.clone(),
        }
    }

    pub(crate) fn repo(&self) -> Option<&RepoContext> {
        match self {
            Self::Repo(repo) => Some(repo),
            Self::Namespace(_) => None,
        }
    }

    pub(crate) fn repo_memory_target(
        &self,
    ) -> Option<crate::conversations::ConversationRepoMemoryTarget> {
        self.repo().and_then(|repo| {
            repo.memory.as_ref().map(
                |memory| crate::conversations::ConversationRepoMemoryTarget {
                    repo_id: repo.repo_id.clone(),
                    store: memory.store.clone(),
                    embedder: memory.embedder.clone(),
                    fallback_dim: 0,
                },
            )
        })
    }

    pub(crate) fn scope_label(&self) -> String {
        match self {
            Self::Repo(repo) => repo.indexer.repo_root().display().to_string(),
            Self::Namespace(namespace) => {
                format!("conversation_namespace:{}", namespace.namespace)
            }
        }
    }

    pub(crate) fn scope_id(&self) -> String {
        match self {
            Self::Repo(repo) => repo.repo_id.clone(),
            Self::Namespace(namespace) => format!("namespace:{}", namespace.namespace),
        }
    }
}

#[derive(Clone)]
pub struct RequestId(pub String);

#[derive(Clone)]
pub struct MemoryState {
    pub store: MemoryStore,
    pub embedder: OllamaEmbedder,
    pub repo_id: String,
}

#[derive(Clone)]
pub struct ConversationState {
    pub store: crate::conversations::ConversationStore,
    pub knowledge: crate::knowledge::KnowledgeStore,
    pub config: crate::config::MemoryConversationConfig,
    pub max_wakeup_tokens: usize,
    pub max_episodic_summaries: usize,
    pub max_knowledge_facts: usize,
    pub max_transcript_snippets: usize,
}

#[derive(Clone)]
pub struct ProfileState {
    pub manager: ProfileManager,
    pub embedder: Option<ProfileEmbedder>,
}

#[derive(Clone)]
pub struct PersonalPreferencesState {
    pub store: PersonalPreferencesStore,
    pub config: crate::config::MemoryPersonalPreferencesConfig,
}

pub fn router(state: AppState) -> Router {
    let mut router = Router::new()
        .route("/healthz", get(healthz))
        .route("/search", get(search_handler))
        .route("/v1/capabilities", get(capabilities_handler))
        .route(
            "/v1/admin/repos/provision",
            post(crate::api::v1::admin::admin_repo_provision_handler),
        )
        .route(
            "/v1/admin/repos/:repo_id",
            delete(crate::api::v1::admin::admin_repo_delete_handler),
        )
        .route(
            "/v1/admin/repos/:repo_id/access-bindings",
            axum::routing::put(crate::api::v1::admin::admin_repo_access_bindings_handler),
        )
        .route(
            "/v1/admin/repos/:repo_id/documents/ingest",
            post(crate::api::v1::admin::admin_repo_documents_ingest_handler),
        )
        .route(
            "/v1/admin/auth/cache/invalidate",
            post(crate::api::v1::admin::admin_auth_cache_invalidate_handler),
        )
        .route("/v1/search/rerank", post(rerank_handler))
        .route("/v1/search/batch", post(batch_search_handler))
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
            "/v1/profile/delete",
            post(crate::api::v1::profile::profile_delete_handler),
        )
        .route(
            "/v1/profile/import",
            post(crate::api::v1::profile::profile_import_handler),
        )
        .route(
            "/v1/personal-preferences/status",
            get(crate::api::v1::personal_preferences::personal_preferences_status_handler),
        )
        .route(
            "/v1/personal-preferences/categories",
            get(crate::api::v1::personal_preferences::personal_preferences_categories_handler),
        )
        .route(
            "/v1/personal-preferences/captures",
            get(crate::api::v1::personal_preferences::personal_preferences_list_captures_handler),
        )
        .route(
            "/v1/personal-preferences/captures/:capture_id",
            get(crate::api::v1::personal_preferences::personal_preferences_read_capture_handler)
                .delete(crate::api::v1::personal_preferences::personal_preferences_delete_handler),
        )
        .route(
            "/v1/personal-preferences/captures/:capture_id/redact",
            post(crate::api::v1::personal_preferences::personal_preferences_redact_handler),
        )
        .route(
            "/v1/personal-preferences/search",
            get(crate::api::v1::personal_preferences::personal_preferences_search_handler)
                .post(
                    crate::api::v1::encrypted_search_compat::personal_preferences_search_alias_handler,
                ),
        )
        .route(
            "/v1/personal-preferences/read",
            post(crate::api::v1::encrypted_search_compat::personal_preferences_read_alias_handler),
        )
        .route(
            "/v1/personal-preferences/write",
            post(crate::api::v1::encrypted_search_compat::personal_preferences_write_alias_handler),
        )
        .route(
            "/v1/personal-preferences/evaluate",
            post(crate::api::v1::encrypted_search_compat::personal_preferences_evaluate_alias_handler),
        )
        .route(
            "/v1/personal-preferences/delete",
            post(crate::api::v1::encrypted_search_compat::personal_preferences_delete_alias_handler),
        )
        .route(
            "/v1/personal-preferences/claims",
            get(crate::api::v1::personal_preferences::personal_preferences_claims_handler),
        )
        .route(
            "/v1/personal-preferences/claims/:claim_id",
            get(crate::api::v1::personal_preferences::personal_preferences_claim_read_handler),
        )
        .route(
            "/v1/personal-preferences/claims/:claim_id/review",
            post(crate::api::v1::personal_preferences::personal_preferences_claim_review_handler),
        )
        .route(
            "/v1/personal-preferences/claims/:claim_id/override",
            post(crate::api::v1::personal_preferences::personal_preferences_claim_override_handler),
        )
        .route(
            "/v1/personal-preferences/claims/:claim_id/forget",
            post(crate::api::v1::personal_preferences::personal_preferences_claim_forget_handler),
        )
        .route(
            "/v1/personal-preferences/feedback",
            post(crate::api::v1::personal_preferences::personal_preferences_feedback_handler),
        )
        .route(
            "/v1/personal-preferences/snapshots",
            get(crate::api::v1::personal_preferences::personal_preferences_snapshots_handler),
        )
        .route(
            "/v1/personal-preferences/snapshots/:snapshot_id",
            get(crate::api::v1::personal_preferences::personal_preferences_snapshot_read_handler),
        )
        .route(
            "/v1/personal-preferences/snapshots/rebuild",
            post(
                crate::api::v1::personal_preferences::personal_preferences_snapshots_rebuild_handler,
            ),
        )
        .route(
            "/v1/personal-preferences/clone/context",
            post(
                crate::api::v1::personal_preferences::personal_preferences_clone_context_handler,
            ),
        )
        .route(
            "/v1/personal-preferences/clone/explain",
            post(
                crate::api::v1::personal_preferences::personal_preferences_clone_explain_handler,
            ),
        )
        .route(
            "/v1/personal-preferences/clone/evaluate",
            post(
                crate::api::v1::personal_preferences::personal_preferences_clone_evaluate_handler,
            ),
        )
        .route(
            "/v1/personal-preferences/reviews",
            get(crate::api::v1::personal_preferences::personal_preferences_reviews_handler),
        )
        .route(
            "/v1/personal-preferences/reviews/:record_id",
            get(crate::api::v1::personal_preferences::personal_preferences_review_log_handler)
                .post(crate::api::v1::personal_preferences::personal_preferences_review_handler),
        )
        .route(
            "/v1/personal-preferences/process",
            post(crate::api::v1::personal_preferences::personal_preferences_process_handler),
        )
        .route(
            "/v1/personal-preferences/scan",
            post(crate::api::v1::personal_preferences::personal_preferences_scan_handler),
        )
        .route(
            "/v1/personal-preferences/prune",
            post(crate::api::v1::personal_preferences::personal_preferences_prune_handler),
        )
        .route(
            "/v1/personal-preferences/export",
            post(crate::api::v1::personal_preferences::personal_preferences_export_handler),
        )
        .route(
            "/v1/personal-preferences/purge",
            post(crate::api::v1::personal_preferences::personal_preferences_purge_handler),
        )
        .route(
            "/v1/delegate",
            post(crate::api::v1::delegate::delegate_handler),
        )
        .route(
            "/v1/telemetry/delegation",
            get(crate::api::v1::telemetry::delegation_telemetry_handler),
        )
        .route(
            "/v1/initialize",
            post(crate::api::v1::initialize::initialize_handler),
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
            "/v1/impact/diagnostics",
            get(crate::api::v1::graph::impact_diagnostics_handler),
        )
        .route("/v1/symbols", get(crate::api::v1::symbols::symbols_handler))
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
            "/v1/index",
            post(crate::api::v1::encrypted_search_compat::index_compat_handler),
        )
        .route(
            "/v1/index/jobs/:job_id",
            get(crate::api::v1::encrypted_search_compat::index_job_handler),
        )
        .route(
            "/v1/index/ingest",
            post(crate::api::v1::index::index_ingest_handler),
        )
        .route(
            "/v1/index/status",
            get(crate::api::v1::index::index_status_handler),
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
            "/v1/rag",
            post(crate::api::v1::encrypted_search_compat::rag_handler),
        )
        .route(
            "/v1/web/cache/flush",
            post(crate::api::v1::web::web_cache_flush_handler),
        )
        .route(
            "/v1/tree",
            get(crate::api::v1::encrypted_search_compat::tree_handler),
        )
        .route(
            "/v1/files",
            get(crate::api::v1::encrypted_search_compat::files_handler),
        )
        .route(
            "/v1/stats",
            get(crate::api::v1::encrypted_search_compat::stats_handler),
        )
        .route(
            "/v1/repo/inspect",
            get(crate::api::v1::encrypted_search_compat::repo_inspect_handler),
        )
        .route("/v1/memory/store", post(memory_store_handler))
        .route("/v1/memory/recall", post(memory_recall_handler))
        .route("/v1/memory/delete", post(memory_delete_handler))
        .route(
            "/v1/memory/repo/recall",
            post(crate::api::v1::encrypted_search_compat::repo_memory_recall_alias_handler),
        )
        .route(
            "/v1/memory/repo/save",
            post(crate::api::v1::encrypted_search_compat::repo_memory_save_alias_handler),
        )
        .route(
            "/v1/memory/repo/delete",
            post(crate::api::v1::encrypted_search_compat::repo_memory_delete_alias_handler),
        )
        .route(
            "/v1/memory/profile/get",
            post(crate::api::v1::encrypted_search_compat::profile_get_alias_handler),
        )
        .route(
            "/v1/memory/profile/save",
            post(crate::api::v1::encrypted_search_compat::profile_save_alias_handler),
        )
        .route(
            "/v1/memory/profile/delete",
            post(crate::api::v1::encrypted_search_compat::profile_delete_alias_handler),
        )
        .route(
            "/v1/memory/layers",
            get(crate::api::v1::memory_layers::memory_layers_handler),
        )
        .route(
            "/v1/memory/route",
            post(crate::api::v1::memory_layers::memory_route_handler),
        )
        .route(
            "/v1/diary/write",
            post(crate::api::v1::diary::diary_write_handler),
        )
        .route(
            "/v1/diary/read",
            get(crate::api::v1::diary::diary_read_handler)
                .post(crate::api::v1::encrypted_search_compat::diary_read_alias_handler),
        )
        .route(
            "/v1/diary/delete",
            post(crate::api::v1::diary::diary_delete_handler),
        )
        .route(
            "/v1/conversations",
            get(crate::api::v1::conversations::conversation_list_handler),
        )
        .route(
            "/v1/conversations/list",
            post(crate::api::v1::encrypted_search_compat::conversation_list_alias_handler),
        )
        .route(
            "/v1/conversations/search",
            get(crate::api::v1::conversations::conversation_search_handler)
                .post(crate::api::v1::encrypted_search_compat::conversation_search_alias_handler),
        )
        .route(
            "/v1/conversations/import",
            post(crate::api::v1::conversations::conversation_import_handler),
        )
        .route(
            "/v1/conversations/prune",
            post(crate::api::v1::conversations::conversation_prune_handler),
        )
        .route(
            "/v1/conversations/:session_id",
            get(crate::api::v1::conversations::conversation_read_handler)
                .delete(crate::api::v1::conversations::conversation_delete_handler),
        )
        .route(
            "/v1/conversations/:session_id/export",
            get(crate::api::v1::conversations::conversation_export_handler),
        )
        .route(
            "/v1/conversations/:session_id/redact",
            post(crate::api::v1::conversations::conversation_redact_handler),
        )
        .route(
            "/v1/conversations/read",
            post(crate::api::v1::encrypted_search_compat::conversation_read_alias_handler),
        )
        .route(
            "/v1/conversations/export",
            post(crate::api::v1::encrypted_search_compat::conversation_export_alias_handler),
        )
        .route(
            "/v1/conversations/redact",
            post(crate::api::v1::encrypted_search_compat::conversation_redact_alias_handler),
        )
        .route(
            "/v1/conversations/delete",
            post(crate::api::v1::encrypted_search_compat::conversation_delete_alias_handler),
        )
        .route(
            "/v1/kg/query",
            get(crate::api::v1::kg::kg_query_handler)
                .post(crate::api::v1::encrypted_search_compat::kg_query_alias_handler),
        )
        .route(
            "/v1/kg/search/nodes",
            get(crate::api::v1::kg::kg_search_nodes_handler),
        )
        .route(
            "/v1/kg/search-nodes",
            post(crate::api::v1::encrypted_search_compat::kg_search_nodes_alias_handler),
        )
        .route(
            "/v1/kg/search/edges",
            get(crate::api::v1::kg::kg_search_edges_handler),
        )
        .route(
            "/v1/kg/search-edges",
            post(crate::api::v1::encrypted_search_compat::kg_search_edges_alias_handler),
        )
        .route(
            "/v1/kg/search/episodes",
            get(crate::api::v1::kg::kg_search_episodes_handler),
        )
        .route(
            "/v1/kg/search-episodes",
            post(crate::api::v1::encrypted_search_compat::kg_search_episodes_alias_handler),
        )
        .route(
            "/v1/kg/timeline",
            get(crate::api::v1::kg::kg_timeline_handler)
                .post(crate::api::v1::encrypted_search_compat::kg_timeline_alias_handler),
        )
        .route(
            "/v1/kg/neighborhood",
            get(crate::api::v1::kg::kg_neighborhood_handler)
                .post(crate::api::v1::encrypted_search_compat::kg_neighborhood_alias_handler),
        )
        .route(
            "/v1/kg/entity-links",
            get(crate::api::v1::kg::kg_entity_links_handler)
                .post(crate::api::v1::encrypted_search_compat::kg_entity_links_alias_handler),
        )
        .route(
            "/v1/kg/episode",
            get(crate::api::v1::kg::kg_episode_handler)
                .post(crate::api::v1::encrypted_search_compat::kg_episode_alias_handler),
        )
        .route(
            "/v1/kg/edge/delete",
            post(crate::api::v1::kg::kg_delete_edge_handler),
        )
        .route(
            "/v1/kg/delete-edge",
            post(crate::api::v1::encrypted_search_compat::kg_delete_edge_alias_handler),
        )
        .route(
            "/v1/kg/episode/delete",
            post(crate::api::v1::kg::kg_delete_episode_handler),
        )
        .route(
            "/v1/kg/delete-episode",
            post(crate::api::v1::encrypted_search_compat::kg_delete_episode_alias_handler),
        )
        .route(
            "/v1/kg/rebuild",
            post(crate::api::v1::kg::kg_rebuild_handler),
        )
        .route("/v1/kg/clear", post(crate::api::v1::kg::kg_clear_handler))
        .route("/v1/wakeup", post(crate::api::v1::wakeup::wakeup_handler))
        .route(
            "/v1/hooks/conversation",
            post(crate::api::v1::hooks::conversation_hook_handler),
        )
        .route(
            "/v1/gates/status",
            get(crate::api::v1::gates::gates_status_handler),
        )
        .route("/v1/mcp", post(crate::api::mcp_http::mcp_request_handler))
        .route(
            "/v1/mcp/message",
            post(crate::api::mcp_http::mcp_message_handler),
        )
        .route("/v1/mcp/sse", get(crate::api::mcp_http::mcp_sse_handler))
        .route(
            "/sse",
            get(crate::api::mcp_http::mcp_sse_handler)
                .post(crate::api::mcp_http::mcp_request_handler),
        )
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
    router = router.layer(middleware::from_fn_with_state(
        state.clone(),
        metrics_middleware,
    ));
    router.with_state(state)
}

async fn healthz() -> &'static str {
    "ok"
}

#[derive(Deserialize)]
pub(crate) struct RepoIdQuery {
    #[serde(default)]
    pub(crate) repo_id: Option<String>,
    #[serde(default, alias = "namespace")]
    pub(crate) conversation_namespace: Option<String>,
}

#[derive(Deserialize)]
pub(crate) struct MemoryStoreRequest {
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
pub(crate) struct MemoryRecallRequest {
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

#[derive(Deserialize)]
pub(crate) struct MemoryDeleteRequest {
    #[serde(default, alias = "memory_id")]
    id: Option<String>,
    #[serde(default)]
    repo_id: Option<String>,
}

#[derive(Serialize)]
struct MemoryDeleteResponse {
    id: String,
    deleted: bool,
}

fn header_dag_session_id(headers: &HeaderMap) -> Option<String> {
    headers
        .get(DAG_SESSION_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string())
}

pub(crate) async fn memory_store_handler(
    State(state): State<AppState>,
    axum::extract::Extension(request_id): axum::extract::Extension<RequestId>,
    headers: HeaderMap,
    Query(repo_id): Query<RepoIdQuery>,
    Json(req): Json<MemoryStoreRequest>,
) -> impl IntoResponse {
    let repo = match resolve_repo_context(
        &state,
        &headers,
        repo_id.repo_id.as_deref(),
        req.repo_id.as_deref(),
        false,
    ) {
        Ok(repo) => repo,
        Err(err) => return repo_error_response(err),
    };
    let Some(memory) = repo.memory.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            "memory is disabled; start the daemon with --enable-memory=true",
        );
    };

    let text = req.text.trim();
    if text.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "text must not be empty",
        );
    }

    let started = Instant::now();
    let repo_root = repo.indexer.repo_root().display().to_string();
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
    let metadata = inject_repo_metadata(metadata, &repo.repo_id);
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

pub(crate) async fn memory_recall_handler(
    State(state): State<AppState>,
    axum::extract::Extension(request_id): axum::extract::Extension<RequestId>,
    headers: HeaderMap,
    Query(repo_id): Query<RepoIdQuery>,
    Json(req): Json<MemoryRecallRequest>,
) -> impl IntoResponse {
    let repo = match resolve_repo_context(
        &state,
        &headers,
        repo_id.repo_id.as_deref(),
        req.repo_id.as_deref(),
        false,
    ) {
        Ok(repo) => repo,
        Err(err) => return repo_error_response(err),
    };
    let Some(memory) = repo.memory.clone() else {
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

    let started = Instant::now();
    let repo_root = repo.indexer.repo_root().display().to_string();
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
            let (items, dropped) = filter_memory_items_by_repo(items, &repo.repo_id);
            if dropped > 0 {
                state.metrics.inc_memory_repo_mismatch(dropped as u64);
                warn!(
                    target: "docdexd",
                    repo_id = %repo.repo_id,
                    dropped,
                    "memory_recall dropped items with mismatched repo id"
                );
            }
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

pub(crate) async fn memory_delete_handler(
    State(state): State<AppState>,
    axum::extract::Extension(request_id): axum::extract::Extension<RequestId>,
    headers: HeaderMap,
    Query(repo_id): Query<RepoIdQuery>,
    Json(req): Json<MemoryDeleteRequest>,
) -> impl IntoResponse {
    let repo = match resolve_repo_context(
        &state,
        &headers,
        repo_id.repo_id.as_deref(),
        req.repo_id.as_deref(),
        false,
    ) {
        Ok(repo) => repo,
        Err(err) => return repo_error_response(err),
    };
    let Some(memory) = repo.memory.clone() else {
        return json_error(
            StatusCode::CONFLICT,
            ERR_MEMORY_DISABLED,
            "memory is disabled; start the daemon with --enable-memory=true",
        );
    };

    let id = req.id.as_deref().map(str::trim).unwrap_or("");
    if id.is_empty() {
        return json_error(
            StatusCode::BAD_REQUEST,
            ERR_INVALID_ARGUMENT,
            "id is required",
        );
    }

    let store = memory.store.clone();
    let id_owned = id.to_string();
    let delete = tokio::task::spawn_blocking(move || store.delete(&id_owned)).await;
    match delete {
        Ok(Ok(deleted)) => Json(MemoryDeleteResponse {
            id: id.to_string(),
            deleted,
        })
        .into_response(),
        Ok(Err(err)) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                request_id = %request_id.0,
                error = ?err,
                "memory_delete persistence failed"
            );
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "memory delete failed",
            )
        }
        Err(err) => {
            state.metrics.inc_error();
            warn!(
                target: "docdexd",
                request_id = %request_id.0,
                error = ?err,
                "memory_delete task join failed"
            );
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "memory delete failed",
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
                    "dag_session_id=<optional>",
                    "repo_id=<optional>",
                    "x-docdex-dag-session=<header optional>",
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
                    "docdex.dag_session_id=<string optional>",
                    "docdex.diff=<{mode,base,head,paths}>",
                    "repo_id=<optional (query or body)>",
                    "x-docdex-agent-id=<header optional>",
                    "x-docdex-dag-session=<header optional>",
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
                method: "POST",
                path: "/v1/memory/delete",
                description: "Delete a repo memory item by id (requires memory enabled).",
                params: &["id=<memory id>", "repo_id=<optional>"],
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
                path: "/v1/profile/delete",
                description: "Delete a profile preference by id.",
                params: &["preference_id=<string>"],
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
                description: "Run a web discovery query (requires DOCDEX_WEB_ENABLED=1; daemon enables by default).",
                params: &[
                    "query=<string>",
                    "limit=<int optional>",
                    "dag_session_id=<optional>",
                    "x-docdex-dag-session=<header optional>",
                ],
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
                description: "Prometheus-style metrics (rate limits, errors, HTTP latency).",
                params: &[],
            },
            AiHelpEndpoint {
                method: "GET",
                path: "/v1/telemetry/delegation",
                description: "Delegation savings telemetry (tokens + USD).",
                params: &["repo_id=<optional>"],
            },
            AiHelpEndpoint {
                method: "GET",
                path: "/v1/gates/status",
                description: "Quality gate summary (error rate, latency p95, soak status).",
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
                command: "docdexd serve --repo <path> [--host 127.0.0.1] [--port 28491]",
                description: "Serve HTTP API with watcher for incremental ingest.",
                example: "docdexd serve --repo /workspace --host 127.0.0.1 --port 28491",
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
                description: "Run a web discovery query (requires DOCDEX_WEB_ENABLED=1; daemon enables by default).",
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
                command: "docdexd mcp-add --repo <path>",
                description: "Register Docdex MCP in supported agent CLIs.",
                example: "docdexd mcp-add --repo /workspace",
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
                name: "docdex_conversation_import",
                description: "Import a normalized conversation session or prefixed plain-text transcript into repo-scoped conversation memory.",
                args: &[
                    "messages (array, optional)",
                    "transcript_text (string, optional)",
                    "source/title/agent_id/metadata (optional)",
                    "project_root or repo_path (string, optional)",
                ],
                returns: &["session_id", "deduplicated", "message_count", "summary", "working_memory?"],
            },
            AiHelpMcpTool {
                name: "docdex_wakeup",
                description: "Assemble bounded startup memory from prior conversation history.",
                args: &[
                    "agent_id (string, optional)",
                    "query (string, optional)",
                    "max_tokens (int, optional)",
                    "project_root or repo_path (string, optional)",
                ],
                returns: &["text", "trace", "working_memory?", "episodic_summaries[]", "transcript_snippets[]"],
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
            "Web discovery is enabled when DOCDEX_WEB_ENABLED=1 (daemon sets this by default); set DOCDEX_WEB_ENABLED=0 to disable.",
            "When running remote, set --auth-token and TLS (certbot or manual cert/key).",
            "Keep server logging minimal for agent pipelines (e.g., --log warn --access-log=false).",
            "Use state_dir per project to keep indexes isolated; run separate serve instances per repo.",
            "When targeting a specific repo over HTTP, pass repo_id (or x-docdex-repo-id header); mismatches are rejected.",
            "Use text_only=true on /snippet or --strip-snippet-html/--disable-snippet-text to trim payloads.",
            "When building prompts, keep rel_path + summary + trimmed snippet; drop score/token_estimate/doc_id and normalize whitespace.",
            "Trim noisy content up front with --exclude-dir/--exclude-prefix so snippets stay relevant and short.",
            "Cache doc_id/rel_path/summary client-side to avoid repeat snippet fetches; only call /snippet for new doc_ids.",
            "For MCP-aware agents, use the daemon HTTP MCP endpoint (e.g., http://127.0.0.1:28491/v1/mcp) and call docdex_search/docdex_web_research/docdex_index as needed.",
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
    #[serde(default, alias = "asyncWeb")]
    async_web: Option<bool>,
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
    #[serde(default, alias = "session_id", alias = "dagSessionId")]
    dag_session_id: Option<String>,
    #[serde(default)]
    repo_id: Option<String>,
}

#[derive(Deserialize)]
struct RerankRequest {
    query: String,
    candidates: Vec<Hit>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    repo_id: Option<String>,
}

#[derive(Serialize)]
struct RerankResponse {
    hits: Vec<Hit>,
    input_count: usize,
    returned_count: usize,
    limit: usize,
    truncated: bool,
}

#[derive(Deserialize)]
struct BatchSearchRequest {
    queries: Vec<String>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    include_libs: Option<bool>,
    #[serde(default)]
    repo_id: Option<String>,
}

#[derive(Serialize)]
struct BatchSearchItem {
    query: String,
    response: SearchResponse,
}

#[derive(Serialize)]
struct BatchSearchResponse {
    results: Vec<BatchSearchItem>,
    query_count: usize,
    effective_query_count: usize,
    limit: usize,
    truncated: bool,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dag_session_id: Option<String>,
    pub repo_root: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo_id: Option<String>,
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

fn structural_ranking_available(indexer: &Indexer) -> bool {
    !indexer.config().repo_encryption().is_enabled() && indexer.symbols_enabled()
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
    if !structural_ranking_available(indexer) {
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
        let (weighted_count, name_matches) =
            symbol_match_score_details(&symbol_match, &query_tokens);
        let base_boost =
            (weighted_count.max(1.0) * SYMBOL_SCORE_PER_MATCH).min(SYMBOL_SCORE_MAX_BOOST);
        let name_boost =
            (name_matches as f32 * SYMBOL_NAME_MATCH_BONUS).min(SYMBOL_NAME_MATCH_MAX_BOOST);
        let boost = base_boost + name_boost;
        if let Some(idx) = by_path.get(&symbol_match.file).copied() {
            let hit = &mut hits[idx];
            let delta = hit.score * SYMBOL_SCORE_SCALE + boost;
            hit.score += delta;
            if let Some(score_breakdown) = hit.score_breakdown.as_mut() {
                score_breakdown.structural_relevance += delta;
                score_breakdown.total = hit.score;
            } else {
                let base_query = (hit.score - delta).max(0.0);
                let mut score_breakdown = build_hit_score_breakdown(base_query, delta, 0.0);
                score_breakdown.total = hit.score;
                hit.score_breakdown = Some(score_breakdown);
            }
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
    if !structural_ranking_available(indexer) {
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
        let weighted_count = ast_weighted_match_count(indexer, &ast_match.file, &ast_query.kinds)
            .unwrap_or_else(|_| ast_match.match_count.max(1) as f32);
        let boost = (weighted_count.max(1.0) * AST_SCORE_PER_MATCH).min(AST_SCORE_MAX_BOOST);
        if let Some(idx) = by_path.get(&ast_match.file).copied() {
            let hit = &mut hits[idx];
            let delta = hit.score * AST_SCORE_SCALE + boost;
            hit.score += delta;
            if let Some(score_breakdown) = hit.score_breakdown.as_mut() {
                score_breakdown.structural_relevance += delta;
                score_breakdown.total = hit.score;
            } else {
                let base_query = (hit.score - delta).max(0.0);
                let mut score_breakdown = build_hit_score_breakdown(base_query, delta, 0.0);
                score_breakdown.total = hit.score;
                hit.score_breakdown = Some(score_breakdown);
            }
            continue;
        }
        if mode == RankingMode::IncludeNewHits {
            if let Some(hit) = build_ast_hit(indexer, &ast_match, query, &ast_query.labels, boost)?
            {
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
        | "arrow_function" => 2.0,
        "class_definition" | "class_declaration" | "class_item" => 1.0,
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

fn ast_weighted_match_count(indexer: &Indexer, rel_path: &str, kinds: &[String]) -> Result<f32> {
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
    let score = SYMBOL_SCORE_BASE + boost;
    let snippet_signal = match snippet_origin {
        SearchSnippetOrigin::Query => "snippet_origin_query",
        SearchSnippetOrigin::Preview => "snippet_origin_preview",
        SearchSnippetOrigin::Summary => "snippet_origin_summary",
    };
    let score_breakdown = Some(build_hit_score_breakdown(SYMBOL_SCORE_BASE, boost, 0.0));
    let provenance = Some(build_hit_provenance(
        &snapshot.doc_id,
        &snapshot.rel_path,
        &snapshot.rel_path,
        line_start,
        line_end,
    ));
    let retrieval_explanation = Some(build_retrieval_explanation(
        "Symbol-aware ranking boosted this hit based on query-aligned definitions.",
        vec!["symbol_match_boost".to_string(), snippet_signal.to_string()],
    ));
    Ok(Some(Hit {
        doc_id: snapshot.doc_id.clone(),
        rel_path: snapshot.rel_path.clone(),
        path: snapshot.rel_path.clone(),
        kind: snapshot.kind,
        doc_type: snapshot.doc_type,
        score,
        summary: snapshot.summary,
        snippet: snippet_text,
        token_estimate: snapshot.token_estimate,
        snippet_origin: Some(snippet_origin),
        snippet_truncated: Some(snippet_truncated),
        line_start,
        line_end,
        score_breakdown,
        provenance,
        retrieval_explanation,
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
            (ast_snippet, SearchSnippetOrigin::Summary, false, None, None)
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
    let score = AST_SCORE_BASE + boost;
    let snippet_signal = match snippet_origin {
        SearchSnippetOrigin::Query => "snippet_origin_query",
        SearchSnippetOrigin::Preview => "snippet_origin_preview",
        SearchSnippetOrigin::Summary => "snippet_origin_summary",
    };
    let score_breakdown = Some(build_hit_score_breakdown(AST_SCORE_BASE, boost, 0.0));
    let provenance = Some(build_hit_provenance(
        &snapshot.doc_id,
        &snapshot.rel_path,
        &snapshot.rel_path,
        line_start,
        line_end,
    ));
    let retrieval_explanation = Some(build_retrieval_explanation(
        "AST-aware ranking boosted this hit based on matched structural node kinds.",
        vec!["ast_match_boost".to_string(), snippet_signal.to_string()],
    ));
    Ok(Some(Hit {
        doc_id: snapshot.doc_id.clone(),
        rel_path: snapshot.rel_path.clone(),
        path: snapshot.rel_path.clone(),
        kind: snapshot.kind,
        doc_type: snapshot.doc_type,
        score,
        summary: snapshot.summary,
        snippet: snippet_text,
        token_estimate: snapshot.token_estimate,
        snippet_origin: Some(snippet_origin),
        snippet_truncated: Some(snippet_truncated),
        line_start,
        line_end,
        score_breakdown,
        provenance,
        retrieval_explanation,
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
        "class" => Some(&["class_definition", "class_declaration", "class_item"]),
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

fn normalize_rel_path_input(raw: &str, repo_root: &FsPath) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.contains("://") {
        return None;
    }
    let raw_path = FsPath::new(trimmed);
    if raw_path.is_absolute() {
        let rel = raw_path.strip_prefix(repo_root).ok()?;
        if rel
            .components()
            .any(|component| matches!(component, Component::ParentDir))
        {
            return None;
        }
        let rel_str = rel.to_string_lossy().replace('\\', "/");
        return if rel_str.is_empty() {
            None
        } else {
            Some(rel_str)
        };
    }
    let cleaned = trimmed.replace('\\', "/");
    let cleaned = cleaned.trim_start_matches("./").trim_start_matches('/');
    if cleaned.is_empty() {
        return None;
    }
    let rel_path = FsPath::new(cleaned);
    if rel_path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return None;
    }
    Some(cleaned.to_string())
}

fn is_explicit_path_query(rel_path: &str) -> bool {
    let lowered = rel_path.to_ascii_lowercase();
    lowered.ends_with(".yaml") || lowered.ends_with(".yml") || lowered.ends_with(".json")
}

fn hit_from_snapshot(snapshot: DocSnapshot, snippet: Option<SnippetResult>) -> Hit {
    let (snippet_text, snippet_origin, snippet_truncated, line_start, line_end) =
        if let Some(snippet) = snippet {
            let origin = match snippet.origin {
                SnippetOrigin::Query => SearchSnippetOrigin::Query,
                SnippetOrigin::Preview => SearchSnippetOrigin::Preview,
            };
            (
                snippet.text,
                origin,
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
    let score = 1.0_f32;
    let snippet_signal = match snippet_origin {
        SearchSnippetOrigin::Query => "snippet_origin_query",
        SearchSnippetOrigin::Preview => "snippet_origin_preview",
        SearchSnippetOrigin::Summary => "snippet_origin_summary",
    };
    let doc_id = snapshot.doc_id;
    let rel_path = snapshot.rel_path;
    let kind = snapshot.kind;
    let doc_type = snapshot.doc_type;
    let summary = snapshot.summary;
    let token_estimate = snapshot.token_estimate;
    let score_breakdown = Some(build_hit_score_breakdown(score, 0.0, 0.0));
    let provenance = Some(build_hit_provenance(
        &doc_id, &rel_path, &rel_path, line_start, line_end,
    ));
    let retrieval_explanation = Some(build_retrieval_explanation(
        "Direct path lookup returned the indexed file snapshot.",
        vec!["path_query_match".to_string(), snippet_signal.to_string()],
    ));

    Hit {
        doc_id,
        rel_path: rel_path.clone(),
        path: rel_path,
        kind,
        doc_type,
        score,
        summary,
        snippet: snippet_text,
        token_estimate,
        snippet_origin: Some(snippet_origin),
        snippet_truncated: Some(snippet_truncated),
        line_start,
        line_end,
        score_breakdown,
        provenance,
        retrieval_explanation,
    }
}

fn path_hit_for_query(indexer: &Indexer, query: &str, window: usize) -> Result<Option<Hit>> {
    let Some(rel_path) = normalize_rel_path_input(query, indexer.repo_root()) else {
        return Ok(None);
    };
    if !is_explicit_path_query(&rel_path) {
        return Ok(None);
    }
    let Some((doc, snippet)) = indexer.snapshot_with_snippet(&rel_path, None, window)? else {
        return Ok(None);
    };
    Ok(Some(hit_from_snapshot(doc, snippet)))
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

fn query_overlap_ratio(tokens: &[String], text: &str) -> f32 {
    if tokens.is_empty() {
        return 0.0;
    }
    let lowered = text.to_lowercase();
    let matched = tokens
        .iter()
        .filter(|token| lowered.contains(token.as_str()))
        .count() as f32;
    (matched / tokens.len() as f32).clamp(0.0, 1.0)
}

pub(crate) fn rerank_hits(query: &str, mut candidates: Vec<Hit>, limit: usize) -> Vec<Hit> {
    let tokens = extract_query_tokens(query);
    for hit in candidates.iter_mut() {
        let summary_overlap = query_overlap_ratio(&tokens, &hit.summary);
        let snippet_overlap = query_overlap_ratio(&tokens, &hit.snippet);
        let path_overlap = query_overlap_ratio(&tokens, &hit.rel_path);
        let lexical =
            (summary_overlap * 0.45 + snippet_overlap * 0.35 + path_overlap * 0.20).clamp(0.0, 1.0);

        let anchor_bonus = if hit.line_start.is_some() && hit.line_end.is_some() {
            0.08
        } else {
            0.0
        };
        let origin_bonus = match hit.snippet_origin.as_ref() {
            Some(SearchSnippetOrigin::Query) => 0.05,
            Some(SearchSnippetOrigin::Preview) => 0.02,
            Some(SearchSnippetOrigin::Summary) | None => 0.0,
        };
        let structural = anchor_bonus + origin_bonus;

        let delta = lexical + structural;
        let base_score = hit.score.max(0.0);
        hit.score = base_score + delta;

        if let Some(score_breakdown) = hit.score_breakdown.as_mut() {
            score_breakdown.query_relevance += lexical;
            score_breakdown.structural_relevance += structural;
            score_breakdown.total = hit.score;
        } else {
            let mut score_breakdown =
                build_hit_score_breakdown(base_score + lexical, structural, 0.0);
            score_breakdown.total = hit.score;
            hit.score_breakdown = Some(score_breakdown);
        }

        if hit.provenance.is_none() {
            hit.provenance = Some(build_hit_provenance(
                &hit.doc_id,
                &hit.rel_path,
                &hit.path,
                hit.line_start,
                hit.line_end,
            ));
        }

        let origin_signal = match hit.snippet_origin.as_ref() {
            Some(SearchSnippetOrigin::Query) => "snippet_origin_query",
            Some(SearchSnippetOrigin::Preview) => "snippet_origin_preview",
            Some(SearchSnippetOrigin::Summary) | None => "snippet_origin_summary",
        };
        if let Some(explanation) = hit.retrieval_explanation.as_mut() {
            if !explanation
                .signals
                .iter()
                .any(|signal| signal == "rerank_applied")
            {
                explanation.signals.push("rerank_applied".to_string());
            }
            if !explanation
                .signals
                .iter()
                .any(|signal| signal.as_str() == origin_signal)
            {
                explanation.signals.push(origin_signal.to_string());
            }
        } else {
            hit.retrieval_explanation = Some(build_retrieval_explanation(
                "Rerank prioritized lexical overlap and evidence anchor quality.",
                vec!["rerank_applied".to_string(), origin_signal.to_string()],
            ));
        }
    }

    sort_hits_deterministically(&mut candidates);
    if candidates.len() > limit {
        candidates.truncate(limit);
    }
    candidates
}

fn now_epoch_ms() -> Result<u128> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_millis())
}

pub(crate) fn build_search_meta(
    indexer: &Indexer,
    query: Option<SearchQueryMeta>,
    context_assembly: Option<ContextAssemblyMeta>,
) -> Result<SearchMeta> {
    let generated_at_epoch_ms = now_epoch_ms()?;
    let last_updated = indexer.stats().ok().and_then(|s| s.last_updated_epoch_ms);
    let repo_id = repo_manager::repo_fingerprint_sha256(indexer.repo_root()).ok();
    Ok(SearchMeta {
        generated_at_epoch_ms,
        index_last_updated_epoch_ms: last_updated,
        dag_session_id: None,
        repo_root: indexer.repo_root().display().to_string(),
        repo_id,
        query,
        context_assembly,
    })
}

async fn capabilities_handler(State(state): State<AppState>) -> impl IntoResponse {
    Json(capabilities::current_capabilities_with_config(
        &state.repo_encryption,
        state.auth.config(),
    ))
}

async fn authorize_encrypted_repo_http(
    state: &AppState,
    headers: &HeaderMap,
    repo: &RepoContext,
    operation: RepoOperation,
    request_id: Option<&str>,
    path: &str,
) -> Result<(), Response> {
    if !repo.indexer.config().repo_encryption().is_enabled() {
        return Ok(());
    }
    match state
        .auth
        .authorize_repo_access(headers, &repo.repo_id, operation)
        .await
    {
        Ok(_) => {
            if let Some(audit) = state.audit.as_ref() {
                audit.log(
                    "encrypted_repo_auth",
                    "allow",
                    request_id,
                    Some(path),
                    None,
                    Some(StatusCode::OK.as_u16()),
                    None,
                    None,
                );
            }
            Ok(())
        }
        Err(err) => {
            state.metrics.inc_auth_deny();
            if let Some(audit) = state.audit.as_ref() {
                audit.log(
                    "encrypted_repo_auth",
                    "deny",
                    request_id,
                    Some(path),
                    None,
                    Some(status_for_app_error(err.code).as_u16()),
                    None,
                    None,
                );
            }
            let status = status_for_app_error(err.code);
            let response = if let Some(details) = err.details {
                json_error_with_details(status, err.code, err.message, details)
            } else {
                json_error(status, err.code, err.message)
            };
            Err(response)
        }
    }
}

async fn rerank_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(repo_query): Query<RepoIdQuery>,
    Json(request): Json<RerankRequest>,
) -> impl IntoResponse {
    let RerankRequest {
        query,
        candidates,
        limit,
        repo_id,
    } = request;
    let repo_hint = repo_id.as_deref().or(repo_query.repo_id.as_deref());
    if let Err(err) = resolve_repo_context(&state, &headers, repo_hint, None, false) {
        return repo_error_response(err);
    }

    let query = query.trim();
    if query.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: ErrorDetail::new("invalid_query", "query must not be empty"),
            }),
        )
            .into_response();
    }

    let input_count = candidates.len();
    if input_count == 0 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: ErrorDetail::new("invalid_candidates", "candidates must not be empty"),
            }),
        )
            .into_response();
    }

    let mut candidates = candidates;
    let truncated = input_count > RERANK_MAX_CANDIDATES;
    if truncated {
        candidates.truncate(RERANK_MAX_CANDIDATES);
    }

    let max_limit = state.security.max_limit.min(RERANK_MAX_CANDIDATES).max(1);
    let limit = limit.unwrap_or(candidates.len()).clamp(1, max_limit);
    let hits = rerank_hits(query, candidates, limit);

    Json(RerankResponse {
        returned_count: hits.len(),
        hits,
        input_count,
        limit,
        truncated,
    })
    .into_response()
}

async fn batch_search_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(repo_query): Query<RepoIdQuery>,
    Json(request): Json<BatchSearchRequest>,
) -> impl IntoResponse {
    let BatchSearchRequest {
        queries,
        limit,
        include_libs,
        repo_id,
    } = request;
    let repo_hint = repo_id.as_deref().or(repo_query.repo_id.as_deref());
    let repo = match resolve_repo_context(&state, &headers, repo_hint, None, false) {
        Ok(repo) => repo,
        Err(err) => return repo_error_response(err),
    };
    if let Err(response) = authorize_encrypted_repo_http(
        &state,
        &headers,
        &repo,
        RepoOperation::Search,
        None,
        "/v1/search/batch",
    )
    .await
    {
        return response;
    }

    if queries.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: ErrorDetail::new("invalid_queries", "queries must not be empty"),
            }),
        )
            .into_response();
    }

    let query_count = queries.len();
    let mut normalized = queries
        .into_iter()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    if normalized.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorBody {
                error: ErrorDetail::new("invalid_queries", "queries must include non-empty values"),
            }),
        )
            .into_response();
    }

    let truncated = normalized.len() > BATCH_SEARCH_MAX_QUERIES;
    if truncated {
        normalized.truncate(BATCH_SEARCH_MAX_QUERIES);
    }

    let limit = limit.unwrap_or(8).clamp(1, state.security.max_limit);
    let include_libs = include_libs.unwrap_or(true);
    let libs_indexer = if include_libs {
        repo.libs_indexer.as_deref()
    } else {
        None
    };

    let mut results = Vec::with_capacity(normalized.len());
    for query in normalized {
        match run_query(
            &repo.indexer,
            libs_indexer,
            &query,
            limit,
            RankingSurface::Search,
        )
        .await
        {
            Ok(response) => results.push(BatchSearchItem { query, response }),
            Err(err) => {
                state.metrics.inc_error();
                if let Some(app) = err.downcast_ref::<AppError>() {
                    return json_error(
                        status_for_app_error(app.code),
                        app.code,
                        app.message.clone(),
                    )
                    .into_response();
                }
                warn!(target: "docdexd", error = ?err, "batch search failed");
                return json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ERR_INTERNAL_ERROR,
                    "batch search failed",
                )
                .into_response();
            }
        }
    }

    Json(BatchSearchResponse {
        effective_query_count: results.len(),
        results,
        query_count,
        limit,
        truncated,
    })
    .into_response()
}

async fn search_handler(
    State(state): State<AppState>,
    axum::extract::Extension(request_id): axum::extract::Extension<RequestId>,
    headers: HeaderMap,
    Query(params): Query<SearchParams>,
) -> impl IntoResponse {
    let repo = match resolve_repo_context(&state, &headers, params.repo_id.as_deref(), None, false)
    {
        Ok(repo) => repo,
        Err(err) => {
            return repo_error_response(err);
        }
    };
    if let Err(response) = authorize_encrypted_repo_http(
        &state,
        &headers,
        &repo,
        RepoOperation::Search,
        Some(&request_id.0),
        "/search",
    )
    .await
    {
        return response;
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

    let skip_local_search = params.skip_local_search.unwrap_or(false);
    if state.repo_encryption.is_enabled()
        && !state.repo_encryption.web_discovery_enabled
        && (params.force_web.unwrap_or(false) || skip_local_search)
    {
        return json_error(
            status_for_app_error(crate::error::ERR_REPO_ENCRYPTION_UNSUPPORTED),
            crate::error::ERR_REPO_ENCRYPTION_UNSUPPORTED,
            "web discovery is disabled by repository encryption policy",
        )
        .into_response();
    }
    if !skip_local_search {
        if !repo.indexer.index_ready() {
            let indexing_in_progress = match repo.indexer.indexing_in_progress() {
                Ok(value) => value,
                Err(err) => {
                    state.metrics.inc_error();
                    if let Some(app) = err.downcast_ref::<AppError>() {
                        return json_error(
                            status_for_app_error(app.code),
                            app.code,
                            app.message.clone(),
                        )
                        .into_response();
                    }
                    warn!(target: "docdexd", error = ?err, "indexing gate lookup failed");
                    return json_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        ERR_INTERNAL_ERROR,
                        "indexing gate lookup failed",
                    )
                    .into_response();
                }
            };
            if !indexing_in_progress && !repo.indexer.is_read_only() {
                let indexer = repo.indexer.clone();
                tokio::spawn(async move {
                    let _ = crate::index::ensure_indexed(indexer).await;
                });
            }
            let status_url = format!("/v1/index/status?repo_id={}", repo.repo_id);
            let details = json!({
                "status": if indexing_in_progress { "indexing" } else { "missing" },
                "indexing_in_progress": indexing_in_progress,
                "status_url": status_url,
                "retry_after_ms": 2000,
                "recovery_steps": [
                    "Wait for indexing to complete, then retry the search.",
                    "Call /v1/index/status to check readiness.",
                    "If indexing is stuck, run POST /v1/index/rebuild."
                ]
            });
            return json_error_with_details(
                StatusCode::ACCEPTED,
                ERR_INDEXING_IN_PROGRESS,
                "indexing in progress",
                details,
            )
            .into_response();
        }
        if let Err(err) = crate::index::ensure_indexed(repo.indexer.clone()).await {
            if let Some(app) = err.downcast_ref::<AppError>() {
                return json_error(
                    status_for_app_error(app.code),
                    app.code,
                    app.message.clone(),
                )
                .into_response();
            }
            state.metrics.inc_error();
            warn!(target: "docdexd", error = ?err, "indexing failed");
            return json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                ERR_INTERNAL_ERROR,
                "indexing failed",
            )
            .into_response();
        }
    }

    if !skip_local_search && !state.repo_encryption.is_enabled() {
        match path_hit_for_query(&repo.indexer, query, DEFAULT_SNIPPET_WINDOW) {
            Ok(Some(hit)) => {
                let mut hits = vec![hit];
                let query_meta = Some(SearchQueryMeta {
                    raw: query.to_string(),
                    effective: query.to_string(),
                    rewrite: QueryRewrite::None,
                });
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
                let meta =
                    build_search_meta(&repo.indexer, query_meta, Some(context_assembly)).ok();
                let top_score_normalized = top_score.map(normalize_score);
                let response = SearchResponse {
                    hits,
                    top_score,
                    top_score_camel: top_score,
                    top_score_normalized: top_score_normalized,
                    top_score_normalized_camel: top_score_normalized,
                    web_context: None,
                    web_discovery: None,
                    impact_context: None,
                    profile_context: None,
                    memory_context: None,
                    symbols_context: None,
                    meta,
                };
                return Json(response).into_response();
            }
            Ok(None) => {}
            Err(err) => {
                state.metrics.inc_error();
                warn!(
                    target: "docdexd",
                    error = ?err,
                    request_id = %request_id.0,
                    "path lookup failed"
                );
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("internal error (request id: {})", request_id.0),
                )
                    .into_response();
            }
        }
    }

    let include_libs = params.include_libs.unwrap_or(true);
    let libs_indexer = if include_libs {
        repo.libs_indexer.clone()
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

    let header_dag_session_id = header_dag_session_id(&headers);
    let request_id_value = request_id.0;
    let request_id_str = request_id_value.as_str();
    let param_dag_session_id = params
        .dag_session_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let dag_session_id = header_dag_session_id
        .as_deref()
        .or(param_dag_session_id)
        .unwrap_or(request_id_str);
    let plan = WaterfallPlan::new(
        WebGateConfig::from_env(),
        if state.repo_encryption.is_enabled() && !state.repo_encryption.web_discovery_enabled {
            Tier2Config::default()
        } else {
            Tier2Config::enabled()
        },
        memory_budget_from_max_answer_tokens(state.max_answer_tokens),
        ProfileBudget::default(),
    );
    let force_web = params.force_web.unwrap_or(false);
    let disable_web_cache = params.no_cache.unwrap_or(false);
    let llm_filter_local_results = params.llm_filter_local_results.unwrap_or(false);
    let async_web = params.async_web.unwrap_or(true);

    match run_waterfall(WaterfallRequest {
        request_id: request_id_str,
        dag_session_id: Some(dag_session_id),
        global_state_dir: state.global_state_dir.clone(),
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
        indexer: repo.indexer.clone(),
        libs_indexer,
        plan,
        tier2_limiter: None,
        memory: repo.memory.as_ref(),
        profile_state: state.profile_state.as_ref(),
        profile_agent_id: None,
        memory_route: None,
        ranking_surface: RankingSurface::Search,
        async_web,
    })
    .await
    {
        Ok(waterfall_result) => {
            let mut response = waterfall_result.search_response;
            let mut hits = std::mem::take(&mut response.hits);
            let query_meta = response.meta.as_ref().and_then(|meta| meta.query.clone());
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
            let mut meta =
                build_search_meta(&repo.indexer, query_meta, Some(context_assembly)).ok();
            if let Some(meta) = meta.as_mut() {
                meta.dag_session_id = Some(dag_session_id.to_string());
            }
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
            Json(response).into_response()
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
            if let Some(app) = err.downcast_ref::<AppError>() {
                let status = status_for_app_error(app.code);
                if let Some(details) = app.details.clone() {
                    return json_error_with_details(status, app.code, app.message.clone(), details)
                        .into_response();
                }
                return json_error(status, app.code, app.message.clone()).into_response();
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
    let repo = match resolve_repo_context(&state, &headers, params.repo_id.as_deref(), None, false)
    {
        Ok(repo) => repo,
        Err(err) => {
            return repo_error_response(err);
        }
    };
    if let Err(response) = authorize_encrypted_repo_http(
        &state,
        &headers,
        &repo,
        RepoOperation::Snippet,
        Some(&request_id.0),
        "/snippet",
    )
    .await
    {
        return response;
    }
    let window = params
        .window
        .unwrap_or(DEFAULT_SNIPPET_WINDOW)
        .clamp(MIN_SNIPPET_WINDOW, MAX_SNIPPET_WINDOW);
    let strip_html_flag = params.strip_html.unwrap_or(false)
        | params.text_only.unwrap_or(false)
        | state.security.strip_snippet_html;
    let snapshot = if doc_id.starts_with("libs:") {
        match repo.libs_indexer.as_deref() {
            Some(libs) => libs.snapshot_with_snippet(&doc_id, params.q.as_deref(), window),
            None => Ok(None),
        }
    } else {
        match repo
            .indexer
            .snapshot_with_snippet(&doc_id, params.q.as_deref(), window)
        {
            Ok(Some(result)) => Ok(Some(result)),
            Ok(None) => {
                if let Some(normalized) =
                    normalize_rel_path_input(&doc_id, repo.indexer.repo_root())
                {
                    repo.indexer
                        .snapshot_with_snippet(&normalized, params.q.as_deref(), window)
                } else {
                    Ok(None)
                }
            }
            Err(err) => Err(err),
        }
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
            if let Some(app) = err.downcast_ref::<AppError>() {
                let status = status_for_app_error(app.code);
                if let Some(details) = app.details.clone() {
                    return json_error_with_details(status, app.code, app.message.clone(), details)
                        .into_response();
                }
                return json_error(status, app.code, app.message.clone()).into_response();
            }
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
    connect_info: Option<ConnectInfo<SocketAddr>>,
    request_id: Option<axum::extract::Extension<RequestId>>,
    mut request: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Result<Response, Response> {
    let request_id = request_id
        .map(|ext| ext.0)
        .unwrap_or_else(|| RequestId(Uuid::new_v4().to_string()));
    let has_request_id = request.extensions().get::<RequestId>().is_some();
    if !has_request_id {
        request
            .extensions_mut()
            .insert::<RequestId>(request_id.clone());
    }
    let (addr, is_ipc) = connect_info
        .map(|info| (info.0, false))
        .unwrap_or_else(|| (SocketAddr::from(([127, 0, 0, 1], 0)), true));
    let path = request.uri().path().to_string();
    let size_hint = request.body().size_hint();
    if !is_ipc && !state.security.ip_allowed(addr.ip()) {
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
                let denied_total = state.metrics.rate_limit_denies();
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
                        error: ErrorDetail::rate_limited_with_context(
                            &err,
                            Some(addr.ip().to_string()),
                            Some(limiter.per_minute()),
                            Some(limiter.burst()),
                            Some(denied_total),
                        ),
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
        let defer_auth_to_route = state.auth.may_defer_route_auth(
            request.headers(),
            &path,
            state.repo_encryption.is_enabled(),
        );
        if !state.security.auth_matches(request.headers()) && !defer_auth_to_route {
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

async fn metrics_middleware(
    State(state): State<AppState>,
    request: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Result<Response, Response> {
    let path = request.uri().path();
    if matches!(path, "/healthz" | "/metrics") {
        return Ok(next.run(request).await);
    }
    let start = Instant::now();
    let response = next.run(request).await;
    let duration_ms = start.elapsed().as_millis();
    state
        .metrics
        .record_http_request(duration_ms, response.status().as_u16());
    Ok(response)
}

async fn access_log_middleware(
    State(state): State<AppState>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    mut request: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Result<Response, (StatusCode, HeaderMap)> {
    let addr = connect_info
        .map(|info| info.0)
        .unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], 0)));
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
