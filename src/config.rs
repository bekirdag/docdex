use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use clap::{ArgAction, Args};
use serde::{Deserialize, Serialize};
use tracing::warn;

#[path = "config/env_overrides.rs"]
mod env_overrides;
#[path = "config/runtime.rs"]
mod runtime;

pub use env_overrides::write_config;
use env_overrides::{apply_env_overrides, default_state_dir, expand_config_path};
pub use runtime::*;

use crate::auth::AuthConfig;
use crate::impact::{
    apply_impact_settings, ImpactSettings, DEFAULT_DYNAMIC_IMPORT_SCAN_LIMIT,
    DEFAULT_IMPORT_TRACES_ENABLED,
};
use crate::repo_encryption::RepoEncryptionConfig;

const DEFAULT_CONFIG_FILE: &str = "config.toml";
const DEFAULT_HTTP_BIND_ADDR: &str = "127.0.0.1:28491";
const DEFAULT_LOG_LEVEL: &str = "info";
const DEFAULT_LLM_PROVIDER: &str = "ollama";
const DEFAULT_LLM_BASE_URL: &str = "http://127.0.0.1:11434";
const DEFAULT_LLM_MODEL: &str = "phi3.5:3.8b";
const DEFAULT_EMBED_MODEL: &str = "nomic-embed-text";
const DEFAULT_DELEGATION_MODE: &str = "draft_only";
const DEFAULT_DELEGATION_LOCAL_SELECTION_POLICY: &str = "task_capability";
const DEFAULT_DELEGATION_TIMEOUT_MS: u64 = 300_000;
const DEFAULT_DELEGATION_MAX_TOKENS: u32 = 500_000;
const DEFAULT_DELEGATION_MAX_CONTEXT_CHARS: usize = 250_000;
const DEFAULT_PROFILE_EMBED_MODEL: &str = "nomic-embed-text-v1.5";
const DEFAULT_PROFILE_EMBED_DIM: usize = 768;
const DEFAULT_MEMORY_BACKEND: &str = "sqlite";
const DEFAULT_CONVERSATION_WAKEUP_TOKENS: usize = 160;
const DEFAULT_CONVERSATION_WAKEUP_DIARY_EPISODE_LIMIT: usize = 3;
const DEFAULT_CONVERSATION_SUMMARY_LIMIT: usize = 3;
const DEFAULT_CONVERSATION_KNOWLEDGE_LIMIT: usize = 3;
const DEFAULT_CONVERSATION_SNIPPET_LIMIT: usize = 2;
const DEFAULT_CONVERSATION_AUTO_RETENTION_DAYS: u32 = 30;
const DEFAULT_CONVERSATION_WORKING_MEMORY_RETENTION_DAYS: u32 = 30;
const DEFAULT_CONVERSATION_HOOK_EVENT_RETENTION_DAYS: u32 = 30;
const DEFAULT_CONVERSATION_EPISODIC_ROLLUP_RETENTION_DAYS: u32 = 180;
const DEFAULT_CONVERSATION_SWEEPER_INTERVAL_SECONDS: u64 = 600;
const DEFAULT_CONVERSATION_GRAPH_STRICT_VALIDATION: bool = true;
const DEFAULT_PERSONAL_PREFERENCES_CONTEXT_RECORD_LIMIT: usize = 8;
const DEFAULT_PERSONAL_PREFERENCES_CONTEXT_TOKEN_BUDGET: usize = 600;
const DEFAULT_PERSONAL_PREFERENCES_MAX_PARALLEL_DIGEST_JOBS: usize = 1;
const DEFAULT_PERSONAL_PREFERENCES_DIGEST_INTERVAL_SECONDS: u64 = 30;
const DEFAULT_PERSONAL_PREFERENCES_RAW_RETENTION_DAYS: u32 = 0;
const DEFAULT_PERSONAL_PREFERENCES_DERIVED_RETENTION_DAYS: u32 = 0;
const DEFAULT_DISCOVERY_PROVIDER: &str = "duckduckgo_lite";
const DEFAULT_WEB_ENGINE: &str = "chromium";
const DEFAULT_MSWARM_BASE_URL: &str = "https://api.mswarm.org/";
const DEFAULT_MSWARM_CLIENT_TYPE: &str = "free_docdex_client";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default)]
    pub core: CoreConfig,
    #[serde(default)]
    pub llm: LlmConfig,
    #[serde(default)]
    pub search: SearchConfig,
    #[serde(default)]
    pub code_intelligence: CodeIntelligenceConfig,
    #[serde(default)]
    pub web: WebConfigSection,
    #[serde(default)]
    pub integrations: IntegrationsConfig,
    #[serde(default)]
    pub memory: MemoryConfig,
    #[serde(default)]
    pub features: FeatureFlagsConfig,
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub repo_encryption: RepoEncryptionConfig,
}

#[derive(Debug, Deserialize)]
struct AppConfigCompat {
    #[serde(flatten)]
    config: AppConfig,
    #[serde(default)]
    personal_preferences: Option<MemoryPersonalPreferencesConfig>,
}

#[derive(Debug, Serialize)]
struct AppConfigWrite<'a> {
    core: &'a CoreConfig,
    llm: &'a LlmConfig,
    search: &'a SearchConfig,
    code_intelligence: &'a CodeIntelligenceConfig,
    web: &'a WebConfigSection,
    integrations: &'a IntegrationsConfig,
    memory: MemoryConfigWrite<'a>,
    features: &'a FeatureFlagsConfig,
    server: &'a ServerConfig,
    auth: &'a AuthConfig,
    repo_encryption: &'a RepoEncryptionConfig,
    personal_preferences: &'a MemoryPersonalPreferencesConfig,
}

#[derive(Debug, Serialize)]
struct MemoryConfigWrite<'a> {
    backend: &'a str,
    profile: &'a MemoryProfileConfig,
    conversations: &'a MemoryConversationConfig,
}

impl<'a> From<&'a AppConfig> for AppConfigWrite<'a> {
    fn from(config: &'a AppConfig) -> Self {
        Self {
            core: &config.core,
            llm: &config.llm,
            search: &config.search,
            code_intelligence: &config.code_intelligence,
            web: &config.web,
            integrations: &config.integrations,
            memory: MemoryConfigWrite {
                backend: config.memory.backend.as_str(),
                profile: &config.memory.profile,
                conversations: &config.memory.conversations,
            },
            features: &config.features,
            server: &config.server,
            auth: &config.auth,
            repo_encryption: &config.repo_encryption,
            personal_preferences: &config.memory.personal_preferences,
        }
    }
}

impl AppConfigCompat {
    fn into_config(mut self) -> AppConfig {
        if let Some(personal_preferences) = self.personal_preferences.take() {
            self.config.memory.personal_preferences = personal_preferences;
        }
        self.config
    }
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            core: CoreConfig::default(),
            llm: LlmConfig::default(),
            search: SearchConfig::default(),
            code_intelligence: CodeIntelligenceConfig::default(),
            web: WebConfigSection::default(),
            integrations: IntegrationsConfig::default(),
            memory: MemoryConfig::default(),
            features: FeatureFlagsConfig::default(),
            server: ServerConfig::default(),
            auth: AuthConfig::default(),
            repo_encryption: RepoEncryptionConfig::default(),
        }
    }
}

impl AppConfig {
    pub fn load_default() -> Result<Self> {
        let path = default_config_path()?;
        load_config_from_path(&path)
    }

    pub fn apply_defaults(&mut self) -> Result<()> {
        if self.core.global_state_dir.is_none() {
            self.core.global_state_dir = Some(default_state_dir()?);
        }
        if self.core.log_level.trim().is_empty() {
            self.core.log_level = DEFAULT_LOG_LEVEL.to_string();
        }
        if self.llm.provider.trim().is_empty() {
            self.llm.provider = DEFAULT_LLM_PROVIDER.to_string();
        }
        if self.llm.base_url.trim().is_empty() {
            self.llm.base_url = DEFAULT_LLM_BASE_URL.to_string();
        }
        if self.llm.default_model.trim().is_empty() {
            self.llm.default_model = DEFAULT_LLM_MODEL.to_string();
        }
        if self.llm.embedding_model.trim().is_empty() {
            self.llm.embedding_model = DEFAULT_EMBED_MODEL.to_string();
        }
        self.llm.delegation.apply_defaults();
        if self.web.discovery_provider.trim().is_empty() {
            self.web.discovery_provider = DEFAULT_DISCOVERY_PROVIDER.to_string();
        }
        if self.web.user_agent.trim().is_empty() {
            self.web.user_agent = default_web_user_agent();
        }
        if self.integrations.mswarm.base_url.trim().is_empty() {
            self.integrations.mswarm.base_url = default_mswarm_base_url();
        }
        self.auth.apply_defaults();
        self.repo_encryption.apply_defaults();
        if self.web.scraper.engine.trim().is_empty() {
            self.web.scraper.engine = DEFAULT_WEB_ENGINE.to_string();
        }
        if self.memory.backend.trim().is_empty() {
            self.memory.backend = DEFAULT_MEMORY_BACKEND.to_string();
        } else if !self
            .memory
            .backend
            .eq_ignore_ascii_case(DEFAULT_MEMORY_BACKEND)
        {
            warn!(
                target: "docdexd",
                backend = %self.memory.backend,
                "unknown memory backend; falling back to sqlite"
            );
            self.memory.backend = DEFAULT_MEMORY_BACKEND.to_string();
        }
        if self.memory.profile.embedding_model.trim().is_empty() {
            self.memory.profile.embedding_model = DEFAULT_PROFILE_EMBED_MODEL.to_string();
        }
        if self.memory.profile.embedding_dim == 0 {
            warn!(
                target: "docdexd",
                "memory.profile.embedding_dim must be > 0; using default"
            );
            self.memory.profile.embedding_dim = DEFAULT_PROFILE_EMBED_DIM;
        }
        if self.memory.conversations.max_wakeup_tokens == 0 {
            warn!(
                target: "docdexd",
                "memory.conversations.max_wakeup_tokens must be > 0; using default"
            );
            self.memory.conversations.max_wakeup_tokens = default_conversation_wakeup_tokens();
        }
        if self.memory.conversations.max_wakeup_diary_episodes == 0 {
            warn!(
                target: "docdexd",
                "memory.conversations.max_wakeup_diary_episodes must be > 0; using default"
            );
            self.memory.conversations.max_wakeup_diary_episodes =
                default_conversation_wakeup_diary_episode_limit();
        }
        if self.memory.conversations.max_episodic_summaries == 0 {
            warn!(
                target: "docdexd",
                "memory.conversations.max_episodic_summaries must be > 0; using default"
            );
            self.memory.conversations.max_episodic_summaries = default_conversation_summary_limit();
        }
        if self.memory.conversations.max_knowledge_facts == 0 {
            warn!(
                target: "docdexd",
                "memory.conversations.max_knowledge_facts must be > 0; using default"
            );
            self.memory.conversations.max_knowledge_facts = default_conversation_knowledge_limit();
        }
        if self.memory.conversations.max_transcript_snippets == 0 {
            warn!(
                target: "docdexd",
                "memory.conversations.max_transcript_snippets must be > 0; using default"
            );
            self.memory.conversations.max_transcript_snippets =
                default_conversation_snippet_limit();
        }
        if self.memory.conversations.auto_capture_retention_days == 0 {
            warn!(
                target: "docdexd",
                "memory.conversations.auto_capture_retention_days must be > 0; using default"
            );
            self.memory.conversations.auto_capture_retention_days =
                default_conversation_auto_retention_days();
        }
        if self.memory.conversations.hook_event_retention_days == 0 {
            warn!(
                target: "docdexd",
                "memory.conversations.hook_event_retention_days must be > 0; using default"
            );
            self.memory.conversations.hook_event_retention_days =
                default_conversation_hook_event_retention_days();
        }
        if self.memory.conversations.working_memory_retention_days == 0 {
            warn!(
                target: "docdexd",
                "memory.conversations.working_memory_retention_days must be > 0; using default"
            );
            self.memory.conversations.working_memory_retention_days =
                default_conversation_working_memory_retention_days();
        }
        if self.memory.conversations.episodic_rollup_retention_days == 0 {
            warn!(
                target: "docdexd",
                "memory.conversations.episodic_rollup_retention_days must be > 0; using default"
            );
            self.memory.conversations.episodic_rollup_retention_days =
                default_conversation_episodic_rollup_retention_days();
        }
        if self.memory.conversations.sweeper_interval_seconds == 0 {
            warn!(
                target: "docdexd",
                "memory.conversations.sweeper_interval_seconds must be > 0; using default"
            );
            self.memory.conversations.sweeper_interval_seconds =
                default_conversation_sweeper_interval_seconds();
        }
        self.memory.conversations.graph.apply_defaults();
        if self.memory.personal_preferences.max_context_records == 0 {
            warn!(
                target: "docdexd",
                "memory.personal_preferences.max_context_records must be > 0; using default"
            );
            self.memory.personal_preferences.max_context_records =
                default_personal_preferences_context_record_limit();
        }
        if self.memory.personal_preferences.max_context_tokens == 0 {
            warn!(
                target: "docdexd",
                "memory.personal_preferences.max_context_tokens must be > 0; using default"
            );
            self.memory.personal_preferences.max_context_tokens =
                default_personal_preferences_context_token_budget();
        }
        if self.memory.personal_preferences.max_parallel_digest_jobs == 0 {
            warn!(
                target: "docdexd",
                "memory.personal_preferences.max_parallel_digest_jobs must be > 0; using default"
            );
            self.memory.personal_preferences.max_parallel_digest_jobs =
                default_personal_preferences_max_parallel_digest_jobs();
        }
        if self.memory.personal_preferences.digest_interval_seconds == 0 {
            warn!(
                target: "docdexd",
                "memory.personal_preferences.digest_interval_seconds must be > 0; using default"
            );
            self.memory.personal_preferences.digest_interval_seconds =
                default_personal_preferences_digest_interval_seconds();
        }
        if self.memory.personal_preferences.enabled
            && self.memory.personal_preferences.capture_enabled
            && (self
                .memory
                .personal_preferences
                .capture_supported_client_transcripts
                || self.memory.personal_preferences.digest_enabled)
            && !self.memory.personal_preferences.process_in_background
        {
            warn!(
                target: "docdexd",
                "personal preferences capture/digest automation is enabled but process_in_background is false; transcript scanning and digest processing require manual commands"
            );
        }
        self.memory
            .personal_preferences
            .source_allowlist
            .retain(|item| !item.trim().is_empty());
        self.memory
            .personal_preferences
            .source_denylist
            .retain(|item| !item.trim().is_empty());
        self.memory
            .personal_preferences
            .client_transcript_roots
            .retain(|item| !item.trim().is_empty());
        self.memory.personal_preferences.content_encryption_key_env = self
            .memory
            .personal_preferences
            .content_encryption_key_env
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
        if self.code_intelligence.dynamic_import_scan_limit == 0 {
            warn!(
                target: "docdexd",
                "dynamic_import_scan_limit must be > 0; using default"
            );
            self.code_intelligence.dynamic_import_scan_limit = default_dynamic_import_scan_limit();
        }
        if self.server.http_bind_addr.trim().is_empty() {
            self.server.http_bind_addr = DEFAULT_HTTP_BIND_ADDR.to_string();
        }
        let mcp_ipc_mode = self.server.mcp_ipc_mode.trim();
        if mcp_ipc_mode.is_empty() {
            self.server.mcp_ipc_mode = default_mcp_ipc_mode();
        } else {
            let normalized = mcp_ipc_mode.to_lowercase();
            if normalized == "auto" || normalized == "off" {
                self.server.mcp_ipc_mode = normalized;
            } else {
                warn!(
                    target: "docdexd",
                    value = %mcp_ipc_mode,
                    "invalid server.mcp_ipc_mode; expected auto or off"
                );
                self.server.mcp_ipc_mode = default_mcp_ipc_mode();
            }
        }
        if self.server.hook_socket_path.trim().is_empty() {
            self.server.hook_socket_path = default_hook_socket_path();
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreConfig {
    #[serde(default)]
    pub global_state_dir: Option<PathBuf>,
    #[serde(default = "default_log_level")]
    pub log_level: String,
    #[serde(default = "default_max_concurrent_fetches")]
    pub max_concurrent_fetches: u32,
}

impl Default for CoreConfig {
    fn default() -> Self {
        Self {
            global_state_dir: None,
            log_level: default_log_level(),
            max_concurrent_fetches: default_max_concurrent_fetches(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmConfig {
    #[serde(default = "default_llm_provider")]
    pub provider: String,
    #[serde(default = "default_llm_base_url")]
    pub base_url: String,
    #[serde(default = "default_llm_model")]
    pub default_model: String,
    #[serde(default)]
    pub agent_id: String,
    #[serde(default = "default_embed_model")]
    pub embedding_model: String,
    #[serde(default = "default_max_answer_tokens")]
    pub max_answer_tokens: u32,
    #[serde(default)]
    pub delegation: DelegationConfig,
}

impl Default for LlmConfig {
    fn default() -> Self {
        Self {
            provider: default_llm_provider(),
            base_url: default_llm_base_url(),
            default_model: default_llm_model(),
            agent_id: String::new(),
            embedding_model: default_embed_model(),
            max_answer_tokens: default_max_answer_tokens(),
            delegation: DelegationConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationLaneConfig {
    #[serde(default)]
    pub local_agent_id: String,
    #[serde(default)]
    pub cloud_agent_id: String,
    #[serde(default)]
    pub primary_agent_id: String,
}

impl DelegationLaneConfig {
    fn is_empty(&self) -> bool {
        self.local_agent_id.trim().is_empty()
            && self.cloud_agent_id.trim().is_empty()
            && self.primary_agent_id.trim().is_empty()
    }
}

impl Default for DelegationLaneConfig {
    fn default() -> Self {
        Self {
            local_agent_id: String::new(),
            cloud_agent_id: String::new(),
            primary_agent_id: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationCloudConfig {
    #[serde(default = "default_delegation_cloud_enabled")]
    pub enabled: bool,
    #[serde(default = "default_delegation_cloud_provider")]
    pub provider: String,
    #[serde(default = "default_delegation_cloud_limit")]
    pub limit: usize,
    #[serde(default = "default_delegation_cloud_sync_limit")]
    pub sync_limit: usize,
    #[serde(default = "default_delegation_cloud_sorted_by_catalog_rating")]
    pub sorted_by_catalog_rating: bool,
    #[serde(default = "default_delegation_cloud_max_cost_per_million")]
    pub max_cost_per_million: f64,
    #[serde(default = "default_delegation_cloud_min_context")]
    pub min_context: usize,
    #[serde(default = "default_delegation_cloud_min_reasoning")]
    pub min_reasoning: f64,
}

impl Default for DelegationCloudConfig {
    fn default() -> Self {
        Self {
            enabled: default_delegation_cloud_enabled(),
            provider: default_delegation_cloud_provider(),
            limit: default_delegation_cloud_limit(),
            sync_limit: default_delegation_cloud_sync_limit(),
            sorted_by_catalog_rating: default_delegation_cloud_sorted_by_catalog_rating(),
            max_cost_per_million: default_delegation_cloud_max_cost_per_million(),
            min_context: default_delegation_cloud_min_context(),
            min_reasoning: default_delegation_cloud_min_reasoning(),
        }
    }
}

impl DelegationCloudConfig {
    fn apply_defaults(&mut self) {
        if self.provider.trim().is_empty() {
            self.provider = default_delegation_cloud_provider();
        }
        if self.limit == 0 {
            self.limit = default_delegation_cloud_limit();
        }
        if self.sync_limit == 0 {
            self.sync_limit = default_delegation_cloud_sync_limit();
        }
        if self.min_context == 0 {
            self.min_context = default_delegation_cloud_min_context();
        }
        self.max_cost_per_million = sanitize_non_negative_f64(self.max_cost_per_million);
        self.min_reasoning = sanitize_non_negative_f64(self.min_reasoning);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationConfig {
    #[serde(default = "default_delegation_enabled")]
    pub enabled: bool,
    #[serde(default = "default_delegation_auto_enable")]
    pub auto_enable: bool,
    #[serde(default = "default_delegation_enforce_local")]
    pub enforce_local: bool,
    #[serde(default = "default_delegation_allow_fallback_to_primary")]
    pub allow_fallback_to_primary: bool,
    #[serde(default = "default_delegation_re_evaluate")]
    pub re_evaluate: bool,
    #[serde(default)]
    pub local_agent_id: String,
    #[serde(default)]
    pub cloud_agent_id: String,
    #[serde(default)]
    pub primary_agent_id: String,
    #[serde(default, skip_serializing_if = "DelegationLaneConfig::is_empty")]
    pub code: DelegationLaneConfig,
    #[serde(default, skip_serializing_if = "DelegationLaneConfig::is_empty")]
    pub general: DelegationLaneConfig,
    #[serde(default)]
    pub cloud: DelegationCloudConfig,
    #[serde(default = "default_delegation_local_selection_policy")]
    pub local_selection_policy: String,
    #[serde(default = "default_delegation_use_cached_local_decision")]
    pub use_cached_local_decision: bool,
    #[serde(default = "default_delegation_mode")]
    pub mode: String,
    #[serde(default = "default_delegation_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_delegation_max_tokens")]
    pub max_tokens: u32,
    #[serde(default = "default_delegation_max_context_chars")]
    pub max_context_chars: usize,
    #[serde(
        default = "default_delegation_primary_usd_per_million_tokens",
        alias = "primary_usd_per_1k_tokens"
    )]
    pub primary_usd_per_million_tokens: f64,
    #[serde(
        default = "default_delegation_local_usd_per_million_tokens",
        alias = "local_usd_per_1k_tokens"
    )]
    pub local_usd_per_million_tokens: f64,
    #[serde(default)]
    pub task_allowlist: Vec<String>,
}

impl Default for DelegationConfig {
    fn default() -> Self {
        Self {
            enabled: default_delegation_enabled(),
            auto_enable: default_delegation_auto_enable(),
            enforce_local: default_delegation_enforce_local(),
            allow_fallback_to_primary: default_delegation_allow_fallback_to_primary(),
            re_evaluate: default_delegation_re_evaluate(),
            local_agent_id: String::new(),
            cloud_agent_id: String::new(),
            primary_agent_id: String::new(),
            code: DelegationLaneConfig::default(),
            general: DelegationLaneConfig::default(),
            cloud: DelegationCloudConfig::default(),
            local_selection_policy: default_delegation_local_selection_policy(),
            use_cached_local_decision: default_delegation_use_cached_local_decision(),
            mode: default_delegation_mode(),
            timeout_ms: default_delegation_timeout_ms(),
            max_tokens: default_delegation_max_tokens(),
            max_context_chars: default_delegation_max_context_chars(),
            primary_usd_per_million_tokens: default_delegation_primary_usd_per_million_tokens(),
            local_usd_per_million_tokens: default_delegation_local_usd_per_million_tokens(),
            task_allowlist: Vec::new(),
        }
    }
}

impl DelegationConfig {
    fn apply_defaults(&mut self) {
        self.local_selection_policy =
            normalize_delegation_local_selection_policy(&self.local_selection_policy);
        if self.mode.trim().is_empty() {
            self.mode = default_delegation_mode();
        }
        if self.timeout_ms == 0 {
            self.timeout_ms = default_delegation_timeout_ms();
        }
        if self.max_tokens == 0 {
            self.max_tokens = default_delegation_max_tokens();
        }
        if self.max_context_chars == 0 {
            self.max_context_chars = default_delegation_max_context_chars();
        }
        self.primary_usd_per_million_tokens =
            sanitize_non_negative_f64(self.primary_usd_per_million_tokens);
        self.local_usd_per_million_tokens =
            sanitize_non_negative_f64(self.local_usd_per_million_tokens);
        self.cloud.apply_defaults();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SearchConfig {
    #[serde(default = "default_web_trigger_threshold")]
    pub web_trigger_threshold: f32,
    #[serde(default = "default_web_min_match_ratio")]
    pub web_min_match_ratio: f32,
    #[serde(default = "default_local_relevance_threshold")]
    pub local_relevance_threshold: f32,
    #[serde(default = "default_max_repo_hits")]
    pub max_repo_hits: usize,
    #[serde(default = "default_max_web_hits")]
    pub max_web_hits: usize,
    #[serde(default = "default_symbol_ranking_enabled")]
    pub symbol_ranking_enabled: bool,
    #[serde(default = "default_ast_ranking_enabled")]
    pub ast_ranking_enabled: bool,
    #[serde(default = "default_chat_symbol_ranking_enabled")]
    pub chat_symbol_ranking_enabled: bool,
    #[serde(default = "default_chat_ast_ranking_enabled")]
    pub chat_ast_ranking_enabled: bool,
}

impl Default for SearchConfig {
    fn default() -> Self {
        Self {
            web_trigger_threshold: default_web_trigger_threshold(),
            web_min_match_ratio: default_web_min_match_ratio(),
            local_relevance_threshold: default_local_relevance_threshold(),
            max_repo_hits: default_max_repo_hits(),
            max_web_hits: default_max_web_hits(),
            symbol_ranking_enabled: default_symbol_ranking_enabled(),
            ast_ranking_enabled: default_ast_ranking_enabled(),
            chat_symbol_ranking_enabled: default_chat_symbol_ranking_enabled(),
            chat_ast_ranking_enabled: default_chat_ast_ranking_enabled(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeIntelligenceConfig {
    #[serde(default = "default_dynamic_import_scan_limit")]
    pub dynamic_import_scan_limit: usize,
    #[serde(default = "default_import_traces_enabled")]
    pub import_traces_enabled: bool,
}

impl Default for CodeIntelligenceConfig {
    fn default() -> Self {
        Self {
            dynamic_import_scan_limit: default_dynamic_import_scan_limit(),
            import_traces_enabled: default_import_traces_enabled(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebConfigSection {
    #[serde(default = "default_discovery_provider")]
    pub discovery_provider: String,
    #[serde(default = "default_web_user_agent")]
    pub user_agent: String,
    #[serde(default)]
    pub ddg_base_url: Option<String>,
    #[serde(default)]
    pub ddg_proxy_base_url: Option<String>,
    #[serde(default = "default_web_min_spacing_ms")]
    pub min_spacing_ms: u64,
    #[serde(default = "default_web_cache_ttl_secs")]
    pub cache_ttl_secs: u64,
    #[serde(default)]
    pub blocklist: Vec<String>,
    #[serde(default)]
    pub boilerplate_phrases: Vec<String>,
    #[serde(default)]
    pub boilerplate_phrases_path: Option<PathBuf>,
    #[serde(default)]
    pub providers: WebProviderConfig,
    #[serde(default)]
    pub scraper: WebScraperConfig,
}

impl Default for WebConfigSection {
    fn default() -> Self {
        Self {
            discovery_provider: default_discovery_provider(),
            user_agent: default_web_user_agent(),
            ddg_base_url: None,
            ddg_proxy_base_url: None,
            min_spacing_ms: default_web_min_spacing_ms(),
            cache_ttl_secs: default_web_cache_ttl_secs(),
            blocklist: Vec::new(),
            boilerplate_phrases: Vec::new(),
            boilerplate_phrases_path: None,
            providers: WebProviderConfig::default(),
            scraper: WebScraperConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebProviderConfig {
    #[serde(default)]
    pub brave_api_key: Option<String>,
    #[serde(default)]
    pub google_cse_api_key: Option<String>,
    #[serde(default)]
    pub google_cse_cx: Option<String>,
    #[serde(default)]
    pub bing_api_key: Option<String>,
}

impl Default for WebProviderConfig {
    fn default() -> Self {
        Self {
            brave_api_key: None,
            google_cse_api_key: None,
            google_cse_cx: None,
            bing_api_key: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebScraperConfig {
    #[serde(default = "default_web_engine")]
    pub engine: String,
    #[serde(default = "default_web_headless")]
    pub headless: bool,
    #[serde(default)]
    pub chrome_binary_path: Option<PathBuf>,
    #[serde(default)]
    pub user_data_dir: Option<PathBuf>,
    #[serde(default = "default_web_auto_install")]
    pub auto_install: bool,
    #[serde(default)]
    pub browser_kind: Option<String>,
    #[serde(default = "default_request_delay_ms")]
    pub request_delay_ms: u64,
    #[serde(default = "default_page_load_timeout_secs")]
    pub page_load_timeout_secs: u64,
}

impl Default for WebScraperConfig {
    fn default() -> Self {
        Self {
            engine: default_web_engine(),
            headless: default_web_headless(),
            chrome_binary_path: None,
            user_data_dir: None,
            auto_install: default_web_auto_install(),
            browser_kind: None,
            request_delay_ms: default_request_delay_ms(),
            page_load_timeout_secs: default_page_load_timeout_secs(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationsConfig {
    #[serde(default)]
    pub mswarm: MswarmConfig,
}

impl Default for IntegrationsConfig {
    fn default() -> Self {
        Self {
            mswarm: MswarmConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MswarmConfig {
    #[serde(default = "default_mswarm_base_url")]
    pub base_url: String,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default)]
    pub telemetry: MswarmTelemetryConfig,
}

impl Default for MswarmConfig {
    fn default() -> Self {
        Self {
            base_url: default_mswarm_base_url(),
            api_key: None,
            telemetry: MswarmTelemetryConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MswarmTelemetryConfig {
    #[serde(default = "default_mswarm_telemetry_required")]
    pub required: bool,
    #[serde(default)]
    pub consent_accepted: bool,
    #[serde(default)]
    pub consent_policy_version: String,
    #[serde(default)]
    pub consent_token: Option<String>,
    #[serde(default)]
    pub client_id: String,
    #[serde(default = "default_mswarm_client_type")]
    pub client_type: String,
    #[serde(default)]
    pub registered_at_ms: u64,
    #[serde(default)]
    pub last_upload_at_ms: u64,
    #[serde(default)]
    pub upload_signing_secret: Option<String>,
}

impl Default for MswarmTelemetryConfig {
    fn default() -> Self {
        Self {
            required: default_mswarm_telemetry_required(),
            consent_accepted: false,
            consent_policy_version: String::new(),
            consent_token: None,
            client_id: String::new(),
            client_type: default_mswarm_client_type(),
            registered_at_ms: 0,
            last_upload_at_ms: 0,
            upload_signing_secret: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryConfig {
    #[serde(default = "default_memory_enabled")]
    pub enabled: bool,
    #[serde(default = "default_memory_backend")]
    pub backend: String,
    #[serde(default)]
    pub profile: MemoryProfileConfig,
    #[serde(default)]
    pub conversations: MemoryConversationConfig,
    #[serde(default)]
    pub personal_preferences: MemoryPersonalPreferencesConfig,
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            enabled: default_memory_enabled(),
            backend: default_memory_backend(),
            profile: MemoryProfileConfig::default(),
            conversations: MemoryConversationConfig::default(),
            personal_preferences: MemoryPersonalPreferencesConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryProfileConfig {
    #[serde(default = "default_profile_embed_model")]
    pub embedding_model: String,
    #[serde(default = "default_profile_embed_dim")]
    pub embedding_dim: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryConversationConfig {
    #[serde(default = "default_conversation_memory_enabled")]
    pub enabled: bool,
    #[serde(default = "default_conversation_auto_capture")]
    pub auto_capture: bool,
    #[serde(default = "default_conversation_archive_raw_transcripts")]
    pub archive_raw_transcripts: bool,
    #[serde(default = "default_conversation_wakeup_include_recent_diary_episodes")]
    pub wakeup_include_recent_diary_episodes: bool,
    #[serde(default = "default_conversation_wakeup_tokens")]
    pub max_wakeup_tokens: usize,
    #[serde(default = "default_conversation_wakeup_diary_episode_limit")]
    pub max_wakeup_diary_episodes: usize,
    #[serde(default = "default_conversation_summary_limit")]
    pub max_episodic_summaries: usize,
    #[serde(default = "default_conversation_knowledge_limit")]
    pub max_knowledge_facts: usize,
    #[serde(default = "default_conversation_snippet_limit")]
    pub max_transcript_snippets: usize,
    #[serde(default = "default_conversation_auto_retention_days")]
    pub auto_capture_retention_days: u32,
    #[serde(default)]
    pub manual_retention_days: u32,
    #[serde(default)]
    pub diary_retention_days: u32,
    #[serde(default = "default_conversation_hook_event_retention_days")]
    pub hook_event_retention_days: u32,
    #[serde(default = "default_conversation_working_memory_retention_days")]
    pub working_memory_retention_days: u32,
    #[serde(default = "default_conversation_episodic_rollup_retention_days")]
    pub episodic_rollup_retention_days: u32,
    #[serde(default = "default_conversation_sweeper_interval_seconds")]
    pub sweeper_interval_seconds: u64,
    #[serde(default)]
    pub source_allowlist: Vec<String>,
    #[serde(default)]
    pub source_denylist: Vec<String>,
    #[serde(default)]
    pub graph: MemoryConversationGraphConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryPersonalPreferencesConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_personal_preferences_storage_root")]
    pub storage_root: String,
    #[serde(default = "default_personal_preferences_capture_enabled")]
    pub capture_enabled: bool,
    #[serde(
        default = "default_personal_preferences_capture_docdex_conversations",
        alias = "auto_capture_chat_completions"
    )]
    pub capture_docdex_conversations: bool,
    #[serde(
        default = "default_personal_preferences_capture_conversation_hooks",
        alias = "auto_capture_conversation_hooks"
    )]
    pub capture_conversation_hooks: bool,
    #[serde(default = "default_personal_preferences_capture_imported_conversations")]
    pub capture_imported_conversations: bool,
    #[serde(default = "default_personal_preferences_capture_supported_client_transcripts")]
    pub capture_supported_client_transcripts: bool,
    #[serde(
        default = "default_personal_preferences_archive_raw_conversations",
        alias = "archive_raw_messages"
    )]
    pub archive_raw_conversations: bool,
    #[serde(default = "default_personal_preferences_export_enabled")]
    pub export_enabled: bool,
    #[serde(default = "default_personal_preferences_purge_enabled")]
    pub purge_enabled: bool,
    #[serde(default = "default_personal_preferences_digest_enabled")]
    pub digest_enabled: bool,
    #[serde(default = "default_personal_preferences_process_in_background")]
    pub process_in_background: bool,
    #[serde(
        default = "default_personal_preferences_digest_with_local_mcoda_only",
        alias = "local_mcoda_only"
    )]
    pub digest_with_local_mcoda_only: bool,
    #[serde(default = "default_personal_preferences_context_injection_enabled")]
    pub context_injection_enabled: bool,
    #[serde(default = "default_personal_preferences_context_record_limit")]
    pub max_context_records: usize,
    #[serde(default = "default_personal_preferences_context_token_budget")]
    pub max_context_tokens: usize,
    #[serde(default = "default_personal_preferences_allow_sensitive_context")]
    pub allow_sensitive_context: bool,
    #[serde(default = "default_personal_preferences_auto_project_safe_preferences_to_profile")]
    pub auto_project_safe_preferences_to_profile: bool,
    #[serde(default = "default_personal_preferences_max_parallel_digest_jobs")]
    pub max_parallel_digest_jobs: usize,
    #[serde(
        default = "default_personal_preferences_digest_interval_seconds",
        alias = "processing_interval_seconds"
    )]
    pub digest_interval_seconds: u64,
    #[serde(default = "default_personal_preferences_review_required_for_sensitive")]
    pub review_required_for_sensitive: bool,
    #[serde(default = "default_personal_preferences_transcript_secret_scrubber_enabled")]
    pub transcript_secret_scrubber_enabled: bool,
    #[serde(default)]
    pub content_encryption_key_env: Option<String>,
    #[serde(default)]
    pub client_transcript_roots: Vec<String>,
    #[serde(default)]
    pub source_allowlist: Vec<String>,
    #[serde(default)]
    pub source_denylist: Vec<String>,
    #[serde(default = "default_personal_preferences_raw_retention_days")]
    pub raw_retention_days: u32,
    #[serde(default = "default_personal_preferences_derived_retention_days")]
    pub derived_retention_days: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryConversationGraphConfig {
    #[serde(default = "default_conversation_graph_strict_validation")]
    pub strict_ontology_validation: bool,
    #[serde(default)]
    pub entity_types: Vec<MemoryConversationGraphEntityTypeConfig>,
    #[serde(default)]
    pub relation_types: Vec<MemoryConversationGraphRelationTypeConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryConversationGraphEntityTypeConfig {
    pub name: String,
    #[serde(default)]
    pub aliases: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryConversationGraphRelationTypeConfig {
    pub name: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    #[serde(default)]
    pub subject_types: Vec<String>,
    #[serde(default)]
    pub object_types: Vec<String>,
    #[serde(default = "default_conversation_graph_relation_allow_literal_object")]
    pub allow_literal_object: bool,
    #[serde(default)]
    pub cardinality: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeatureFlagsConfig {
    #[serde(default = "default_enable_hooks")]
    pub hooks: bool,
    #[serde(default = "default_enable_project_map")]
    pub project_map: bool,
    #[serde(default = "default_enable_tui_overlay")]
    pub tui_overlay: bool,
    #[serde(default = "default_enable_workflow_prompt")]
    pub workflow_prompt: bool,
}

impl Default for FeatureFlagsConfig {
    fn default() -> Self {
        Self {
            hooks: default_enable_hooks(),
            project_map: default_enable_project_map(),
            tui_overlay: default_enable_tui_overlay(),
            workflow_prompt: default_enable_workflow_prompt(),
        }
    }
}

impl Default for MemoryProfileConfig {
    fn default() -> Self {
        Self {
            embedding_model: default_profile_embed_model(),
            embedding_dim: default_profile_embed_dim(),
        }
    }
}

impl Default for MemoryConversationConfig {
    fn default() -> Self {
        Self {
            enabled: default_conversation_memory_enabled(),
            auto_capture: default_conversation_auto_capture(),
            archive_raw_transcripts: default_conversation_archive_raw_transcripts(),
            wakeup_include_recent_diary_episodes:
                default_conversation_wakeup_include_recent_diary_episodes(),
            max_wakeup_tokens: default_conversation_wakeup_tokens(),
            max_wakeup_diary_episodes: default_conversation_wakeup_diary_episode_limit(),
            max_episodic_summaries: default_conversation_summary_limit(),
            max_knowledge_facts: default_conversation_knowledge_limit(),
            max_transcript_snippets: default_conversation_snippet_limit(),
            auto_capture_retention_days: default_conversation_auto_retention_days(),
            manual_retention_days: 0,
            diary_retention_days: 0,
            hook_event_retention_days: default_conversation_hook_event_retention_days(),
            working_memory_retention_days: default_conversation_working_memory_retention_days(),
            episodic_rollup_retention_days: default_conversation_episodic_rollup_retention_days(),
            sweeper_interval_seconds: default_conversation_sweeper_interval_seconds(),
            source_allowlist: Vec::new(),
            source_denylist: Vec::new(),
            graph: MemoryConversationGraphConfig::default(),
        }
    }
}

impl Default for MemoryPersonalPreferencesConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            storage_root: default_personal_preferences_storage_root(),
            capture_enabled: default_personal_preferences_capture_enabled(),
            capture_docdex_conversations: default_personal_preferences_capture_docdex_conversations(
            ),
            capture_conversation_hooks: default_personal_preferences_capture_conversation_hooks(),
            capture_imported_conversations:
                default_personal_preferences_capture_imported_conversations(),
            capture_supported_client_transcripts:
                default_personal_preferences_capture_supported_client_transcripts(),
            archive_raw_conversations: default_personal_preferences_archive_raw_conversations(),
            export_enabled: default_personal_preferences_export_enabled(),
            purge_enabled: default_personal_preferences_purge_enabled(),
            digest_enabled: default_personal_preferences_digest_enabled(),
            process_in_background: default_personal_preferences_process_in_background(),
            digest_with_local_mcoda_only: default_personal_preferences_digest_with_local_mcoda_only(
            ),
            context_injection_enabled: default_personal_preferences_context_injection_enabled(),
            max_context_records: default_personal_preferences_context_record_limit(),
            max_context_tokens: default_personal_preferences_context_token_budget(),
            allow_sensitive_context: default_personal_preferences_allow_sensitive_context(),
            auto_project_safe_preferences_to_profile:
                default_personal_preferences_auto_project_safe_preferences_to_profile(),
            max_parallel_digest_jobs: default_personal_preferences_max_parallel_digest_jobs(),
            digest_interval_seconds: default_personal_preferences_digest_interval_seconds(),
            review_required_for_sensitive:
                default_personal_preferences_review_required_for_sensitive(),
            transcript_secret_scrubber_enabled:
                default_personal_preferences_transcript_secret_scrubber_enabled(),
            content_encryption_key_env: None,
            client_transcript_roots: Vec::new(),
            source_allowlist: Vec::new(),
            source_denylist: Vec::new(),
            raw_retention_days: default_personal_preferences_raw_retention_days(),
            derived_retention_days: default_personal_preferences_derived_retention_days(),
        }
    }
}

impl MemoryConversationConfig {
    pub fn allows_source(&self, source: &str) -> bool {
        let normalized = source.trim().to_ascii_lowercase();
        if normalized.is_empty() {
            return true;
        }
        if self
            .source_denylist
            .iter()
            .map(|item| item.trim().to_ascii_lowercase())
            .any(|item| !item.is_empty() && item == normalized)
        {
            return false;
        }
        if self.source_allowlist.is_empty() {
            return true;
        }
        self.source_allowlist
            .iter()
            .map(|item| item.trim().to_ascii_lowercase())
            .any(|item| !item.is_empty() && item == normalized)
    }
}

impl MemoryPersonalPreferencesConfig {
    pub fn allows_source(&self, source: &str) -> bool {
        let normalized = source.trim();
        if normalized.is_empty() {
            return true;
        }
        let normalized = normalized.to_ascii_lowercase();
        if self
            .source_denylist
            .iter()
            .any(|item| item.trim().eq_ignore_ascii_case(&normalized))
        {
            return false;
        }
        if self.source_allowlist.is_empty() {
            return true;
        }
        self.source_allowlist
            .iter()
            .any(|item| item.trim().eq_ignore_ascii_case(&normalized))
    }

    pub fn resolved_storage_root(&self, global_state_dir: Option<&Path>) -> Result<PathBuf> {
        let configured = self.storage_root.trim();
        if !configured.is_empty() {
            return expand_config_path(configured, global_state_dir);
        }
        let state_dir = match global_state_dir {
            Some(path) => path.to_path_buf(),
            None => default_state_dir()?,
        };
        Ok(crate::state_layout::personal_preferences_root_for_base(
            &state_dir,
        ))
    }
}

impl Default for MemoryConversationGraphConfig {
    fn default() -> Self {
        Self {
            strict_ontology_validation: default_conversation_graph_strict_validation(),
            entity_types: Vec::new(),
            relation_types: Vec::new(),
        }
    }
}

impl MemoryConversationGraphConfig {
    fn apply_defaults(&mut self) {
        self.entity_types
            .retain(|item| !item.name.trim().is_empty());
        for item in &mut self.entity_types {
            item.aliases.retain(|alias| !alias.trim().is_empty());
        }
        self.relation_types
            .retain(|item| !item.name.trim().is_empty());
        for item in &mut self.relation_types {
            item.aliases.retain(|alias| !alias.trim().is_empty());
            item.subject_types
                .retain(|entity_type| !entity_type.trim().is_empty());
            item.object_types
                .retain(|entity_type| !entity_type.trim().is_empty());
            item.cardinality = item
                .cardinality
                .as_deref()
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned);
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_http_bind_addr")]
    pub http_bind_addr: String,
    #[serde(default = "default_enable_mcp")]
    pub enable_mcp: bool,
    #[serde(default = "default_mcp_ipc_mode")]
    pub mcp_ipc_mode: String,
    #[serde(default = "default_mcp_socket_path")]
    pub mcp_socket_path: String,
    #[serde(default = "default_mcp_pipe_name")]
    pub mcp_pipe_name: String,
    #[serde(default = "default_hook_socket_path")]
    pub hook_socket_path: String,
    #[serde(default = "default_server_default_agent_id")]
    pub default_agent_id: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            http_bind_addr: default_http_bind_addr(),
            enable_mcp: default_enable_mcp(),
            mcp_ipc_mode: default_mcp_ipc_mode(),
            mcp_socket_path: default_mcp_socket_path(),
            mcp_pipe_name: default_mcp_pipe_name(),
            hook_socket_path: default_hook_socket_path(),
            default_agent_id: default_server_default_agent_id(),
        }
    }
}

pub fn load_config_from_path(path: &Path) -> Result<AppConfig> {
    if !path.exists() {
        let mut config = default_config_with_paths()?;
        write_config(path, &config)?;
        apply_env_overrides(&mut config);
        apply_impact_settings(ImpactSettings {
            dynamic_import_scan_limit: config.code_intelligence.dynamic_import_scan_limit,
            import_traces_enabled: config.code_intelligence.import_traces_enabled,
        });
        return Ok(config);
    }
    let text =
        std::fs::read_to_string(path).with_context(|| format!("read config {}", path.display()))?;
    if text.trim().is_empty() {
        let mut config = default_config_with_paths()?;
        write_config(path, &config)?;
        apply_env_overrides(&mut config);
        apply_impact_settings(ImpactSettings {
            dynamic_import_scan_limit: config.code_intelligence.dynamic_import_scan_limit,
            import_traces_enabled: config.code_intelligence.import_traces_enabled,
        });
        return Ok(config);
    }
    let mut config =
        parse_config_text(&text).with_context(|| format!("parse config {}", path.display()))?;
    config.apply_defaults()?;
    apply_env_overrides(&mut config);
    let mut updated = false;
    if apply_browser_defaults(&mut config) {
        updated = true;
    }
    if updated {
        write_config(path, &config)?;
    }
    apply_impact_settings(ImpactSettings {
        dynamic_import_scan_limit: config.code_intelligence.dynamic_import_scan_limit,
        import_traces_enabled: config.code_intelligence.import_traces_enabled,
    });
    Ok(config)
}

pub(crate) fn parse_config_text(text: &str) -> Result<AppConfig, toml::de::Error> {
    let parsed: AppConfigCompat = toml::from_str(text)?;
    Ok(parsed.into_config())
}

pub fn default_config_path() -> Result<PathBuf> {
    #[cfg(test)]
    {
        let _guard = crate::setup::test_support::ENV_LOCK.lock();
        return default_config_path_inner();
    }
    #[cfg(not(test))]
    {
        default_config_path_inner()
    }
}

fn default_config_path_inner() -> Result<PathBuf> {
    if let Ok(value) = std::env::var("DOCDEX_CONFIG_PATH") {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return Ok(PathBuf::from(trimmed));
        }
    }
    let state_dir = default_state_dir()?;
    let base = state_dir.parent().ok_or_else(|| {
        anyhow!(
            "unable to resolve config directory from {}",
            state_dir.display()
        )
    })?;
    Ok(base.join(DEFAULT_CONFIG_FILE))
}

fn default_config_with_paths() -> Result<AppConfig> {
    let mut config = AppConfig::default();
    config.apply_defaults()?;
    apply_browser_defaults(&mut config);
    Ok(config)
}

fn default_log_level() -> String {
    DEFAULT_LOG_LEVEL.to_string()
}

fn default_max_concurrent_fetches() -> u32 {
    2
}

fn default_llm_provider() -> String {
    DEFAULT_LLM_PROVIDER.to_string()
}

fn default_llm_base_url() -> String {
    DEFAULT_LLM_BASE_URL.to_string()
}

fn default_llm_model() -> String {
    DEFAULT_LLM_MODEL.to_string()
}

fn default_embed_model() -> String {
    DEFAULT_EMBED_MODEL.to_string()
}

fn default_delegation_enabled() -> bool {
    false
}

fn default_delegation_auto_enable() -> bool {
    true
}

fn default_delegation_enforce_local() -> bool {
    false
}

fn default_delegation_allow_fallback_to_primary() -> bool {
    false
}

fn default_delegation_re_evaluate() -> bool {
    true
}

fn default_delegation_mode() -> String {
    DEFAULT_DELEGATION_MODE.to_string()
}

fn default_delegation_local_selection_policy() -> String {
    DEFAULT_DELEGATION_LOCAL_SELECTION_POLICY.to_string()
}

fn default_delegation_use_cached_local_decision() -> bool {
    true
}

fn default_delegation_timeout_ms() -> u64 {
    DEFAULT_DELEGATION_TIMEOUT_MS
}

fn default_delegation_max_tokens() -> u32 {
    DEFAULT_DELEGATION_MAX_TOKENS
}

fn default_delegation_max_context_chars() -> usize {
    DEFAULT_DELEGATION_MAX_CONTEXT_CHARS
}

fn default_delegation_primary_usd_per_million_tokens() -> f64 {
    0.0
}

fn default_delegation_local_usd_per_million_tokens() -> f64 {
    0.0
}

fn default_delegation_cloud_enabled() -> bool {
    true
}

fn default_delegation_cloud_provider() -> String {
    "openrouter".to_string()
}

fn default_delegation_cloud_limit() -> usize {
    12
}

fn default_delegation_cloud_sync_limit() -> usize {
    12
}

fn default_delegation_cloud_sorted_by_catalog_rating() -> bool {
    true
}

fn default_delegation_cloud_max_cost_per_million() -> f64 {
    1.0
}

fn default_delegation_cloud_min_context() -> usize {
    128_000
}

fn default_delegation_cloud_min_reasoning() -> f64 {
    6.5
}

fn normalize_delegation_local_selection_policy(value: &str) -> String {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "" | "task_capability" | "task-capability" => {
            DEFAULT_DELEGATION_LOCAL_SELECTION_POLICY.to_string()
        }
        "mcoda_zero_cost_most_capable"
        | "mcoda-zero-cost-most-capable"
        | "zero_cost_mcoda_most_capable"
        | "zero-cost-mcoda-most-capable" => "mcoda_zero_cost_most_capable".to_string(),
        _ => {
            warn!(
                target: "docdexd",
                value = %value,
                "invalid delegation local selection policy; falling back to task_capability"
            );
            DEFAULT_DELEGATION_LOCAL_SELECTION_POLICY.to_string()
        }
    }
}

fn sanitize_non_negative_f64(value: f64) -> f64 {
    if value.is_finite() && value >= 0.0 {
        value
    } else {
        0.0
    }
}

fn default_profile_embed_model() -> String {
    DEFAULT_PROFILE_EMBED_MODEL.to_string()
}

fn default_profile_embed_dim() -> usize {
    DEFAULT_PROFILE_EMBED_DIM
}

fn default_server_default_agent_id() -> String {
    String::new()
}

fn default_mcp_ipc_mode() -> String {
    "auto".to_string()
}

fn default_mcp_socket_path() -> String {
    String::new()
}

fn default_mcp_pipe_name() -> String {
    String::new()
}

fn default_hook_socket_path() -> String {
    String::new()
}

fn default_enable_hooks() -> bool {
    true
}

fn default_enable_project_map() -> bool {
    true
}

fn default_enable_tui_overlay() -> bool {
    true
}

fn default_enable_workflow_prompt() -> bool {
    false
}

fn default_max_answer_tokens() -> u32 {
    1024
}

fn default_web_trigger_threshold() -> f32 {
    0.7
}

fn default_max_repo_hits() -> usize {
    8
}

fn default_max_web_hits() -> usize {
    8
}

fn default_symbol_ranking_enabled() -> bool {
    true
}

fn default_ast_ranking_enabled() -> bool {
    true
}

fn default_chat_symbol_ranking_enabled() -> bool {
    true
}

fn default_chat_ast_ranking_enabled() -> bool {
    true
}

fn default_dynamic_import_scan_limit() -> usize {
    DEFAULT_DYNAMIC_IMPORT_SCAN_LIMIT
}

fn default_import_traces_enabled() -> bool {
    DEFAULT_IMPORT_TRACES_ENABLED
}

fn default_web_min_match_ratio() -> f32 {
    0.2
}

fn default_local_relevance_threshold() -> f32 {
    0.7
}

pub(crate) fn default_discovery_provider() -> String {
    DEFAULT_DISCOVERY_PROVIDER.to_string()
}

pub(crate) fn default_web_user_agent() -> String {
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".to_string()
}

pub(crate) fn default_mswarm_base_url() -> String {
    DEFAULT_MSWARM_BASE_URL.to_string()
}

fn default_mswarm_telemetry_required() -> bool {
    true
}

fn default_mswarm_client_type() -> String {
    DEFAULT_MSWARM_CLIENT_TYPE.to_string()
}

fn default_web_min_spacing_ms() -> u64 {
    2_000
}

fn default_web_cache_ttl_secs() -> u64 {
    2_592_000
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repo_encryption_config_defaults_are_disabled() {
        let mut config = AppConfig::default();
        config.apply_defaults().expect("apply defaults");

        assert_eq!(config.auth.mode, crate::auth::AuthMode::LocalOrExternal);
        assert!(config.auth.static_token.enabled);
        assert!(!config.auth.static_token.encrypted_repo_data_access);
        assert!(!config.auth.external_api_key_introspection.enabled);
        assert!(!config.auth.service_token.enabled);
        assert!(!config.auth.service_token.encrypted_repo_data_access);
        assert!(!config.repo_encryption.is_enabled());
        assert_eq!(
            config.repo_encryption.encryption_mode,
            crate::repo_encryption::RepoEncryptionMode::Disabled
        );
        assert!(!config.repo_encryption.semantic_search_enabled);
        assert!(!config.repo_encryption.web_discovery_enabled);
        assert!(!config.repo_encryption.full_file_open_enabled);
        assert!(!config.repo_encryption.shared_bearer_token_sufficient);
    }

    #[test]
    fn repo_encryption_config_parses_explicit_enabled_policy() {
        let text = r#"
[repo_encryption]
encryption_mode = "application_managed_encryption"
key_env = "DOCDEX_TEST_REPO_KEY"
key_id = "test-key"
semantic_search_enabled = false
web_discovery_enabled = false
full_file_open_enabled = false
plaintext_term_index_enabled = true
max_results_per_query = 7
max_snippet_chars = 144
"#;
        let mut config = parse_config_text(text).expect("parse config");
        config.apply_defaults().expect("apply defaults");

        assert!(config.repo_encryption.is_enabled());
        assert_eq!(
            config.repo_encryption.encryption_mode,
            crate::repo_encryption::RepoEncryptionMode::ApplicationManagedEncryption
        );
        assert_eq!(config.repo_encryption.max_results_per_query, 7);
        assert_eq!(config.repo_encryption.max_snippet_chars, 144);
        assert_eq!(
            config.repo_encryption.key_env.as_deref(),
            Some("DOCDEX_TEST_REPO_KEY")
        );
        assert_eq!(config.repo_encryption.key_id.as_deref(), Some("test-key"));
        assert!(config.repo_encryption.plaintext_term_index_enabled);
        assert!(!config.repo_encryption.semantic_search_enabled);
        assert!(!config.repo_encryption.web_discovery_enabled);
        assert!(!config.repo_encryption.full_file_open_enabled);
        assert!(!config.repo_encryption.shared_bearer_token_sufficient);
    }

    #[test]
    fn repo_encryption_env_enabled_sanitizes_shared_bearer_flag() {
        let _guard = crate::setup::test_support::ENV_LOCK.lock();
        std::env::set_var("DOCDEX_REPO_ENCRYPTION_ENABLED", "true");
        std::env::remove_var("DOCDEX_REPO_ENCRYPTION_MODE");
        std::env::remove_var("DOCDEX_REPO_ENCRYPTION_KEY_ENV");
        std::env::remove_var("DOCDEX_REPO_ENCRYPTION_KEY_ID");
        std::env::remove_var("DOCDEX_REPO_ENCRYPTION_PLAINTEXT_TERM_INDEX_ENABLED");
        std::env::remove_var("DOCDEX_REPO_ENCRYPTION_WEB_DISCOVERY_ENABLED");

        let mut config = AppConfig {
            repo_encryption: RepoEncryptionConfig {
                shared_bearer_token_sufficient: true,
                ..RepoEncryptionConfig::default()
            },
            ..AppConfig::default()
        };
        apply_env_overrides(&mut config);

        assert!(config.repo_encryption.is_enabled());
        assert_eq!(
            config.repo_encryption.encryption_mode,
            crate::repo_encryption::RepoEncryptionMode::ApplicationManagedEncryption
        );
        assert!(!config.repo_encryption.shared_bearer_token_sufficient);

        std::env::remove_var("DOCDEX_REPO_ENCRYPTION_ENABLED");
    }

    #[test]
    fn repo_encryption_env_sets_key_metadata_and_term_index_policy() {
        let _guard = crate::setup::test_support::ENV_LOCK.lock();
        std::env::set_var("DOCDEX_REPO_ENCRYPTION_ENABLED", "true");
        std::env::set_var("DOCDEX_REPO_ENCRYPTION_KEY_ENV", "DOCDEX_TEST_KEY");
        std::env::set_var("DOCDEX_REPO_ENCRYPTION_KEY_ID", "test-key-id");
        std::env::set_var(
            "DOCDEX_REPO_ENCRYPTION_PLAINTEXT_TERM_INDEX_ENABLED",
            "false",
        );
        std::env::set_var("DOCDEX_REPO_ENCRYPTION_WEB_DISCOVERY_ENABLED", "true");

        let mut config = AppConfig::default();
        apply_env_overrides(&mut config);

        assert!(config.repo_encryption.is_enabled());
        assert_eq!(
            config.repo_encryption.key_env.as_deref(),
            Some("DOCDEX_TEST_KEY")
        );
        assert_eq!(
            config.repo_encryption.key_id.as_deref(),
            Some("test-key-id")
        );
        assert!(!config.repo_encryption.plaintext_term_index_enabled);
        assert!(config.repo_encryption.web_discovery_enabled);

        std::env::remove_var("DOCDEX_REPO_ENCRYPTION_ENABLED");
        std::env::remove_var("DOCDEX_REPO_ENCRYPTION_KEY_ENV");
        std::env::remove_var("DOCDEX_REPO_ENCRYPTION_KEY_ID");
        std::env::remove_var("DOCDEX_REPO_ENCRYPTION_PLAINTEXT_TERM_INDEX_ENABLED");
        std::env::remove_var("DOCDEX_REPO_ENCRYPTION_WEB_DISCOVERY_ENABLED");
    }

    #[test]
    fn repo_encryption_env_mode_takes_precedence_over_enabled_toggle() {
        let _guard = crate::setup::test_support::ENV_LOCK.lock();
        std::env::set_var("DOCDEX_REPO_ENCRYPTION_ENABLED", "true");
        std::env::set_var("DOCDEX_REPO_ENCRYPTION_MODE", "disabled");
        std::env::remove_var("DOCDEX_REPO_ENCRYPTION_KEY_ENV");
        std::env::remove_var("DOCDEX_REPO_ENCRYPTION_KEY_ID");
        std::env::remove_var("DOCDEX_REPO_ENCRYPTION_PLAINTEXT_TERM_INDEX_ENABLED");
        std::env::remove_var("DOCDEX_REPO_ENCRYPTION_WEB_DISCOVERY_ENABLED");

        let mut config = AppConfig::default();
        apply_env_overrides(&mut config);

        assert!(!config.repo_encryption.is_enabled());
        assert_eq!(
            config.repo_encryption.encryption_mode,
            crate::repo_encryption::RepoEncryptionMode::Disabled
        );

        std::env::remove_var("DOCDEX_REPO_ENCRYPTION_ENABLED");
        std::env::remove_var("DOCDEX_REPO_ENCRYPTION_MODE");
    }

    #[test]
    fn auth_config_parses_external_and_service_providers() {
        let text = r#"
[auth]
mode = "external_only"
reject_ambiguous_credentials = true

[auth.static_token]
enabled = true
token_env = "DOCDEX_STATIC_FOR_TEST"
encrypted_repo_data_access = false

[auth.external_api_key_introspection]
enabled = true
issuer = "external-test"
url = "https://authority.example/introspect"
service_token_env = "DOCDEX_INTROSPECTION_TOKEN_FOR_TEST"
cache_ttl_seconds = 45
negative_cache_ttl_seconds = 5
timeout_ms = 2500
fail_closed = true
accepted_headers = ["x-api-key", "authorization"]
required_status = "active"

[auth.service_token]
enabled = true
token_env = "DOCDEX_SERVICE_FOR_TEST"
encrypted_repo_data_access = true
"#;
        let mut config = parse_config_text(text).expect("parse config");
        config.apply_defaults().expect("apply defaults");

        assert_eq!(config.auth.mode, crate::auth::AuthMode::ExternalOnly);
        assert!(config.auth.external_api_key_introspection.enabled);
        assert_eq!(
            config.auth.external_api_key_introspection.issuer,
            "external-test"
        );
        assert_eq!(config.auth.external_api_key_introspection.timeout_ms, 2500);
        assert!(config.auth.service_token.enabled);
        assert_eq!(
            config.auth.service_token.token_env.as_str(),
            "DOCDEX_SERVICE_FOR_TEST"
        );
        assert!(config.auth.service_token.encrypted_repo_data_access);
    }

    #[test]
    fn auth_env_overrides_enable_external_and_service_auth() {
        let _guard = crate::setup::test_support::ENV_LOCK.lock();
        std::env::set_var("DOCDEX_AUTH_MODE", "local_or_external");
        std::env::set_var("DOCDEX_AUTH_EXTERNAL_API_KEY_INTROSPECTION_ENABLED", "true");
        std::env::set_var(
            "DOCDEX_AUTH_EXTERNAL_API_KEY_INTROSPECTION_URL",
            "https://authority.example/introspect",
        );
        std::env::set_var("DOCDEX_AUTH_EXTERNAL_API_KEY_INTROSPECTION_TOKEN", "secret");
        std::env::set_var("DOCDEX_AUTH_SERVICE_TOKEN_ENABLED", "true");
        std::env::set_var("DOCDEX_AUTH_SERVICE_TOKEN", "admin-secret");
        std::env::set_var(
            "DOCDEX_AUTH_SERVICE_TOKEN_ENCRYPTED_REPO_DATA_ACCESS",
            "true",
        );

        let mut config = AppConfig::default();
        apply_env_overrides(&mut config);

        assert_eq!(config.auth.mode, crate::auth::AuthMode::LocalOrExternal);
        assert!(config.auth.external_api_key_introspection.enabled);
        assert_eq!(
            config.auth.external_api_key_introspection.url,
            "https://authority.example/introspect"
        );
        assert_eq!(
            config.auth.external_api_key_introspection.service_token_env,
            "DOCDEX_AUTH_EXTERNAL_API_KEY_INTROSPECTION_TOKEN"
        );
        assert!(config.auth.service_token.enabled);
        assert_eq!(
            config.auth.service_token.token_env,
            "DOCDEX_AUTH_SERVICE_TOKEN"
        );
        assert!(config.auth.service_token.encrypted_repo_data_access);

        std::env::remove_var("DOCDEX_AUTH_MODE");
        std::env::remove_var("DOCDEX_AUTH_EXTERNAL_API_KEY_INTROSPECTION_ENABLED");
        std::env::remove_var("DOCDEX_AUTH_EXTERNAL_API_KEY_INTROSPECTION_URL");
        std::env::remove_var("DOCDEX_AUTH_EXTERNAL_API_KEY_INTROSPECTION_TOKEN");
        std::env::remove_var("DOCDEX_AUTH_SERVICE_TOKEN_ENABLED");
        std::env::remove_var("DOCDEX_AUTH_SERVICE_TOKEN");
        std::env::remove_var("DOCDEX_AUTH_SERVICE_TOKEN_ENCRYPTED_REPO_DATA_ACCESS");
    }
}
