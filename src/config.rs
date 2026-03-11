use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use clap::{ArgAction, Args};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::impact::{
    apply_impact_settings, ImpactSettings, DEFAULT_DYNAMIC_IMPORT_SCAN_LIMIT,
    DEFAULT_IMPORT_TRACES_ENABLED,
};

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
const DEFAULT_DISCOVERY_PROVIDER: &str = "duckduckgo_lite";
const DEFAULT_WEB_ENGINE: &str = "chromium";

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
    pub memory: MemoryConfig,
    #[serde(default)]
    pub features: FeatureFlagsConfig,
    #[serde(default)]
    pub server: ServerConfig,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            core: CoreConfig::default(),
            llm: LlmConfig::default(),
            search: SearchConfig::default(),
            code_intelligence: CodeIntelligenceConfig::default(),
            web: WebConfigSection::default(),
            memory: MemoryConfig::default(),
            features: FeatureFlagsConfig::default(),
            server: ServerConfig::default(),
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
    pub primary_agent_id: String,
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
            primary_agent_id: String::new(),
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
pub struct MemoryConfig {
    #[serde(default = "default_memory_enabled")]
    pub enabled: bool,
    #[serde(default = "default_memory_backend")]
    pub backend: String,
    #[serde(default)]
    pub profile: MemoryProfileConfig,
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            enabled: default_memory_enabled(),
            backend: default_memory_backend(),
            profile: MemoryProfileConfig::default(),
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
    let mut config: AppConfig =
        toml::from_str(&text).with_context(|| format!("parse config {}", path.display()))?;
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

fn apply_env_overrides(config: &mut AppConfig) {
    if let Some(value) = env_trimmed("DOCDEX_LLM_AGENT").or_else(|| env_trimmed("DOCDEX_AGENT")) {
        config.llm.agent_id = value;
    }
    if let Some(value) = env_bool("DOCDEX_DELEGATION_ENABLED") {
        config.llm.delegation.enabled = value;
    }
    if let Some(value) = env_bool("DOCDEX_DELEGATION_AUTO_ENABLE") {
        config.llm.delegation.auto_enable = value;
    }
    if let Some(value) = env_bool("DOCDEX_DELEGATION_ENFORCE_LOCAL") {
        config.llm.delegation.enforce_local = value;
    }
    if let Some(value) = env_bool("DOCDEX_DELEGATION_ALLOW_FALLBACK") {
        config.llm.delegation.allow_fallback_to_primary = value;
    }
    if let Some(value) = env_bool("DOCDEX_DELEGATION_REEVALUATE") {
        config.llm.delegation.re_evaluate = value;
    }
    if let Some(value) = env_trimmed("DOCDEX_DELEGATION_LOCAL_AGENT") {
        config.llm.delegation.local_agent_id = value;
    }
    if let Some(value) = env_trimmed("DOCDEX_DELEGATION_PRIMARY_AGENT") {
        config.llm.delegation.primary_agent_id = value;
    }
    if let Some(value) = env_trimmed("DOCDEX_DELEGATION_LOCAL_SELECTION_POLICY") {
        config.llm.delegation.local_selection_policy =
            normalize_delegation_local_selection_policy(&value);
    }
    if let Some(value) = env_bool("DOCDEX_DELEGATION_USE_CACHED_LOCAL_DECISION") {
        config.llm.delegation.use_cached_local_decision = value;
    }
    if let Some(value) = env_trimmed("DOCDEX_DELEGATION_MODE") {
        let normalized = value.to_lowercase();
        if normalized == "draft_only" || normalized == "draft_then_refine" {
            config.llm.delegation.mode = normalized;
        } else {
            warn!(
                target: "docdexd",
                value = %value,
                "invalid DOCDEX_DELEGATION_MODE; expected draft_only or draft_then_refine"
            );
        }
    }
    if let Some(value) = env_u64("DOCDEX_DELEGATION_TIMEOUT_MS") {
        config.llm.delegation.timeout_ms = value;
    }
    if let Some(value) = env_u32("DOCDEX_DELEGATION_MAX_TOKENS") {
        config.llm.delegation.max_tokens = value;
    }
    if let Some(value) = env_f64("DOCDEX_DELEGATION_PRIMARY_USD_PER_MILLION_TOKENS")
        .or_else(|| env_f64("DOCDEX_DELEGATION_PRIMARY_USD_PER_1K_TOKENS"))
    {
        config.llm.delegation.primary_usd_per_million_tokens = sanitize_non_negative_f64(value);
    }
    if let Some(value) = env_f64("DOCDEX_DELEGATION_LOCAL_USD_PER_MILLION_TOKENS")
        .or_else(|| env_f64("DOCDEX_DELEGATION_LOCAL_USD_PER_1K_TOKENS"))
    {
        config.llm.delegation.local_usd_per_million_tokens = sanitize_non_negative_f64(value);
    }
    if let Some(value) = env_mcp_ipc_mode("DOCDEX_MCP_IPC") {
        config.server.mcp_ipc_mode = value;
    }
    if let Some(value) = env_trimmed("DOCDEX_MCP_SOCKET_PATH") {
        config.server.mcp_socket_path = value;
    }
    if let Some(value) = env_trimmed("DOCDEX_MCP_PIPE_NAME") {
        config.server.mcp_pipe_name = value;
    }
}

pub fn write_config(path: &Path, config: &AppConfig) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Err(anyhow!("config path has no parent directory"));
    };
    std::fs::create_dir_all(parent)
        .with_context(|| format!("create config directory {}", parent.display()))?;
    let payload = toml::to_string_pretty(config).context("serialize config")?;
    std::fs::write(path, payload).with_context(|| format!("write config {}", path.display()))?;
    Ok(())
}

fn default_state_dir() -> Result<PathBuf> {
    crate::state_paths::default_state_base_dir()
}

fn env_trimmed(key: &str) -> Option<String> {
    let raw = std::env::var(key).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn env_bool(key: &str) -> Option<bool> {
    let raw = env_trimmed(key)?;
    match raw.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn env_u64(key: &str) -> Option<u64> {
    let raw = env_trimmed(key)?;
    raw.parse::<u64>().ok()
}

fn env_u32(key: &str) -> Option<u32> {
    let raw = env_trimmed(key)?;
    raw.parse::<u32>().ok()
}

fn env_f64(key: &str) -> Option<f64> {
    let raw = env_trimmed(key)?;
    raw.parse::<f64>().ok()
}

fn env_mcp_ipc_mode(key: &str) -> Option<String> {
    let raw = env_trimmed(key)?;
    let normalized = raw.to_lowercase();
    match normalized.as_str() {
        "1" | "true" | "yes" | "on" | "auto" => Some("auto".to_string()),
        "0" | "false" | "no" | "off" => Some("off".to_string()),
        _ => None,
    }
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

fn default_discovery_provider() -> String {
    DEFAULT_DISCOVERY_PROVIDER.to_string()
}

pub(crate) fn default_web_user_agent() -> String {
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36".to_string()
}

fn default_web_min_spacing_ms() -> u64 {
    2_000
}

fn default_web_cache_ttl_secs() -> u64 {
    2_592_000
}

#[cfg(test)]
mod tests;

fn default_web_engine() -> String {
    DEFAULT_WEB_ENGINE.to_string()
}

pub(crate) fn apply_browser_defaults(config: &mut AppConfig) -> bool {
    let mut updated = false;
    if !config
        .web
        .scraper
        .engine
        .trim()
        .eq_ignore_ascii_case("chromium")
    {
        config.web.scraper.engine = "chromium".to_string();
        updated = true;
    }
    let browser_kind = config
        .web
        .scraper
        .browser_kind
        .as_deref()
        .map(|kind| kind.trim())
        .unwrap_or("");
    if browser_kind.is_empty() || !browser_kind.eq_ignore_ascii_case("chromium") {
        config.web.scraper.browser_kind = Some("chromium".to_string());
        updated = true;
    }
    if let Some(path) = config.web.scraper.chrome_binary_path.as_ref() {
        if !path.is_file() {
            config.web.scraper.chrome_binary_path = None;
            updated = true;
        }
    }

    let resolved = crate::web::browser_install::resolve_installed_browser();

    match resolved {
        Some(path) => {
            if config.web.scraper.chrome_binary_path.as_ref() != Some(&path) {
                config.web.scraper.chrome_binary_path = Some(path);
                updated = true;
            }
        }
        None => {
            if config.web.scraper.chrome_binary_path.is_some() {
                config.web.scraper.chrome_binary_path = None;
                updated = true;
            }
        }
    }

    updated
}

fn default_web_headless() -> bool {
    true
}

fn default_web_auto_install() -> bool {
    true
}

fn default_request_delay_ms() -> u64 {
    1000
}

fn default_page_load_timeout_secs() -> u64 {
    15
}

fn default_memory_enabled() -> bool {
    true
}

fn default_memory_backend() -> String {
    DEFAULT_MEMORY_BACKEND.to_string()
}

fn default_http_bind_addr() -> String {
    DEFAULT_HTTP_BIND_ADDR.to_string()
}

fn default_enable_mcp() -> bool {
    true
}

#[derive(Debug, Args, Clone)]
pub struct RepoArgs {
    #[arg(long, default_value = ".", help = "Repository/workspace root to index")]
    pub repo: PathBuf,
    #[arg(
        long,
        env = "DOCDEX_STATE_DIR",
        help = "Override state storage directory (default: ~/.docdex/state). Relative paths resolve under the repo root. Absolute paths outside the repo are treated as shared base dirs and scoped to <state-dir>/repos/<repo_id>/index to prevent cross-repo mixing."
    )]
    pub state_dir: Option<PathBuf>,
    #[arg(
        long,
        env = "DOCDEX_EXCLUDE_PREFIXES",
        value_delimiter = ',',
        value_parser = non_empty_string,
        help = "Additional relative path prefixes to skip (comma-separated)"
    )]
    pub exclude_prefix: Vec<String>,
    #[arg(
        long,
        env = "DOCDEX_EXCLUDE_DIRS",
        value_delimiter = ',',
        value_parser = non_empty_string,
        help = "Additional directory names to skip anywhere under the repo (comma-separated)"
    )]
    pub exclude_dir: Vec<String>,
    #[arg(
        long,
        env = "DOCDEX_ENABLE_SYMBOL_EXTRACTION",
        value_parser = clap::builder::BoolishValueParser::new(),
        default_value_t = true,
        action = ArgAction::Set,
        help = "Deprecated (no-op): symbol + impact extraction are always enabled for indexing"
    )]
    pub enable_symbol_extraction: bool,
}

impl RepoArgs {
    pub fn repo_root(&self) -> PathBuf {
        self.repo
            .canonicalize()
            .unwrap_or_else(|_| self.repo.clone())
    }

    pub fn state_dir_override(&self) -> Option<PathBuf> {
        self.state_dir.clone()
    }

    pub fn exclude_dir_overrides(&self) -> Vec<String> {
        self.exclude_dir.clone()
    }

    pub fn exclude_prefix_overrides(&self) -> Vec<String> {
        self.exclude_prefix.clone()
    }

    pub fn symbols_enabled(&self) -> bool {
        if !self.enable_symbol_extraction {
            warn!(
                target: "docdexd",
                "symbol + impact extraction are always enabled; ignoring --enable-symbol-extraction=false"
            );
        }
        true
    }
}

pub fn non_empty_string(value: &str) -> Result<String, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("value cannot be empty".into());
    }
    Ok(trimmed.to_string())
}
