use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use clap::{ArgAction, Args};
use serde::{Deserialize, Serialize};

const DEFAULT_CONFIG_FILE: &str = "config.toml";
const DEFAULT_HTTP_BIND_ADDR: &str = "127.0.0.1:3210";
const DEFAULT_LOG_LEVEL: &str = "info";
const DEFAULT_LLM_PROVIDER: &str = "ollama";
const DEFAULT_LLM_BASE_URL: &str = "http://127.0.0.1:11434";
const DEFAULT_LLM_MODEL: &str = "phi3.5:3.8b";
const DEFAULT_EMBED_MODEL: &str = "nomic-embed-text";
const DEFAULT_MEMORY_BACKEND: &str = "sqlite";
const DEFAULT_DISCOVERY_PROVIDER: &str = "duckduckgo_html";
const DEFAULT_WEB_ENGINE: &str = "chrome";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    #[serde(default)]
    pub core: CoreConfig,
    #[serde(default)]
    pub llm: LlmConfig,
    #[serde(default)]
    pub search: SearchConfig,
    #[serde(default)]
    pub web: WebConfigSection,
    #[serde(default)]
    pub memory: MemoryConfig,
    #[serde(default)]
    pub server: ServerConfig,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            core: CoreConfig::default(),
            llm: LlmConfig::default(),
            search: SearchConfig::default(),
            web: WebConfigSection::default(),
            memory: MemoryConfig::default(),
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
        }
        if self.server.http_bind_addr.trim().is_empty() {
            self.server.http_bind_addr = DEFAULT_HTTP_BIND_ADDR.to_string();
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
    #[serde(default = "default_embed_model")]
    pub embedding_model: String,
    #[serde(default = "default_max_answer_tokens")]
    pub max_answer_tokens: u32,
}

impl Default for LlmConfig {
    fn default() -> Self {
        Self {
            provider: default_llm_provider(),
            base_url: default_llm_base_url(),
            default_model: default_llm_model(),
            embedding_model: default_embed_model(),
            max_answer_tokens: default_max_answer_tokens(),
        }
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
}

impl Default for SearchConfig {
    fn default() -> Self {
        Self {
            web_trigger_threshold: default_web_trigger_threshold(),
            web_min_match_ratio: default_web_min_match_ratio(),
            local_relevance_threshold: default_local_relevance_threshold(),
            max_repo_hits: default_max_repo_hits(),
            max_web_hits: default_max_web_hits(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebConfigSection {
    #[serde(default = "default_discovery_provider")]
    pub discovery_provider: String,
    #[serde(default = "default_web_user_agent")]
    pub user_agent: String,
    #[serde(default = "default_web_min_spacing_ms")]
    pub min_spacing_ms: u64,
    #[serde(default = "default_web_cache_ttl_secs")]
    pub cache_ttl_secs: u64,
    #[serde(default)]
    pub blocklist: Vec<String>,
    #[serde(default)]
    pub scraper: WebScraperConfig,
}

impl Default for WebConfigSection {
    fn default() -> Self {
        Self {
            discovery_provider: default_discovery_provider(),
            user_agent: default_web_user_agent(),
            min_spacing_ms: default_web_min_spacing_ms(),
            cache_ttl_secs: default_web_cache_ttl_secs(),
            blocklist: Vec::new(),
            scraper: WebScraperConfig::default(),
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
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            enabled: default_memory_enabled(),
            backend: default_memory_backend(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_http_bind_addr")]
    pub http_bind_addr: String,
    #[serde(default = "default_enable_mcp")]
    pub enable_mcp: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            http_bind_addr: default_http_bind_addr(),
            enable_mcp: default_enable_mcp(),
        }
    }
}

pub fn load_config_from_path(path: &Path) -> Result<AppConfig> {
    if !path.exists() {
        let config = default_config_with_paths()?;
        write_config(path, &config)?;
        return Ok(config);
    }
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read config {}", path.display()))?;
    if text.trim().is_empty() {
        let config = default_config_with_paths()?;
        write_config(path, &config)?;
        return Ok(config);
    }
    let mut config: AppConfig =
        toml::from_str(&text).with_context(|| format!("parse config {}", path.display()))?;
    config.apply_defaults()?;
    let mut updated = false;
    if apply_browser_defaults(&mut config) {
        updated = true;
    }
    if updated {
        write_config(path, &config)?;
    }
    Ok(config)
}

pub fn default_config_path() -> Result<PathBuf> {
    let state_dir = default_state_dir()?;
    let base = state_dir
        .parent()
        .ok_or_else(|| anyhow!("unable to resolve config directory from {}", state_dir.display()))?;
    Ok(base.join(DEFAULT_CONFIG_FILE))
}

fn default_config_with_paths() -> Result<AppConfig> {
    let mut config = AppConfig::default();
    config.apply_defaults()?;
    apply_browser_defaults(&mut config);
    Ok(config)
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

fn default_max_answer_tokens() -> u32 {
    1024
}

fn default_web_trigger_threshold() -> f32 {
    0.45
}

fn default_max_repo_hits() -> usize {
    8
}

fn default_max_web_hits() -> usize {
    8
}

fn default_web_min_match_ratio() -> f32 {
    0.2
}

fn default_local_relevance_threshold() -> f32 {
    0.6
}

fn default_discovery_provider() -> String {
    DEFAULT_DISCOVERY_PROVIDER.to_string()
}

fn default_web_user_agent() -> String {
    format!("docdexd/{}", env!("CARGO_PKG_VERSION"))
}

fn default_web_min_spacing_ms() -> u64 {
    2_000
}

fn default_web_cache_ttl_secs() -> u64 {
    86_400
}

fn default_web_engine() -> String {
    DEFAULT_WEB_ENGINE.to_string()
}

fn apply_browser_defaults(config: &mut AppConfig) -> bool {
    let engine = config.web.scraper.engine.trim().to_ascii_lowercase();
    let needs_chrome = matches!(engine.as_str(), "chrome" | "chromium" | "chromium-browser");
    if !needs_chrome || config.web.scraper.chrome_binary_path.is_some() {
        return false;
    }
    if let Some(path) = crate::util::detect_chrome_binary() {
        config.web.scraper.chrome_binary_path = Some(path);
        return true;
    }
    false
}

fn default_web_headless() -> bool {
    true
}

fn default_request_delay_ms() -> u64 {
    1000
}

fn default_page_load_timeout_secs() -> u64 {
    15
}

fn default_memory_enabled() -> bool {
    false
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

#[derive(Debug, Args)]
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
        default_value_t = false,
        action = ArgAction::Set,
        help = "Enable best-effort symbol extraction into a per-repo symbols store (symbols.db)"
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
        self.enable_symbol_extraction
    }
}

pub fn non_empty_string(value: &str) -> Result<String, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("value cannot be empty".into());
    }
    Ok(trimmed.to_string())
}
