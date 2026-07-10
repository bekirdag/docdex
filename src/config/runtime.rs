use super::*;

pub(crate) fn default_web_engine() -> String {
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

pub(crate) fn default_web_headless() -> bool {
    true
}

pub(crate) fn default_web_auto_install() -> bool {
    true
}

pub(crate) fn default_request_delay_ms() -> u64 {
    1000
}

pub(crate) fn default_page_load_timeout_secs() -> u64 {
    15
}

pub(crate) fn default_memory_enabled() -> bool {
    true
}

pub(crate) fn default_memory_backend() -> String {
    DEFAULT_MEMORY_BACKEND.to_string()
}

pub(crate) fn default_conversation_memory_enabled() -> bool {
    true
}

pub(crate) fn default_conversation_auto_capture() -> bool {
    false
}

pub(crate) fn default_conversation_archive_raw_transcripts() -> bool {
    true
}

pub(crate) fn default_conversation_wakeup_include_recent_diary_episodes() -> bool {
    false
}

pub(crate) fn default_conversation_wakeup_tokens() -> usize {
    DEFAULT_CONVERSATION_WAKEUP_TOKENS
}

pub(crate) fn default_conversation_wakeup_diary_episode_limit() -> usize {
    DEFAULT_CONVERSATION_WAKEUP_DIARY_EPISODE_LIMIT
}

pub(crate) fn default_conversation_summary_limit() -> usize {
    DEFAULT_CONVERSATION_SUMMARY_LIMIT
}

pub(crate) fn default_conversation_knowledge_limit() -> usize {
    DEFAULT_CONVERSATION_KNOWLEDGE_LIMIT
}

pub(crate) fn default_conversation_snippet_limit() -> usize {
    DEFAULT_CONVERSATION_SNIPPET_LIMIT
}

pub(crate) fn default_conversation_auto_retention_days() -> u32 {
    DEFAULT_CONVERSATION_AUTO_RETENTION_DAYS
}

pub(crate) fn default_conversation_working_memory_retention_days() -> u32 {
    DEFAULT_CONVERSATION_WORKING_MEMORY_RETENTION_DAYS
}

pub(crate) fn default_conversation_hook_event_retention_days() -> u32 {
    DEFAULT_CONVERSATION_HOOK_EVENT_RETENTION_DAYS
}

pub(crate) fn default_conversation_episodic_rollup_retention_days() -> u32 {
    DEFAULT_CONVERSATION_EPISODIC_ROLLUP_RETENTION_DAYS
}

pub(crate) fn default_conversation_sweeper_interval_seconds() -> u64 {
    DEFAULT_CONVERSATION_SWEEPER_INTERVAL_SECONDS
}

pub(crate) fn default_conversation_graph_strict_validation() -> bool {
    DEFAULT_CONVERSATION_GRAPH_STRICT_VALIDATION
}

pub(crate) fn default_conversation_graph_relation_allow_literal_object() -> bool {
    true
}

pub(crate) fn default_personal_preferences_storage_root() -> String {
    "~/.docdex/personal_preferences".to_string()
}

pub(crate) fn default_personal_preferences_enabled() -> bool {
    true
}

pub(crate) fn default_personal_preferences_capture_enabled() -> bool {
    true
}

pub(crate) fn default_personal_preferences_capture_docdex_conversations() -> bool {
    true
}

pub(crate) fn default_personal_preferences_capture_conversation_hooks() -> bool {
    true
}

pub(crate) fn default_personal_preferences_capture_imported_conversations() -> bool {
    true
}

pub(crate) fn default_personal_preferences_capture_supported_client_transcripts() -> bool {
    false
}

pub(crate) fn default_personal_preferences_archive_raw_conversations() -> bool {
    true
}

pub(crate) fn default_personal_preferences_export_enabled() -> bool {
    true
}

pub(crate) fn default_personal_preferences_purge_enabled() -> bool {
    true
}

pub(crate) fn default_personal_preferences_digest_enabled() -> bool {
    true
}

pub(crate) fn default_personal_preferences_process_in_background() -> bool {
    true
}

pub(crate) fn default_personal_preferences_digest_with_local_mcoda_only() -> bool {
    true
}

pub(crate) fn default_personal_preferences_context_injection_enabled() -> bool {
    true
}

pub(crate) fn default_personal_preferences_context_record_limit() -> usize {
    DEFAULT_PERSONAL_PREFERENCES_CONTEXT_RECORD_LIMIT
}

pub(crate) fn default_personal_preferences_context_token_budget() -> usize {
    DEFAULT_PERSONAL_PREFERENCES_CONTEXT_TOKEN_BUDGET
}

pub(crate) fn default_personal_preferences_allow_sensitive_context() -> bool {
    false
}

pub(crate) fn default_personal_preferences_auto_project_safe_preferences_to_profile() -> bool {
    true
}

pub(crate) fn default_personal_preferences_max_parallel_digest_jobs() -> usize {
    DEFAULT_PERSONAL_PREFERENCES_MAX_PARALLEL_DIGEST_JOBS
}

pub(crate) fn default_personal_preferences_digest_interval_seconds() -> u64 {
    DEFAULT_PERSONAL_PREFERENCES_DIGEST_INTERVAL_SECONDS
}

pub(crate) fn default_personal_preferences_review_required_for_sensitive() -> bool {
    true
}

pub(crate) fn default_personal_preferences_transcript_secret_scrubber_enabled() -> bool {
    true
}

pub(crate) fn default_personal_preferences_raw_retention_days() -> u32 {
    DEFAULT_PERSONAL_PREFERENCES_RAW_RETENTION_DAYS
}

pub(crate) fn default_personal_preferences_derived_retention_days() -> u32 {
    DEFAULT_PERSONAL_PREFERENCES_DERIVED_RETENTION_DAYS
}

pub(crate) fn default_user_memory_sync_enabled() -> bool {
    false
}

pub(crate) fn default_user_memory_sync_raw_evidence_enabled() -> bool {
    false
}

pub(crate) fn default_user_memory_sync_pull_interval_seconds() -> u64 {
    DEFAULT_USER_MEMORY_SYNC_PULL_INTERVAL_SECONDS
}

pub(crate) fn default_user_memory_sync_max_upload_bytes_per_cycle() -> usize {
    DEFAULT_USER_MEMORY_SYNC_MAX_UPLOAD_BYTES_PER_CYCLE
}

pub(crate) fn default_http_bind_addr() -> String {
    DEFAULT_HTTP_BIND_ADDR.to_string()
}

pub(crate) fn default_enable_mcp() -> bool {
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
