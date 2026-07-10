use super::*;

pub(crate) fn apply_env_overrides(config: &mut AppConfig) {
    if let Some(value) = env_trimmed("DOCDEX_LLM_AGENT").or_else(|| env_trimmed("DOCDEX_AGENT")) {
        config.llm.agent_id = value;
    }
    if let Some(value) = env_bool("DOCDEX_ENABLE_MEMORY") {
        config.memory.enabled = value;
    }
    if let Some(value) = env_bool("DOCDEX_CONVERSATION_MEMORY_ENABLED") {
        config.memory.conversations.enabled = value;
    }
    if let Some(value) = env_bool("DOCDEX_CONVERSATION_AUTO_CAPTURE") {
        config.memory.conversations.auto_capture = value;
    }
    if let Some(value) = env_bool("DOCDEX_PERSONAL_PREFERENCES_ENABLED")
        .or_else(|| env_bool("DOCDEX_ENABLE_PERSONAL_PREFERENCES"))
        .or_else(|| env_bool("DOCDEX_MIND_CLONE_ENABLED"))
    {
        config.memory.personal_preferences.enabled = value;
    }
    if let Some(value) = env_trimmed("DOCDEX_PERSONAL_PREFERENCES_STORAGE_ROOT") {
        config.memory.personal_preferences.storage_root = value;
    }
    if let Some(value) = env_bool("DOCDEX_PERSONAL_PREFERENCES_CAPTURE_ENABLED") {
        config.memory.personal_preferences.capture_enabled = value;
    }
    if let Some(value) = env_bool("DOCDEX_PERSONAL_PREFERENCES_CAPTURE_CHAT_COMPLETIONS") {
        config
            .memory
            .personal_preferences
            .capture_docdex_conversations = value;
    }
    if let Some(value) = env_bool("DOCDEX_PERSONAL_PREFERENCES_CAPTURE_CONVERSATION_HOOKS") {
        config
            .memory
            .personal_preferences
            .capture_conversation_hooks = value;
    }
    if let Some(value) = env_bool("DOCDEX_PERSONAL_PREFERENCES_CAPTURE_IMPORTED_CONVERSATIONS") {
        config
            .memory
            .personal_preferences
            .capture_imported_conversations = value;
    }
    if let Some(value) = env_bool("DOCDEX_PERSONAL_PREFERENCES_CAPTURE_CLIENT_TRANSCRIPTS") {
        config
            .memory
            .personal_preferences
            .capture_supported_client_transcripts = value;
    }
    if let Some(value) = env_bool("DOCDEX_PERSONAL_PREFERENCES_ARCHIVE_RAW") {
        config.memory.personal_preferences.archive_raw_conversations = value;
    }
    if let Some(value) = env_bool("DOCDEX_PERSONAL_PREFERENCES_DIGEST_ENABLED") {
        config.memory.personal_preferences.digest_enabled = value;
    }
    if let Some(value) = env_bool("DOCDEX_PERSONAL_PREFERENCES_PROCESS_IN_BACKGROUND") {
        config.memory.personal_preferences.process_in_background = value;
    }
    if let Some(value) = env_bool("DOCDEX_PERSONAL_PREFERENCES_CONTEXT_INJECTION_ENABLED") {
        config.memory.personal_preferences.context_injection_enabled = value;
    }
    if let Some(value) = env_bool("DOCDEX_PERSONAL_PREFERENCES_AUTO_PROJECT_SAFE_TO_PROFILE") {
        config
            .memory
            .personal_preferences
            .auto_project_safe_preferences_to_profile = value;
    }
    if let Some(value) = env_bool("DOCDEX_PERSONAL_PREFERENCES_SECRET_SCRUBBER_ENABLED") {
        config
            .memory
            .personal_preferences
            .transcript_secret_scrubber_enabled = value;
    }
    if let Some(value) = env_trimmed("DOCDEX_PERSONAL_PREFERENCES_CONTENT_ENCRYPTION_KEY_ENV") {
        config
            .memory
            .personal_preferences
            .content_encryption_key_env = Some(value);
    }
    if let Some(value) = env_bool("DOCDEX_USER_MEMORY_SYNC_ENABLED") {
        config.memory.user_memory_sync.enabled = value;
    }
    if let Some(value) = env_trimmed("DOCDEX_USER_MEMORY_SYNC_SERVER_BASE_URL") {
        config.memory.user_memory_sync.server_base_url = Some(value);
    }
    if let Some(value) = env_trimmed("DOCDEX_USER_MEMORY_SYNC_API_KEY_ENV") {
        config.memory.user_memory_sync.api_key_env = Some(value);
    }
    if let Some(value) = env_trimmed("DOCDEX_USER_MEMORY_SYNC_ENCRYPTION_KEY_ENV") {
        config.memory.user_memory_sync.encryption_key_env = Some(value);
    }
    if let Some(value) = env_trimmed("DOCDEX_USER_MEMORY_SYNC_DEVICE_ID") {
        config.memory.user_memory_sync.device_id = Some(value);
    }
    if let Some(value) = env_trimmed("DOCDEX_USER_MEMORY_SYNC_LANES") {
        config.memory.user_memory_sync.enabled_lanes = value
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(ToOwned::to_owned)
            .collect();
    }
    if let Some(value) = env_bool("DOCDEX_USER_MEMORY_SYNC_RAW_EVIDENCE_ENABLED") {
        config.memory.user_memory_sync.raw_evidence_enabled = value;
    }
    if let Some(value) = env_u64("DOCDEX_USER_MEMORY_SYNC_PULL_INTERVAL_SECONDS") {
        config.memory.user_memory_sync.pull_interval_seconds = value;
    }
    if let Some(value) = env_usize("DOCDEX_USER_MEMORY_SYNC_MAX_UPLOAD_BYTES_PER_CYCLE") {
        config.memory.user_memory_sync.max_upload_bytes_per_cycle = value;
    }
    if let Some(value) = env_trimmed("DOCDEX_WEB_DISCOVERY_PROVIDER") {
        config.web.discovery_provider = value;
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
    if let Some(value) = env_trimmed("DOCDEX_DELEGATION_CLOUD_AGENT") {
        config.llm.delegation.cloud_agent_id = value;
    }
    if let Some(value) = env_trimmed("DOCDEX_DELEGATION_PRIMARY_AGENT") {
        config.llm.delegation.primary_agent_id = value;
    }
    if let Some(value) = env_trimmed("DOCDEX_DELEGATION_CODE_LOCAL_AGENT") {
        config.llm.delegation.code.local_agent_id = value;
    }
    if let Some(value) = env_trimmed("DOCDEX_DELEGATION_CODE_CLOUD_AGENT") {
        config.llm.delegation.code.cloud_agent_id = value;
    }
    if let Some(value) = env_trimmed("DOCDEX_DELEGATION_CODE_PRIMARY_AGENT") {
        config.llm.delegation.code.primary_agent_id = value;
    }
    if let Some(value) = env_trimmed("DOCDEX_DELEGATION_GENERAL_LOCAL_AGENT") {
        config.llm.delegation.general.local_agent_id = value;
    }
    if let Some(value) = env_trimmed("DOCDEX_DELEGATION_GENERAL_CLOUD_AGENT") {
        config.llm.delegation.general.cloud_agent_id = value;
    }
    if let Some(value) = env_trimmed("DOCDEX_DELEGATION_GENERAL_PRIMARY_AGENT") {
        config.llm.delegation.general.primary_agent_id = value;
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
    if let Some(value) = env_bool("DOCDEX_DELEGATION_CLOUD_ENABLED") {
        config.llm.delegation.cloud.enabled = value;
    }
    if let Some(value) = env_trimmed("DOCDEX_DELEGATION_CLOUD_PROVIDER") {
        config.llm.delegation.cloud.provider = value;
    }
    if let Some(value) = env_usize("DOCDEX_DELEGATION_CLOUD_LIMIT") {
        config.llm.delegation.cloud.limit = value;
    }
    if let Some(value) = env_usize("DOCDEX_DELEGATION_CLOUD_SYNC_LIMIT") {
        config.llm.delegation.cloud.sync_limit = value;
    }
    if let Some(value) = env_bool("DOCDEX_DELEGATION_CLOUD_SORTED_BY_CATALOG_RATING") {
        config.llm.delegation.cloud.sorted_by_catalog_rating = value;
    }
    if let Some(value) = env_f64("DOCDEX_DELEGATION_CLOUD_MAX_COST_PER_MILLION") {
        config.llm.delegation.cloud.max_cost_per_million = sanitize_non_negative_f64(value);
    }
    if let Some(value) = env_usize("DOCDEX_DELEGATION_CLOUD_MIN_CONTEXT") {
        config.llm.delegation.cloud.min_context = value;
    }
    if let Some(value) = env_f64("DOCDEX_DELEGATION_CLOUD_MIN_REASONING") {
        config.llm.delegation.cloud.min_reasoning = sanitize_non_negative_f64(value);
    }
    if let Some(value) = env_trimmed("DOCDEX_MSWARM_BASE_URL") {
        config.integrations.mswarm.base_url = value;
    }
    if let Some(value) = env_trimmed("DOCDEX_MSWARM_API_KEY") {
        config.integrations.mswarm.api_key = Some(value);
    }
    if let Some(value) = env_bool("DOCDEX_MSWARM_CONSENT_ACCEPTED") {
        config.integrations.mswarm.telemetry.consent_accepted = value;
    }
    if let Some(value) = env_trimmed("DOCDEX_MSWARM_CONSENT_POLICY_VERSION") {
        config.integrations.mswarm.telemetry.consent_policy_version = value;
    }
    if let Some(value) = env_trimmed("DOCDEX_MSWARM_CONSENT_TOKEN") {
        config.integrations.mswarm.telemetry.consent_token = Some(value);
    }
    if let Some(value) = env_trimmed("DOCDEX_MSWARM_CLIENT_ID") {
        config.integrations.mswarm.telemetry.client_id = value;
    }
    if let Some(value) = env_trimmed("DOCDEX_MSWARM_UPLOAD_SIGNING_SECRET") {
        config.integrations.mswarm.telemetry.upload_signing_secret = Some(value);
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
    if let Some(value) = env_trimmed("DOCDEX_AUTH_MODE") {
        match value.to_ascii_lowercase().as_str() {
            "local_only" => config.auth.mode = crate::auth::AuthMode::LocalOnly,
            "local_or_external" => config.auth.mode = crate::auth::AuthMode::LocalOrExternal,
            "external_only" => config.auth.mode = crate::auth::AuthMode::ExternalOnly,
            _ => warn!(
                target: "docdexd",
                value = %value,
                "invalid DOCDEX_AUTH_MODE; expected local_only, local_or_external, or external_only"
            ),
        }
    }
    if let Some(value) = env_bool("DOCDEX_AUTH_REJECT_AMBIGUOUS_CREDENTIALS") {
        config.auth.reject_ambiguous_credentials = value;
    }
    if let Some(value) = env_bool("DOCDEX_AUTH_STATIC_TOKEN_ENABLED") {
        config.auth.static_token.enabled = value;
    }
    if let Some(value) = env_trimmed("DOCDEX_AUTH_STATIC_TOKEN_ENV") {
        config.auth.static_token.token_env = value;
    }
    if let Some(value) = env_bool("DOCDEX_AUTH_STATIC_TOKEN_ENCRYPTED_REPO_DATA_ACCESS") {
        config.auth.static_token.encrypted_repo_data_access = value;
    }
    if let Some(value) = env_bool("DOCDEX_AUTH_EXTERNAL_API_KEY_INTROSPECTION_ENABLED") {
        config.auth.external_api_key_introspection.enabled = value;
    }
    if let Some(value) = env_trimmed("DOCDEX_AUTH_EXTERNAL_API_KEY_INTROSPECTION_ISSUER") {
        config.auth.external_api_key_introspection.issuer = value;
    }
    if let Some(value) = env_trimmed("DOCDEX_AUTH_EXTERNAL_API_KEY_INTROSPECTION_URL") {
        config.auth.external_api_key_introspection.url = value;
    }
    if let Some(value) = env_trimmed("DOCDEX_AUTH_EXTERNAL_API_KEY_INTROSPECTION_TOKEN_ENV") {
        config.auth.external_api_key_introspection.service_token_env = value;
    } else if env_trimmed("DOCDEX_AUTH_EXTERNAL_API_KEY_INTROSPECTION_TOKEN").is_some() {
        config.auth.external_api_key_introspection.service_token_env =
            "DOCDEX_AUTH_EXTERNAL_API_KEY_INTROSPECTION_TOKEN".to_string();
    }
    if let Some(value) = env_u64("DOCDEX_AUTH_EXTERNAL_API_KEY_INTROSPECTION_CACHE_TTL_SECONDS") {
        config.auth.external_api_key_introspection.cache_ttl_seconds = value;
    }
    if let Some(value) =
        env_u64("DOCDEX_AUTH_EXTERNAL_API_KEY_INTROSPECTION_NEGATIVE_CACHE_TTL_SECONDS")
    {
        config
            .auth
            .external_api_key_introspection
            .negative_cache_ttl_seconds = value;
    }
    if let Some(value) = env_u64("DOCDEX_AUTH_EXTERNAL_API_KEY_INTROSPECTION_TIMEOUT_MS") {
        config.auth.external_api_key_introspection.timeout_ms = value;
    }
    if let Some(value) = env_bool("DOCDEX_AUTH_EXTERNAL_API_KEY_INTROSPECTION_FAIL_CLOSED") {
        config.auth.external_api_key_introspection.fail_closed = value;
    }
    if let Some(value) = env_trimmed("DOCDEX_AUTH_EXTERNAL_API_KEY_INTROSPECTION_HEADERS") {
        config.auth.external_api_key_introspection.accepted_headers = value
            .split(',')
            .map(|item| item.trim().to_string())
            .filter(|item| !item.is_empty())
            .collect();
    }
    if let Some(value) = env_trimmed("DOCDEX_AUTH_EXTERNAL_API_KEY_INTROSPECTION_REQUIRED_STATUS") {
        config.auth.external_api_key_introspection.required_status = value;
    }
    if let Some(value) = env_bool("DOCDEX_AUTH_SERVICE_TOKEN_ENABLED") {
        config.auth.service_token.enabled = value;
    }
    if let Some(value) = env_bool("DOCDEX_AUTH_SERVICE_TOKEN_ENCRYPTED_REPO_DATA_ACCESS") {
        config.auth.service_token.encrypted_repo_data_access = value;
    }
    if let Some(value) = env_trimmed("DOCDEX_AUTH_SERVICE_TOKEN_ENV") {
        config.auth.service_token.token_env = value;
    } else if env_trimmed("DOCDEX_AUTH_SERVICE_TOKEN").is_some() {
        config.auth.service_token.token_env = "DOCDEX_AUTH_SERVICE_TOKEN".to_string();
    }
    config.auth.apply_defaults();
    if let Some(value) = env_bool("DOCDEX_REPO_ENCRYPTION_ENABLED") {
        config.repo_encryption.encryption_mode = if value {
            crate::repo_encryption::RepoEncryptionMode::ApplicationManagedEncryption
        } else {
            crate::repo_encryption::RepoEncryptionMode::Disabled
        };
    }
    if let Some(value) = env_trimmed("DOCDEX_REPO_ENCRYPTION_MODE") {
        if let Some(mode) = crate::repo_encryption::parse_repo_encryption_mode(&value) {
            config.repo_encryption.encryption_mode = mode;
        } else {
            warn!(
                target: "docdexd",
                value = %value,
                "invalid DOCDEX_REPO_ENCRYPTION_MODE; expected disabled or application_managed_encryption"
            );
        }
    }
    if let Some(value) = env_trimmed("DOCDEX_REPO_ENCRYPTION_KEY_ENV") {
        config.repo_encryption.key_env = Some(value);
    }
    if let Some(value) = env_trimmed("DOCDEX_REPO_ENCRYPTION_KEY_ID") {
        config.repo_encryption.key_id = Some(value);
    }
    if let Some(value) = env_bool("DOCDEX_REPO_ENCRYPTION_PLAINTEXT_TERM_INDEX_ENABLED") {
        config.repo_encryption.plaintext_term_index_enabled = value;
    }
    if let Some(value) = env_bool("DOCDEX_REPO_ENCRYPTION_WEB_DISCOVERY_ENABLED") {
        config.repo_encryption.web_discovery_enabled = value;
    }
    config.repo_encryption.apply_defaults();
}

pub fn write_config(path: &Path, config: &AppConfig) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Err(anyhow!("config path has no parent directory"));
    };
    std::fs::create_dir_all(parent)
        .with_context(|| format!("create config directory {}", parent.display()))?;
    let payload =
        toml::to_string_pretty(&AppConfigWrite::from(config)).context("serialize config")?;
    std::fs::write(path, payload).with_context(|| format!("write config {}", path.display()))?;
    Ok(())
}

pub(crate) fn default_state_dir() -> Result<PathBuf> {
    crate::state_paths::default_state_base_dir()
}

fn resolve_home_dir() -> Result<PathBuf> {
    if let Some(home) = std::env::var_os("HOME") {
        return Ok(PathBuf::from(home));
    }
    if let Some(home) = std::env::var_os("USERPROFILE") {
        return Ok(PathBuf::from(home));
    }
    let drive =
        std::env::var_os("HOMEDRIVE").ok_or_else(|| anyhow!("unable to resolve home directory"))?;
    let path =
        std::env::var_os("HOMEPATH").ok_or_else(|| anyhow!("unable to resolve home directory"))?;
    Ok(PathBuf::from(drive).join(path))
}

pub(crate) fn expand_config_path(raw: &str, global_state_dir: Option<&Path>) -> Result<PathBuf> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return match global_state_dir {
            Some(path) => Ok(path.to_path_buf()),
            None => default_state_dir(),
        };
    }
    if trimmed == "~" {
        return resolve_home_dir();
    }
    if let Some(suffix) = trimmed.strip_prefix("~/") {
        return Ok(resolve_home_dir()?.join(suffix));
    }
    let path = PathBuf::from(trimmed);
    if path.is_absolute() {
        return Ok(path);
    }
    match global_state_dir {
        Some(base) => Ok(base.join(path)),
        None => Ok(default_state_dir()?.join(path)),
    }
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

fn env_usize(key: &str) -> Option<usize> {
    let raw = env_trimmed(key)?;
    raw.parse::<usize>().ok()
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
