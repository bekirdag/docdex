use super::*;
use crate::setup::test_support::ENV_LOCK;
use parking_lot::ReentrantMutexGuard;
use tempfile::TempDir;

struct EnvGuard {
    key: &'static str,
    prev: Option<String>,
    _lock: ReentrantMutexGuard<'static, ()>,
}

impl EnvGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let lock = ENV_LOCK.lock();
        let prev = std::env::var(key).ok();
        std::env::set_var(key, value);
        Self {
            key,
            prev,
            _lock: lock,
        }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        if let Some(ref value) = self.prev {
            std::env::set_var(self.key, value);
        } else {
            std::env::remove_var(self.key);
        }
    }
}

#[test]
fn apply_defaults_fills_core_fields() -> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let _env = EnvGuard::set("HOME", temp.path().to_string_lossy().as_ref());

    let mut config = AppConfig {
        core: CoreConfig {
            global_state_dir: None,
            log_level: "".to_string(),
            max_concurrent_fetches: 0,
        },
        llm: LlmConfig {
            provider: "".to_string(),
            base_url: "".to_string(),
            default_model: "".to_string(),
            agent_id: "".to_string(),
            embedding_model: "".to_string(),
            max_answer_tokens: 0,
            delegation: DelegationConfig::default(),
        },
        search: SearchConfig::default(),
        code_intelligence: CodeIntelligenceConfig::default(),
        web: WebConfigSection::default(),
        memory: MemoryConfig::default(),
        features: FeatureFlagsConfig::default(),
        server: ServerConfig::default(),
    };
    config.memory.backend = "unknown".to_string();
    config.memory.profile.embedding_dim = 0;
    config.apply_defaults()?;

    assert!(config.core.global_state_dir.is_some());
    assert!(!config.core.log_level.trim().is_empty());
    assert_eq!(config.memory.backend, DEFAULT_MEMORY_BACKEND);
    assert!(config.llm.base_url.starts_with("http"));
    Ok(())
}

#[test]
fn apply_defaults_sets_profile_embedding_dim() -> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let _env = EnvGuard::set("HOME", temp.path().to_string_lossy().as_ref());

    let mut config = AppConfig::default();
    config.memory.profile.embedding_dim = 0;
    config.apply_defaults()?;

    assert_eq!(
        config.memory.profile.embedding_dim,
        DEFAULT_PROFILE_EMBED_DIM
    );
    Ok(())
}

#[test]
fn apply_defaults_sets_delegation_defaults() -> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let _env = EnvGuard::set("HOME", temp.path().to_string_lossy().as_ref());

    let mut config = AppConfig::default();
    config.llm.delegation.mode = "".to_string();
    config.llm.delegation.timeout_ms = 0;
    config.llm.delegation.max_tokens = 0;
    config.llm.delegation.max_context_chars = 0;
    config.apply_defaults()?;

    assert!(!config.llm.delegation.enabled);
    assert!(config.llm.delegation.auto_enable);
    assert!(!config.llm.delegation.enforce_local);
    assert!(!config.llm.delegation.allow_fallback_to_primary);
    assert!(config.llm.delegation.re_evaluate);
    assert!(config.llm.delegation.code.local_agent_id.is_empty());
    assert!(config.llm.delegation.code.primary_agent_id.is_empty());
    assert!(config.llm.delegation.general.local_agent_id.is_empty());
    assert!(config.llm.delegation.general.primary_agent_id.is_empty());
    assert_eq!(
        config.llm.delegation.local_selection_policy,
        "task_capability"
    );
    assert!(config.llm.delegation.use_cached_local_decision);
    assert_eq!(config.llm.delegation.mode, DEFAULT_DELEGATION_MODE);
    assert_eq!(
        config.llm.delegation.timeout_ms,
        DEFAULT_DELEGATION_TIMEOUT_MS
    );
    assert_eq!(
        config.llm.delegation.max_tokens,
        DEFAULT_DELEGATION_MAX_TOKENS
    );
    assert_eq!(
        config.llm.delegation.max_context_chars,
        DEFAULT_DELEGATION_MAX_CONTEXT_CHARS
    );
    assert_eq!(config.llm.delegation.primary_usd_per_million_tokens, 0.0);
    assert_eq!(config.llm.delegation.local_usd_per_million_tokens, 0.0);
    Ok(())
}

#[test]
fn delegation_auto_enable_defaults() -> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let _env = EnvGuard::set("HOME", temp.path().to_string_lossy().as_ref());
    let config = AppConfig::default();
    assert!(config.llm.delegation.auto_enable);
    Ok(())
}

#[test]
fn delegation_auto_enable_env_override() -> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let config_path = temp.path().join("config.toml");
    let _home = EnvGuard::set("HOME", temp.path().to_string_lossy().as_ref());
    let _auto = EnvGuard::set("DOCDEX_DELEGATION_AUTO_ENABLE", "0");
    let config = load_config_from_path(&config_path)?;
    assert!(!config.llm.delegation.auto_enable);
    Ok(())
}

#[test]
fn load_config_applies_delegation_env_overrides() -> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let config_path = temp.path().join("config.toml");
    let _home = EnvGuard::set("HOME", temp.path().to_string_lossy().as_ref());
    let _enabled = EnvGuard::set("DOCDEX_DELEGATION_ENABLED", "1");
    let _enforce = EnvGuard::set("DOCDEX_DELEGATION_ENFORCE_LOCAL", "1");
    let _fallback = EnvGuard::set("DOCDEX_DELEGATION_ALLOW_FALLBACK", "1");
    let _reeval = EnvGuard::set("DOCDEX_DELEGATION_REEVALUATE", "0");
    let _local = EnvGuard::set("DOCDEX_DELEGATION_LOCAL_AGENT", "local-agent");
    let _primary = EnvGuard::set("DOCDEX_DELEGATION_PRIMARY_AGENT", "primary-agent");
    let _code_local = EnvGuard::set("DOCDEX_DELEGATION_CODE_LOCAL_AGENT", "qwen3-coder");
    let _code_primary = EnvGuard::set("DOCDEX_DELEGATION_CODE_PRIMARY_AGENT", "qwen3-coder");
    let _general_local = EnvGuard::set("DOCDEX_DELEGATION_GENERAL_LOCAL_AGENT", "qwen-3.5-35b");
    let _general_primary = EnvGuard::set("DOCDEX_DELEGATION_GENERAL_PRIMARY_AGENT", "qwen-3.5-35b");
    let _mode = EnvGuard::set("DOCDEX_DELEGATION_MODE", "draft_then_refine");
    let _policy = EnvGuard::set(
        "DOCDEX_DELEGATION_LOCAL_SELECTION_POLICY",
        "mcoda_zero_cost_most_capable",
    );
    let _cached = EnvGuard::set("DOCDEX_DELEGATION_USE_CACHED_LOCAL_DECISION", "0");
    let _timeout = EnvGuard::set("DOCDEX_DELEGATION_TIMEOUT_MS", "42000");
    let _max_tokens = EnvGuard::set("DOCDEX_DELEGATION_MAX_TOKENS", "777");
    let _primary_rate = EnvGuard::set("DOCDEX_DELEGATION_PRIMARY_USD_PER_MILLION_TOKENS", "1.25");
    let _local_rate = EnvGuard::set("DOCDEX_DELEGATION_LOCAL_USD_PER_MILLION_TOKENS", "0.05");

    let config = load_config_from_path(&config_path)?;

    assert!(config.llm.delegation.enabled);
    assert!(config.llm.delegation.enforce_local);
    assert!(config.llm.delegation.allow_fallback_to_primary);
    assert!(!config.llm.delegation.re_evaluate);
    assert_eq!(config.llm.delegation.local_agent_id, "local-agent");
    assert_eq!(config.llm.delegation.primary_agent_id, "primary-agent");
    assert_eq!(config.llm.delegation.code.local_agent_id, "qwen3-coder");
    assert_eq!(config.llm.delegation.code.primary_agent_id, "qwen3-coder");
    assert_eq!(config.llm.delegation.general.local_agent_id, "qwen-3.5-35b");
    assert_eq!(
        config.llm.delegation.general.primary_agent_id,
        "qwen-3.5-35b"
    );
    assert_eq!(
        config.llm.delegation.local_selection_policy,
        "mcoda_zero_cost_most_capable"
    );
    assert!(!config.llm.delegation.use_cached_local_decision);
    assert_eq!(config.llm.delegation.mode, "draft_then_refine");
    assert_eq!(config.llm.delegation.timeout_ms, 42000);
    assert_eq!(config.llm.delegation.max_tokens, 777);
    assert!((config.llm.delegation.primary_usd_per_million_tokens - 1.25).abs() < 1e-6);
    assert!((config.llm.delegation.local_usd_per_million_tokens - 0.05).abs() < 1e-6);
    Ok(())
}

#[test]
fn load_config_applies_legacy_delegation_pricing_env_aliases(
) -> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let config_path = temp.path().join("config.toml");
    let _home = EnvGuard::set("HOME", temp.path().to_string_lossy().as_ref());
    let _primary_rate = EnvGuard::set("DOCDEX_DELEGATION_PRIMARY_USD_PER_1K_TOKENS", "1.25");
    let _local_rate = EnvGuard::set("DOCDEX_DELEGATION_LOCAL_USD_PER_1K_TOKENS", "0.05");

    let config = load_config_from_path(&config_path)?;

    assert!((config.llm.delegation.primary_usd_per_million_tokens - 1.25).abs() < 1e-6);
    assert!((config.llm.delegation.local_usd_per_million_tokens - 0.05).abs() < 1e-6);
    Ok(())
}

#[test]
fn load_config_parses_nested_delegation_lanes() -> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let config_path = temp.path().join("config.toml");
    let _home = EnvGuard::set("HOME", temp.path().to_string_lossy().as_ref());
    std::fs::write(
        &config_path,
        r#"[llm.delegation.code]
local_agent_id = "qwen3-coder"
primary_agent_id = "qwen3-coder"

[llm.delegation.general]
local_agent_id = "qwen-3.5-35b"
primary_agent_id = "qwen-3.5-35b"
"#,
    )?;

    let config = load_config_from_path(&config_path)?;

    assert_eq!(config.llm.delegation.code.local_agent_id, "qwen3-coder");
    assert_eq!(config.llm.delegation.code.primary_agent_id, "qwen3-coder");
    assert_eq!(config.llm.delegation.general.local_agent_id, "qwen-3.5-35b");
    assert_eq!(
        config.llm.delegation.general.primary_agent_id,
        "qwen-3.5-35b"
    );
    Ok(())
}

#[test]
fn load_config_prefers_canonical_delegation_pricing_env_names(
) -> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let config_path = temp.path().join("config.toml");
    let _home = EnvGuard::set("HOME", temp.path().to_string_lossy().as_ref());
    let _legacy_primary = EnvGuard::set("DOCDEX_DELEGATION_PRIMARY_USD_PER_1K_TOKENS", "1.25");
    let _legacy_local = EnvGuard::set("DOCDEX_DELEGATION_LOCAL_USD_PER_1K_TOKENS", "0.05");
    let _primary_rate = EnvGuard::set("DOCDEX_DELEGATION_PRIMARY_USD_PER_MILLION_TOKENS", "2.5");
    let _local_rate = EnvGuard::set("DOCDEX_DELEGATION_LOCAL_USD_PER_MILLION_TOKENS", "0.15");

    let config = load_config_from_path(&config_path)?;

    assert!((config.llm.delegation.primary_usd_per_million_tokens - 2.5).abs() < 1e-6);
    assert!((config.llm.delegation.local_usd_per_million_tokens - 0.15).abs() < 1e-6);
    Ok(())
}

#[test]
fn load_config_reads_legacy_delegation_pricing_toml_aliases(
) -> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let config_path = temp.path().join("config.toml");
    let _home = EnvGuard::set("HOME", temp.path().to_string_lossy().as_ref());
    std::fs::write(
        &config_path,
        r#"[llm.delegation]
primary_usd_per_1k_tokens = 7.5
local_usd_per_1k_tokens = 0.25
"#,
    )?;

    let config = load_config_from_path(&config_path)?;

    assert!((config.llm.delegation.primary_usd_per_million_tokens - 7.5).abs() < 1e-6);
    assert!((config.llm.delegation.local_usd_per_million_tokens - 0.25).abs() < 1e-6);
    Ok(())
}

#[test]
fn write_config_uses_canonical_delegation_pricing_names() -> Result<(), Box<dyn std::error::Error>>
{
    let temp = TempDir::new()?;
    let config_path = temp.path().join("config.toml");
    let _home = EnvGuard::set("HOME", temp.path().to_string_lossy().as_ref());
    let mut config = AppConfig::default();
    config.llm.delegation.primary_usd_per_million_tokens = 7.5;
    config.llm.delegation.local_usd_per_million_tokens = 0.25;

    write_config(&config_path, &config)?;

    let written = std::fs::read_to_string(&config_path)?;
    assert!(written.contains("primary_usd_per_million_tokens = 7.5"));
    assert!(written.contains("local_usd_per_million_tokens = 0.25"));
    assert!(!written.contains("primary_usd_per_1k_tokens"));
    assert!(!written.contains("local_usd_per_1k_tokens"));
    Ok(())
}

#[test]
fn load_config_applies_main_llm_agent_env_override() -> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let config_path = temp.path().join("config.toml");
    let _home = EnvGuard::set("HOME", temp.path().to_string_lossy().as_ref());
    let _agent = EnvGuard::set("DOCDEX_LLM_AGENT", "mcoda-main");
    let config = load_config_from_path(&config_path)?;
    assert_eq!(config.llm.agent_id, "mcoda-main");
    Ok(())
}

#[test]
fn delegation_pricing_clamps_invalid_values() -> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let _env = EnvGuard::set("HOME", temp.path().to_string_lossy().as_ref());

    let mut config = AppConfig::default();
    config.llm.delegation.primary_usd_per_million_tokens = -5.0;
    config.llm.delegation.local_usd_per_million_tokens = f64::NAN;
    config.apply_defaults()?;

    assert_eq!(config.llm.delegation.primary_usd_per_million_tokens, 0.0);
    assert_eq!(config.llm.delegation.local_usd_per_million_tokens, 0.0);
    Ok(())
}

#[test]
fn default_web_user_agent_looks_like_browser() {
    let ua = default_web_user_agent();
    assert!(ua.contains("Mozilla/5.0"));
    assert!(!ua.to_ascii_lowercase().contains("docdexd/"));
}

#[test]
fn apply_defaults_normalizes_mcp_ipc_mode() -> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let _env = EnvGuard::set("HOME", temp.path().to_string_lossy().as_ref());

    let mut config = AppConfig::default();
    config.server.mcp_ipc_mode = "invalid".to_string();
    config.apply_defaults()?;

    assert_eq!(config.server.mcp_ipc_mode, "auto");
    Ok(())
}

#[test]
fn load_config_applies_mcp_ipc_env_overrides() -> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let config_path = temp.path().join("config.toml");
    let _home = EnvGuard::set("HOME", temp.path().to_string_lossy().as_ref());
    let _ipc = EnvGuard::set("DOCDEX_MCP_IPC", "0");
    let _socket = EnvGuard::set("DOCDEX_MCP_SOCKET_PATH", "/tmp/docdex-mcp.sock");
    let _pipe = EnvGuard::set("DOCDEX_MCP_PIPE_NAME", "docdex-mcp-test");

    let config = load_config_from_path(&config_path)?;

    assert_eq!(config.server.mcp_ipc_mode, "off");
    assert_eq!(config.server.mcp_socket_path, "/tmp/docdex-mcp.sock");
    assert_eq!(config.server.mcp_pipe_name, "docdex-mcp-test");
    Ok(())
}
