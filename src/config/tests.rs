use super::*;
use once_cell::sync::Lazy;
use std::sync::{Mutex, MutexGuard};
use tempfile::TempDir;

static ENV_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

struct EnvGuard {
    key: &'static str,
    prev: Option<String>,
    _lock: MutexGuard<'static, ()>,
}

impl EnvGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let lock = ENV_LOCK.lock().expect("env lock");
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
            embedding_model: "".to_string(),
            max_answer_tokens: 0,
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
