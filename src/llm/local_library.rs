use crate::config::{DelegationConfig, LlmConfig};
use crate::mcoda::registry::{McodaAgent, McodaRegistry};
use crate::ollama;
use crate::setup::ollama as setup_ollama;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::future::{Future, Ready};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::{info, warn};
use url::Url;

const LIBRARY_DIR: &str = "llm";
const LIBRARY_FILE: &str = "local_model_library.json";
const LIBRARY_VERSION: u32 = 1;
const CAP_CODE_WRITER: &str = "code_writer";
const CAP_CODE_REVIEWER: &str = "code_reviewer";
const CAP_GENERAL_CHAT: &str = "general_chat";
const CAP_EMBEDDING: &str = "embedding";
const CAP_VISION: &str = "vision";
const DEFAULT_LIBRARY_TTL_SECS: u64 = 300;
const WEB_CLASSIFY_TTL_SECS: u64 = 7 * 24 * 60 * 60;
const MAX_WEB_CLASSIFICATIONS_PER_REFRESH: usize = 3;

#[derive(Debug, Clone)]
pub(crate) struct ModelClassification {
    pub capabilities: Vec<String>,
    pub method: String,
}

type NoWebFuture = Ready<Result<String>>;

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct LocalModelLibrary {
    #[serde(default = "default_library_version")]
    pub version: u32,
    #[serde(default)]
    pub updated_at_ms: u128,
    #[serde(default)]
    pub models: Vec<LocalModelEntry>,
    #[serde(default)]
    pub agents: Vec<LocalAgentEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalModelEntry {
    pub name: String,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default)]
    pub classification_method: String,
    #[serde(default)]
    pub last_seen_at_ms: u128,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_classified_at_ms: Option<u128>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalAgentEntry {
    pub agent_id: String,
    pub agent_slug: String,
    pub adapter: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_complexity: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rating: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_per_million: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reasoning_rating: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_status: Option<String>,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default)]
    pub classification_method: String,
    #[serde(default)]
    pub last_seen_at_ms: u128,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_classified_at_ms: Option<u128>,
}

fn default_library_version() -> u32 {
    LIBRARY_VERSION
}

pub(crate) fn resolve_local_ollama_base_url(llm_config: &LlmConfig) -> Option<String> {
    let provider = llm_config.provider.trim();
    if provider.eq_ignore_ascii_case("ollama") {
        let base_url = llm_config.base_url.trim();
        if !base_url.is_empty() && is_local_ollama_base_url(base_url) {
            return Some(base_url.to_string());
        }
    }
    if let Some(value) = env_trimmed("DOCDEX_OLLAMA_BASE_URL") {
        if is_local_ollama_base_url(&value) {
            return Some(value);
        }
    }
    if let Some(value) = env_trimmed("DOCDEX_EMBEDDING_BASE_URL") {
        if is_local_ollama_base_url(&value) {
            return Some(value);
        }
    }
    let default_url = "http://127.0.0.1:11434";
    if is_local_ollama_base_url(default_url) {
        return Some(default_url.to_string());
    }
    None
}

pub(crate) fn is_local_ollama_base_url(base_url: &str) -> bool {
    let trimmed = base_url.trim();
    if trimmed.to_ascii_lowercase().starts_with("http://[::1]") {
        return true;
    }
    if let Ok(url) = Url::parse(base_url) {
        if url.scheme() != "http" {
            return false;
        }
        if let Some(host) = url.host_str() {
            return is_loopback_host(host);
        }
    }
    let Some(rest) = trimmed.strip_prefix("http://") else {
        return false;
    };
    let host_port = rest.split('/').next().unwrap_or("");
    let host = if host_port.starts_with('[') {
        host_port
            .trim_start_matches('[')
            .split(']')
            .next()
            .unwrap_or("")
    } else {
        host_port.split(':').next().unwrap_or(host_port)
    };
    is_loopback_host(host)
}

pub(crate) fn normalize_model_name(name: &str) -> String {
    name.trim().to_string()
}

fn normalize_model_key(name: &str) -> String {
    name.trim().to_ascii_lowercase()
}

pub(crate) fn classify_model_known(name: &str) -> Option<ModelClassification> {
    let key = normalize_model_key(name);
    if key.contains("phi") {
        return Some(ModelClassification {
            capabilities: vec![CAP_CODE_WRITER.to_string(), CAP_GENERAL_CHAT.to_string()],
            method: "known_map".to_string(),
        });
    }
    if key.contains("codellama")
        || key.contains("deepseek-coder")
        || (key.contains("qwen") && key.contains("coder"))
        || key.contains("codestral")
    {
        return Some(ModelClassification {
            capabilities: vec![CAP_CODE_WRITER.to_string(), CAP_CODE_REVIEWER.to_string()],
            method: "known_map".to_string(),
        });
    }
    if key.contains("llama") {
        return Some(ModelClassification {
            capabilities: vec![CAP_GENERAL_CHAT.to_string()],
            method: "known_map".to_string(),
        });
    }
    None
}

pub(crate) fn classify_model_heuristic(name: &str) -> ModelClassification {
    let key = normalize_model_key(name);
    let mut caps = Vec::new();
    if key.contains("embed") {
        caps.push(CAP_EMBEDDING.to_string());
    }
    if key.contains("vision") || key.contains("llava") || key.contains("clip") {
        caps.push(CAP_VISION.to_string());
    }
    if key.contains("code") || key.contains("coder") {
        caps.push(CAP_CODE_WRITER.to_string());
        caps.push(CAP_CODE_REVIEWER.to_string());
    }
    if key.contains("instruct") || key.contains("chat") {
        caps.push(CAP_GENERAL_CHAT.to_string());
    }
    if caps.is_empty() {
        caps.push(CAP_GENERAL_CHAT.to_string());
    }
    normalize_caps(caps, "heuristic")
}

pub(crate) async fn classify_model_with_web_text<F, Fut>(
    model_name: &str,
    fetcher: F,
) -> Result<Option<ModelClassification>>
where
    F: FnOnce(String) -> Fut,
    Fut: Future<Output = Result<String>>,
{
    let query = format!("Ollama model {} best use cases", model_name);
    let text = fetcher(query).await?;
    Ok(classify_model_from_web_text(&text))
}

pub(crate) async fn discover_ollama_models(
    base_url: &str,
    timeout: Duration,
    allow_start: bool,
) -> Vec<String> {
    let mut models: HashSet<String> = HashSet::new();
    match ollama::list_models(base_url, timeout).await {
        Ok(list) => {
            for model in list {
                let name = normalize_model_name(&model);
                if !name.is_empty() {
                    models.insert(name);
                }
            }
        }
        Err(err) => {
            warn!(
                target: "docdexd",
                error = ?err,
                base_url = %base_url,
                "ollama model discovery failed via /api/tags"
            );
        }
    }

    if models.is_empty() {
        if let Some(bin) = setup_ollama::resolve_ollama_path(None) {
            let cli_models = if allow_start {
                setup_ollama::list_models(&bin)
            } else {
                match setup_ollama::list_models_if_running(&bin) {
                    Ok(Some(models)) => Ok(models),
                    Ok(None) => Ok(Vec::new()),
                    Err(err) => Err(err),
                }
            };
            match cli_models {
                Ok(list) => {
                    for model in list {
                        let name = normalize_model_name(&model);
                        if !name.is_empty() {
                            models.insert(name);
                        }
                    }
                }
                Err(err) => {
                    warn!(
                        target: "docdexd",
                        error = ?err,
                        "ollama model discovery failed via CLI"
                    );
                }
            }
        }
    }

    models.into_iter().collect()
}

pub(crate) fn discover_mcoda_agents() -> Vec<LocalAgentEntry> {
    let registry = match McodaRegistry::load_default() {
        Ok(Some(registry)) => registry,
        Ok(None) => return Vec::new(),
        Err(err) => {
            warn!(
                target: "docdexd",
                error = ?err,
                "mcoda registry load failed"
            );
            return Vec::new();
        }
    };
    let now = now_ms();
    registry
        .agents
        .iter()
        .map(|agent| mcoda_agent_entry(agent, now))
        .collect()
}

pub(crate) fn library_has_candidates(library: &LocalModelLibrary) -> bool {
    if !library.agents.is_empty() {
        return true;
    }
    library
        .models
        .iter()
        .any(|entry| is_candidate_capabilities(&entry.capabilities))
}

pub(crate) fn delegation_is_enabled(
    config: &DelegationConfig,
    library: Option<&LocalModelLibrary>,
) -> bool {
    if config.enabled {
        return true;
    }
    if !config.auto_enable {
        return false;
    }
    let enabled = library.map_or(false, library_has_candidates);
    if enabled {
        info!(
            target: "docdexd",
            "delegation auto-enabled via local model library"
        );
    }
    enabled
}

pub(crate) async fn refresh_local_library_if_stale(
    state_dir_override: Option<&Path>,
    llm_config: &LlmConfig,
    allow_start_ollama: bool,
) -> Result<LocalModelLibrary> {
    refresh_local_library_if_stale_with_web::<fn(String) -> NoWebFuture, NoWebFuture>(
        state_dir_override,
        llm_config,
        allow_start_ollama,
        None,
    )
    .await
}

pub(crate) async fn refresh_local_library_if_stale_with_web<F, Fut>(
    state_dir_override: Option<&Path>,
    llm_config: &LlmConfig,
    allow_start_ollama: bool,
    mut web_fetcher: Option<&mut F>,
) -> Result<LocalModelLibrary>
where
    F: FnMut(String) -> Fut,
    Fut: Future<Output = Result<String>>,
{
    let mut library = load_local_library(state_dir_override)?;
    let now = now_ms();
    if library.updated_at_ms > 0 {
        let elapsed_ms = now.saturating_sub(library.updated_at_ms);
        if elapsed_ms < library_ttl().as_millis() as u128 {
            return Ok(library);
        }
    }

    let mut models = Vec::new();
    let mut web_budget = MAX_WEB_CLASSIFICATIONS_PER_REFRESH;
    if let Some(base_url) = resolve_local_ollama_base_url(llm_config) {
        let discovered =
            discover_ollama_models(&base_url, Duration::from_secs(2), allow_start_ollama).await;
        for name in discovered {
            let existing = library.models.iter().find(|entry| entry.name == name);
            let mut classification =
                classify_model_known(&name).unwrap_or_else(|| classify_model_heuristic(&name));
            let should_web = classification.method == "heuristic"
                && web_budget > 0
                && is_web_candidate(&classification.capabilities)
                && should_web_classify(existing, now)
                && web_fetcher.is_some();
            if should_web {
                if let Some(fetcher) = web_fetcher.as_mut() {
                    if let Ok(Some(web_classification)) =
                        classify_model_with_web_text(&name, fetcher).await
                    {
                        classification = web_classification;
                        web_budget = web_budget.saturating_sub(1);
                    }
                }
            }
            let last_classified_at_ms = if classification.method == "web" {
                Some(now)
            } else {
                existing.and_then(|entry| entry.last_classified_at_ms)
            };
            models.push(LocalModelEntry {
                name: name.clone(),
                source: "ollama".to_string(),
                capabilities: classification.capabilities,
                notes: existing.and_then(|entry| entry.notes.clone()),
                classification_method: classification.method,
                last_seen_at_ms: now,
                last_classified_at_ms,
            });
        }
    }

    let agents = discover_mcoda_agents();

    library.updated_at_ms = now;
    library.models = models;
    library.agents = agents;
    save_local_library(state_dir_override, &library)?;
    let (known_count, heuristic_count, web_count, other_count) =
        classification_method_counts(&library.models);
    info!(
        target: "docdexd",
        models = library.models.len(),
        agents = library.agents.len(),
        known = known_count,
        heuristic = heuristic_count,
        web = web_count,
        other = other_count,
        "local model library refreshed"
    );
    Ok(library)
}

pub fn library_path(state_dir_override: Option<&Path>) -> Result<PathBuf> {
    let root = resolve_state_root(state_dir_override)?;
    Ok(root.join(LIBRARY_DIR).join(LIBRARY_FILE))
}

pub fn load_local_library(state_dir_override: Option<&Path>) -> Result<LocalModelLibrary> {
    let path = library_path(state_dir_override)?;
    if !path.exists() {
        return Ok(LocalModelLibrary::default());
    }
    let raw = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    match serde_json::from_str::<LocalModelLibrary>(&raw) {
        Ok(mut library) => {
            if library.version == 0 {
                library.version = LIBRARY_VERSION;
            }
            Ok(library)
        }
        Err(err) => {
            warn!(
                target: "docdexd",
                error = ?err,
                path = %path.display(),
                "local model library is corrupt; rebuilding"
            );
            backup_corrupt_library(&path);
            Ok(LocalModelLibrary::default())
        }
    }
}

pub fn save_local_library(
    state_dir_override: Option<&Path>,
    library: &LocalModelLibrary,
) -> Result<()> {
    let path = library_path(state_dir_override)?;
    ensure_library_dir(&path)?;
    let payload = serde_json::to_string_pretty(library).context("serialize local model library")?;
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, payload).with_context(|| format!("write {}", tmp.display()))?;
    fs::rename(&tmp, &path).with_context(|| format!("rename {}", path.display()))?;
    Ok(())
}

fn resolve_state_root(state_dir_override: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = state_dir_override {
        return Ok(path.to_path_buf());
    }
    if let Ok(value) = std::env::var("DOCDEX_STATE_DIR") {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return Ok(PathBuf::from(trimmed));
        }
    }
    crate::state_paths::default_state_base_dir()
}

fn ensure_library_dir(path: &Path) -> Result<()> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    crate::state_layout::ensure_state_dir_secure(parent)
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

fn env_u64(key: &str) -> Option<u64> {
    let raw = env_trimmed(key)?;
    raw.parse::<u64>().ok()
}

fn library_ttl() -> Duration {
    env_u64("DOCDEX_LOCAL_LIBRARY_TTL_SECS")
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(DEFAULT_LIBRARY_TTL_SECS))
}

fn web_classify_ttl() -> Duration {
    env_u64("DOCDEX_LOCAL_LIBRARY_WEB_TTL_SECS")
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_secs(WEB_CLASSIFY_TTL_SECS))
}

fn normalize_agent_capabilities(adapter: &str, capabilities: &[String]) -> Vec<String> {
    let mut tags: Vec<String> = Vec::new();
    for capability in capabilities {
        let normalized = capability.trim().to_ascii_lowercase();
        if normalized.is_empty() {
            continue;
        }
        match normalized.as_str() {
            "code_write" => tags.push(CAP_CODE_WRITER.to_string()),
            "code_review" => tags.push(CAP_CODE_REVIEWER.to_string()),
            "chat" => tags.push(CAP_GENERAL_CHAT.to_string()),
            _ => tags.push(normalized),
        }
    }
    let adapter_name = adapter.trim().to_ascii_lowercase();
    if adapter_name == "ollama" || adapter_name.starts_with("ollama-") {
        tags.push("local".to_string());
    }
    tags.sort();
    tags.dedup();
    tags
}

fn classify_model_from_web_text(text: &str) -> Option<ModelClassification> {
    let lowered = text.to_ascii_lowercase();
    let mut caps = Vec::new();
    if lowered.contains("embedding") {
        caps.push(CAP_EMBEDDING.to_string());
    }
    if lowered.contains("vision")
        || lowered.contains("image")
        || lowered.contains("multimodal")
        || lowered.contains("visual")
    {
        caps.push(CAP_VISION.to_string());
    }
    if lowered.contains("code")
        || lowered.contains("coding")
        || lowered.contains("programming")
        || lowered.contains("developer")
    {
        caps.push(CAP_CODE_WRITER.to_string());
        caps.push(CAP_CODE_REVIEWER.to_string());
    }
    if lowered.contains("review") || lowered.contains("refactor") {
        caps.push(CAP_CODE_REVIEWER.to_string());
    }
    if lowered.contains("chat") || lowered.contains("assistant") {
        caps.push(CAP_GENERAL_CHAT.to_string());
    }
    if caps.is_empty() {
        return None;
    }
    Some(normalize_caps(caps, "web"))
}

fn normalize_caps(mut caps: Vec<String>, method: &str) -> ModelClassification {
    caps.sort();
    caps.dedup();
    ModelClassification {
        capabilities: caps,
        method: method.to_string(),
    }
}

fn classification_method_counts(models: &[LocalModelEntry]) -> (usize, usize, usize, usize) {
    let mut known = 0;
    let mut heuristic = 0;
    let mut web = 0;
    let mut other = 0;
    for entry in models {
        match entry.classification_method.as_str() {
            "known_map" => known += 1,
            "heuristic" => heuristic += 1,
            "web" => web += 1,
            _ => other += 1,
        }
    }
    (known, heuristic, web, other)
}

fn is_web_candidate(capabilities: &[String]) -> bool {
    capabilities.len() == 1 && capabilities.contains(&CAP_GENERAL_CHAT.to_string())
}

fn should_web_classify(existing: Option<&LocalModelEntry>, now_ms: u128) -> bool {
    let Some(existing) = existing else {
        return true;
    };
    if existing.classification_method != "web" {
        return true;
    }
    let Some(last_ms) = existing.last_classified_at_ms else {
        return true;
    };
    now_ms.saturating_sub(last_ms) > web_classify_ttl().as_millis() as u128
}

fn is_candidate_capabilities(capabilities: &[String]) -> bool {
    if capabilities.is_empty() {
        return true;
    }
    capabilities
        .iter()
        .any(|cap| cap == CAP_CODE_WRITER || cap == CAP_CODE_REVIEWER || cap == CAP_GENERAL_CHAT)
}

fn mcoda_agent_entry(agent: &McodaAgent, now_ms: u128) -> LocalAgentEntry {
    let max_complexity = agent.max_complexity.filter(|value| *value >= 0);
    let usage = agent
        .best_usage
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string());
    let health_status = agent
        .health_status
        .as_ref()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string());
    LocalAgentEntry {
        agent_id: agent.id.clone(),
        agent_slug: agent.slug.clone(),
        adapter: agent.adapter.clone(),
        default_model: agent.default_model.clone(),
        max_complexity,
        rating: agent.rating,
        cost_per_million: agent.cost_per_million,
        usage,
        reasoning_rating: agent.reasoning_rating,
        health_status,
        capabilities: normalize_agent_capabilities(&agent.adapter, &agent.capabilities),
        notes: None,
        classification_method: "registry".to_string(),
        last_seen_at_ms: now_ms,
        last_classified_at_ms: None,
    }
}

fn is_loopback_host(host: &str) -> bool {
    let host = host.trim();
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    if host == "0.0.0.0" || host == "::1" {
        return true;
    }
    if host.starts_with("127.") {
        return true;
    }
    false
}

fn backup_corrupt_library(path: &Path) {
    let backup_name = match path.file_name().and_then(|name| name.to_str()) {
        Some(name) => format!("{}.corrupt-{}", name, now_ms()),
        None => format!("local_model_library.json.corrupt-{}", now_ms()),
    };
    let backup = path.with_file_name(backup_name);
    if let Err(err) = fs::rename(path, &backup) {
        warn!(
            target: "docdexd",
            error = ?err,
            path = %path.display(),
            backup = %backup.display(),
            "failed to back up corrupt local model library"
        );
    }
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup::test_support::ENV_LOCK;
    use rusqlite::{params, Connection};
    use std::fs;
    use tempfile::TempDir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    struct EnvVarGuard {
        key: &'static str,
        prev: Option<std::ffi::OsString>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
            let prev = std::env::var_os(key);
            std::env::set_var(key, value);
            Self { key, prev }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(value) = self.prev.take() {
                std::env::set_var(self.key, value);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    #[test]
    fn local_library_roundtrip() -> Result<()> {
        let _guard = ENV_LOCK.lock();
        let dir = TempDir::new()?;
        std::env::set_var("DOCDEX_STATE_DIR", dir.path());
        let library = LocalModelLibrary {
            updated_at_ms: 42,
            models: vec![LocalModelEntry {
                name: "phi3.5:3.8b".to_string(),
                source: "ollama".to_string(),
                capabilities: vec!["code_writer".to_string()],
                notes: Some("test".to_string()),
                classification_method: "known_map".to_string(),
                last_seen_at_ms: 1,
                last_classified_at_ms: Some(2),
            }],
            agents: vec![LocalAgentEntry {
                agent_id: "agent-1".to_string(),
                agent_slug: "agent-one".to_string(),
                adapter: "ollama".to_string(),
                default_model: Some("phi3.5".to_string()),
                max_complexity: Some(3),
                rating: Some(9.1),
                cost_per_million: Some(1.2),
                usage: Some("code_reviewer".to_string()),
                reasoning_rating: Some(7.4),
                health_status: Some("healthy".to_string()),
                capabilities: vec!["code_reviewer".to_string()],
                notes: None,
                classification_method: "heuristic".to_string(),
                last_seen_at_ms: 3,
                last_classified_at_ms: None,
            }],
            ..LocalModelLibrary::default()
        };
        save_local_library(None, &library)?;
        let loaded = load_local_library(None)?;
        std::env::remove_var("DOCDEX_STATE_DIR");
        assert_eq!(loaded.updated_at_ms, 42);
        assert_eq!(loaded.models.len(), 1);
        assert_eq!(loaded.agents.len(), 1);
        Ok(())
    }

    #[test]
    fn local_library_corrupt_falls_back() -> Result<()> {
        let _guard = ENV_LOCK.lock();
        let dir = TempDir::new()?;
        std::env::set_var("DOCDEX_STATE_DIR", dir.path());
        let path = library_path(None)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, "{not json")?;
        let loaded = load_local_library(None)?;
        std::env::remove_var("DOCDEX_STATE_DIR");
        assert!(loaded.models.is_empty());
        assert!(loaded.agents.is_empty());
        Ok(())
    }

    #[test]
    fn ollama_base_url_local_detection() {
        assert!(is_local_ollama_base_url("http://127.0.0.1:11434"));
        assert!(is_local_ollama_base_url("http://localhost:11434"));
        assert!(is_local_ollama_base_url("http://[::1]:11434"));
        assert!(!is_local_ollama_base_url("https://127.0.0.1:11434"));
        assert!(!is_local_ollama_base_url("http://192.168.1.10:11434"));
    }

    #[test]
    fn ollama_model_name_normalization() {
        assert_eq!(normalize_model_name("  Phi3.5:3.8b  "), "Phi3.5:3.8b");
        assert_eq!(normalize_model_name(""), "");
    }

    #[test]
    fn classify_model_known_families() {
        let phi = classify_model_known("phi3.5:3.8b").expect("phi mapping");
        assert!(phi.capabilities.contains(&CAP_CODE_WRITER.to_string()));
        assert!(phi.capabilities.contains(&CAP_GENERAL_CHAT.to_string()));
        let deepseek = classify_model_known("deepseek-coder:6.7b").expect("deepseek mapping");
        assert!(deepseek
            .capabilities
            .contains(&CAP_CODE_REVIEWER.to_string()));
    }

    #[test]
    fn classify_model_heuristics() {
        let embed = classify_model_heuristic("text-embedding-3-large");
        assert!(embed.capabilities.contains(&CAP_EMBEDDING.to_string()));
        let vision = classify_model_heuristic("llava:latest");
        assert!(vision.capabilities.contains(&CAP_VISION.to_string()));
        let code = classify_model_heuristic("my-code-model");
        assert!(code.capabilities.contains(&CAP_CODE_WRITER.to_string()));
    }

    #[test]
    fn mcoda_agent_mapping() {
        let agent = McodaAgent {
            id: "agent-1".to_string(),
            slug: "local-test".to_string(),
            adapter: "ollama".to_string(),
            default_model: Some("phi3.5:3.8b".to_string()),
            config: None,
            created_at: None,
            updated_at: None,
            rating: Some(7.5),
            cost_per_million: Some(2.25),
            max_complexity: Some(4),
            best_usage: Some("code_writer".to_string()),
            reasoning_rating: Some(8.5),
            health_status: Some("healthy".to_string()),
            cli_binary: None,
            capabilities: vec![
                "code_write".to_string(),
                "code_review".to_string(),
                "chat".to_string(),
            ],
            models: Vec::new(),
            auth: None,
        };
        let entry = mcoda_agent_entry(&agent, 10);
        assert_eq!(entry.agent_id, "agent-1");
        assert!(entry.capabilities.contains(&"code_writer".to_string()));
        assert!(entry.capabilities.contains(&"code_reviewer".to_string()));
        assert!(entry.capabilities.contains(&"general_chat".to_string()));
        assert!(entry.capabilities.contains(&"local".to_string()));
        assert_eq!(entry.rating, Some(7.5));
        assert_eq!(entry.cost_per_million, Some(2.25));
        assert_eq!(entry.max_complexity, Some(4));
        assert_eq!(entry.usage.as_deref(), Some("code_writer"));
        assert_eq!(entry.reasoning_rating, Some(8.5));
        assert_eq!(entry.health_status.as_deref(), Some("healthy"));
        assert_eq!(entry.classification_method, "registry");
        assert_eq!(entry.last_seen_at_ms, 10);
    }

    #[test]
    fn discover_mcoda_agents_reads_registry() -> Result<()> {
        let _guard = ENV_LOCK.lock();
        let dir = TempDir::new()?;
        let mcoda_dir = dir.path().join(".mcoda");
        fs::create_dir_all(&mcoda_dir)?;
        let db_path = mcoda_dir.join("mcoda.db");
        let conn = Connection::open(&db_path)?;
        conn.execute_batch(
            "CREATE TABLE agents (
                id TEXT PRIMARY KEY,
                slug TEXT NOT NULL,
                adapter TEXT NOT NULL,
                default_model TEXT,
                config_json TEXT,
                created_at TEXT,
                updated_at TEXT,
                rating REAL,
                cost_per_million REAL,
                max_complexity INTEGER,
                best_usage TEXT,
                reasoning_rating REAL
            );
            CREATE TABLE agent_capabilities (
                agent_id TEXT NOT NULL,
                capability TEXT NOT NULL
            );
            CREATE TABLE agent_health (
                agent_id TEXT PRIMARY KEY,
                status TEXT NOT NULL
            );",
        )?;
        conn.execute(
            "INSERT INTO agents (id, slug, adapter, default_model, config_json, created_at, updated_at, rating, cost_per_million, max_complexity, best_usage, reasoning_rating)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                "agent-1",
                "agent-one",
                "ollama",
                Option::<String>::None,
                Option::<String>::None,
                Option::<String>::None,
                Option::<String>::None,
                8.25,
                1.5,
                6,
                "code_writer",
                9.0
            ],
        )?;
        conn.execute(
            "INSERT INTO agent_capabilities (agent_id, capability) VALUES (?1, ?2)",
            params!["agent-1", "Code_Writer"],
        )?;
        conn.execute(
            "INSERT INTO agent_health (agent_id, status) VALUES (?1, ?2)",
            params!["agent-1", "healthy"],
        )?;
        drop(conn);

        let _home = EnvVarGuard::set("HOME", dir.path());
        let _userprofile = EnvVarGuard::set("USERPROFILE", dir.path());
        let agents = discover_mcoda_agents();

        assert_eq!(agents.len(), 1);
        let entry = &agents[0];
        assert_eq!(entry.agent_id, "agent-1");
        assert_eq!(entry.agent_slug, "agent-one");
        assert_eq!(entry.adapter, "ollama");
        assert!(entry.capabilities.contains(&"code_writer".to_string()));
        assert!(entry.capabilities.contains(&"local".to_string()));
        assert_eq!(entry.rating, Some(8.25));
        assert_eq!(entry.cost_per_million, Some(1.5));
        assert_eq!(entry.max_complexity, Some(6));
        assert_eq!(entry.usage.as_deref(), Some("code_writer"));
        assert_eq!(entry.reasoning_rating, Some(9.0));
        assert_eq!(entry.health_status.as_deref(), Some("healthy"));
        assert_eq!(entry.classification_method, "registry");
        Ok(())
    }

    #[tokio::test]
    async fn discover_ollama_models_reads_tags() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let server = tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buffer = [0u8; 512];
                let _ = socket.read(&mut buffer).await;
                let body =
                    "{\"models\":[{\"name\":\"phi3.5:3.8b\"},{\"name\":\"text-embedding-3-large\"}]}";
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });

        let base_url = format!("http://{}", addr);
        let models = discover_ollama_models(&base_url, Duration::from_secs(1), false).await;
        let _ = server.await;
        assert!(models.contains(&"phi3.5:3.8b".to_string()));
        assert!(models.contains(&"text-embedding-3-large".to_string()));
        Ok(())
    }

    #[tokio::test]
    async fn classify_model_web_stub() -> Result<()> {
        let result = classify_model_with_web_text("mystery-model", |query| async move {
            assert!(query.contains("mystery-model"));
            Ok("Great for code generation and coding assistants.".to_string())
        })
        .await?;
        let classification = result.expect("web classification");
        assert!(classification
            .capabilities
            .contains(&CAP_CODE_WRITER.to_string()));
        Ok(())
    }

    #[tokio::test]
    async fn local_library_refresh_ttl() -> Result<()> {
        let _guard = ENV_LOCK.lock();
        let dir = TempDir::new()?;
        std::env::set_var("DOCDEX_STATE_DIR", dir.path());
        std::env::set_var("DOCDEX_LOCAL_LIBRARY_TTL_SECS", "99999");
        let mut library = LocalModelLibrary::default();
        library.updated_at_ms = now_ms();
        library.models.push(LocalModelEntry {
            name: "phi3.5:3.8b".to_string(),
            source: "ollama".to_string(),
            capabilities: vec![CAP_CODE_WRITER.to_string()],
            notes: None,
            classification_method: "known_map".to_string(),
            last_seen_at_ms: library.updated_at_ms,
            last_classified_at_ms: None,
        });
        save_local_library(None, &library)?;
        let refreshed = refresh_local_library_if_stale(None, &LlmConfig::default(), false).await?;
        std::env::remove_var("DOCDEX_LOCAL_LIBRARY_TTL_SECS");
        std::env::remove_var("DOCDEX_STATE_DIR");
        assert_eq!(refreshed.updated_at_ms, library.updated_at_ms);
        assert_eq!(refreshed.models.len(), 1);
        Ok(())
    }

    #[test]
    fn local_library_refresh_has_candidates() {
        let mut library = LocalModelLibrary::default();
        library.models.push(LocalModelEntry {
            name: "embed-only".to_string(),
            source: "ollama".to_string(),
            capabilities: vec![CAP_EMBEDDING.to_string()],
            notes: None,
            classification_method: "heuristic".to_string(),
            last_seen_at_ms: 1,
            last_classified_at_ms: None,
        });
        assert!(!library_has_candidates(&library));
        library.agents.push(LocalAgentEntry {
            agent_id: "agent".to_string(),
            agent_slug: "agent".to_string(),
            adapter: "openai".to_string(),
            default_model: None,
            max_complexity: None,
            rating: None,
            cost_per_million: None,
            usage: None,
            reasoning_rating: None,
            health_status: None,
            capabilities: Vec::new(),
            notes: None,
            classification_method: "registry".to_string(),
            last_seen_at_ms: 2,
            last_classified_at_ms: None,
        });
        assert!(library_has_candidates(&library));
    }
}
