use crate::config;
use crate::embeddings::{self, EmbeddingTargetHints, DEFAULT_PROFILE_EMBEDDING_MODEL};
use crate::llm::local_library::load_local_library;
use crate::profiles::{
    Agent, Preference, PreferenceCategory, ProfileEmbedder, ProfileImportSummary, ProfileManager,
};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub(crate) async fn run(command: crate::cli::ProfileCommand) -> Result<()> {
    match command {
        crate::cli::ProfileCommand::List { agent_id } => run_list(agent_id).await,
        crate::cli::ProfileCommand::Add {
            agent_id,
            category,
            content,
            role,
        } => run_add(agent_id, category, content, role).await,
        crate::cli::ProfileCommand::Search {
            agent_id,
            query,
            top_k,
        } => run_search(agent_id, query, top_k).await,
        crate::cli::ProfileCommand::Export { out } => run_export(out).await,
        crate::cli::ProfileCommand::Import { path } => run_import(path).await,
    }
}

async fn run_list(agent_id: Option<String>) -> Result<()> {
    let config = config::AppConfig::load_default()?;
    let state_dir = resolve_state_dir(&config)?;
    let manager = ProfileManager::new(&state_dir, config.memory.profile.embedding_dim)?;
    let mut agents = manager.list_agents()?;
    if let Some(ref agent_id) = agent_id {
        agents.retain(|agent| agent.id == *agent_id);
    }
    let preferences = manager.list_preferences(agent_id.as_deref())?;
    let response = ProfileListResponse {
        agents,
        preferences: preferences
            .into_iter()
            .map(PreferenceRecord::from)
            .collect(),
    };
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn run_add(
    agent_id: String,
    category: String,
    content: String,
    role: Option<String>,
) -> Result<()> {
    let config = config::AppConfig::load_default()?;
    let state_dir = resolve_state_dir(&config)?;
    let manager = ProfileManager::new(&state_dir, config.memory.profile.embedding_dim)?;
    let category = parse_category(&category)?;
    let embedder = resolve_profile_embedder(&config)?;
    let now_ms = now_epoch_ms();

    if manager.get_agent(&agent_id)?.is_none() {
        let role = role.unwrap_or_else(|| "custom".to_string());
        manager.create_agent(&agent_id, &role, now_ms)?;
    }

    let embedding = embedder.embed_with_metadata(&content).await?;
    let preference = manager.add_preference_with_embedding_metadata(
        &agent_id,
        &content,
        &embedding.embedding,
        category,
        now_ms,
        Some(&embedding.provider),
        Some(&embedding.model),
    )?;
    let response = ProfileAddResponse {
        preference: PreferenceRecord::from(preference),
    };
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn run_search(agent_id: String, query: String, top_k: usize) -> Result<()> {
    let config = config::AppConfig::load_default()?;
    let state_dir = resolve_state_dir(&config)?;
    let manager = ProfileManager::new(&state_dir, config.memory.profile.embedding_dim)?;
    let embedder = resolve_profile_embedder(&config)?;
    let embedding = embedder.embed(&query).await?;
    let results = manager.search_preferences(&agent_id, &embedding, top_k.max(1))?;
    let response = ProfileSearchResponse {
        query,
        results: results
            .into_iter()
            .map(|result| ProfileSearchHit {
                score: result.score,
                preference: PreferenceRecord::from(result.preference),
            })
            .collect(),
    };
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn run_export(out: PathBuf) -> Result<()> {
    let config = config::AppConfig::load_default()?;
    let state_dir = resolve_state_dir(&config)?;
    let manager = ProfileManager::new(&state_dir, config.memory.profile.embedding_dim)?;
    let agents = manager.list_agents()?;
    let preferences = manager.list_preferences(None)?;
    let manifest = ProfileSyncManifest {
        schema_version: manager.schema_version(),
        embedding_dim: manager.embedding_dim(),
        agents: agents.clone(),
        preferences: preferences
            .into_iter()
            .map(PreferenceRecord::from)
            .collect(),
    };
    let payload = serde_json::to_string_pretty(&manifest)?;
    std::fs::write(&out, payload).with_context(|| format!("write {}", out.display()))?;
    let response = ProfileExportResponse {
        path: out.display().to_string(),
        agents: agents.len(),
        preferences: manifest.preferences.len(),
    };
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn run_import(path: PathBuf) -> Result<()> {
    let config = config::AppConfig::load_default()?;
    let state_dir = resolve_state_dir(&config)?;
    let manager = ProfileManager::new(&state_dir, config.memory.profile.embedding_dim)?;
    let embedder = resolve_profile_embedder(&config)?;
    let raw = std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let manifest: ProfileSyncManifest = serde_json::from_str(&raw)?;
    if manifest.schema_version != manager.schema_version() {
        anyhow::bail!("profile schema_version mismatch");
    }
    if manifest.embedding_dim != manager.embedding_dim() {
        anyhow::bail!("profile embedding_dim mismatch");
    }
    let mut preferences = Vec::with_capacity(manifest.preferences.len());
    for pref in manifest.preferences {
        let embedding = embedder.embed_with_metadata(&pref.content).await?;
        let embedding_dim = embedding.embedding.len();
        preferences.push(Preference {
            id: pref.id,
            agent_id: pref.agent_id,
            content: pref.content,
            embedding: Some(embedding.embedding),
            embedding_provider: Some(embedding.provider),
            embedding_model: Some(embedding.model),
            embedding_dim: Some(embedding_dim),
            category: pref.category,
            last_updated: pref.last_updated,
        });
    }
    let summary = manager.import_preferences(&manifest.agents, &preferences)?;
    let response = ProfileImportResponse::from(path.as_path(), &summary);
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

fn resolve_state_dir(config: &config::AppConfig) -> Result<PathBuf> {
    config
        .core
        .global_state_dir
        .clone()
        .context("global_state_dir is not configured")
}

fn resolve_profile_embedder(config: &config::AppConfig) -> Result<ProfileEmbedder> {
    let library = load_local_library(config.core.global_state_dir.as_deref()).ok();
    let profile_base_url = env_non_empty("DOCDEX_PROFILE_EMBEDDING_BASE_URL")
        .or_else(|| env_non_empty("DOCDEX_EMBEDDING_BASE_URL"));
    let profile_base_explicit = embeddings::env_present("DOCDEX_PROFILE_EMBEDDING_BASE_URL")
        || embeddings::env_present("DOCDEX_EMBEDDING_BASE_URL");
    let profile_model_env = env_non_empty("DOCDEX_PROFILE_EMBEDDING_MODEL");
    let profile_model_config = config.memory.profile.embedding_model.clone();
    let profile_model_explicit = profile_model_env.is_some()
        || profile_model_config.trim() != DEFAULT_PROFILE_EMBEDDING_MODEL;
    let hints = EmbeddingTargetHints::profile()
        .explicit_provider(
            env_non_empty("DOCDEX_PROFILE_EMBEDDING_PROVIDER")
                .or_else(|| env_non_empty("DOCDEX_EMBEDDING_PROVIDER")),
        )
        .explicit_base_url(profile_base_url, profile_base_explicit)
        .explicit_model(
            profile_model_env.or(Some(profile_model_config)),
            profile_model_explicit,
        )
        .legacy_ollama_base_url(env_non_empty("DOCDEX_OLLAMA_BASE_URL"));
    let target = embeddings::resolve_embedding_target(&config.llm, library.as_ref(), hints)?;
    let timeout_ms = env_u64("DOCDEX_PROFILE_EMBEDDING_TIMEOUT_MS")
        .or_else(|| env_u64("DOCDEX_EMBEDDING_TIMEOUT_MS"))
        .unwrap_or(0);
    let timeout = Duration::from_millis(timeout_ms);
    ProfileEmbedder::with_target(target, timeout, config.memory.profile.embedding_dim)
}

fn parse_category(raw: &str) -> Result<PreferenceCategory> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "style" => Ok(PreferenceCategory::Style),
        "tooling" => Ok(PreferenceCategory::Tooling),
        "constraint" => Ok(PreferenceCategory::Constraint),
        "workflow" => Ok(PreferenceCategory::Workflow),
        _ => anyhow::bail!(
            "invalid category `{raw}` (expected: style, tooling, constraint, workflow)"
        ),
    }
}

fn env_non_empty(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn env_u64(key: &str) -> Option<u64> {
    env_non_empty(key)?.parse::<u64>().ok()
}

fn now_epoch_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}

#[derive(Serialize)]
struct ProfileListResponse {
    agents: Vec<Agent>,
    preferences: Vec<PreferenceRecord>,
}

#[derive(Serialize)]
struct ProfileAddResponse {
    preference: PreferenceRecord,
}

#[derive(Serialize)]
struct ProfileSearchResponse {
    query: String,
    results: Vec<ProfileSearchHit>,
}

#[derive(Serialize)]
struct ProfileSearchHit {
    score: f32,
    preference: PreferenceRecord,
}

#[derive(Serialize)]
struct ProfileExportResponse {
    path: String,
    agents: usize,
    preferences: usize,
}

#[derive(Serialize)]
struct ProfileImportResponse {
    path: String,
    agents: usize,
    inserted: usize,
    updated: usize,
    skipped: usize,
}

impl ProfileImportResponse {
    fn from(path: &Path, summary: &ProfileImportSummary) -> Self {
        Self {
            path: path.display().to_string(),
            agents: summary.agents,
            inserted: summary.inserted,
            updated: summary.updated,
            skipped: summary.skipped,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct ProfileSyncManifest {
    schema_version: u32,
    embedding_dim: usize,
    agents: Vec<Agent>,
    preferences: Vec<PreferenceRecord>,
}

#[derive(Serialize, Deserialize)]
struct PreferenceRecord {
    id: String,
    agent_id: String,
    content: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    embedding_provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    embedding_model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    embedding_dim: Option<usize>,
    category: PreferenceCategory,
    last_updated: i64,
}

impl From<Preference> for PreferenceRecord {
    fn from(pref: Preference) -> Self {
        PreferenceRecord {
            id: pref.id,
            agent_id: pref.agent_id,
            content: pref.content,
            embedding_provider: pref.embedding_provider,
            embedding_model: pref.embedding_model,
            embedding_dim: pref.embedding_dim,
            category: pref.category,
            last_updated: pref.last_updated,
        }
    }
}
