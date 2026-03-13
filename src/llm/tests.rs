use super::delegation::{
    allowlist_allows, compute_delegation_savings, local_selection_policy_requires_fresh_library,
    mode_from_config, parse_local_target_override, reevaluation_should_use_primary_client,
    render_prompt, resolve_delegation_client, resolve_local_cost_per_million,
    resolve_primary_cost_per_million, run_flow_with_client_candidates,
    run_flow_with_client_candidates_with_failure_history, run_flow_with_clients,
    select_local_target, select_local_target_with_config, select_primary_target,
    update_cached_local_selection_from_completion, validate_output, DelegationEnforcementError,
    DelegationFailureHistoryContext, DelegationMode, DelegationPricingContext,
    DelegationReevaluation, LocalTarget, TaskType,
};
use super::delegation_rating::{
    compute_alpha, compute_run_score, estimate_complexity, fallback_quality_score,
    review_from_output, update_ema_rating, RunScoreInput,
};
use super::{load_catalog, recommended_model, supports, LlmModel};
use crate::config::{DelegationConfig, LlmConfig};
use crate::hardware::{GraphicsInfo, HardwareProfile};
use crate::llm::adapter::{LlmClient, LlmCompletion, LlmFuture};
use crate::llm::local_library::{LocalAgentEntry, LocalModelEntry, LocalModelLibrary};
use crate::mcoda::ratings::{apply_agent_rating, AgentRunRating};
use crate::setup::test_support::ENV_LOCK;
use anyhow::anyhow;
use parking_lot::ReentrantMutexGuard;
use rusqlite::Connection;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::sync::Arc;
use std::time::Duration;
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

fn make_model(id: &str, min_ram_gb: f64, requires_gpu: bool) -> LlmModel {
    LlmModel {
        id: id.to_string(),
        display_name: id.to_string(),
        min_ram_gb,
        requires_gpu,
        description: String::new(),
    }
}

fn make_profile(total_gb: f64, gpu: bool) -> HardwareProfile {
    let total_memory_bytes = (total_gb * 1024.0 * 1024.0 * 1024.0) as u64;
    let graphics = if gpu {
        vec![GraphicsInfo {
            name: "test-gpu".to_string(),
            memory_total_bytes: 8 * 1024 * 1024 * 1024,
        }]
    } else {
        Vec::new()
    };
    HardwareProfile {
        total_memory_bytes,
        graphics,
    }
}

fn seed_mcoda_registry_with_adapter(
    home: &Path,
    agent_id: &str,
    slug: &str,
    adapter: &str,
    status: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mcoda_dir = home.join(".mcoda");
    fs::create_dir_all(&mcoda_dir)?;
    let db_path = mcoda_dir.join("mcoda.db");
    let conn = Connection::open(db_path)?;
    conn.execute_batch(
        "CREATE TABLE agents (
            id TEXT PRIMARY KEY,
            slug TEXT NOT NULL,
            adapter TEXT NOT NULL,
            default_model TEXT,
            config_json TEXT,
            created_at TEXT,
            updated_at TEXT
        );
        CREATE TABLE agent_health (
            agent_id TEXT PRIMARY KEY,
            status TEXT NOT NULL
        );",
    )?;
    conn.execute(
        "INSERT INTO agents (id, slug, adapter, default_model, config_json, created_at, updated_at)
         VALUES (?1, ?2, ?3, NULL, NULL, ?4, ?5)",
        rusqlite::params![
            agent_id,
            slug,
            adapter,
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:00Z"
        ],
    )?;
    conn.execute(
        "INSERT INTO agent_health (agent_id, status) VALUES (?1, ?2)",
        rusqlite::params![agent_id, status],
    )?;
    Ok(())
}

fn seed_mcoda_registry(
    home: &Path,
    agent_id: &str,
    slug: &str,
    status: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    seed_mcoda_registry_with_adapter(home, agent_id, slug, "ollama-remote", status)
}

fn seed_mcoda_registry_priced_agent(
    home: &Path,
    agent_id: &str,
    slug: &str,
    adapter: &str,
    default_model: Option<&str>,
    cost_per_million: Option<f64>,
    status: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mcoda_dir = home.join(".mcoda");
    fs::create_dir_all(&mcoda_dir)?;
    let db_path = mcoda_dir.join("mcoda.db");
    let conn = Connection::open(db_path)?;
    conn.execute_batch(
        "CREATE TABLE agents (
            id TEXT PRIMARY KEY,
            slug TEXT NOT NULL,
            adapter TEXT NOT NULL,
            default_model TEXT,
            config_json TEXT,
            created_at TEXT,
            updated_at TEXT,
            cost_per_million REAL
        );
        CREATE TABLE agent_health (
            agent_id TEXT PRIMARY KEY,
            status TEXT NOT NULL
        );",
    )?;
    conn.execute(
        "INSERT INTO agents (id, slug, adapter, default_model, config_json, created_at, updated_at, cost_per_million)
         VALUES (?1, ?2, ?3, ?4, NULL, ?5, ?6, ?7)",
        rusqlite::params![
            agent_id,
            slug,
            adapter,
            default_model,
            "2026-01-01T00:00:00Z",
            "2026-01-01T00:00:00Z",
            cost_per_million
        ],
    )?;
    conn.execute(
        "INSERT INTO agent_health (agent_id, status) VALUES (?1, ?2)",
        rusqlite::params![agent_id, status],
    )?;
    Ok(())
}

fn make_local_agent(
    agent_id: &str,
    agent_slug: &str,
    cost_per_million: Option<f64>,
    max_complexity: Option<i64>,
    rating: Option<f64>,
    reasoning_rating: Option<f64>,
    usage: Option<&str>,
    health_status: Option<&str>,
    capabilities: &[&str],
) -> LocalAgentEntry {
    LocalAgentEntry {
        agent_id: agent_id.to_string(),
        agent_slug: agent_slug.to_string(),
        adapter: "ollama-remote".to_string(),
        default_model: None,
        max_complexity,
        rating,
        cost_per_million,
        usage: usage.map(|value| value.to_string()),
        reasoning_rating,
        health_status: health_status.map(|value| value.to_string()),
        capabilities: capabilities
            .iter()
            .map(|value| (*value).to_string())
            .collect(),
        notes: None,
        classification_method: "registry".to_string(),
        last_seen_at_ms: 0,
        last_classified_at_ms: None,
    }
}

fn zero_cost_policy_config() -> LlmConfig {
    let mut config = LlmConfig::default();
    config.delegation = DelegationConfig::default();
    config.delegation.local_selection_policy = "mcoda_zero_cost_most_capable".to_string();
    config.delegation.use_cached_local_decision = true;
    config
}

struct StaticClient {
    output: String,
    adapter: String,
    model: Option<String>,
}

impl StaticClient {
    fn new(output: &str, adapter: &str) -> Self {
        Self {
            output: output.to_string(),
            adapter: adapter.to_string(),
            model: None,
        }
    }
}

impl LlmClient for StaticClient {
    fn generate<'a>(
        &'a self,
        _prompt: &'a str,
        _max_tokens: u32,
        _timeout: Duration,
    ) -> LlmFuture<'a> {
        let output = self.output.clone();
        let adapter = self.adapter.clone();
        let model = self.model.clone();
        Box::pin(async move {
            Ok(LlmCompletion {
                output,
                adapter,
                model,
                metadata: None,
            })
        })
    }
}

struct ErrorClient;

impl LlmClient for ErrorClient {
    fn generate<'a>(
        &'a self,
        _prompt: &'a str,
        _max_tokens: u32,
        _timeout: Duration,
    ) -> LlmFuture<'a> {
        Box::pin(async move { Err(anyhow!("boom")) })
    }
}

struct SlowClient {
    delay: Duration,
    output: String,
    adapter: String,
}

impl SlowClient {
    fn new(delay: Duration, output: &str, adapter: &str) -> Self {
        Self {
            delay,
            output: output.to_string(),
            adapter: adapter.to_string(),
        }
    }
}

struct CountingClient {
    calls: Arc<AtomicUsize>,
    output: String,
    adapter: String,
}

impl CountingClient {
    fn new(calls: Arc<AtomicUsize>, output: &str, adapter: &str) -> Self {
        Self {
            calls,
            output: output.to_string(),
            adapter: adapter.to_string(),
        }
    }
}

impl LlmClient for CountingClient {
    fn generate<'a>(
        &'a self,
        _prompt: &'a str,
        _max_tokens: u32,
        _timeout: Duration,
    ) -> LlmFuture<'a> {
        let calls = Arc::clone(&self.calls);
        let output = self.output.clone();
        let adapter = self.adapter.clone();
        Box::pin(async move {
            calls.fetch_add(1, AtomicOrdering::SeqCst);
            Ok(LlmCompletion {
                output,
                adapter,
                model: None,
                metadata: None,
            })
        })
    }
}

impl LlmClient for SlowClient {
    fn generate<'a>(
        &'a self,
        _prompt: &'a str,
        _max_tokens: u32,
        _timeout: Duration,
    ) -> LlmFuture<'a> {
        let delay = self.delay;
        let output = self.output.clone();
        let adapter = self.adapter.clone();
        Box::pin(async move {
            tokio::time::sleep(delay).await;
            Ok(LlmCompletion {
                output,
                adapter,
                model: None,
                metadata: None,
            })
        })
    }
}

#[test]
fn load_catalog_is_sorted_by_ram_requirement() -> Result<(), Box<dyn std::error::Error>> {
    let models = load_catalog()?;
    for window in models.windows(2) {
        assert!(
            window[0].min_ram_gb <= window[1].min_ram_gb,
            "catalog not sorted: {} > {}",
            window[0].min_ram_gb,
            window[1].min_ram_gb
        );
    }
    Ok(())
}

#[test]
fn supports_requires_gpu_when_flagged() {
    let model = make_model("gpu-only", 8.0, true);
    let no_gpu = make_profile(16.0, false);
    let with_gpu = make_profile(16.0, true);

    assert!(!supports(&no_gpu, &model));
    assert!(supports(&with_gpu, &model));
}

#[test]
fn recommended_model_prefers_tier_match() {
    let catalog = vec![
        make_model("ultra-light", 0.0, false),
        make_model("phi3.5:3.8b", 16.0, false),
        make_model("llama3.1:70b", 32.0, true),
    ];
    let profile = make_profile(16.0, false);

    let recommended = recommended_model(&profile, &catalog).expect("expected model");
    assert_eq!(recommended.id, "phi3.5:3.8b");
}

#[test]
fn task_type_parse_accepts_variants() {
    assert_eq!(
        TaskType::parse("generate_tests"),
        Some(TaskType::GenerateTests)
    );
    assert_eq!(
        TaskType::parse("GENERATE-TESTS"),
        Some(TaskType::GenerateTests)
    );
    assert_eq!(
        TaskType::parse("write_docstring"),
        Some(TaskType::WriteDocstring)
    );
    assert_eq!(
        TaskType::parse("scaffold-boilerplate"),
        Some(TaskType::ScaffoldBoilerplate)
    );
    assert_eq!(
        TaskType::parse("refactorsimple"),
        Some(TaskType::RefactorSimple)
    );
    assert_eq!(TaskType::parse("format_code"), Some(TaskType::FormatCode));
    assert_eq!(TaskType::parse("unknown"), None);
}

#[test]
fn delegation_mode_parse_accepts_variants() {
    assert_eq!(
        DelegationMode::parse("draft_only"),
        Some(DelegationMode::DraftOnly)
    );
    assert_eq!(
        DelegationMode::parse("draft-then-refine"),
        Some(DelegationMode::DraftThenRefine)
    );
    assert_eq!(DelegationMode::parse("invalid"), None);
}

#[test]
fn delegation_savings_zero_on_empty_tokens() {
    let zero = compute_delegation_savings(0, 0.0, 2000.0);
    assert_eq!(zero.token_savings, 0);
    assert_eq!(zero.cost_savings_micros, 0);
}

#[test]
fn delegation_savings_uses_rate_delta() {
    let savings = compute_delegation_savings(1500, 500.0, 2000.0);
    assert_eq!(savings.token_savings, 1500);
    assert_eq!(savings.cost_savings_micros, 2_250_000);

    let negative = compute_delegation_savings(1500, 3000.0, 2000.0);
    assert_eq!(negative.token_savings, 1500);
    assert_eq!(negative.cost_savings_micros, 0);
}

#[test]
fn delegation_primary_cost_prefers_runtime_caller_agent() {
    let mut config = LlmConfig::default();
    config.delegation.primary_agent_id = "free-local".to_string();
    config.delegation.primary_usd_per_million_tokens = 3.0;
    let library = LocalModelLibrary {
        models: Vec::new(),
        agents: vec![
            make_local_agent(
                "free-local",
                "free-local",
                Some(0.0),
                None,
                None,
                None,
                Some("general_chat"),
                Some("healthy"),
                &["general_chat"],
            ),
            make_local_agent(
                "paid-main",
                "paid-main",
                Some(10.0),
                None,
                None,
                None,
                Some("general_chat"),
                Some("healthy"),
                &["general_chat"],
            ),
        ],
        ..LocalModelLibrary::default()
    };
    let pricing_context = DelegationPricingContext {
        caller_agent_id: Some("paid-main".to_string()),
        caller_model: None,
        primary_cost_per_million: None,
    };

    let cost =
        resolve_primary_cost_per_million(&config, Some(&pricing_context), None, Some(&library));
    assert!((cost - 10.0).abs() < 1e-6);
}

#[test]
fn delegation_primary_cost_resolves_runtime_caller_model_from_registry(
) -> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let _home = EnvGuard::set("HOME", temp.path().to_string_lossy().as_ref());
    let _profile = EnvGuard::set("USERPROFILE", temp.path().to_string_lossy().as_ref());
    let _disable_cli = EnvGuard::set("DOCDEX_DISABLE_MCODA_CLI", "1");
    seed_mcoda_registry_priced_agent(
        temp.path(),
        "agent-1",
        "codex-main",
        "codex-cli",
        Some("gpt-5.2-codex"),
        Some(10.0),
        "healthy",
    )?;

    let config = LlmConfig::default();
    let pricing_context = DelegationPricingContext {
        caller_agent_id: None,
        caller_model: Some("gpt-5.2-codex".to_string()),
        primary_cost_per_million: None,
    };

    let cost = resolve_primary_cost_per_million(&config, Some(&pricing_context), None, None);
    assert!((cost - 10.0).abs() < 1e-6);
    Ok(())
}

#[test]
fn delegation_primary_cost_falls_back_to_configured_rate_when_unresolved() {
    let mut config = LlmConfig::default();
    config.delegation.primary_usd_per_million_tokens = 12.5;

    let cost = resolve_primary_cost_per_million(&config, None, None, None);
    assert!((cost - 12.5).abs() < 1e-6);
}

#[test]
fn delegation_local_cost_falls_back_to_configured_rate_when_unresolved() {
    let mut config = LlmConfig::default();
    config.delegation.local_usd_per_million_tokens = 0.15;

    let cost = resolve_local_cost_per_million(&config, None, None, None);
    assert!((cost - 0.15).abs() < 1e-6);
}

#[test]
fn run_score_matches_reference_formula() {
    let score = compute_run_score(RunScoreInput {
        quality_score: 7.0,
        total_cost: 0.05,
        duration_seconds: 600.0,
        iterations: 2.0,
        budgets: None,
        weights: None,
    });
    assert!((score - 2.5).abs() < 1e-6);
}

#[test]
fn ema_update_rounds_to_two_decimals() {
    let alpha = compute_alpha(50);
    let updated = update_ema_rating(5.0, 7.0, alpha);
    assert!((updated - 5.08).abs() < 1e-6);
}

#[test]
fn review_parsing_accepts_fenced_json() {
    let raw = "```json\n{\"quality_score\": 8, \"reasoning\": \"ok\"}\n```";
    let outcome = review_from_output(raw, 7.0);
    assert!((outcome.quality_score - 8.0).abs() < 1e-6);
    assert_eq!(outcome.reasoning.as_deref(), Some("ok"));
}

#[test]
fn fallback_quality_score_penalizes_warnings() {
    let warnings = vec!["one".to_string(), "two".to_string()];
    let score = fallback_quality_score(&warnings);
    assert!((score - 6.0).abs() < 1e-6);
}

#[test]
fn estimate_complexity_scales_with_context() {
    let low = estimate_complexity(TaskType::FormatCode, 100);
    let high = estimate_complexity(TaskType::FormatCode, 9000);
    assert!(low < high);
}

#[test]
fn mcoda_rating_updates_agent_and_inserts_run() -> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let db_path = temp.path().join("mcoda.db");
    let conn = Connection::open(&db_path)?;
    conn.execute_batch(
        "CREATE TABLE agents (
            id TEXT PRIMARY KEY,
            slug TEXT,
            adapter TEXT,
            rating REAL,
            reasoning_rating REAL,
            max_complexity INTEGER,
            rating_samples INTEGER,
            rating_last_score REAL,
            rating_updated_at TEXT,
            complexity_samples INTEGER,
            complexity_updated_at TEXT
        );
        CREATE TABLE agent_run_ratings (
            id TEXT PRIMARY KEY,
            agent_id TEXT,
            job_id TEXT,
            command_run_id TEXT,
            task_id TEXT,
            task_key TEXT,
            command_name TEXT,
            discipline TEXT,
            complexity INTEGER,
            quality_score REAL,
            tokens_total INTEGER,
            duration_seconds REAL,
            iterations INTEGER,
            total_cost REAL,
            run_score REAL,
            rating_version TEXT,
            raw_review_json TEXT,
            created_at TEXT
        );",
    )?;
    conn.execute(
        "INSERT INTO agents (id, slug, adapter, rating, reasoning_rating, max_complexity, rating_samples, rating_last_score, rating_updated_at, complexity_samples, complexity_updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        rusqlite::params![
            "agent-1",
            "agent-1",
            "local",
            6.0,
            6.0,
            5,
            0,
            6.0,
            "2024-01-01T00:00:00Z",
            0,
            "2024-01-01T00:00:00Z"
        ],
    )?;
    drop(conn);

    let run = AgentRunRating {
        agent_id: "agent-1".to_string(),
        command_name: "delegation".to_string(),
        discipline: None,
        complexity: 5,
        quality_score: 8.0,
        tokens_total: 1200,
        duration_seconds: 12.0,
        iterations: 1,
        total_cost: 0.01,
        run_score: 8.0,
        rating_version: "v1".to_string(),
        raw_review_json: Some("{\"quality_score\":8}".to_string()),
        created_at: "2024-01-02T00:00:00Z".to_string(),
    };
    let result = apply_agent_rating(&db_path, "agent-1", &run, 50, "2024-01-02T00:00:00Z")?;
    assert!(result.is_some());

    let conn = Connection::open(&db_path)?;
    let (rating_samples, max_complexity, rating_last_score): (i64, i64, f64) = conn.query_row(
        "SELECT rating_samples, max_complexity, rating_last_score FROM agents WHERE id = ?1",
        rusqlite::params!["agent-1"],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    assert_eq!(rating_samples, 1);
    assert_eq!(max_complexity, 6);
    assert!((rating_last_score - 8.0).abs() < 1e-6);
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM agent_run_ratings", [], |row| {
        row.get(0)
    })?;
    assert_eq!(count, 1);
    Ok(())
}

#[test]
fn render_prompt_replaces_placeholders_and_truncates() {
    let rendered = render_prompt(TaskType::GenerateTests, "Add tests", "abcdef", 3);
    assert!(rendered.prompt.contains("Add tests"));
    assert!(rendered.truncated);
    assert!(!rendered.prompt.contains("abcdef"));
}

#[test]
fn resolve_delegation_client_uses_ollama_fallback() {
    let mut config = LlmConfig::default();
    config.delegation = DelegationConfig::default();
    config.delegation.local_agent_id = "".to_string();
    let client = resolve_delegation_client(&config, None, None);
    assert!(client.is_ok());
}

#[test]
fn resolve_delegation_client_accepts_model_override_prefix() {
    let mut config = LlmConfig::default();
    config.delegation = DelegationConfig::default();
    let client = resolve_delegation_client(&config, Some("model:phi3.5:3.8b"), None);
    assert!(client.is_ok());
}

#[test]
fn resolve_delegation_client_errors_for_non_ollama_fallback() {
    let mut config = LlmConfig::default();
    config.provider = "openai".to_string();
    config.delegation = DelegationConfig::default();
    let client = resolve_delegation_client(&config, None, None);
    assert!(client.is_err());
}

#[test]
fn resolve_delegation_client_errors_for_missing_mcoda_agent(
) -> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let _home = EnvGuard::set("HOME", temp.path().to_string_lossy().as_ref());
    let _profile = EnvGuard::set("USERPROFILE", temp.path().to_string_lossy().as_ref());

    let mut config = LlmConfig::default();
    config.delegation = DelegationConfig::default();
    let result = resolve_delegation_client(&config, Some("missing-agent"), None);
    assert!(result.is_err());
    Ok(())
}

#[test]
fn resolve_delegation_client_missing_mcoda_agent_includes_available_slugs(
) -> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let _home = EnvGuard::set("HOME", temp.path().to_string_lossy().as_ref());
    let _profile = EnvGuard::set("USERPROFILE", temp.path().to_string_lossy().as_ref());
    let _disable_cli = EnvGuard::set("DOCDEX_DISABLE_MCODA_CLI", "1");
    seed_mcoda_registry(temp.path(), "agent-1", "healthy-agent", "healthy")?;

    let mut config = LlmConfig::default();
    config.delegation = DelegationConfig::default();
    let err = resolve_delegation_client(&config, Some("missing-agent"), None)
        .err()
        .expect("missing agent error");
    let message = err.to_string();
    assert!(message.contains("mcoda agent not found: missing-agent"));
    assert!(message.contains("healthy-agent"));
    Ok(())
}

#[test]
fn resolve_delegation_client_rejects_unhealthy_mcoda_agent(
) -> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let _home = EnvGuard::set("HOME", temp.path().to_string_lossy().as_ref());
    let _profile = EnvGuard::set("USERPROFILE", temp.path().to_string_lossy().as_ref());
    let _disable_cli = EnvGuard::set("DOCDEX_DISABLE_MCODA_CLI", "1");
    seed_mcoda_registry(temp.path(), "agent-2", "unhealthy-agent", "unhealthy")?;

    let mut config = LlmConfig::default();
    config.delegation = DelegationConfig::default();
    let err = resolve_delegation_client(&config, Some("unhealthy-agent"), None)
        .err()
        .expect("unavailable agent error");
    let message = err.to_string();
    assert!(message.contains("mcoda agent unavailable"));
    assert!(message.contains("health status: unhealthy"));
    Ok(())
}

#[test]
fn resolve_delegation_client_supports_claude_cli_agent() -> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let _home = EnvGuard::set("HOME", temp.path().to_string_lossy().as_ref());
    let _profile = EnvGuard::set("USERPROFILE", temp.path().to_string_lossy().as_ref());
    let _disable_cli = EnvGuard::set("DOCDEX_DISABLE_MCODA_CLI", "1");
    seed_mcoda_registry_with_adapter(
        temp.path(),
        "agent-3",
        "claude-agent",
        "claude-cli",
        "healthy",
    )?;

    let mut config = LlmConfig::default();
    config.delegation = DelegationConfig::default();
    let result = resolve_delegation_client(&config, Some("claude-agent"), None);
    assert!(result.is_ok());
    Ok(())
}

#[test]
fn parse_local_target_override_matches_model_name() {
    let mut library = LocalModelLibrary::default();
    library.models.push(LocalModelEntry {
        name: "phi3.5:3.8b".to_string(),
        source: "ollama".to_string(),
        capabilities: vec!["code_writer".to_string()],
        notes: None,
        classification_method: "heuristic".to_string(),
        last_seen_at_ms: 0,
        last_classified_at_ms: None,
    });
    let target = parse_local_target_override("phi3.5:3.8b", Some(&library)).expect("target");
    match target {
        LocalTarget::OllamaModel(name) => assert_eq!(name, "phi3.5:3.8b"),
        _ => panic!("expected ollama model target"),
    }
}

#[test]
fn parse_local_target_override_matches_agent_slug() {
    let mut library = LocalModelLibrary::default();
    library.agents.push(LocalAgentEntry {
        agent_id: "agent-1".to_string(),
        agent_slug: "devstral-local".to_string(),
        adapter: "ollama-remote".to_string(),
        default_model: None,
        max_complexity: None,
        rating: None,
        cost_per_million: None,
        usage: None,
        reasoning_rating: None,
        health_status: None,
        capabilities: vec!["code_writer".to_string()],
        notes: None,
        classification_method: "registry".to_string(),
        last_seen_at_ms: 0,
        last_classified_at_ms: None,
    });
    let target = parse_local_target_override("devstral-local", Some(&library)).expect("target");
    match target {
        LocalTarget::McodaAgent(id) => assert_eq!(id, "agent-1"),
        _ => panic!("expected mcoda agent target"),
    }
}

#[test]
fn delegation_selects_local_healthy_mcoda_agent() {
    let mut library = LocalModelLibrary::default();
    library.agents.push(LocalAgentEntry {
        agent_id: "agent-unhealthy".to_string(),
        agent_slug: "agent-unhealthy".to_string(),
        adapter: "ollama-remote".to_string(),
        default_model: None,
        max_complexity: None,
        rating: None,
        cost_per_million: None,
        usage: None,
        reasoning_rating: None,
        health_status: Some("unhealthy".to_string()),
        capabilities: vec!["code_writer".to_string()],
        notes: None,
        classification_method: "registry".to_string(),
        last_seen_at_ms: 0,
        last_classified_at_ms: None,
    });
    library.agents.push(LocalAgentEntry {
        agent_id: "agent-healthy".to_string(),
        agent_slug: "agent-healthy".to_string(),
        adapter: "ollama-remote".to_string(),
        default_model: None,
        max_complexity: None,
        rating: None,
        cost_per_million: None,
        usage: None,
        reasoning_rating: None,
        health_status: Some("healthy".to_string()),
        capabilities: vec!["code_writer".to_string()],
        notes: None,
        classification_method: "registry".to_string(),
        last_seen_at_ms: 0,
        last_classified_at_ms: None,
    });

    let selected = select_local_target(TaskType::GenerateTests, &library).expect("selection");
    match selected {
        LocalTarget::McodaAgent(id) => assert_eq!(id, "agent-healthy"),
        _ => panic!("expected healthy mcoda target"),
    }
}

#[test]
fn delegation_skips_paid_mcoda_agent_for_automatic_local_selection() {
    let mut library = LocalModelLibrary::default();
    library.agents.push(make_local_agent(
        "agent-paid",
        "agent-paid",
        Some(2.5),
        Some(8),
        Some(8.8),
        Some(8.9),
        Some("code_writer"),
        Some("healthy"),
        &["code_writer", "code_reviewer"],
    ));
    library.agents.push(make_local_agent(
        "agent-free",
        "agent-free",
        Some(0.0),
        Some(6),
        Some(7.2),
        Some(7.4),
        Some("code_writer"),
        Some("healthy"),
        &["code_writer"],
    ));

    let selected = select_local_target(TaskType::GenerateTests, &library).expect("selection");
    match selected {
        LocalTarget::McodaAgent(id) => assert_eq!(id, "agent-free"),
        _ => panic!("expected free mcoda target"),
    }
}

#[test]
fn delegation_skips_expensive_adapter_for_automatic_local_selection() {
    let mut library = LocalModelLibrary::default();
    library.agents.push(LocalAgentEntry {
        agent_id: "agent-claude".to_string(),
        agent_slug: "claude-sonnet".to_string(),
        adapter: "claude-cli".to_string(),
        default_model: Some("claude-3.7-sonnet".to_string()),
        max_complexity: Some(9),
        rating: Some(9.0),
        cost_per_million: Some(0.0),
        usage: Some("code_writer".to_string()),
        reasoning_rating: Some(9.1),
        health_status: Some("healthy".to_string()),
        capabilities: vec!["code_writer".to_string(), "code_reviewer".to_string()],
        notes: None,
        classification_method: "registry".to_string(),
        last_seen_at_ms: 0,
        last_classified_at_ms: None,
    });
    library.agents.push(make_local_agent(
        "agent-local",
        "agent-local",
        Some(0.0),
        Some(6),
        Some(7.0),
        Some(7.2),
        Some("code_writer"),
        Some("healthy"),
        &["code_writer"],
    ));

    let selected = select_local_target(TaskType::GenerateTests, &library).expect("selection");
    match selected {
        LocalTarget::McodaAgent(id) => assert_eq!(id, "agent-local"),
        _ => panic!("expected eligible local mcoda target"),
    }
}

#[test]
fn delegation_zero_cost_policy_selects_most_capable_mcoda_agent_and_caches_it(
) -> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let config = zero_cost_policy_config();
    let mut library = LocalModelLibrary::default();
    library.agents.push(make_local_agent(
        "agent-basic",
        "agent-basic",
        Some(0.0),
        Some(4),
        Some(7.0),
        Some(6.0),
        Some("code_writer"),
        Some("healthy"),
        &["code_writer"],
    ));
    library.agents.push(make_local_agent(
        "agent-best",
        "agent-best",
        Some(0.0),
        Some(8),
        Some(9.3),
        Some(9.7),
        Some("code_reviewer"),
        Some("healthy"),
        &["code_writer", "code_reviewer", "general_chat"],
    ));
    library.agents.push(make_local_agent(
        "agent-paid",
        "agent-paid",
        Some(2.5),
        Some(10),
        Some(10.0),
        Some(10.0),
        Some("code_reviewer"),
        Some("healthy"),
        &["code_writer", "code_reviewer", "general_chat"],
    ));

    let selected = select_local_target_with_config(
        Some(temp.path()),
        &config,
        TaskType::GenerateTests,
        &mut library,
    )
    .expect("selection");

    match selected {
        LocalTarget::McodaAgent(id) => assert_eq!(id, "agent-best"),
        _ => panic!("expected mcoda target"),
    }
    let cached = library
        .cached_local_agent_selection
        .as_ref()
        .expect("cached selection");
    assert_eq!(cached.agent_id, "agent-best");
    assert_eq!(cached.policy, "mcoda_zero_cost_most_capable");
    Ok(())
}

#[test]
fn delegation_zero_cost_policy_reuses_cached_agent_when_still_available(
) -> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let config = zero_cost_policy_config();
    let mut library = LocalModelLibrary::default();
    library.agents.push(make_local_agent(
        "agent-cached",
        "agent-cached",
        Some(0.0),
        Some(5),
        Some(7.0),
        Some(7.0),
        Some("code_writer"),
        Some("healthy"),
        &["code_writer"],
    ));

    let first = select_local_target_with_config(
        Some(temp.path()),
        &config,
        TaskType::GenerateTests,
        &mut library,
    )
    .expect("first selection");
    match first {
        LocalTarget::McodaAgent(id) => assert_eq!(id, "agent-cached"),
        _ => panic!("expected mcoda target"),
    }

    library.agents.push(make_local_agent(
        "agent-better",
        "agent-better",
        Some(0.0),
        Some(9),
        Some(9.8),
        Some(9.9),
        Some("code_reviewer"),
        Some("healthy"),
        &["code_writer", "code_reviewer", "general_chat"],
    ));

    let second = select_local_target_with_config(
        Some(temp.path()),
        &config,
        TaskType::GenerateTests,
        &mut library,
    )
    .expect("second selection");
    match second {
        LocalTarget::McodaAgent(id) => assert_eq!(id, "agent-cached"),
        _ => panic!("expected cached mcoda target"),
    }
    Ok(())
}

#[test]
fn delegation_zero_cost_policy_reselects_when_cached_agent_becomes_invalid(
) -> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let config = zero_cost_policy_config();
    let mut library = LocalModelLibrary::default();
    library.agents.push(make_local_agent(
        "agent-old",
        "agent-old",
        Some(0.0),
        Some(5),
        Some(7.0),
        Some(7.0),
        Some("code_writer"),
        Some("healthy"),
        &["code_writer"],
    ));

    let _ = select_local_target_with_config(
        Some(temp.path()),
        &config,
        TaskType::GenerateTests,
        &mut library,
    )
    .expect("initial selection");

    library.agents[0].health_status = Some("unhealthy".to_string());
    library.agents.push(make_local_agent(
        "agent-new",
        "agent-new",
        Some(0.0),
        Some(8),
        Some(8.8),
        Some(9.1),
        Some("code_reviewer"),
        Some("healthy"),
        &["code_writer", "code_reviewer"],
    ));

    let selected = select_local_target_with_config(
        Some(temp.path()),
        &config,
        TaskType::GenerateTests,
        &mut library,
    )
    .expect("reselection");

    match selected {
        LocalTarget::McodaAgent(id) => assert_eq!(id, "agent-new"),
        _ => panic!("expected replacement mcoda target"),
    }
    let cached = library
        .cached_local_agent_selection
        .as_ref()
        .expect("cached selection");
    assert_eq!(cached.agent_id, "agent-new");
    Ok(())
}

#[test]
fn delegation_zero_cost_policy_falls_back_when_no_zero_cost_mcoda_agent(
) -> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let config = zero_cost_policy_config();
    let mut library = LocalModelLibrary::default();
    library.models.push(LocalModelEntry {
        name: "code-model".to_string(),
        source: "ollama".to_string(),
        capabilities: vec!["code_writer".to_string()],
        notes: None,
        classification_method: "heuristic".to_string(),
        last_seen_at_ms: 0,
        last_classified_at_ms: None,
    });

    let selected = select_local_target_with_config(
        Some(temp.path()),
        &config,
        TaskType::GenerateTests,
        &mut library,
    )
    .expect("fallback selection");

    match selected {
        LocalTarget::OllamaModel(name) => assert_eq!(name, "code-model"),
        _ => panic!("expected ollama fallback"),
    }
    assert!(library.cached_local_agent_selection.is_none());
    Ok(())
}

#[test]
fn zero_cost_policy_uses_cache_without_forcing_fresh_library() {
    let config = zero_cost_policy_config();
    assert!(!local_selection_policy_requires_fresh_library(&config));

    let mut uncached = zero_cost_policy_config();
    uncached.delegation.use_cached_local_decision = false;
    assert!(local_selection_policy_requires_fresh_library(&uncached));
}

#[test]
fn delegation_updates_cached_zero_cost_agent_after_successful_alternate_completion(
) -> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let config = zero_cost_policy_config();
    let mut library = LocalModelLibrary::default();
    library.agents.push(LocalAgentEntry {
        agent_id: "agent-qwen".to_string(),
        agent_slug: "qwen-3.5-27b".to_string(),
        adapter: "ollama-remote".to_string(),
        default_model: Some("qwen3.5:27b".to_string()),
        max_complexity: Some(7),
        rating: Some(6.8),
        cost_per_million: Some(0.0),
        usage: Some("code_writer".to_string()),
        reasoning_rating: Some(7.2),
        health_status: Some("healthy".to_string()),
        capabilities: vec!["code_writer".to_string()],
        notes: None,
        classification_method: "mcoda".to_string(),
        last_seen_at_ms: 0,
        last_classified_at_ms: None,
    });
    library.agents.push(LocalAgentEntry {
        agent_id: "agent-local-alt".to_string(),
        agent_slug: "local-alt".to_string(),
        adapter: "ollama-remote".to_string(),
        default_model: Some("qwen3.5:32b".to_string()),
        max_complexity: Some(6),
        rating: Some(7.1),
        cost_per_million: Some(0.0),
        usage: Some("code_writer".to_string()),
        reasoning_rating: Some(7.3),
        health_status: Some("healthy".to_string()),
        capabilities: vec!["code_writer".to_string()],
        notes: None,
        classification_method: "mcoda".to_string(),
        last_seen_at_ms: 0,
        last_classified_at_ms: None,
    });
    library.cached_local_agent_selection =
        Some(crate::llm::local_library::CachedLocalAgentSelection {
            policy: "mcoda_zero_cost_most_capable".to_string(),
            agent_id: "agent-qwen".to_string(),
            agent_slug: "qwen-3.5-27b".to_string(),
            selected_at_ms: 0,
        });

    let completion = LlmCompletion {
        output: "/// doc".to_string(),
        adapter: "ollama-remote".to_string(),
        model: Some("qwen3.5:32b".to_string()),
        metadata: None,
    };

    let updated = update_cached_local_selection_from_completion(
        Some(temp.path()),
        &config,
        &mut library,
        &completion,
    );

    assert!(updated);
    let cached = library
        .cached_local_agent_selection
        .as_ref()
        .expect("cached selection");
    assert_eq!(cached.agent_id, "agent-local-alt");
    assert_eq!(cached.agent_slug, "local-alt");
    Ok(())
}

#[test]
fn delegation_does_not_cache_expensive_mcoda_completion() -> Result<(), Box<dyn std::error::Error>>
{
    let temp = TempDir::new()?;
    let config = zero_cost_policy_config();
    let mut library = LocalModelLibrary::default();
    library.agents.push(LocalAgentEntry {
        agent_id: "agent-qwen".to_string(),
        agent_slug: "qwen-3.5-27b".to_string(),
        adapter: "ollama-remote".to_string(),
        default_model: Some("qwen3.5:27b".to_string()),
        max_complexity: Some(7),
        rating: Some(6.8),
        cost_per_million: Some(0.0),
        usage: Some("code_writer".to_string()),
        reasoning_rating: Some(7.2),
        health_status: Some("healthy".to_string()),
        capabilities: vec!["code_writer".to_string()],
        notes: None,
        classification_method: "mcoda".to_string(),
        last_seen_at_ms: 0,
        last_classified_at_ms: None,
    });
    library.agents.push(LocalAgentEntry {
        agent_id: "agent-claude".to_string(),
        agent_slug: "claude-sonnet".to_string(),
        adapter: "claude-cli".to_string(),
        default_model: Some("claude-3.7-sonnet".to_string()),
        max_complexity: Some(9),
        rating: Some(9.1),
        cost_per_million: Some(0.0),
        usage: Some("code_writer".to_string()),
        reasoning_rating: Some(9.2),
        health_status: Some("healthy".to_string()),
        capabilities: vec!["code_writer".to_string(), "code_reviewer".to_string()],
        notes: None,
        classification_method: "mcoda".to_string(),
        last_seen_at_ms: 0,
        last_classified_at_ms: None,
    });
    library.cached_local_agent_selection =
        Some(crate::llm::local_library::CachedLocalAgentSelection {
            policy: "mcoda_zero_cost_most_capable".to_string(),
            agent_id: "agent-qwen".to_string(),
            agent_slug: "qwen-3.5-27b".to_string(),
            selected_at_ms: 0,
        });

    let completion = LlmCompletion {
        output: "/// doc".to_string(),
        adapter: "claude-cli".to_string(),
        model: Some("claude-3.7-sonnet".to_string()),
        metadata: None,
    };

    let updated = update_cached_local_selection_from_completion(
        Some(temp.path()),
        &config,
        &mut library,
        &completion,
    );

    assert!(!updated);
    let cached = library
        .cached_local_agent_selection
        .as_ref()
        .expect("cached selection");
    assert_eq!(cached.agent_id, "agent-qwen");
    assert_eq!(cached.agent_slug, "qwen-3.5-27b");
    Ok(())
}

#[test]
fn delegation_selects_code_writer() {
    let mut library = LocalModelLibrary::default();
    library.models.push(LocalModelEntry {
        name: "embed-only".to_string(),
        source: "ollama".to_string(),
        capabilities: vec!["embedding".to_string()],
        notes: None,
        classification_method: "heuristic".to_string(),
        last_seen_at_ms: 0,
        last_classified_at_ms: None,
    });
    library.models.push(LocalModelEntry {
        name: "code-model".to_string(),
        source: "ollama".to_string(),
        capabilities: vec!["code_writer".to_string()],
        notes: None,
        classification_method: "heuristic".to_string(),
        last_seen_at_ms: 0,
        last_classified_at_ms: None,
    });
    let selected = select_local_target(TaskType::GenerateTests, &library).expect("selection");
    match selected {
        LocalTarget::OllamaModel(name) => assert_eq!(name, "code-model"),
        _ => panic!("unexpected target selection"),
    }
}

#[test]
fn delegation_selects_falls_back_without_candidates() {
    let mut library = LocalModelLibrary::default();
    library.models.push(LocalModelEntry {
        name: "embed-only".to_string(),
        source: "ollama".to_string(),
        capabilities: vec!["embedding".to_string()],
        notes: None,
        classification_method: "heuristic".to_string(),
        last_seen_at_ms: 0,
        last_classified_at_ms: None,
    });
    let selected = select_local_target(TaskType::GenerateTests, &library);
    assert!(selected.is_none());
}

#[test]
fn delegation_selects_primary_prefers_mcoda_on_tie() {
    let mut library = LocalModelLibrary::default();
    library.models.push(LocalModelEntry {
        name: "ollama-code".to_string(),
        source: "ollama".to_string(),
        capabilities: vec!["code_writer".to_string()],
        notes: None,
        classification_method: "heuristic".to_string(),
        last_seen_at_ms: 0,
        last_classified_at_ms: None,
    });
    library.agents.push(LocalAgentEntry {
        agent_id: "agent-1".to_string(),
        agent_slug: "agent-one".to_string(),
        adapter: "ollama".to_string(),
        default_model: None,
        max_complexity: None,
        rating: None,
        cost_per_million: None,
        usage: None,
        reasoning_rating: None,
        health_status: None,
        capabilities: vec!["code_writer".to_string()],
        notes: None,
        classification_method: "registry".to_string(),
        last_seen_at_ms: 0,
        last_classified_at_ms: None,
    });
    let selected =
        select_primary_target(TaskType::GenerateTests, &library, None).expect("selection");
    match selected {
        LocalTarget::McodaAgent(id) => assert_eq!(id, "agent-1"),
        _ => panic!("unexpected primary selection"),
    }
}

#[test]
fn delegation_selects_primary_avoids_local_target_when_possible() {
    let mut library = LocalModelLibrary::default();
    library.models.push(LocalModelEntry {
        name: "local-model".to_string(),
        source: "ollama".to_string(),
        capabilities: vec!["code_writer".to_string()],
        notes: None,
        classification_method: "heuristic".to_string(),
        last_seen_at_ms: 0,
        last_classified_at_ms: None,
    });
    library.agents.push(LocalAgentEntry {
        agent_id: "agent-1".to_string(),
        agent_slug: "agent-one".to_string(),
        adapter: "ollama".to_string(),
        default_model: None,
        max_complexity: None,
        rating: None,
        cost_per_million: None,
        usage: None,
        reasoning_rating: None,
        health_status: None,
        capabilities: vec!["code_writer".to_string()],
        notes: None,
        classification_method: "registry".to_string(),
        last_seen_at_ms: 0,
        last_classified_at_ms: None,
    });
    let local_target = LocalTarget::OllamaModel("local-model".to_string());
    let selected = select_primary_target(TaskType::GenerateTests, &library, Some(&local_target))
        .expect("selection");
    match selected {
        LocalTarget::McodaAgent(id) => assert_eq!(id, "agent-1"),
        _ => panic!("unexpected primary selection"),
    }
}

#[test]
fn delegation_selects_primary_skips_embedding_only_models() {
    let mut library = LocalModelLibrary::default();
    library.models.push(LocalModelEntry {
        name: "embed-only".to_string(),
        source: "ollama".to_string(),
        capabilities: vec!["embedding".to_string()],
        notes: None,
        classification_method: "heuristic".to_string(),
        last_seen_at_ms: 0,
        last_classified_at_ms: None,
    });
    let selected = select_primary_target(TaskType::GenerateTests, &library, None);
    assert!(selected.is_none());
}

#[test]
fn validate_output_rejects_empty_or_wrapped_fences() {
    assert!(validate_output(TaskType::FormatCode, "").is_err());
    assert!(validate_output(TaskType::FormatCode, "```js\ncode\n```").is_err());
    assert!(validate_output(TaskType::FormatCode, "let a = 1;\n```\ncode\n```").is_ok());
    assert!(validate_output(TaskType::FormatCode, "let a = 1;").is_ok());
}

#[test]
fn allowlist_allows_when_empty() {
    let allowlist: Vec<String> = Vec::new();
    assert!(allowlist_allows(TaskType::FormatCode, &allowlist));
}

#[test]
fn allowlist_blocks_when_missing() {
    let allowlist = vec!["generate_tests".to_string(), "write_docstring".to_string()];
    assert!(!allowlist_allows(TaskType::FormatCode, &allowlist));
    assert!(allowlist_allows(TaskType::GenerateTests, &allowlist));
}

#[test]
fn mode_from_config_falls_back_on_invalid() {
    assert_eq!(mode_from_config("draft_only"), DelegationMode::DraftOnly);
    assert_eq!(
        mode_from_config("draft_then_refine"),
        DelegationMode::DraftThenRefine
    );
    assert_eq!(mode_from_config("invalid"), DelegationMode::DraftOnly);
}

#[tokio::test]
async fn delegation_flow_refines_with_primary() {
    let local = Arc::new(StaticClient::new("draft", "local"));
    let primary = Arc::new(StaticClient::new("refined", "primary"));
    let result = run_flow_with_clients(
        TaskType::FormatCode,
        "Format this code",
        "let  a=1;",
        200,
        DelegationMode::DraftThenRefine,
        16,
        Duration::from_secs(1),
        local,
        Some(primary),
        false,
        None,
    )
    .await
    .expect("delegation flow");
    assert_eq!(result.completion.output, "refined");
    assert!(!result.draft);
    assert!(!result.fallback_used);
}

#[tokio::test]
async fn delegation_flow_falls_back_to_primary_on_local_error() {
    let local = Arc::new(ErrorClient);
    let primary = Arc::new(StaticClient::new("primary", "primary"));
    let result = run_flow_with_clients(
        TaskType::FormatCode,
        "Format this code",
        "let  a=1;",
        200,
        DelegationMode::DraftOnly,
        16,
        Duration::from_secs(1),
        local,
        Some(primary),
        false,
        None,
    )
    .await
    .expect("delegation flow");
    assert_eq!(result.completion.output, "primary");
    assert!(!result.draft);
    assert!(result.fallback_used);
}

#[tokio::test]
async fn delegation_flow_returns_draft_when_refine_fails() {
    let local = Arc::new(StaticClient::new("draft", "local"));
    let primary = Arc::new(ErrorClient);
    let result = run_flow_with_clients(
        TaskType::FormatCode,
        "Format this code",
        "let  a=1;",
        200,
        DelegationMode::DraftThenRefine,
        16,
        Duration::from_secs(1),
        local,
        Some(primary),
        false,
        None,
    )
    .await
    .expect("delegation flow");
    assert_eq!(result.completion.output, "draft");
    assert!(result.draft);
    assert!(result.fallback_used);
}

#[tokio::test]
async fn delegation_flow_writes_completion_failure_history() {
    let state_dir = TempDir::new().expect("temp state dir");
    let result = run_flow_with_client_candidates_with_failure_history(
        TaskType::FormatCode,
        "Format this code",
        "let  a=1;",
        200,
        DelegationMode::DraftOnly,
        16,
        Duration::from_secs(1),
        vec![Arc::new(ErrorClient)],
        vec!["test-local".to_string()],
        vec![Arc::new(StaticClient::new("primary", "primary"))],
        false,
        None,
        None,
        Some(DelegationFailureHistoryContext {
            global_state_dir: Some(state_dir.path().to_path_buf()),
            repo_id: Some("repo-1".to_string()),
            repo_root: Some("/tmp/repo".to_string()),
            source: Some("test".to_string()),
        }),
    )
    .await
    .expect("delegation flow");

    assert_eq!(result.completion.output, "primary");
    let history_path = state_dir
        .path()
        .join("logs")
        .join("errors")
        .join("delegation_local_failures.jsonl");
    let raw = fs::read_to_string(history_path).expect("read failure history");
    let record: serde_json::Value = serde_json::from_str(raw.lines().next().expect("history line"))
        .expect("parse history line");
    assert_eq!(
        record.get("kind").and_then(|value| value.as_str()),
        Some("local_completion_failed")
    );
    assert_eq!(
        record
            .get("recovery_action")
            .and_then(|value| value.as_str()),
        Some("fallback_to_primary")
    );
    assert_eq!(
        record.get("local_target").and_then(|value| value.as_str()),
        Some("test-local")
    );
    assert_eq!(
        record.get("repo_id").and_then(|value| value.as_str()),
        Some("repo-1")
    );
}

#[tokio::test]
async fn delegation_flow_writes_validation_failure_history() {
    let state_dir = TempDir::new().expect("temp state dir");
    let err = run_flow_with_client_candidates_with_failure_history(
        TaskType::FormatCode,
        "Format this code",
        "let  a=1;",
        200,
        DelegationMode::DraftOnly,
        16,
        Duration::from_secs(1),
        vec![Arc::new(StaticClient::new("", "local"))],
        vec!["test-local".to_string()],
        Vec::new(),
        false,
        None,
        None,
        Some(DelegationFailureHistoryContext {
            global_state_dir: Some(state_dir.path().to_path_buf()),
            repo_id: Some("repo-2".to_string()),
            repo_root: Some("/tmp/repo".to_string()),
            source: Some("test".to_string()),
        }),
    )
    .await
    .err()
    .expect("delegation error");

    assert!(err.to_string().contains("failure history"));
    let history_path = state_dir
        .path()
        .join("logs")
        .join("errors")
        .join("delegation_local_failures.jsonl");
    let raw = fs::read_to_string(history_path).expect("read failure history");
    let record: serde_json::Value = serde_json::from_str(raw.lines().next().expect("history line"))
        .expect("parse history line");
    assert_eq!(
        record.get("kind").and_then(|value| value.as_str()),
        Some("local_validation_failed")
    );
    assert_eq!(
        record
            .get("recovery_action")
            .and_then(|value| value.as_str()),
        Some("return_error")
    );
    assert_eq!(
        record.get("source").and_then(|value| value.as_str()),
        Some("test")
    );
}

#[tokio::test]
async fn delegation_flow_tries_alternate_local_candidates_before_primary() {
    let local_clients: Vec<Arc<dyn LlmClient>> = vec![
        Arc::new(ErrorClient),
        Arc::new(StaticClient::new("alternate", "local")),
    ];
    let primary_clients: Vec<Arc<dyn LlmClient>> =
        vec![Arc::new(StaticClient::new("primary", "primary"))];
    let result = run_flow_with_client_candidates(
        TaskType::FormatCode,
        "Format this code",
        "let  a=1;",
        200,
        DelegationMode::DraftOnly,
        16,
        Duration::from_secs(1),
        local_clients,
        primary_clients,
        false,
        None,
        None,
    )
    .await
    .expect("delegation flow");
    assert_eq!(result.completion.output, "alternate");
    assert!(result.draft);
    assert!(!result.fallback_used);
    assert!(result
        .warnings
        .iter()
        .any(|warning| warning.contains("alternate local target")));
}

#[tokio::test]
async fn delegation_flow_tries_alternate_primary_candidates_after_local_failure() {
    let local_clients: Vec<Arc<dyn LlmClient>> = vec![Arc::new(ErrorClient)];
    let primary_clients: Vec<Arc<dyn LlmClient>> = vec![
        Arc::new(ErrorClient),
        Arc::new(StaticClient::new("primary", "primary")),
    ];
    let result = run_flow_with_client_candidates(
        TaskType::FormatCode,
        "Format this code",
        "let  a=1;",
        200,
        DelegationMode::DraftOnly,
        16,
        Duration::from_secs(1),
        local_clients,
        primary_clients,
        false,
        None,
        None,
    )
    .await
    .expect("delegation flow");
    assert_eq!(result.completion.output, "primary");
    assert!(!result.draft);
    assert!(result.fallback_used);
    assert!(result
        .warnings
        .iter()
        .any(|warning| warning.contains("alternate primary target")));
}

#[tokio::test]
async fn delegation_flow_code_sample_returns_expected_output() {
    let sample = "export function sum(a: number, b: number) {\n  return a + b;\n}\n";
    let local = Arc::new(StaticClient::new(sample, "local"));
    let result = run_flow_with_clients(
        TaskType::FormatCode,
        "Format this code sample",
        "export function sum(a:number,b:number){return a+b;}",
        200,
        DelegationMode::DraftOnly,
        16,
        Duration::from_secs(1),
        local,
        None,
        false,
        None,
    )
    .await
    .expect("delegation flow");
    assert_eq!(result.completion.output, sample);
    assert!(result.draft);
    assert!(!result.fallback_used);
}

#[tokio::test]
async fn delegation_flow_re_evaluates_mcoda_agent() -> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let home = temp.path().to_str().ok_or("temp path is not valid utf-8")?;
    let _guard = EnvGuard::set("HOME", home);
    let mcoda_dir = temp.path().join(".mcoda");
    fs::create_dir_all(&mcoda_dir)?;
    let db_path = mcoda_dir.join("mcoda.db");
    let conn = Connection::open(&db_path)?;
    conn.execute_batch(
        "CREATE TABLE agents (
            id TEXT PRIMARY KEY,
            slug TEXT,
            adapter TEXT,
            rating REAL,
            reasoning_rating REAL,
            max_complexity INTEGER,
            rating_samples INTEGER,
            rating_last_score REAL,
            rating_updated_at TEXT,
            complexity_samples INTEGER,
            complexity_updated_at TEXT
        );
        CREATE TABLE agent_run_ratings (
            id TEXT PRIMARY KEY,
            agent_id TEXT,
            job_id TEXT,
            command_run_id TEXT,
            task_id TEXT,
            task_key TEXT,
            command_name TEXT,
            discipline TEXT,
            complexity INTEGER,
            quality_score REAL,
            tokens_total INTEGER,
            duration_seconds REAL,
            iterations INTEGER,
            total_cost REAL,
            run_score REAL,
            rating_version TEXT,
            raw_review_json TEXT,
            created_at TEXT
        );",
    )?;
    conn.execute(
        "INSERT INTO agents (id, slug, adapter, rating, reasoning_rating, max_complexity, rating_samples, rating_last_score, rating_updated_at, complexity_samples, complexity_updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        rusqlite::params![
            "agent-1",
            "agent-1",
            "local",
            6.0,
            6.0,
            5,
            0,
            6.0,
            "2024-01-01T00:00:00Z",
            0,
            "2024-01-01T00:00:00Z"
        ],
    )?;
    drop(conn);

    let local = Arc::new(StaticClient::new("ok", "local"));
    let primary = Arc::new(StaticClient::new("{\"quality_score\":8}", "primary"));
    let reevaluation = DelegationReevaluation {
        agent_id: "agent-1".to_string(),
        cost_per_million: 0.01,
        rating_window: 50,
    };
    let result = run_flow_with_clients(
        TaskType::FormatCode,
        "Format this code",
        "let  a=1;",
        200,
        DelegationMode::DraftOnly,
        16,
        Duration::from_secs(1),
        local,
        Some(primary),
        false,
        Some(reevaluation),
    )
    .await?;
    assert_eq!(result.completion.output, "ok");

    tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            let conn = Connection::open(&db_path).expect("open mcoda db");
            let rating_samples: i64 = conn
                .query_row(
                    "SELECT rating_samples FROM agents WHERE id = ?1",
                    rusqlite::params!["agent-1"],
                    |row| row.get(0),
                )
                .expect("load rating samples");
            let count: i64 = conn
                .query_row("SELECT COUNT(*) FROM agent_run_ratings", [], |row| {
                    row.get(0)
                })
                .expect("count run ratings");
            if rating_samples == 1 && count == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("re-evaluation should complete in background");
    Ok(())
}

#[tokio::test]
async fn delegation_flow_re_evaluation_does_not_block_response(
) -> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::new()?;
    let home = temp.path().to_str().ok_or("temp path is not valid utf-8")?;
    let _guard = EnvGuard::set("HOME", home);
    let mcoda_dir = temp.path().join(".mcoda");
    fs::create_dir_all(&mcoda_dir)?;
    let db_path = mcoda_dir.join("mcoda.db");
    let conn = Connection::open(&db_path)?;
    conn.execute_batch(
        "CREATE TABLE agents (
            id TEXT PRIMARY KEY,
            slug TEXT,
            adapter TEXT,
            rating REAL,
            reasoning_rating REAL,
            max_complexity INTEGER,
            rating_samples INTEGER,
            rating_last_score REAL,
            rating_updated_at TEXT,
            complexity_samples INTEGER,
            complexity_updated_at TEXT
        );
        CREATE TABLE agent_run_ratings (
            id TEXT PRIMARY KEY,
            agent_id TEXT,
            job_id TEXT,
            command_run_id TEXT,
            task_id TEXT,
            task_key TEXT,
            command_name TEXT,
            discipline TEXT,
            complexity INTEGER,
            quality_score REAL,
            tokens_total INTEGER,
            duration_seconds REAL,
            iterations INTEGER,
            total_cost REAL,
            run_score REAL,
            rating_version TEXT,
            raw_review_json TEXT,
            created_at TEXT
        );",
    )?;
    conn.execute(
        "INSERT INTO agents (id, slug, adapter, rating, reasoning_rating, max_complexity, rating_samples, rating_last_score, rating_updated_at, complexity_samples, complexity_updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
        rusqlite::params![
            "agent-1",
            "agent-1",
            "local",
            6.0,
            6.0,
            5,
            0,
            6.0,
            "2024-01-01T00:00:00Z",
            0,
            "2024-01-01T00:00:00Z"
        ],
    )?;
    drop(conn);

    let result = tokio::time::timeout(
        Duration::from_millis(50),
        run_flow_with_client_candidates(
            TaskType::FormatCode,
            "Format this code",
            "let  a=1;",
            200,
            DelegationMode::DraftOnly,
            16,
            Duration::from_secs(1),
            vec![Arc::new(StaticClient::new("ok", "local"))],
            vec![Arc::new(SlowClient::new(
                Duration::from_millis(200),
                "{\"quality_score\":8}",
                "primary",
            ))],
            false,
            Some(DelegationReevaluation {
                agent_id: "agent-1".to_string(),
                cost_per_million: 0.01,
                rating_window: 50,
            }),
            Some(Arc::new(SlowClient::new(
                Duration::from_millis(200),
                "{\"quality_score\":8}",
                "primary",
            ))),
        ),
    )
    .await
    .expect("re-evaluation should not block")
    .expect("delegation flow");

    assert_eq!(result.completion.output, "ok");
    assert!(result.draft);
    Ok(())
}

#[test]
fn reevaluation_primary_client_is_skipped_for_same_mcoda_agent() {
    let reevaluation = DelegationReevaluation {
        agent_id: "agent-1".to_string(),
        cost_per_million: 0.0,
        rating_window: 50,
    };
    let primary_targets = vec![LocalTarget::McodaAgent("agent-1".to_string())];
    assert!(!reevaluation_should_use_primary_client(
        Some(&reevaluation),
        &primary_targets,
    ));
}

#[tokio::test]
async fn delegation_flow_does_not_review_with_same_primary_agent() {
    let primary_calls = Arc::new(AtomicUsize::new(0));
    let result = run_flow_with_client_candidates(
        TaskType::FormatCode,
        "Format this code",
        "let  a=1;",
        200,
        DelegationMode::DraftOnly,
        16,
        Duration::from_secs(1),
        vec![Arc::new(StaticClient::new("ok", "local"))],
        vec![Arc::new(CountingClient::new(
            Arc::clone(&primary_calls),
            "{\"quality_score\":8}",
            "primary",
        ))],
        false,
        Some(DelegationReevaluation {
            agent_id: "agent-1".to_string(),
            cost_per_million: 0.0,
            rating_window: 50,
        }),
        None,
    )
    .await
    .expect("delegation flow");

    tokio::time::sleep(Duration::from_millis(20)).await;

    assert_eq!(result.completion.output, "ok");
    assert_eq!(primary_calls.load(AtomicOrdering::SeqCst), 0);
}

#[tokio::test]
async fn delegation_flow_blocks_primary_when_enforced() {
    let local = Arc::new(ErrorClient);
    let primary = Arc::new(StaticClient::new("primary", "primary"));
    let err = run_flow_with_clients(
        TaskType::FormatCode,
        "Format this code",
        "let  a=1;",
        200,
        DelegationMode::DraftOnly,
        16,
        Duration::from_secs(1),
        local,
        Some(primary),
        true,
        None,
    )
    .await
    .err()
    .expect("delegation error");
    assert!(err.to_string().contains("local delegation failed"));
    assert!(err.downcast_ref::<DelegationEnforcementError>().is_none());
}

#[tokio::test]
async fn delegation_flow_skips_refine_when_primary_blocked() {
    let local = Arc::new(StaticClient::new("draft", "local"));
    let primary = Arc::new(StaticClient::new("refined", "primary"));
    let result = run_flow_with_clients(
        TaskType::FormatCode,
        "Format this code",
        "let  a=1;",
        200,
        DelegationMode::DraftThenRefine,
        16,
        Duration::from_secs(1),
        local,
        Some(primary),
        true,
        None,
    )
    .await
    .expect("delegation flow");
    assert_eq!(result.completion.output, "draft");
    assert!(result.draft);
    assert!(!result.primary_used);
    assert!(!result.fallback_used);
}
