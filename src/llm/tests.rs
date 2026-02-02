use super::delegation::{
    allowlist_allows, compute_delegation_savings, mode_from_config, parse_local_target_override,
    render_prompt, resolve_delegation_client, run_flow_with_clients, select_local_target,
    select_primary_target, validate_output, DelegationEnforcementError, DelegationMode,
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

    let conn = Connection::open(&db_path)?;
    let rating_samples: i64 = conn.query_row(
        "SELECT rating_samples FROM agents WHERE id = ?1",
        rusqlite::params!["agent-1"],
        |row| row.get(0),
    )?;
    assert_eq!(rating_samples, 1);
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM agent_run_ratings", [], |row| {
        row.get(0)
    })?;
    assert_eq!(count, 1);
    Ok(())
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
