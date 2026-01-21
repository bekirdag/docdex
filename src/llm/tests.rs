use super::delegation::{
    allowlist_allows, mode_from_config, render_prompt, resolve_delegation_client,
    run_flow_with_clients, select_local_target, validate_output, DelegationMode, LocalTarget,
    TaskType,
};
use super::{load_catalog, recommended_model, supports, LlmModel};
use crate::config::{DelegationConfig, LlmConfig};
use crate::hardware::{GraphicsInfo, HardwareProfile};
use crate::llm::adapter::{LlmClient, LlmCompletion, LlmFuture};
use crate::llm::local_library::{LocalModelEntry, LocalModelLibrary};
use crate::setup::test_support::ENV_LOCK;
use anyhow::anyhow;
use parking_lot::ReentrantMutexGuard;
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
fn validate_output_rejects_empty_or_fenced() {
    assert!(validate_output(TaskType::FormatCode, "").is_err());
    assert!(validate_output(TaskType::FormatCode, "```js\ncode\n```").is_err());
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
    )
    .await
    .expect("delegation flow");
    assert_eq!(result.completion.output, "draft");
    assert!(result.draft);
    assert!(result.fallback_used);
}
