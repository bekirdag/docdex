use crate::config::LlmConfig;
use crate::llm::adapter::{resolve_agent_adapter, LlmClient, LlmCompletion, LlmFuture};
use crate::llm::local_library::{resolve_local_ollama_base_url, LocalModelLibrary};
use crate::max_size::truncate_utf8_chars;
use crate::mcoda::registry::McodaRegistry;
use crate::ollama::OllamaClient;
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tracing::warn;

const DEFAULT_CONTEXT_CHARS: usize = 12_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskType {
    GenerateTests,
    WriteDocstring,
    ScaffoldBoilerplate,
    RefactorSimple,
    FormatCode,
}

impl TaskType {
    pub fn parse(input: &str) -> Option<Self> {
        let normalized = input.trim().to_ascii_lowercase();
        match normalized.as_str() {
            "generate_tests" | "generate-tests" | "generatetests" => Some(Self::GenerateTests),
            "write_docstring" | "write-docstring" | "writedocstring" => Some(Self::WriteDocstring),
            "scaffold_boilerplate" | "scaffold-boilerplate" | "scaffoldboilerplate" => {
                Some(Self::ScaffoldBoilerplate)
            }
            "refactor_simple" | "refactor-simple" | "refactorsimple" => Some(Self::RefactorSimple),
            "format_code" | "format-code" | "formatcode" => Some(Self::FormatCode),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            TaskType::GenerateTests => "generate_tests",
            TaskType::WriteDocstring => "write_docstring",
            TaskType::ScaffoldBoilerplate => "scaffold_boilerplate",
            TaskType::RefactorSimple => "refactor_simple",
            TaskType::FormatCode => "format_code",
        }
    }

    fn template(&self) -> &'static str {
        match self {
            TaskType::GenerateTests => include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/prompts/delegation/generate_tests.txt"
            )),
            TaskType::WriteDocstring => include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/prompts/delegation/write_docstring.txt"
            )),
            TaskType::ScaffoldBoilerplate => include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/prompts/delegation/scaffold_boilerplate.txt"
            )),
            TaskType::RefactorSimple => include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/prompts/delegation/refactor_simple.txt"
            )),
            TaskType::FormatCode => include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/prompts/delegation/format_code.txt"
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationMode {
    DraftOnly,
    DraftThenRefine,
}

#[derive(Debug, Clone)]
pub enum LocalTarget {
    OllamaModel(String),
    McodaAgent(String),
}

impl DelegationMode {
    pub fn parse(input: &str) -> Option<Self> {
        let normalized = input.trim().to_ascii_lowercase();
        match normalized.as_str() {
            "draft_only" | "draft-only" | "draftonly" => Some(Self::DraftOnly),
            "draft_then_refine" | "draft-then-refine" | "draftthenrefine" => {
                Some(Self::DraftThenRefine)
            }
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            DelegationMode::DraftOnly => "draft_only",
            DelegationMode::DraftThenRefine => "draft_then_refine",
        }
    }
}

#[derive(Debug, Clone)]
pub struct DelegationRequest {
    pub task_type: TaskType,
    pub instruction: String,
    pub context: String,
    pub max_context_chars: usize,
    pub max_tokens: Option<u32>,
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct RenderedPrompt {
    pub prompt: String,
    pub truncated: bool,
}

pub struct DelegationFlowResult {
    pub completion: LlmCompletion,
    pub draft: bool,
    pub truncated: bool,
    pub warnings: Vec<String>,
    pub fallback_used: bool,
    pub token_estimate: u64,
}

#[derive(Debug)]
pub struct DelegationValidationError {
    pub reason: String,
}

impl std::fmt::Display for DelegationValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.reason)
    }
}

impl std::error::Error for DelegationValidationError {}

struct OllamaPromptAdapter {
    client: OllamaClient,
    model: String,
}

impl LlmClient for OllamaPromptAdapter {
    fn generate<'a>(
        &'a self,
        prompt: &'a str,
        max_tokens: u32,
        timeout: Duration,
    ) -> LlmFuture<'a> {
        Box::pin(async move {
            let output = self
                .client
                .generate(&self.model, prompt, max_tokens, timeout)
                .await
                .context("ollama generate")?;
            Ok(LlmCompletion {
                output,
                adapter: "ollama".to_string(),
                model: Some(self.model.clone()),
                metadata: None,
            })
        })
    }
}

pub fn render_prompt(
    task_type: TaskType,
    instruction: &str,
    context: &str,
    max_context_chars: usize,
) -> RenderedPrompt {
    let template = task_type.template();
    let instruction = instruction.trim();
    let context = context.trim();
    let limit = if max_context_chars == 0 {
        DEFAULT_CONTEXT_CHARS
    } else {
        max_context_chars
    };
    let (context_trimmed, truncated) = truncate_utf8_chars(context, limit);
    let prompt = template
        .replace("{{instruction}}", instruction)
        .replace("{{context}}", &context_trimmed);
    RenderedPrompt { prompt, truncated }
}

pub fn render_refine_prompt(
    instruction: &str,
    context: &str,
    draft: &str,
    max_context_chars: usize,
) -> RenderedPrompt {
    let template = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/prompts/delegation/refine_draft.txt"
    ));
    let instruction = instruction.trim();
    let context = context.trim();
    let draft = draft.trim();
    let limit = if max_context_chars == 0 {
        DEFAULT_CONTEXT_CHARS
    } else {
        max_context_chars
    };
    let (context_trimmed, context_truncated) = truncate_utf8_chars(context, limit);
    let (draft_trimmed, draft_truncated) = truncate_utf8_chars(draft, limit);
    let prompt = template
        .replace("{{instruction}}", instruction)
        .replace("{{context}}", &context_trimmed)
        .replace("{{draft}}", &draft_trimmed);
    RenderedPrompt {
        prompt,
        truncated: context_truncated || draft_truncated,
    }
}

fn estimate_token_budget(prompt: &str, max_tokens: u32) -> u64 {
    let prompt_tokens = (prompt.len() as u64 + 3) / 4;
    prompt_tokens.saturating_add(max_tokens as u64)
}

pub fn allowlist_allows(task_type: TaskType, allowlist: &[String]) -> bool {
    if allowlist.is_empty() {
        return true;
    }
    let mut allowed = false;
    let mut invalid = Vec::new();
    for entry in allowlist {
        match TaskType::parse(entry) {
            Some(parsed) => {
                if parsed == task_type {
                    allowed = true;
                }
            }
            None => invalid.push(entry.clone()),
        }
    }
    if !invalid.is_empty() {
        warn!(
            target: "docdexd",
            entries = ?invalid,
            "invalid delegation allowlist entries"
        );
    }
    allowed
}

pub fn mode_from_config(mode: &str) -> DelegationMode {
    match DelegationMode::parse(mode) {
        Some(value) => value,
        None => {
            warn!(
                target: "docdexd",
                value = %mode,
                "invalid delegation mode; falling back to draft_only"
            );
            DelegationMode::DraftOnly
        }
    }
}

pub fn validate_output(task_type: TaskType, output: &str) -> Result<(), DelegationValidationError> {
    let trimmed = output.trim();
    if trimmed.is_empty() {
        return Err(DelegationValidationError {
            reason: "delegation output is empty".to_string(),
        });
    }
    if trimmed.contains("```") {
        return Err(DelegationValidationError {
            reason: "delegation output must not include markdown fences".to_string(),
        });
    }
    match task_type {
        TaskType::GenerateTests
        | TaskType::WriteDocstring
        | TaskType::ScaffoldBoilerplate
        | TaskType::RefactorSimple
        | TaskType::FormatCode => Ok(()),
    }
}

pub fn select_local_target(
    task_type: TaskType,
    library: &LocalModelLibrary,
) -> Option<LocalTarget> {
    let mut best: Option<(LocalTarget, i32, bool)> = None;
    for model in &library.models {
        let score = score_for_task(task_type, &model.capabilities);
        if score <= 0 {
            continue;
        }
        let candidate = LocalTarget::OllamaModel(model.name.clone());
        best = choose_best(best, candidate, score, true);
    }
    for agent in &library.agents {
        let score = score_for_task(task_type, &agent.capabilities);
        if score <= 0 {
            continue;
        }
        let candidate = LocalTarget::McodaAgent(agent.agent_id.clone());
        best = choose_best(best, candidate, score, false);
    }
    best.map(|(target, _, _)| target)
}

fn choose_best(
    current: Option<(LocalTarget, i32, bool)>,
    candidate: LocalTarget,
    score: i32,
    prefers_ollama: bool,
) -> Option<(LocalTarget, i32, bool)> {
    match current {
        None => Some((candidate, score, prefers_ollama)),
        Some((_, best_score, _best_prefers_ollama)) if score > best_score => {
            Some((candidate, score, prefers_ollama))
        }
        Some((_, best_score, best_prefers_ollama)) if score == best_score => {
            if prefers_ollama && !best_prefers_ollama {
                Some((candidate, score, prefers_ollama))
            } else {
                current
            }
        }
        _ => current,
    }
}

fn score_for_task(task_type: TaskType, capabilities: &[String]) -> i32 {
    let has = |cap: &str| capabilities.iter().any(|value| value == cap);
    if capabilities.is_empty() {
        return 1;
    }
    if (has("embedding") || has("vision"))
        && !(has("code_writer") || has("code_reviewer") || has("general_chat"))
    {
        return -100;
    }
    let mut score = 0;
    match task_type {
        TaskType::GenerateTests => {
            if has("code_reviewer") {
                score += 4;
            }
            if has("code_writer") {
                score += 3;
            }
        }
        TaskType::WriteDocstring => {
            if has("code_writer") {
                score += 3;
            }
            if has("general_chat") {
                score += 1;
            }
        }
        TaskType::ScaffoldBoilerplate => {
            if has("code_writer") {
                score += 4;
            }
        }
        TaskType::RefactorSimple => {
            if has("code_reviewer") {
                score += 4;
            }
            if has("code_writer") {
                score += 2;
            }
        }
        TaskType::FormatCode => {
            if has("code_reviewer") {
                score += 4;
            }
            if has("code_writer") {
                score += 1;
            }
        }
    }
    if score == 0 && has("general_chat") {
        score = 1;
    }
    score
}

pub fn resolve_delegation_client(
    llm_config: &LlmConfig,
    local_agent_override: Option<&str>,
    local_target: Option<&LocalTarget>,
) -> Result<Arc<dyn LlmClient>> {
    let agent_id = local_agent_override
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .or_else(|| {
            let trimmed = llm_config.delegation.local_agent_id.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        });

    if let Some(agent_id) = agent_id {
        let registry = McodaRegistry::load_default()
            .context("load mcoda registry")?
            .ok_or_else(|| anyhow!("mcoda registry not found"))?;
        let agent = registry
            .agent_by_id(agent_id)
            .or_else(|| registry.agent_by_slug(agent_id))
            .ok_or_else(|| anyhow!("mcoda agent not found: {agent_id}"))?;
        let adapter = resolve_agent_adapter(agent)
            .with_context(|| format!("resolve mcoda agent adapter {agent_id}"))?;
        return Ok(Arc::new(adapter));
    }

    if let Some(target) = local_target {
        match target {
            LocalTarget::McodaAgent(agent_id) => {
                let registry = McodaRegistry::load_default()
                    .context("load mcoda registry")?
                    .ok_or_else(|| anyhow!("mcoda registry not found"))?;
                let agent = registry
                    .agent_by_id(agent_id)
                    .or_else(|| registry.agent_by_slug(agent_id))
                    .ok_or_else(|| anyhow!("mcoda agent not found: {agent_id}"))?;
                let adapter = resolve_agent_adapter(agent)
                    .with_context(|| format!("resolve mcoda agent adapter {agent_id}"))?;
                return Ok(Arc::new(adapter));
            }
            LocalTarget::OllamaModel(model) => {
                let base_url = resolve_local_ollama_base_url(llm_config)
                    .ok_or_else(|| anyhow!("ollama base_url missing for local delegation"))?;
                return resolve_ollama_adapter(&base_url, model);
            }
        }
    }

    if !llm_config.provider.trim().eq_ignore_ascii_case("ollama") {
        warn!(
            target: "docdexd",
            provider = %llm_config.provider,
            "delegation fallback only supports ollama provider"
        );
        return Err(anyhow!("delegation fallback requires ollama provider"));
    }

    let base_url = llm_config.base_url.trim();
    let model = llm_config.default_model.trim();
    if base_url.is_empty() || model.is_empty() {
        return Err(anyhow!("ollama base_url or model missing for delegation"));
    }
    resolve_ollama_adapter(base_url, model)
}

fn resolve_ollama_adapter(base_url: &str, model: &str) -> Result<Arc<dyn LlmClient>> {
    if base_url.trim().is_empty() || model.trim().is_empty() {
        return Err(anyhow!("ollama base_url or model missing for delegation"));
    }
    let client = OllamaClient::new(base_url.to_string()).context("init ollama client")?;
    Ok(Arc::new(OllamaPromptAdapter {
        client,
        model: model.trim().to_string(),
    }))
}

pub fn resolve_primary_client(llm_config: &LlmConfig) -> Result<Option<Arc<dyn LlmClient>>> {
    let agent_id = llm_config.delegation.primary_agent_id.trim();
    if agent_id.is_empty() {
        return Ok(None);
    }
    let registry = match McodaRegistry::load_default() {
        Ok(Some(registry)) => registry,
        Ok(None) => {
            warn!(
                target: "docdexd",
                agent_id = %agent_id,
                "mcoda registry not found; primary delegation unavailable"
            );
            return Ok(None);
        }
        Err(err) => {
            warn!(
                target: "docdexd",
                agent_id = %agent_id,
                error = ?err,
                "failed to load mcoda registry; primary delegation unavailable"
            );
            return Ok(None);
        }
    };

    let agent = match registry
        .agent_by_id(agent_id)
        .or_else(|| registry.agent_by_slug(agent_id))
    {
        Some(agent) => agent,
        None => {
            warn!(
                target: "docdexd",
                agent_id = %agent_id,
                "primary agent not found in mcoda registry"
            );
            return Ok(None);
        }
    };

    match resolve_agent_adapter(agent) {
        Ok(adapter) => Ok(Some(Arc::new(adapter))),
        Err(err) => {
            warn!(
                target: "docdexd",
                agent_id = %agent_id,
                error = ?err,
                "failed to resolve primary agent adapter"
            );
            Ok(None)
        }
    }
}

pub async fn run_delegated_completion(
    llm_config: &LlmConfig,
    local_agent_override: Option<&str>,
    local_target: Option<&LocalTarget>,
    prompt: &str,
    max_tokens_override: Option<u32>,
    timeout_ms_override: Option<u64>,
) -> Result<LlmCompletion> {
    let max_tokens = max_tokens_override
        .unwrap_or(llm_config.delegation.max_tokens)
        .max(1);
    let timeout_ms = timeout_ms_override
        .unwrap_or(llm_config.delegation.timeout_ms)
        .max(1);
    let client = resolve_delegation_client(llm_config, local_agent_override, local_target)?;
    client
        .generate(prompt, max_tokens, Duration::from_millis(timeout_ms))
        .await
}

pub async fn run_delegation_flow(
    llm_config: &LlmConfig,
    local_agent_override: Option<&str>,
    local_target: Option<&LocalTarget>,
    task_type: TaskType,
    instruction: &str,
    context: &str,
    max_context_chars: usize,
    max_tokens_override: Option<u32>,
    timeout_ms_override: Option<u64>,
    mode: DelegationMode,
) -> Result<DelegationFlowResult> {
    let max_tokens = max_tokens_override
        .unwrap_or(llm_config.delegation.max_tokens)
        .max(1);
    let timeout_ms = timeout_ms_override
        .unwrap_or(llm_config.delegation.timeout_ms)
        .max(1);
    let timeout = Duration::from_millis(timeout_ms);
    let local_client = resolve_delegation_client(llm_config, local_agent_override, local_target)?;
    let primary_client = resolve_primary_client(llm_config)?;
    run_flow_with_clients(
        task_type,
        instruction,
        context,
        max_context_chars,
        mode,
        max_tokens,
        timeout,
        local_client,
        primary_client,
    )
    .await
}

pub(crate) async fn run_flow_with_clients(
    task_type: TaskType,
    instruction: &str,
    context: &str,
    max_context_chars: usize,
    mode: DelegationMode,
    max_tokens: u32,
    timeout: Duration,
    local_client: Arc<dyn LlmClient>,
    primary_client: Option<Arc<dyn LlmClient>>,
) -> Result<DelegationFlowResult> {
    let rendered = render_prompt(task_type, instruction, context, max_context_chars);
    let token_estimate = estimate_token_budget(&rendered.prompt, max_tokens);
    let mut warnings = Vec::new();
    if rendered.truncated {
        warnings.push("context truncated to fit delegation limits".to_string());
    }
    let mut truncated = rendered.truncated;
    let mut fallback_used = false;

    let local_completion = match local_client
        .generate(&rendered.prompt, max_tokens, timeout)
        .await
    {
        Ok(completion) => match validate_output(task_type, &completion.output) {
            Ok(()) => Some(completion),
            Err(err) => {
                warn!(
                    target: "docdexd",
                    fallback_reason = "local_validation_failed",
                    error = %err,
                    "delegation output validation failed"
                );
                None
            }
        },
        Err(err) => {
            warn!(
                target: "docdexd",
                fallback_reason = "local_completion_failed",
                error = ?err,
                "delegation completion failed"
            );
            None
        }
    };

    let Some(local_completion) = local_completion else {
        if let Some(primary) = primary_client {
            fallback_used = true;
            warnings.push("local delegation failed; using primary agent".to_string());
            warn!(
                target: "docdexd",
                fallback_reason = "fallback_to_primary",
                "falling back to primary agent"
            );
            let completion = primary
                .generate(&rendered.prompt, max_tokens, timeout)
                .await
                .context("primary agent completion failed")?;
            validate_output(task_type, &completion.output)
                .map_err(|err| anyhow!(err.to_string()))?;
            return Ok(DelegationFlowResult {
                completion,
                draft: false,
                truncated,
                warnings,
                fallback_used,
                token_estimate,
            });
        }
        warn!(
            target: "docdexd",
            fallback_reason = "primary_missing_for_fallback",
            "delegation failed and no primary agent configured"
        );
        return Err(anyhow!("delegation failed and no primary agent configured"));
    };

    if matches!(mode, DelegationMode::DraftThenRefine) {
        if let Some(primary) = primary_client {
            let refine_rendered = render_refine_prompt(
                instruction,
                context,
                &local_completion.output,
                max_context_chars,
            );
            if refine_rendered.truncated && !truncated {
                warnings.push("context or draft truncated to fit delegation limits".to_string());
            }
            truncated |= refine_rendered.truncated;
            match primary
                .generate(&refine_rendered.prompt, max_tokens, timeout)
                .await
            {
                Ok(refined) => {
                    if let Err(err) = validate_output(task_type, &refined.output) {
                        warn!(
                            target: "docdexd",
                            fallback_reason = "primary_validation_failed",
                            error = %err,
                            "primary refinement output failed validation"
                        );
                    } else {
                        return Ok(DelegationFlowResult {
                            completion: refined,
                            draft: false,
                            truncated,
                            warnings,
                            fallback_used,
                            token_estimate,
                        });
                    }
                }
                Err(err) => {
                    warn!(
                        target: "docdexd",
                        fallback_reason = "primary_refine_failed",
                        error = ?err,
                        "primary refinement failed"
                    );
                }
            }
            fallback_used = true;
            warn!(
                target: "docdexd",
                fallback_reason = "fallback_to_draft",
                "primary refinement failed; returning draft"
            );
            warnings.push("primary refinement failed; returning draft".to_string());
            return Ok(DelegationFlowResult {
                completion: local_completion,
                draft: true,
                truncated,
                warnings,
                fallback_used,
                token_estimate,
            });
        }

        fallback_used = true;
        warn!(
            target: "docdexd",
            fallback_reason = "primary_missing_for_refine",
            "primary agent not configured; returning draft"
        );
        warnings.push("primary agent not configured; returning draft".to_string());
        return Ok(DelegationFlowResult {
            completion: local_completion,
            draft: true,
            truncated,
            warnings,
            fallback_used,
            token_estimate,
        });
    }

    Ok(DelegationFlowResult {
        completion: local_completion,
        draft: true,
        truncated,
        warnings,
        fallback_used,
        token_estimate,
    })
}
