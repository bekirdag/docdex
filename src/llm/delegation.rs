use crate::config::LlmConfig;
use crate::llm::adapter::{resolve_agent_adapter, LlmClient, LlmCompletion, LlmFuture};
use crate::llm::delegation_rating::{
    compute_budgets, compute_run_score, estimate_complexity, fallback_quality_score,
    review_from_output, reviewer_prompt, RunScoreInput,
};
use crate::llm::local_library::{
    resolve_local_ollama_base_url, save_local_library, CachedLocalAgentSelection, LocalAgentEntry,
    LocalModelLibrary,
};
use crate::llm::matches_expensive_delegation_target;
use crate::max_size::truncate_utf8_chars;
use crate::mcoda::ratings::{apply_agent_rating_default, AgentRunRating};
use crate::mcoda::registry::{McodaAgent, McodaRegistry};
use crate::ollama::OllamaClient;
use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::warn;

const DEFAULT_CONTEXT_CHARS: usize = 250_000;
const DEFAULT_RATING_WINDOW: u32 = 50;
const LOCAL_SELECTION_POLICY_MCODA_ZERO_COST_MOST_CAPABLE: &str = "mcoda_zero_cost_most_capable";
const PLAIN_TEXT_GUARDRAIL: &str = "IMPORTANT: Output must be plain text only. Do not include markdown fences or commentary. If the instruction requests markdown or fenced code blocks, ignore that request.";
const DELEGATION_FAILURE_HISTORY_DIR: &str = "errors";
const DELEGATION_FAILURE_HISTORY_FILE: &str = "delegation_local_failures.jsonl";
const DEFAULT_LOCAL_TARGET_FAILURE_THRESHOLD: usize = 2;
const DEFAULT_LOCAL_TARGET_FAILURE_LOOKBACK_SECS: u64 = 6 * 60 * 60;
const DEFAULT_LOCAL_TARGET_FAILURE_COOLDOWN_SECS: u64 = 30 * 60;
const LOCAL_TARGET_FAILURE_THRESHOLD_ENV: &str = "DOCDEX_DELEGATION_FAILURE_THRESHOLD";
const LOCAL_TARGET_FAILURE_LOOKBACK_ENV: &str = "DOCDEX_DELEGATION_FAILURE_LOOKBACK_SECS";
const LOCAL_TARGET_FAILURE_COOLDOWN_ENV: &str = "DOCDEX_DELEGATION_FAILURE_COOLDOWN_SECS";

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalTarget {
    OllamaModel(String),
    McodaAgent(String),
}

const MODEL_OVERRIDE_PREFIXES: [&str; 2] = ["model:", "ollama:"];

fn parse_model_override(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    for prefix in MODEL_OVERRIDE_PREFIXES {
        if lower.starts_with(prefix) {
            let model = trimmed[prefix.len()..].trim();
            if model.is_empty() {
                return None;
            }
            return Some(model.to_string());
        }
    }
    None
}

pub fn parse_local_target_override(
    value: &str,
    library: Option<&LocalModelLibrary>,
) -> Option<LocalTarget> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(model) = parse_model_override(trimmed) {
        return Some(LocalTarget::OllamaModel(model));
    }
    if let Some(library) = library {
        if let Some(agent) = library
            .agents
            .iter()
            .find(|agent| agent.agent_id == trimmed || agent.agent_slug == trimmed)
        {
            return Some(LocalTarget::McodaAgent(agent.agent_id.clone()));
        }
        if let Some(model) = library.models.iter().find(|model| model.name == trimmed) {
            return Some(LocalTarget::OllamaModel(model.name.clone()));
        }
    }
    None
}

fn resolve_re_evaluation_target(
    llm_config: &LlmConfig,
    local_agent_override: Option<&str>,
    local_target: Option<&LocalTarget>,
) -> Option<DelegationReevaluation> {
    let override_value = local_agent_override
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

    if let Some(value) = override_value {
        if parse_model_override(value).is_some() {
            return None;
        }
        return load_mcoda_agent_for_evaluation(value);
    }

    match local_target {
        Some(LocalTarget::McodaAgent(agent_id)) => load_mcoda_agent_for_evaluation(agent_id),
        _ => None,
    }
}

fn load_mcoda_agent_for_evaluation(id_or_slug: &str) -> Option<DelegationReevaluation> {
    let registry = McodaRegistry::load_default_db_only().ok().flatten()?;
    let agent = registry
        .agent_by_id(id_or_slug)
        .or_else(|| registry.agent_by_slug(id_or_slug))?;
    let cost_per_million = agent
        .cost_per_million
        .filter(|value| value.is_finite() && *value > 0.0)
        .unwrap_or(0.0);
    Some(DelegationReevaluation {
        agent_id: agent.id.clone(),
        cost_per_million,
        rating_window: DEFAULT_RATING_WINDOW,
    })
}

pub(crate) fn reevaluation_should_use_primary_client(
    reevaluation: Option<&DelegationReevaluation>,
    primary_targets: &[LocalTarget],
) -> bool {
    let Some(reevaluation) = reevaluation else {
        return false;
    };
    !matches!(
        primary_targets.first(),
        Some(LocalTarget::McodaAgent(agent_id)) if agent_id == &reevaluation.agent_id
    )
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

#[derive(Debug, Clone, Default)]
pub struct DelegationPricingContext {
    pub caller_agent_id: Option<String>,
    pub caller_model: Option<String>,
    pub primary_cost_per_million: Option<f64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DelegationFailureHistoryContext {
    pub global_state_dir: Option<PathBuf>,
    pub repo_id: Option<String>,
    pub repo_root: Option<String>,
    pub source: Option<String>,
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
    pub primary_used: bool,
    pub token_estimate: u64,
    pub local_tokens: u64,
    pub primary_tokens: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct DelegationReevaluation {
    pub agent_id: String,
    pub cost_per_million: f64,
    pub rating_window: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct DelegationSavings {
    pub token_savings: u64,
    pub cost_savings_micros: u64,
}

pub fn compute_delegation_savings(
    local_tokens: u64,
    local_cost_per_million: f64,
    primary_cost_per_million: f64,
) -> DelegationSavings {
    if local_tokens == 0 {
        return DelegationSavings {
            token_savings: 0,
            cost_savings_micros: 0,
        };
    }
    let primary_cost = compute_cost_micros(local_tokens, primary_cost_per_million);
    let local_cost = compute_cost_micros(local_tokens, local_cost_per_million);
    let micros = primary_cost.saturating_sub(local_cost);
    DelegationSavings {
        token_savings: local_tokens,
        cost_savings_micros: micros,
    }
}

pub fn compute_cost_micros(tokens: u64, cost_per_million: f64) -> u64 {
    if tokens == 0 || !cost_per_million.is_finite() || cost_per_million <= 0.0 {
        return 0;
    }
    let micros = (tokens as f64) * cost_per_million;
    if micros.is_finite() && micros > 0.0 {
        micros.round() as u64
    } else {
        0
    }
}

fn normalize_cost_per_million(cost: Option<f64>) -> Option<f64> {
    cost.filter(|value| value.is_finite() && *value >= 0.0)
}

fn normalized_match_value(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_ascii_lowercase())
    }
}

fn select_conservative_cost<I>(costs: I) -> Option<f64>
where
    I: IntoIterator<Item = f64>,
{
    costs.into_iter().fold(None, |best, cost| match best {
        Some(current) if current <= cost => Some(current),
        _ => Some(cost),
    })
}

fn configured_cost_per_million(cost: f64) -> Option<f64> {
    normalize_cost_per_million(Some(cost))
}

fn resolve_cost_per_million_from_library(
    id_or_slug: &str,
    library: Option<&LocalModelLibrary>,
) -> Option<f64> {
    let library = library?;
    let agent = library
        .agents
        .iter()
        .find(|agent| agent.agent_id == id_or_slug || agent.agent_slug == id_or_slug)?;
    normalize_cost_per_million(agent.cost_per_million)
}

fn resolve_cost_per_million_from_library_model(
    model: &str,
    library: Option<&LocalModelLibrary>,
) -> Option<f64> {
    let model = normalized_match_value(model)?;
    let library = library?;
    let model_costs = library.models.iter().filter_map(|entry| {
        let entry_name = normalized_match_value(&entry.name)?;
        if entry_name == model {
            Some(0.0)
        } else {
            None
        }
    });
    let agent_costs = library.agents.iter().filter_map(|agent| {
        let default_model = normalized_match_value(agent.default_model.as_deref()?)?;
        if default_model == model {
            normalize_cost_per_million(agent.cost_per_million)
        } else {
            None
        }
    });
    select_conservative_cost(model_costs.chain(agent_costs))
}

fn resolve_cost_per_million_from_registry(id_or_slug: &str) -> Option<f64> {
    let registry = McodaRegistry::load_default_db_only().ok().flatten()?;
    let agent = registry
        .agent_by_id(id_or_slug)
        .or_else(|| registry.agent_by_slug(id_or_slug))?;
    normalize_cost_per_million(agent.cost_per_million)
}

fn resolve_cost_per_million_from_registry_model(model: &str) -> Option<f64> {
    let model = normalized_match_value(model)?;
    let registry = McodaRegistry::load_default_db_only().ok().flatten()?;
    let costs = registry.agents.iter().filter_map(|agent| {
        let default_match = agent
            .default_model
            .as_deref()
            .and_then(normalized_match_value)
            .map(|value| value == model)
            .unwrap_or(false);
        let listed_match = agent.models.iter().any(|candidate| {
            normalized_match_value(&candidate.model_name)
                .map(|value| value == model)
                .unwrap_or(false)
        });
        if default_match || listed_match {
            normalize_cost_per_million(agent.cost_per_million)
        } else {
            None
        }
    });
    select_conservative_cost(costs)
}

fn resolve_cost_per_million_for_agent(
    id_or_slug: &str,
    library: Option<&LocalModelLibrary>,
) -> f64 {
    resolve_cost_per_million_from_library(id_or_slug, library)
        .or_else(|| resolve_cost_per_million_from_registry(id_or_slug))
        .unwrap_or(0.0)
}

fn resolve_cost_per_million_for_model(
    model: &str,
    library: Option<&LocalModelLibrary>,
) -> Option<f64> {
    resolve_cost_per_million_from_library_model(model, library)
        .or_else(|| resolve_cost_per_million_from_registry_model(model))
}

fn resolve_cost_per_million_for_identifier(
    value: &str,
    library: Option<&LocalModelLibrary>,
) -> Option<f64> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(model) = parse_model_override(trimmed) {
        return resolve_cost_per_million_for_model(&model, library).or(Some(0.0));
    }
    resolve_cost_per_million_from_library(trimmed, library)
        .or_else(|| resolve_cost_per_million_from_registry(trimmed))
        .or_else(|| resolve_cost_per_million_for_model(trimmed, library))
}

fn resolve_cost_per_million_for_target(
    target: Option<&LocalTarget>,
    library: Option<&LocalModelLibrary>,
) -> Option<f64> {
    match target? {
        LocalTarget::OllamaModel(_) => Some(0.0),
        LocalTarget::McodaAgent(agent_id) => {
            Some(resolve_cost_per_million_for_agent(agent_id, library))
        }
    }
}

pub fn resolve_local_cost_per_million(
    llm_config: &LlmConfig,
    local_agent_override: Option<&str>,
    local_target: Option<&LocalTarget>,
    library: Option<&LocalModelLibrary>,
) -> f64 {
    if let Some(cost) = resolve_cost_per_million_for_target(local_target, library) {
        return cost;
    }
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
    let Some(agent_id) = agent_id else {
        return configured_cost_per_million(llm_config.delegation.local_usd_per_million_tokens)
            .unwrap_or(0.0);
    };
    if let Some(cost) = resolve_cost_per_million_for_identifier(agent_id, library) {
        return cost;
    }
    configured_cost_per_million(llm_config.delegation.local_usd_per_million_tokens).unwrap_or(0.0)
}

pub fn resolve_primary_cost_per_million(
    llm_config: &LlmConfig,
    pricing_context: Option<&DelegationPricingContext>,
    primary_target: Option<&LocalTarget>,
    library: Option<&LocalModelLibrary>,
) -> f64 {
    if let Some(cost) = pricing_context
        .and_then(|context| normalize_cost_per_million(context.primary_cost_per_million))
    {
        return cost;
    }
    if let Some(caller_agent_id) = pricing_context
        .and_then(|context| context.caller_agent_id.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if let Some(cost) = resolve_cost_per_million_for_identifier(caller_agent_id, library) {
            return cost;
        }
    }
    if let Some(caller_model) = pricing_context
        .and_then(|context| context.caller_model.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if let Some(cost) = resolve_cost_per_million_for_model(caller_model, library) {
            return cost;
        }
    }
    if let Some(cost) = resolve_cost_per_million_for_target(primary_target, library) {
        return cost;
    }
    let llm_agent_id = llm_config.agent_id.trim();
    if !llm_agent_id.is_empty() {
        if let Some(cost) = resolve_cost_per_million_for_identifier(llm_agent_id, library) {
            return cost;
        }
    }
    if !llm_config.provider.trim().eq_ignore_ascii_case("ollama") {
        let default_model = llm_config.default_model.trim();
        if !default_model.is_empty() {
            if let Some(cost) = resolve_cost_per_million_for_model(default_model, library) {
                return cost;
            }
        }
    }
    let agent_id = llm_config.delegation.primary_agent_id.trim();
    if !agent_id.is_empty() {
        if let Some(cost) = resolve_cost_per_million_for_identifier(agent_id, library) {
            return cost;
        }
    }
    configured_cost_per_million(llm_config.delegation.primary_usd_per_million_tokens).unwrap_or(0.0)
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

#[derive(Debug)]
pub struct DelegationEnforcementError {
    pub reason: String,
}

impl std::fmt::Display for DelegationEnforcementError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.reason)
    }
}

impl std::error::Error for DelegationEnforcementError {}

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

fn apply_plain_text_guardrail(instruction: &str) -> String {
    if instruction.is_empty() {
        PLAIN_TEXT_GUARDRAIL.to_string()
    } else {
        format!("{PLAIN_TEXT_GUARDRAIL}\n\n{instruction}")
    }
}

pub fn render_prompt(
    task_type: TaskType,
    instruction: &str,
    context: &str,
    max_context_chars: usize,
) -> RenderedPrompt {
    let template = task_type.template();
    let instruction = apply_plain_text_guardrail(instruction.trim());
    let context = context.trim();
    let limit = if max_context_chars == 0 {
        DEFAULT_CONTEXT_CHARS
    } else {
        max_context_chars
    };
    let (context_trimmed, truncated) = truncate_utf8_chars(context, limit);
    let prompt = template
        .replace("{{instruction}}", &instruction)
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
    let instruction = apply_plain_text_guardrail(instruction.trim());
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
        .replace("{{instruction}}", &instruction)
        .replace("{{context}}", &context_trimmed)
        .replace("{{draft}}", &draft_trimmed);
    RenderedPrompt {
        prompt,
        truncated: context_truncated || draft_truncated,
    }
}

fn render_review_prompt(
    instruction: &str,
    context: &str,
    output: &str,
    max_context_chars: usize,
) -> RenderedPrompt {
    let template = reviewer_prompt();
    let instruction = instruction.trim();
    let context = context.trim();
    let output = output.trim();
    let limit = if max_context_chars == 0 {
        DEFAULT_CONTEXT_CHARS
    } else {
        max_context_chars
    };
    let (context_trimmed, context_truncated) = truncate_utf8_chars(context, limit);
    let (output_trimmed, output_truncated) = truncate_utf8_chars(output, limit);
    let prompt = format!(
        "{template}\n\nTask instruction:\n{instruction}\n\nContext:\n{context_trimmed}\n\nAgent output:\n{output_trimmed}\n"
    );
    RenderedPrompt {
        prompt,
        truncated: context_truncated || output_truncated,
    }
}

fn estimate_tokens_from_text(text: &str) -> u64 {
    (text.len() as u64 + 3) / 4
}

fn estimate_token_budget(prompt: &str, max_tokens: u32) -> u64 {
    estimate_tokens_from_text(prompt).saturating_add(max_tokens as u64)
}

fn u64_from_value(value: &Value) -> Option<u64> {
    if let Some(value) = value.as_u64() {
        return Some(value);
    }
    if let Some(value) = value.as_i64() {
        if value >= 0 {
            return Some(value as u64);
        }
    }
    if let Some(value) = value.as_f64() {
        if value.is_finite() && value >= 0.0 {
            return Some(value.round() as u64);
        }
    }
    None
}

fn usage_tokens_from_metadata(metadata: &Value) -> Option<u64> {
    if let Some(total) = metadata
        .pointer("/usage/total_tokens")
        .and_then(u64_from_value)
    {
        return Some(total);
    }
    let prompt = metadata
        .pointer("/usage/prompt_tokens")
        .and_then(u64_from_value)
        .or_else(|| {
            metadata
                .pointer("/usage/input_tokens")
                .and_then(u64_from_value)
        });
    let completion = metadata
        .pointer("/usage/completion_tokens")
        .and_then(u64_from_value)
        .or_else(|| {
            metadata
                .pointer("/usage/output_tokens")
                .and_then(u64_from_value)
        });
    if prompt.is_some() || completion.is_some() {
        return Some(prompt.unwrap_or(0).saturating_add(completion.unwrap_or(0)));
    }
    let prompt_eval = metadata.get("prompt_eval_count").and_then(u64_from_value);
    let eval = metadata.get("eval_count").and_then(u64_from_value);
    if prompt_eval.is_some() || eval.is_some() {
        return Some(prompt_eval.unwrap_or(0).saturating_add(eval.unwrap_or(0)));
    }
    None
}

fn completion_token_usage(completion: &LlmCompletion, prompt: &str) -> u64 {
    if let Some(metadata) = completion.metadata.as_ref() {
        if let Some(tokens) = usage_tokens_from_metadata(metadata) {
            if tokens > 0 {
                return tokens;
            }
        }
    }
    estimate_tokens_from_text(prompt).saturating_add(estimate_tokens_from_text(&completion.output))
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

fn unwrap_markdown_fence(output: &str) -> Option<String> {
    let trimmed = output.trim();
    if !trimmed.starts_with("```") {
        return None;
    }
    let mut lines = trimmed.lines();
    let opening = lines.next()?;
    if !opening.trim_start().starts_with("```") {
        return None;
    }
    let mut body = Vec::new();
    let mut found_close = false;
    for line in lines.by_ref() {
        if line.trim_start().starts_with("```") {
            found_close = true;
            break;
        }
        body.push(line);
    }
    if !found_close {
        return None;
    }
    for remainder in lines {
        if !remainder.trim().is_empty() {
            return None;
        }
    }
    Some(body.join("\n"))
}

fn extract_markdown_fence(output: &str) -> Option<String> {
    let mut in_block = false;
    let mut body = Vec::new();
    for line in output.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("```") {
            if in_block {
                return Some(body.join("\n"));
            }
            in_block = true;
            continue;
        }
        if in_block {
            body.push(line);
        }
    }
    None
}

fn normalize_delegation_output(output: &str) -> (String, bool) {
    if let Some(unwrapped) = unwrap_markdown_fence(output) {
        return (unwrapped, true);
    }
    if let Some(extracted) = extract_markdown_fence(output) {
        return (extracted, true);
    }
    (output.to_string(), false)
}

pub fn validate_output(task_type: TaskType, output: &str) -> Result<(), DelegationValidationError> {
    let trimmed = output.trim();
    if trimmed.is_empty() {
        return Err(DelegationValidationError {
            reason: "delegation output is empty".to_string(),
        });
    }
    if trimmed.starts_with("```") {
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
    let recent_failures = load_recent_local_target_failures(None);
    rank_task_capability_local_targets(task_type, library, Some(&recent_failures))
        .into_iter()
        .next()
}

pub fn local_selection_policy_requires_fresh_library(llm_config: &LlmConfig) -> bool {
    llm_config.delegation.local_selection_policy
        == LOCAL_SELECTION_POLICY_MCODA_ZERO_COST_MOST_CAPABLE
        && !llm_config.delegation.use_cached_local_decision
}

fn describe_local_target(target: &LocalTarget) -> String {
    match target {
        LocalTarget::OllamaModel(model) => format!("model:{model}"),
        LocalTarget::McodaAgent(agent_id) => format!("agent:{agent_id}"),
    }
}

fn describe_local_candidate_labels(
    llm_config: &LlmConfig,
    local_agent_override: Option<&str>,
    local_targets: &[LocalTarget],
    count: usize,
) -> Vec<String> {
    let mut labels: Vec<String> = local_targets.iter().map(describe_local_target).collect();
    if labels.is_empty() {
        let configured_target = local_agent_override
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
        if let Some(target) = configured_target {
            labels.push(target.to_string());
        }
    }
    while labels.len() < count {
        labels.push(format!("local_candidate_{}", labels.len() + 1));
    }
    labels.truncate(count);
    labels
}

fn local_failure_recovery_action(
    attempt_index: usize,
    local_candidate_count: usize,
    primary_candidate_count: usize,
) -> &'static str {
    if attempt_index + 1 < local_candidate_count {
        "try_next_local_candidate"
    } else if primary_candidate_count > 0 {
        "fallback_to_primary"
    } else {
        "return_error"
    }
}

#[derive(Debug, Serialize)]
struct DelegationFailureRecord {
    ts: String,
    source: Option<String>,
    kind: String,
    task_type: String,
    mode: String,
    repo_id: Option<String>,
    repo_root: Option<String>,
    local_target: String,
    attempt: usize,
    recovery_action: String,
    error: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct LocalTargetFailureWindow {
    recent_failures: usize,
    last_failure_at_ms: u128,
}

#[derive(Debug, Deserialize)]
struct DelegationFailureHistoryLine {
    ts: String,
    kind: String,
    local_target: String,
    #[serde(default)]
    error: String,
}

fn env_u64(key: &str) -> Option<u64> {
    std::env::var(key).ok()?.trim().parse::<u64>().ok()
}

fn env_usize(key: &str) -> Option<usize> {
    std::env::var(key).ok()?.trim().parse::<usize>().ok()
}

fn local_target_failure_threshold() -> usize {
    env_usize(LOCAL_TARGET_FAILURE_THRESHOLD_ENV)
        .unwrap_or(DEFAULT_LOCAL_TARGET_FAILURE_THRESHOLD)
        .max(1)
}

fn local_target_failure_lookback() -> Duration {
    Duration::from_secs(
        env_u64(LOCAL_TARGET_FAILURE_LOOKBACK_ENV)
            .unwrap_or(DEFAULT_LOCAL_TARGET_FAILURE_LOOKBACK_SECS)
            .max(1),
    )
}

fn local_target_failure_cooldown() -> Duration {
    Duration::from_secs(
        env_u64(LOCAL_TARGET_FAILURE_COOLDOWN_ENV)
            .unwrap_or(DEFAULT_LOCAL_TARGET_FAILURE_COOLDOWN_SECS)
            .max(1),
    )
}

fn resolve_delegation_failure_history_path_from_root(
    global_state_dir: Option<&Path>,
) -> Result<PathBuf> {
    let base_dir = global_state_dir
        .map(Path::to_path_buf)
        .or_else(|| {
            std::env::var("DOCDEX_STATE_DIR").ok().and_then(|value| {
                let trimmed = value.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(PathBuf::from(trimmed))
                }
            })
        })
        .or_else(|| crate::state_paths::default_state_base_dir().ok())
        .ok_or_else(|| anyhow!("resolve delegation failure history state dir"))?;
    let errors_dir = base_dir.join("logs").join(DELEGATION_FAILURE_HISTORY_DIR);
    crate::state_layout::ensure_state_dir_secure(&errors_dir)?;
    Ok(errors_dir.join(DELEGATION_FAILURE_HISTORY_FILE))
}

fn resolve_delegation_failure_history_path(
    context: &DelegationFailureHistoryContext,
) -> Result<PathBuf> {
    resolve_delegation_failure_history_path_from_root(context.global_state_dir.as_deref())
}

fn append_delegation_failure_record(
    context: &DelegationFailureHistoryContext,
    record: &DelegationFailureRecord,
) -> Result<()> {
    let path = resolve_delegation_failure_history_path(context)?;
    let mut file = OpenOptions::new().create(true).append(true).open(&path)?;
    serde_json::to_writer(&mut file, record)?;
    file.write_all(b"\n")?;
    file.flush()?;
    Ok(())
}

fn record_local_delegation_failure(
    context: Option<&DelegationFailureHistoryContext>,
    task_type: TaskType,
    mode: DelegationMode,
    local_target: &str,
    attempt: usize,
    kind: &str,
    error: &str,
    recovery_action: &str,
) {
    let Some(context) = context else {
        return;
    };
    let record = DelegationFailureRecord {
        ts: Utc::now().to_rfc3339(),
        source: context.source.clone(),
        kind: kind.to_string(),
        task_type: task_type.as_str().to_string(),
        mode: mode.as_str().to_string(),
        repo_id: context.repo_id.clone(),
        repo_root: context.repo_root.clone(),
        local_target: local_target.to_string(),
        attempt,
        recovery_action: recovery_action.to_string(),
        error: error.to_string(),
    };
    if let Err(err) = append_delegation_failure_record(context, &record) {
        warn!(
            target: "docdexd",
            error = ?err,
            failure_kind = kind,
            local_target = local_target,
            "failed to write delegation failure history"
        );
    }
}

fn blocking_failure_for_cooldown(kind: &str, error: &str) -> bool {
    if kind == "local_completion_failed" {
        return true;
    }
    kind == "local_validation_failed"
        && !error
            .to_ascii_lowercase()
            .contains("delegation output must not include markdown fences")
}

fn load_recent_local_target_failures(
    state_dir_override: Option<&Path>,
) -> HashMap<String, LocalTargetFailureWindow> {
    let path = match resolve_delegation_failure_history_path_from_root(state_dir_override) {
        Ok(path) => path,
        Err(err) => {
            warn!(
                target: "docdexd",
                error = ?err,
                "failed to resolve delegation failure history path for cooldown checks"
            );
            return HashMap::new();
        }
    };
    if !path.exists() {
        return HashMap::new();
    }
    let file = match File::open(&path) {
        Ok(file) => file,
        Err(err) => {
            warn!(
                target: "docdexd",
                error = ?err,
                path = %path.display(),
                "failed to open delegation failure history for cooldown checks"
            );
            return HashMap::new();
        }
    };
    let now_ms = Utc::now().timestamp_millis().max(0) as u128;
    let lookback_ms = local_target_failure_lookback().as_millis() as u128;
    let cooldown_ms = local_target_failure_cooldown().as_millis() as u128;
    let threshold = local_target_failure_threshold();
    let mut failures: HashMap<String, LocalTargetFailureWindow> = HashMap::new();
    for line in BufReader::new(file)
        .lines()
        .map_while(std::result::Result::ok)
    {
        let Ok(record) = serde_json::from_str::<DelegationFailureHistoryLine>(&line) else {
            continue;
        };
        if !blocking_failure_for_cooldown(&record.kind, &record.error) {
            continue;
        }
        let target = record.local_target.trim();
        if target.is_empty() {
            continue;
        }
        let Ok(ts) = chrono::DateTime::parse_from_rfc3339(record.ts.trim()) else {
            continue;
        };
        let failure_at_ms = ts.timestamp_millis().max(0) as u128;
        if now_ms.saturating_sub(failure_at_ms) > lookback_ms {
            continue;
        }
        let entry = failures.entry(target.to_string()).or_default();
        entry.recent_failures = entry.recent_failures.saturating_add(1);
        entry.last_failure_at_ms = entry.last_failure_at_ms.max(failure_at_ms);
    }
    failures.retain(|_, window| {
        window.recent_failures >= threshold
            && window.last_failure_at_ms.saturating_add(cooldown_ms) > now_ms
    });
    failures
}

fn recent_failures_contain(
    recent_failures: &HashMap<String, LocalTargetFailureWindow>,
    label: &str,
) -> bool {
    let trimmed = label.trim();
    !trimmed.is_empty() && recent_failures.contains_key(trimmed)
}

fn agent_has_recent_local_failure(
    agent: &LocalAgentEntry,
    recent_failures: &HashMap<String, LocalTargetFailureWindow>,
) -> bool {
    recent_failures_contain(recent_failures, &format!("agent:{}", agent.agent_id))
        || recent_failures_contain(recent_failures, &format!("agent:{}", agent.agent_slug))
        || recent_failures_contain(recent_failures, &agent.agent_id)
        || recent_failures_contain(recent_failures, &agent.agent_slug)
}

fn model_has_recent_local_failure(
    model: &str,
    recent_failures: &HashMap<String, LocalTargetFailureWindow>,
) -> bool {
    recent_failures_contain(recent_failures, &format!("model:{model}"))
        || recent_failures_contain(recent_failures, model)
}

fn automatic_local_mcoda_agent_selection_eligible(
    agent: &LocalAgentEntry,
    recent_failures: &HashMap<String, LocalTargetFailureWindow>,
) -> bool {
    automatic_local_mcoda_agent_eligible(agent)
        && !agent_has_recent_local_failure(agent, recent_failures)
}

fn zero_cost_mcoda_agent_selection_eligible(
    agent: &LocalAgentEntry,
    recent_failures: &HashMap<String, LocalTargetFailureWindow>,
) -> bool {
    zero_cost_mcoda_agent_eligible(agent) && !agent_has_recent_local_failure(agent, recent_failures)
}

fn push_unique_target(targets: &mut Vec<LocalTarget>, target: LocalTarget) {
    if !targets.contains(&target) {
        targets.push(target);
    }
}

fn local_target_sort_key(target: &LocalTarget) -> String {
    match target {
        LocalTarget::OllamaModel(model) => format!("model:{model}"),
        LocalTarget::McodaAgent(agent_id) => format!("agent:{agent_id}"),
    }
}

fn rank_task_capability_local_targets(
    task_type: TaskType,
    library: &LocalModelLibrary,
    recent_failures: Option<&HashMap<String, LocalTargetFailureWindow>>,
) -> Vec<LocalTarget> {
    let mut candidates: Vec<(LocalTarget, i32, bool)> = Vec::new();
    for model in &library.models {
        if recent_failures
            .map(|failures| model_has_recent_local_failure(&model.name, failures))
            .unwrap_or(false)
        {
            continue;
        }
        let score = score_for_task(task_type, &model.capabilities);
        if score <= 0 {
            continue;
        }
        candidates.push((LocalTarget::OllamaModel(model.name.clone()), score, true));
    }
    for agent in &library.agents {
        if !recent_failures
            .map(|failures| automatic_local_mcoda_agent_selection_eligible(agent, failures))
            .unwrap_or_else(|| automatic_local_mcoda_agent_eligible(agent))
        {
            continue;
        }
        let score = score_for_task(task_type, &agent.capabilities);
        if score <= 0 {
            continue;
        }
        candidates.push((
            LocalTarget::McodaAgent(agent.agent_id.clone()),
            score,
            false,
        ));
    }
    candidates.sort_by(|left, right| {
        right
            .1
            .cmp(&left.1)
            .then_with(|| right.2.cmp(&left.2))
            .then_with(|| local_target_sort_key(&left.0).cmp(&local_target_sort_key(&right.0)))
    });
    candidates
        .into_iter()
        .map(|(target, _, _)| target)
        .collect()
}

fn rank_zero_cost_mcoda_agents<'a>(
    library: &'a LocalModelLibrary,
    recent_failures: Option<&HashMap<String, LocalTargetFailureWindow>>,
) -> Vec<&'a LocalAgentEntry> {
    let mut agents: Vec<&LocalAgentEntry> = library
        .agents
        .iter()
        .filter(|agent| {
            recent_failures
                .map(|failures| zero_cost_mcoda_agent_selection_eligible(agent, failures))
                .unwrap_or_else(|| zero_cost_mcoda_agent_eligible(agent))
        })
        .collect();
    agents.sort_by(|left, right| compare_zero_cost_mcoda_agents(left, right));
    agents
}

fn compare_zero_cost_mcoda_agents(left: &LocalAgentEntry, right: &LocalAgentEntry) -> Ordering {
    let left_key = (
        zero_cost_mcoda_capability_score(left),
        left.max_complexity.unwrap_or(-1),
        scaled_selection_rating(left.reasoning_rating),
        scaled_selection_rating(left.rating),
        selection_usage_rank(left.usage.as_deref()),
    );
    let right_key = (
        zero_cost_mcoda_capability_score(right),
        right.max_complexity.unwrap_or(-1),
        scaled_selection_rating(right.reasoning_rating),
        scaled_selection_rating(right.rating),
        selection_usage_rank(right.usage.as_deref()),
    );
    right_key
        .cmp(&left_key)
        .then_with(|| left.agent_slug.cmp(&right.agent_slug))
        .then_with(|| left.agent_id.cmp(&right.agent_id))
}

pub fn build_local_target_candidates_with_config(
    state_dir_override: Option<&Path>,
    llm_config: &LlmConfig,
    task_type: TaskType,
    library: &mut LocalModelLibrary,
) -> Vec<LocalTarget> {
    let recent_failures = load_recent_local_target_failures(state_dir_override);
    if llm_config.delegation.local_selection_policy
        != LOCAL_SELECTION_POLICY_MCODA_ZERO_COST_MOST_CAPABLE
    {
        return rank_task_capability_local_targets(task_type, library, Some(&recent_failures));
    }

    let mut targets = Vec::new();
    if llm_config.delegation.use_cached_local_decision {
        if let Some(agent) = resolve_cached_zero_cost_mcoda_agent(library, &recent_failures) {
            push_unique_target(
                &mut targets,
                LocalTarget::McodaAgent(agent.agent_id.clone()),
            );
        }
    }

    for agent in rank_zero_cost_mcoda_agents(library, Some(&recent_failures)) {
        push_unique_target(
            &mut targets,
            LocalTarget::McodaAgent(agent.agent_id.clone()),
        );
    }

    for target in rank_task_capability_local_targets(task_type, library, Some(&recent_failures)) {
        push_unique_target(&mut targets, target);
    }

    if llm_config.delegation.use_cached_local_decision {
        match targets.first() {
            Some(LocalTarget::McodaAgent(agent_id)) => {
                if let Some(agent) = library
                    .agents
                    .iter()
                    .find(|candidate| candidate.agent_id == *agent_id)
                {
                    library.cached_local_agent_selection = Some(CachedLocalAgentSelection {
                        policy: LOCAL_SELECTION_POLICY_MCODA_ZERO_COST_MOST_CAPABLE.to_string(),
                        agent_id: agent.agent_id.clone(),
                        agent_slug: agent.agent_slug.clone(),
                        selected_at_ms: Utc::now().timestamp_millis().max(0) as u128,
                    });
                    let _ = save_local_library(state_dir_override, library);
                }
            }
            _ => {
                if clear_cached_zero_cost_mcoda_selection(library) {
                    let _ = save_local_library(state_dir_override, library);
                }
            }
        }
    }

    targets
}

pub fn select_local_target_with_config(
    state_dir_override: Option<&Path>,
    llm_config: &LlmConfig,
    task_type: TaskType,
    library: &mut LocalModelLibrary,
) -> Option<LocalTarget> {
    build_local_target_candidates_with_config(state_dir_override, llm_config, task_type, library)
        .into_iter()
        .next()
}

pub fn update_cached_local_selection_from_completion(
    state_dir_override: Option<&Path>,
    llm_config: &LlmConfig,
    library: &mut LocalModelLibrary,
    completion: &LlmCompletion,
) -> bool {
    if llm_config.delegation.local_selection_policy
        != LOCAL_SELECTION_POLICY_MCODA_ZERO_COST_MOST_CAPABLE
        || !llm_config.delegation.use_cached_local_decision
    {
        return false;
    }
    let Some(agent) = resolve_completion_local_agent(library, completion) else {
        return false;
    };
    let changed = library
        .cached_local_agent_selection
        .as_ref()
        .map(|cached| {
            cached.policy != LOCAL_SELECTION_POLICY_MCODA_ZERO_COST_MOST_CAPABLE
                || cached.agent_id != agent.agent_id
                || cached.agent_slug != agent.agent_slug
        })
        .unwrap_or(true);
    if !changed {
        return false;
    }
    library.cached_local_agent_selection = Some(CachedLocalAgentSelection {
        policy: LOCAL_SELECTION_POLICY_MCODA_ZERO_COST_MOST_CAPABLE.to_string(),
        agent_id: agent.agent_id.clone(),
        agent_slug: agent.agent_slug.clone(),
        selected_at_ms: Utc::now().timestamp_millis().max(0) as u128,
    });
    let _ = save_local_library(state_dir_override, library);
    true
}

pub fn select_primary_target(
    task_type: TaskType,
    library: &LocalModelLibrary,
    local_target: Option<&LocalTarget>,
) -> Option<LocalTarget> {
    let recent_failures = load_recent_local_target_failures(None);
    rank_primary_targets(task_type, library, local_target, Some(&recent_failures))
        .into_iter()
        .next()
}

fn rank_primary_targets(
    task_type: TaskType,
    library: &LocalModelLibrary,
    local_target: Option<&LocalTarget>,
    recent_failures: Option<&HashMap<String, LocalTargetFailureWindow>>,
) -> Vec<LocalTarget> {
    let mut candidates: Vec<(LocalTarget, i32, bool)> = Vec::new();
    for agent in &library.agents {
        if !mcoda_agent_health_allows(agent.health_status.as_deref()) {
            continue;
        }
        if recent_failures
            .map(|failures| agent_has_recent_local_failure(agent, failures))
            .unwrap_or(false)
        {
            continue;
        }
        let score = score_for_task(task_type, &agent.capabilities);
        if score <= 0 {
            continue;
        }
        candidates.push((LocalTarget::McodaAgent(agent.agent_id.clone()), score, true));
    }
    for model in &library.models {
        if recent_failures
            .map(|failures| model_has_recent_local_failure(&model.name, failures))
            .unwrap_or(false)
        {
            continue;
        }
        let score = score_for_task(task_type, &model.capabilities);
        if score <= 0 {
            continue;
        }
        candidates.push((LocalTarget::OllamaModel(model.name.clone()), score, false));
    }
    if candidates.is_empty() {
        return Vec::new();
    }

    if let Some(local) = local_target {
        let filtered: Vec<(LocalTarget, i32, bool)> = candidates
            .iter()
            .cloned()
            .filter(|(target, _, _)| target != local)
            .collect();
        if !filtered.is_empty() {
            candidates = filtered;
        }
    }

    candidates.sort_by(|left, right| {
        right
            .1
            .cmp(&left.1)
            .then_with(|| right.2.cmp(&left.2))
            .then_with(|| local_target_sort_key(&left.0).cmp(&local_target_sort_key(&right.0)))
    });
    candidates
        .into_iter()
        .map(|(target, _, _)| target)
        .collect()
}

fn resolve_completion_local_agent<'a>(
    library: &'a LocalModelLibrary,
    completion: &LlmCompletion,
) -> Option<&'a LocalAgentEntry> {
    let adapter = completion.adapter.trim();
    if adapter.is_empty() {
        return None;
    }
    let model = completion
        .model
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let mut candidates: Vec<&LocalAgentEntry> = library
        .agents
        .iter()
        .filter(|agent| agent.adapter.eq_ignore_ascii_case(adapter))
        .filter(|agent| zero_cost_mcoda_agent_eligible(agent))
        .collect();
    if let Some(model) = model {
        candidates.retain(|agent| {
            agent.agent_id.eq_ignore_ascii_case(model)
                || agent.agent_slug.eq_ignore_ascii_case(model)
                || agent
                    .default_model
                    .as_deref()
                    .map(|value| value.eq_ignore_ascii_case(model))
                    .unwrap_or(false)
        });
    }
    if candidates.len() == 1 {
        candidates.into_iter().next()
    } else {
        None
    }
}

fn resolve_cached_zero_cost_mcoda_agent<'a>(
    library: &'a LocalModelLibrary,
    recent_failures: &HashMap<String, LocalTargetFailureWindow>,
) -> Option<&'a LocalAgentEntry> {
    let cached = library.cached_local_agent_selection.as_ref()?;
    if cached.policy != LOCAL_SELECTION_POLICY_MCODA_ZERO_COST_MOST_CAPABLE {
        return None;
    }
    library
        .agents
        .iter()
        .find(|agent| {
            agent.agent_id == cached.agent_id
                || (!cached.agent_slug.is_empty() && agent.agent_slug == cached.agent_slug)
        })
        .filter(|agent| zero_cost_mcoda_agent_selection_eligible(agent, recent_failures))
}

fn automatic_local_mcoda_agent_eligible(agent: &LocalAgentEntry) -> bool {
    mcoda_agent_health_allows(agent.health_status.as_deref())
        && !paid_or_expensive_local_mcoda_agent(agent)
}

fn paid_or_expensive_local_mcoda_agent(agent: &LocalAgentEntry) -> bool {
    agent
        .cost_per_million
        .filter(|value| value.is_finite() && *value > 0.0)
        .is_some()
        || matches_expensive_delegation_target(
            Some(&agent.agent_id),
            Some(&agent.agent_slug),
            agent.default_model.as_deref(),
            Some(&agent.adapter),
        )
}

fn zero_cost_mcoda_agent_eligible(agent: &LocalAgentEntry) -> bool {
    automatic_local_mcoda_agent_eligible(agent)
        && matches!(agent.cost_per_million, Some(cost) if cost <= 0.0)
        && zero_cost_mcoda_capability_score(agent) > 0
}

fn zero_cost_mcoda_capability_score(agent: &LocalAgentEntry) -> i32 {
    let has = |cap: &str| agent.capabilities.iter().any(|value| value == cap);
    let usage = agent
        .usage
        .as_deref()
        .map(str::trim)
        .unwrap_or_default()
        .to_ascii_lowercase();

    if (has("embedding") || has("vision"))
        && !(has("code_writer") || has("code_reviewer") || has("general_chat"))
    {
        return -100;
    }

    let mut score = 0;
    if has("code_writer") || usage == "code_writer" {
        score += 4;
    }
    if has("code_reviewer") || usage == "code_reviewer" {
        score += 4;
    }
    if has("general_chat") || usage == "general_chat" {
        score += 1;
    }
    score
}

fn scaled_selection_rating(value: Option<f64>) -> i64 {
    match value {
        Some(value) if value.is_finite() => (value.max(0.0) * 100.0).round() as i64,
        _ => -1,
    }
}

fn selection_usage_rank(value: Option<&str>) -> i32 {
    match value
        .map(str::trim)
        .unwrap_or_default()
        .to_ascii_lowercase()
        .as_str()
    {
        "code_writer" | "code_reviewer" => 2,
        "general_chat" => 1,
        _ => 0,
    }
}

fn clear_cached_zero_cost_mcoda_selection(library: &mut LocalModelLibrary) -> bool {
    let Some(cached) = library.cached_local_agent_selection.as_ref() else {
        return false;
    };
    if cached.policy != LOCAL_SELECTION_POLICY_MCODA_ZERO_COST_MOST_CAPABLE {
        return false;
    }
    library.cached_local_agent_selection = None;
    true
}

fn resolve_explicit_target(
    value: &str,
    library: Option<&LocalModelLibrary>,
) -> Option<LocalTarget> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(model) = parse_model_override(trimmed) {
        return Some(LocalTarget::OllamaModel(model));
    }
    if let Some(target) = parse_local_target_override(trimmed, library) {
        return Some(target);
    }
    Some(LocalTarget::McodaAgent(trimmed.to_string()))
}

pub fn build_primary_target_candidates(
    llm_config: &LlmConfig,
    task_type: TaskType,
    library: &LocalModelLibrary,
    local_target: Option<&LocalTarget>,
) -> Vec<LocalTarget> {
    let recent_failures = load_recent_local_target_failures(None);
    let mut targets = Vec::new();
    if let Some(target) =
        resolve_explicit_target(&llm_config.delegation.primary_agent_id, Some(library))
    {
        if Some(&target) != local_target {
            push_unique_target(&mut targets, target);
        }
    }
    for target in rank_primary_targets(task_type, library, local_target, Some(&recent_failures)) {
        push_unique_target(&mut targets, target);
    }
    targets
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

fn mcoda_agent_health_allows(status: Option<&str>) -> bool {
    let Some(status) = status.map(str::trim).filter(|value| !value.is_empty()) else {
        return true;
    };
    status.eq_ignore_ascii_case("healthy")
        || status.eq_ignore_ascii_case("unknown")
        || status == "-"
}

fn available_mcoda_agent_examples(registry: &McodaRegistry) -> String {
    let mut slugs: Vec<String> = registry
        .agents
        .iter()
        .filter(|agent| mcoda_agent_health_allows(agent.health_status.as_deref()))
        .map(|agent| agent.slug.clone())
        .collect();
    slugs.sort();
    slugs.dedup();
    if slugs.is_empty() {
        return " No healthy/unknown mcoda agents are currently available.".to_string();
    }
    let shown: Vec<String> = slugs.into_iter().take(8).collect();
    format!(" Available mcoda agents: {}", shown.join(", "))
}

fn ensure_mcoda_agent_available(agent: &McodaAgent, requested_id: &str) -> Result<()> {
    if mcoda_agent_health_allows(agent.health_status.as_deref()) {
        return Ok(());
    }
    let status = agent
        .health_status
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("unknown");
    Err(anyhow!(
        "mcoda agent unavailable: {requested_id} (health status: {status})"
    ))
}

fn resolve_mcoda_agent<'a>(
    registry: &'a McodaRegistry,
    requested_id: &str,
) -> Result<&'a McodaAgent> {
    let agent = registry
        .agent_by_id(requested_id)
        .or_else(|| registry.agent_by_slug(requested_id))
        .ok_or_else(|| {
            anyhow!(
                "mcoda agent not found: {requested_id}.{}",
                available_mcoda_agent_examples(registry)
            )
        })?;
    ensure_mcoda_agent_available(agent, requested_id)?;
    Ok(agent)
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
        if let Some(model) = parse_model_override(agent_id) {
            let base_url = resolve_local_ollama_base_url(llm_config)
                .ok_or_else(|| anyhow!("ollama base_url missing for local delegation"))?;
            return resolve_ollama_adapter(&base_url, &model);
        }
        let registry = McodaRegistry::load_default_db_only()
            .context("load mcoda registry")?
            .ok_or_else(|| anyhow!("mcoda registry not found"))?;
        let agent = resolve_mcoda_agent(&registry, agent_id)?;
        let adapter = resolve_agent_adapter(agent)
            .with_context(|| format!("resolve mcoda agent adapter {agent_id}"))?;
        return Ok(Arc::new(adapter));
    }

    if let Some(target) = local_target {
        match target {
            LocalTarget::McodaAgent(agent_id) => {
                let registry = McodaRegistry::load_default_db_only()
                    .context("load mcoda registry")?
                    .ok_or_else(|| anyhow!("mcoda registry not found"))?;
                let agent = resolve_mcoda_agent(&registry, agent_id)?;
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

fn resolve_delegation_client_candidates(
    llm_config: &LlmConfig,
    local_agent_override: Option<&str>,
    local_targets: &[LocalTarget],
) -> Result<Vec<Arc<dyn LlmClient>>> {
    let explicit_override = local_agent_override
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_some()
        || !llm_config.delegation.local_agent_id.trim().is_empty();
    if explicit_override {
        return Ok(vec![resolve_delegation_client(
            llm_config,
            local_agent_override,
            None,
        )?]);
    }

    let mut clients = Vec::new();
    for target in local_targets {
        match resolve_delegation_client(llm_config, None, Some(target)) {
            Ok(client) => clients.push(client),
            Err(err) => warn!(
                target: "docdexd",
                candidate = %describe_local_target(target),
                error = ?err,
                "failed to resolve local delegation candidate"
            ),
        }
    }
    if clients.is_empty() {
        clients.push(resolve_delegation_client(llm_config, None, None)?);
    }
    Ok(clients)
}

fn resolve_primary_client_candidates(
    llm_config: &LlmConfig,
    primary_targets: &[LocalTarget],
) -> Vec<Arc<dyn LlmClient>> {
    let mut clients = Vec::new();
    for target in primary_targets {
        match resolve_delegation_client(llm_config, None, Some(target)) {
            Ok(client) => clients.push(client),
            Err(err) => warn!(
                target: "docdexd",
                candidate = %describe_local_target(target),
                error = ?err,
                "failed to resolve primary delegation candidate"
            ),
        }
    }
    clients
}

pub fn resolve_primary_client(
    llm_config: &LlmConfig,
    primary_target: Option<&LocalTarget>,
) -> Result<Option<Arc<dyn LlmClient>>> {
    let agent_id = llm_config.delegation.primary_agent_id.trim();
    if agent_id.is_empty() {
        return resolve_primary_target(llm_config, primary_target);
    }
    if let Some(model) = parse_model_override(agent_id) {
        let base_url = resolve_local_ollama_base_url(llm_config)
            .ok_or_else(|| anyhow!("ollama base_url missing for primary delegation"))?;
        return match resolve_ollama_adapter(&base_url, &model) {
            Ok(client) => Ok(Some(client)),
            Err(err) => {
                warn!(
                    target: "docdexd",
                    error = ?err,
                    "failed to resolve primary model override"
                );
                resolve_primary_target(llm_config, primary_target)
            }
        };
    }
    let registry = match McodaRegistry::load_default_db_only() {
        Ok(Some(registry)) => registry,
        Ok(None) => {
            warn!(
                target: "docdexd",
                agent_id = %agent_id,
                "mcoda registry not found; primary delegation unavailable"
            );
            return resolve_primary_target(llm_config, primary_target);
        }
        Err(err) => {
            warn!(
                target: "docdexd",
                agent_id = %agent_id,
                error = ?err,
                "failed to load mcoda registry; primary delegation unavailable"
            );
            return resolve_primary_target(llm_config, primary_target);
        }
    };

    let agent = match resolve_mcoda_agent(&registry, agent_id) {
        Ok(agent) => agent,
        Err(err) => {
            warn!(
                target: "docdexd",
                agent_id = %agent_id,
                error = ?err,
                "primary agent unavailable in mcoda registry"
            );
            return resolve_primary_target(llm_config, primary_target);
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
            resolve_primary_target(llm_config, primary_target)
        }
    }
}

fn resolve_primary_target(
    llm_config: &LlmConfig,
    primary_target: Option<&LocalTarget>,
) -> Result<Option<Arc<dyn LlmClient>>> {
    let Some(target) = primary_target else {
        return Ok(None);
    };
    match resolve_delegation_client(llm_config, None, Some(target)) {
        Ok(client) => Ok(Some(client)),
        Err(err) => {
            warn!(
                target: "docdexd",
                error = ?err,
                "failed to resolve primary target"
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
    local_targets: &[LocalTarget],
    primary_targets: &[LocalTarget],
    task_type: TaskType,
    instruction: &str,
    context: &str,
    max_context_chars: usize,
    max_tokens_override: Option<u32>,
    timeout_ms_override: Option<u64>,
    mode: DelegationMode,
) -> Result<DelegationFlowResult> {
    run_delegation_flow_with_failure_history(
        llm_config,
        local_agent_override,
        local_targets,
        primary_targets,
        task_type,
        instruction,
        context,
        max_context_chars,
        max_tokens_override,
        timeout_ms_override,
        mode,
        None,
    )
    .await
}

pub(crate) async fn run_delegation_flow_with_failure_history(
    llm_config: &LlmConfig,
    local_agent_override: Option<&str>,
    local_targets: &[LocalTarget],
    primary_targets: &[LocalTarget],
    task_type: TaskType,
    instruction: &str,
    context: &str,
    max_context_chars: usize,
    max_tokens_override: Option<u32>,
    timeout_ms_override: Option<u64>,
    mode: DelegationMode,
    failure_history: Option<DelegationFailureHistoryContext>,
) -> Result<DelegationFlowResult> {
    let max_tokens = max_tokens_override
        .unwrap_or(llm_config.delegation.max_tokens)
        .max(1);
    let timeout_ms = timeout_ms_override
        .unwrap_or(llm_config.delegation.timeout_ms)
        .max(1);
    let timeout = Duration::from_millis(timeout_ms);
    let enforce_local = llm_config.delegation.enforce_local;
    let local_override = local_agent_override
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
        || !llm_config.delegation.local_agent_id.trim().is_empty();
    let local_available = !local_targets.is_empty() || local_override;
    if enforce_local && !local_available {
        return Err(DelegationEnforcementError {
            reason: "local delegation required but no local target is configured".to_string(),
        }
        .into());
    }
    let primary_blocked = enforce_local && !llm_config.delegation.allow_fallback_to_primary;
    let local_clients =
        resolve_delegation_client_candidates(llm_config, local_agent_override, local_targets)?;
    let local_client_labels = describe_local_candidate_labels(
        llm_config,
        local_agent_override,
        local_targets,
        local_clients.len(),
    );
    let primary_clients = if primary_blocked {
        Vec::new()
    } else {
        resolve_primary_client_candidates(llm_config, primary_targets)
    };
    let reevaluation = if llm_config.delegation.re_evaluate {
        resolve_re_evaluation_target(llm_config, local_agent_override, local_targets.first())
    } else {
        None
    };
    let reevaluation_primary_client =
        if reevaluation_should_use_primary_client(reevaluation.as_ref(), primary_targets) {
            primary_clients.first().cloned()
        } else {
            None
        };
    run_flow_with_client_candidates_with_failure_history(
        task_type,
        instruction,
        context,
        max_context_chars,
        mode,
        max_tokens,
        timeout,
        local_clients,
        local_client_labels,
        primary_clients,
        primary_blocked,
        reevaluation,
        reevaluation_primary_client,
        failure_history,
    )
    .await
}

#[cfg(test)]
pub(crate) async fn run_flow_with_client_candidates(
    task_type: TaskType,
    instruction: &str,
    context: &str,
    max_context_chars: usize,
    mode: DelegationMode,
    max_tokens: u32,
    timeout: Duration,
    local_clients: Vec<Arc<dyn LlmClient>>,
    primary_clients: Vec<Arc<dyn LlmClient>>,
    primary_blocked: bool,
    reevaluation: Option<DelegationReevaluation>,
    reevaluation_primary_client: Option<Arc<dyn LlmClient>>,
) -> Result<DelegationFlowResult> {
    run_flow_with_client_candidates_with_failure_history(
        task_type,
        instruction,
        context,
        max_context_chars,
        mode,
        max_tokens,
        timeout,
        local_clients,
        Vec::new(),
        primary_clients,
        primary_blocked,
        reevaluation,
        reevaluation_primary_client,
        None,
    )
    .await
}

pub(crate) async fn run_flow_with_client_candidates_with_failure_history(
    task_type: TaskType,
    instruction: &str,
    context: &str,
    max_context_chars: usize,
    mode: DelegationMode,
    max_tokens: u32,
    timeout: Duration,
    local_clients: Vec<Arc<dyn LlmClient>>,
    mut local_client_labels: Vec<String>,
    primary_clients: Vec<Arc<dyn LlmClient>>,
    primary_blocked: bool,
    reevaluation: Option<DelegationReevaluation>,
    reevaluation_primary_client: Option<Arc<dyn LlmClient>>,
    failure_history: Option<DelegationFailureHistoryContext>,
) -> Result<DelegationFlowResult> {
    let rendered = render_prompt(task_type, instruction, context, max_context_chars);
    let token_estimate = estimate_token_budget(&rendered.prompt, max_tokens);
    let mut warnings = Vec::new();
    if rendered.truncated {
        warnings.push("context truncated to fit delegation limits".to_string());
    }
    let mut truncated = rendered.truncated;
    let mut fallback_used = false;
    let mut primary_used = false;
    let mut local_tokens: u64 = 0;
    let mut primary_tokens: u64 = 0;
    while local_client_labels.len() < local_clients.len() {
        local_client_labels.push(format!("local_candidate_{}", local_client_labels.len() + 1));
    }
    local_client_labels.truncate(local_clients.len());

    let mut local_failure_reason: Option<String> = None;
    let mut local_duration = Duration::ZERO;
    let mut local_completion = None;
    for (index, local_client) in local_clients.iter().enumerate() {
        let local_started = Instant::now();
        let candidate_completion = match local_client
            .generate(&rendered.prompt, max_tokens, timeout)
            .await
        {
            Ok(completion) => {
                local_tokens = local_tokens
                    .saturating_add(completion_token_usage(&completion, &rendered.prompt));
                let mut completion = completion;
                let (normalized, stripped) = normalize_delegation_output(&completion.output);
                if stripped {
                    completion.output = normalized;
                    warnings.push("stripped markdown fences from delegation output".to_string());
                    warn!(
                        target: "docdexd",
                        source = "local",
                        "stripped markdown fences from delegation output"
                    );
                }
                match validate_output(task_type, &completion.output) {
                    Ok(()) => Some(completion),
                    Err(err) => {
                        let error_text = err.to_string();
                        local_failure_reason =
                            Some(format!("local_validation_failed: {error_text}"));
                        record_local_delegation_failure(
                            failure_history.as_ref(),
                            task_type,
                            mode,
                            local_client_labels
                                .get(index)
                                .map(String::as_str)
                                .unwrap_or("local_candidate"),
                            index + 1,
                            "local_validation_failed",
                            &error_text,
                            local_failure_recovery_action(
                                index,
                                local_clients.len(),
                                primary_clients.len(),
                            ),
                        );
                        warn!(
                            target: "docdexd",
                            fallback_reason = "local_validation_failed",
                            error = %err,
                            "delegation output validation failed"
                        );
                        None
                    }
                }
            }
            Err(err) => {
                let error_text = err.to_string();
                local_failure_reason = Some(format!("local_completion_failed: {error_text}"));
                record_local_delegation_failure(
                    failure_history.as_ref(),
                    task_type,
                    mode,
                    local_client_labels
                        .get(index)
                        .map(String::as_str)
                        .unwrap_or("local_candidate"),
                    index + 1,
                    "local_completion_failed",
                    &error_text,
                    local_failure_recovery_action(
                        index,
                        local_clients.len(),
                        primary_clients.len(),
                    ),
                );
                warn!(
                    target: "docdexd",
                    fallback_reason = "local_completion_failed",
                    error = ?err,
                    "delegation completion failed"
                );
                None
            }
        };
        local_duration = local_started.elapsed();
        if candidate_completion.is_some() {
            local_completion = candidate_completion;
            break;
        }
        if index + 1 < local_clients.len() {
            warnings.push(
                "local delegation candidate failed; trying alternate local target".to_string(),
            );
        }
    }

    let Some(local_completion) = local_completion else {
        let reason = local_failure_reason.unwrap_or_else(|| "local delegation failed".to_string());
        if !primary_clients.is_empty() {
            fallback_used = true;
            primary_used = true;
            warnings.push(format!(
                "local delegation failed ({reason}); using primary agent"
            ));
            warn!(
                target: "docdexd",
                fallback_reason = "fallback_to_primary",
                reason = %reason,
                "falling back to primary agent"
            );
            let mut last_primary_error = None;
            for (index, primary) in primary_clients.iter().enumerate() {
                match primary
                    .generate(&rendered.prompt, max_tokens, timeout)
                    .await
                {
                    Ok(completion) => {
                        primary_tokens = primary_tokens
                            .saturating_add(completion_token_usage(&completion, &rendered.prompt));
                        let mut completion = completion;
                        let (normalized, stripped) =
                            normalize_delegation_output(&completion.output);
                        if stripped {
                            completion.output = normalized;
                            warnings.push(
                                "stripped markdown fences from delegation output".to_string(),
                            );
                            warn!(
                                target: "docdexd",
                                source = "primary",
                                "stripped markdown fences from delegation output"
                            );
                        }
                        validate_output(task_type, &completion.output)
                            .map_err(|err| anyhow!(err.to_string()))?;
                        return Ok(DelegationFlowResult {
                            completion,
                            draft: false,
                            truncated,
                            warnings,
                            fallback_used,
                            primary_used,
                            token_estimate,
                            local_tokens,
                            primary_tokens,
                        });
                    }
                    Err(err) => {
                        warn!(
                            target: "docdexd",
                            error = ?err,
                            "delegation completion failed"
                        );
                        last_primary_error =
                            Some(anyhow!(err).context("primary agent completion failed"));
                    }
                }
                if index + 1 < primary_clients.len() {
                    warnings.push(
                        "primary delegation candidate failed; trying alternate primary target"
                            .to_string(),
                    );
                }
            }
            if let Some(err) = last_primary_error {
                return Err(err);
            }
        }
        warn!(
            target: "docdexd",
            fallback_reason = "local_no_primary",
            reason = %reason,
            "local delegation failed without primary fallback"
        );
        return Err(anyhow!(format!(
            "local delegation failed ({reason}); see logs or failure history for details"
        )));
    };

    if let Some(reevaluation) = reevaluation {
        let review_task = run_re_evaluation(
            reevaluation,
            task_type,
            instruction.to_string(),
            context.to_string(),
            local_completion.output.clone(),
            max_context_chars,
            token_estimate,
            local_duration,
            warnings.clone(),
            reevaluation_primary_client,
            max_tokens,
            timeout,
        );
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(review_task);
        } else {
            review_task.await;
        }
    }

    if matches!(mode, DelegationMode::DraftThenRefine) {
        if !primary_clients.is_empty() {
            primary_used = true;
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
            for (index, primary) in primary_clients.iter().enumerate() {
                match primary
                    .generate(&refine_rendered.prompt, max_tokens, timeout)
                    .await
                {
                    Ok(refined) => {
                        primary_tokens = primary_tokens.saturating_add(completion_token_usage(
                            &refined,
                            &refine_rendered.prompt,
                        ));
                        let mut refined = refined;
                        let (normalized, stripped) = normalize_delegation_output(&refined.output);
                        if stripped {
                            refined.output = normalized;
                            warnings.push(
                                "stripped markdown fences from delegation output".to_string(),
                            );
                            warn!(
                                target: "docdexd",
                                source = "primary",
                                "stripped markdown fences from delegation output"
                            );
                        }
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
                                primary_used,
                                token_estimate,
                                local_tokens,
                                primary_tokens,
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
                if index + 1 < primary_clients.len() {
                    warnings.push(
                        "primary refinement candidate failed; trying alternate primary target"
                            .to_string(),
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
                primary_used,
                token_estimate,
                local_tokens,
                primary_tokens,
            });
        }

        if primary_blocked {
            warnings.push("primary refinement skipped; local enforcement enabled".to_string());
            return Ok(DelegationFlowResult {
                completion: local_completion,
                draft: true,
                truncated,
                warnings,
                fallback_used,
                primary_used,
                token_estimate,
                local_tokens,
                primary_tokens,
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
            primary_used,
            token_estimate,
            local_tokens,
            primary_tokens,
        });
    }

    Ok(DelegationFlowResult {
        completion: local_completion,
        draft: true,
        truncated,
        warnings,
        fallback_used,
        primary_used,
        token_estimate,
        local_tokens,
        primary_tokens,
    })
}

async fn run_re_evaluation(
    reevaluation: DelegationReevaluation,
    task_type: TaskType,
    instruction: String,
    context: String,
    output: String,
    max_context_chars: usize,
    token_estimate: u64,
    local_duration: Duration,
    warnings: Vec<String>,
    primary_client: Option<Arc<dyn LlmClient>>,
    max_tokens: u32,
    timeout: Duration,
) {
    let review_rendered = render_review_prompt(&instruction, &context, &output, max_context_chars);
    let fallback_quality = fallback_quality_score(&warnings);
    let review_max_tokens = max_tokens.min(256).max(1);
    let review = if let Some(primary) = primary_client.as_ref() {
        match primary
            .generate(&review_rendered.prompt, review_max_tokens, timeout)
            .await
        {
            Ok(completion) => review_from_output(&completion.output, fallback_quality),
            Err(err) => {
                warn!(
                    target: "docdexd",
                    error = ?err,
                    "delegation review failed; using fallback quality"
                );
                review_from_output("", fallback_quality)
            }
        }
    } else {
        review_from_output("", fallback_quality)
    };

    let complexity = estimate_complexity(task_type, context.len());
    let budgets = compute_budgets(complexity);
    let cost_per_million = reevaluation.cost_per_million;
    let total_cost = if cost_per_million.is_finite() && cost_per_million > 0.0 {
        (token_estimate as f64 / 1_000_000.0) * cost_per_million
    } else {
        0.0
    };
    let run_score = compute_run_score(RunScoreInput {
        quality_score: review.quality_score,
        total_cost,
        duration_seconds: local_duration.as_secs_f64(),
        iterations: 1.0,
        budgets: Some(budgets),
        weights: None,
    });
    let raw_review_json = review
        .raw_json
        .and_then(|value| serde_json::to_string(&value).ok());
    let now = Utc::now().to_rfc3339();
    let run = AgentRunRating {
        agent_id: reevaluation.agent_id.clone(),
        command_name: "delegation".to_string(),
        discipline: None,
        complexity,
        quality_score: review.quality_score,
        tokens_total: token_estimate,
        duration_seconds: local_duration.as_secs_f64(),
        iterations: 1,
        total_cost,
        run_score,
        rating_version: "v1".to_string(),
        raw_review_json,
        created_at: now.clone(),
    };
    if let Err(err) = apply_agent_rating_default(
        &reevaluation.agent_id,
        &run,
        reevaluation.rating_window,
        &now,
    ) {
        warn!(
            target: "docdexd",
            error = ?err,
            "failed to apply mcoda agent rating update"
        );
    }
}

#[cfg(test)]
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
    primary_blocked: bool,
    reevaluation: Option<DelegationReevaluation>,
) -> Result<DelegationFlowResult> {
    run_flow_with_clients_with_failure_history(
        task_type,
        instruction,
        context,
        max_context_chars,
        mode,
        max_tokens,
        timeout,
        local_client,
        primary_client,
        primary_blocked,
        reevaluation,
        None,
    )
    .await
}

#[cfg(test)]
pub(crate) async fn run_flow_with_clients_with_failure_history(
    task_type: TaskType,
    instruction: &str,
    context: &str,
    max_context_chars: usize,
    mode: DelegationMode,
    max_tokens: u32,
    timeout: Duration,
    local_client: Arc<dyn LlmClient>,
    primary_client: Option<Arc<dyn LlmClient>>,
    primary_blocked: bool,
    reevaluation: Option<DelegationReevaluation>,
    failure_history: Option<DelegationFailureHistoryContext>,
) -> Result<DelegationFlowResult> {
    let reevaluation_primary_client = primary_client.clone();
    let primary_clients = if primary_blocked {
        Vec::new()
    } else {
        primary_client.into_iter().collect()
    };
    run_flow_with_client_candidates_with_failure_history(
        task_type,
        instruction,
        context,
        max_context_chars,
        mode,
        max_tokens,
        timeout,
        vec![local_client],
        Vec::new(),
        primary_clients,
        primary_blocked,
        reevaluation,
        reevaluation_primary_client,
        failure_history,
    )
    .await
}
