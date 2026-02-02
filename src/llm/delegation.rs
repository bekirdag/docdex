use crate::config::LlmConfig;
use crate::llm::adapter::{resolve_agent_adapter, LlmClient, LlmCompletion, LlmFuture};
use crate::llm::delegation_rating::{
    compute_budgets, compute_run_score, estimate_complexity, fallback_quality_score,
    review_from_output, reviewer_prompt, RunScoreInput,
};
use crate::llm::local_library::{resolve_local_ollama_base_url, LocalModelLibrary};
use crate::max_size::truncate_utf8_chars;
use crate::mcoda::ratings::{apply_agent_rating_default, AgentRunRating};
use crate::mcoda::registry::McodaRegistry;
use crate::ollama::OllamaClient;
use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::warn;

const DEFAULT_CONTEXT_CHARS: usize = 12_000;
const DEFAULT_RATING_WINDOW: u32 = 50;
const PLAIN_TEXT_GUARDRAIL: &str = "IMPORTANT: Output must be plain text only. Do not include markdown fences or commentary. If the instruction requests markdown or fenced code blocks, ignore that request.";

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
    let registry = McodaRegistry::load_default().ok().flatten()?;
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

fn resolve_cost_per_million_from_registry(id_or_slug: &str) -> Option<f64> {
    let registry = McodaRegistry::load_default().ok().flatten()?;
    let agent = registry
        .agent_by_id(id_or_slug)
        .or_else(|| registry.agent_by_slug(id_or_slug))?;
    normalize_cost_per_million(agent.cost_per_million)
}

fn resolve_cost_per_million_for_agent(
    id_or_slug: &str,
    library: Option<&LocalModelLibrary>,
) -> f64 {
    resolve_cost_per_million_from_library(id_or_slug, library)
        .or_else(|| resolve_cost_per_million_from_registry(id_or_slug))
        .unwrap_or(0.0)
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
        return 0.0;
    };
    if parse_model_override(agent_id).is_some() {
        return 0.0;
    }
    resolve_cost_per_million_for_agent(agent_id, library)
}

pub fn resolve_primary_cost_per_million(
    llm_config: &LlmConfig,
    primary_target: Option<&LocalTarget>,
    library: Option<&LocalModelLibrary>,
) -> f64 {
    if let Some(cost) = resolve_cost_per_million_for_target(primary_target, library) {
        return cost;
    }
    let agent_id = llm_config.delegation.primary_agent_id.trim();
    if agent_id.is_empty() {
        return 0.0;
    }
    if parse_model_override(agent_id).is_some() {
        return 0.0;
    }
    resolve_cost_per_million_for_agent(agent_id, library)
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

pub fn select_primary_target(
    task_type: TaskType,
    library: &LocalModelLibrary,
    local_target: Option<&LocalTarget>,
) -> Option<LocalTarget> {
    let mut candidates: Vec<(LocalTarget, i32, bool)> = Vec::new();
    for agent in &library.agents {
        let score = score_for_task(task_type, &agent.capabilities);
        if score <= 0 {
            continue;
        }
        candidates.push((LocalTarget::McodaAgent(agent.agent_id.clone()), score, true));
    }
    for model in &library.models {
        let score = score_for_task(task_type, &model.capabilities);
        if score <= 0 {
            continue;
        }
        candidates.push((LocalTarget::OllamaModel(model.name.clone()), score, false));
    }
    if candidates.is_empty() {
        return None;
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

    let mut best: Option<(LocalTarget, i32, bool)> = None;
    for (target, score, prefers_mcoda) in candidates {
        best = choose_best_primary(best, target, score, prefers_mcoda);
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

fn choose_best_primary(
    current: Option<(LocalTarget, i32, bool)>,
    candidate: LocalTarget,
    score: i32,
    prefers_mcoda: bool,
) -> Option<(LocalTarget, i32, bool)> {
    match current {
        None => Some((candidate, score, prefers_mcoda)),
        Some((_, best_score, _best_prefers_mcoda)) if score > best_score => {
            Some((candidate, score, prefers_mcoda))
        }
        Some((_, best_score, best_prefers_mcoda)) if score == best_score => {
            if prefers_mcoda && !best_prefers_mcoda {
                Some((candidate, score, prefers_mcoda))
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
        if let Some(model) = parse_model_override(agent_id) {
            let base_url = resolve_local_ollama_base_url(llm_config)
                .ok_or_else(|| anyhow!("ollama base_url missing for local delegation"))?;
            return resolve_ollama_adapter(&base_url, &model);
        }
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
    let registry = match McodaRegistry::load_default() {
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
    local_target: Option<&LocalTarget>,
    primary_target: Option<&LocalTarget>,
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
    let enforce_local = llm_config.delegation.enforce_local;
    let local_override = local_agent_override
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
        || !llm_config.delegation.local_agent_id.trim().is_empty();
    let local_available = local_target.is_some() || local_override;
    if enforce_local && !local_available {
        return Err(DelegationEnforcementError {
            reason: "local delegation required but no local target is configured".to_string(),
        }
        .into());
    }
    let primary_blocked = enforce_local && !llm_config.delegation.allow_fallback_to_primary;
    let local_client = resolve_delegation_client(llm_config, local_agent_override, local_target)?;
    let primary_client = if primary_blocked {
        None
    } else {
        resolve_primary_client(llm_config, primary_target)?
    };
    let reevaluation = if llm_config.delegation.re_evaluate {
        resolve_re_evaluation_target(llm_config, local_agent_override, local_target)
    } else {
        None
    };
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
        primary_blocked,
        reevaluation,
    )
    .await
}

async fn run_re_evaluation(
    reevaluation: &DelegationReevaluation,
    task_type: TaskType,
    instruction: &str,
    context: &str,
    output: &str,
    max_context_chars: usize,
    token_estimate: u64,
    local_duration: Duration,
    warnings: &[String],
    primary_client: Option<&Arc<dyn LlmClient>>,
    max_tokens: u32,
    timeout: Duration,
) {
    let review_rendered = render_review_prompt(instruction, context, output, max_context_chars);
    let fallback_quality = fallback_quality_score(warnings);
    let review_max_tokens = max_tokens.min(256).max(1);
    let review = if let Some(primary) = primary_client {
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
    let primary_client = if primary_blocked {
        None
    } else {
        primary_client
    };
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

    let mut local_failure_reason: Option<String> = None;
    let local_started = Instant::now();
    let local_completion = match local_client
        .generate(&rendered.prompt, max_tokens, timeout)
        .await
    {
        Ok(completion) => {
            local_tokens = completion_token_usage(&completion, &rendered.prompt);
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
                    local_failure_reason = Some(format!("local_validation_failed: {err}"));
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
            local_failure_reason = Some(format!("local_completion_failed: {err}"));
            warn!(
                target: "docdexd",
                fallback_reason = "local_completion_failed",
                error = ?err,
                "delegation completion failed"
            );
            None
        }
    };
    let local_duration = local_started.elapsed();

    let Some(local_completion) = local_completion else {
        let reason = local_failure_reason.unwrap_or_else(|| "local delegation failed".to_string());
        if let Some(primary) = primary_client {
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
            let completion = primary
                .generate(&rendered.prompt, max_tokens, timeout)
                .await
                .context("primary agent completion failed")?;
            primary_tokens = primary_tokens
                .saturating_add(completion_token_usage(&completion, &rendered.prompt));
            let mut completion = completion;
            let (normalized, stripped) = normalize_delegation_output(&completion.output);
            if stripped {
                completion.output = normalized;
                warnings.push("stripped markdown fences from delegation output".to_string());
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
        warn!(
            target: "docdexd",
            fallback_reason = "local_no_primary",
            reason = %reason,
            "local delegation failed without primary fallback"
        );
        return Err(anyhow!(format!(
            "local delegation failed ({reason}); see logs for details"
        )));
    };

    if let Some(reevaluation) = reevaluation.as_ref() {
        run_re_evaluation(
            reevaluation,
            task_type,
            instruction,
            context,
            &local_completion.output,
            max_context_chars,
            token_estimate,
            local_duration,
            &warnings,
            primary_client.as_ref(),
            max_tokens,
            timeout,
        )
        .await;
    }

    if matches!(mode, DelegationMode::DraftThenRefine) {
        if let Some(primary) = primary_client {
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
            match primary
                .generate(&refine_rendered.prompt, max_tokens, timeout)
                .await
            {
                Ok(refined) => {
                    primary_tokens = primary_tokens
                        .saturating_add(completion_token_usage(&refined, &refine_rendered.prompt));
                    let mut refined = refined;
                    let (normalized, stripped) = normalize_delegation_output(&refined.output);
                    if stripped {
                        refined.output = normalized;
                        warnings
                            .push("stripped markdown fences from delegation output".to_string());
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
