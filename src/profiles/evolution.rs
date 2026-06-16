use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

use crate::llm::adapter::{LlmClient, LlmCompletion, LlmFuture};
use crate::metrics;
use crate::ollama::OllamaClient;
use crate::profiles::manager::PreferenceRecall;
use crate::profiles::{PreferenceCategory, ProfileEmbedder, ProfileManager};
use std::collections::BTreeSet;
use tracing::{info, warn};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvolutionAction {
    Add,
    Update,
    Ignore,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct EvolutionDecision {
    pub action: EvolutionAction,
    pub target_preference_id: Option<String>,
    pub new_content: Option<String>,
    pub reasoning: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct EvolutionOutcome {
    pub action: EvolutionAction,
    pub preference_id: Option<String>,
    pub reasoning: String,
}

pub struct EvolutionEngine {
    manager: ProfileManager,
    embedder: ProfileEmbedder,
    llm: Arc<dyn LlmClient>,
    max_tokens: u32,
    timeout: Duration,
    retries: usize,
    recall_k: usize,
}

const STRONG_MATCH_THRESHOLD: f32 = 0.82;
const MIN_MATCH_TOKENS: usize = 2;
const MIN_MATCH_CHARS: usize = 10;

impl EvolutionEngine {
    pub fn new(
        manager: ProfileManager,
        embedder: ProfileEmbedder,
        llm: Arc<dyn LlmClient>,
    ) -> Self {
        Self {
            manager,
            embedder,
            llm,
            max_tokens: 256,
            timeout: Duration::from_secs(8),
            retries: 2,
            recall_k: 8,
        }
    }

    async fn call_llm_for_decision(&self, prompt: &str) -> Result<EvolutionDecision> {
        let response = self
            .llm
            .generate(prompt, self.max_tokens, self.timeout)
            .await
            .context("evolution decision generate")?;
        parse_decision(&response.output)
    }

    async fn decide_with_retry(&self, prompt: &str) -> Result<EvolutionDecision> {
        let mut last_err: Option<anyhow::Error> = None;
        for attempt in 0..=self.retries {
            match self.call_llm_for_decision(prompt).await {
                Ok(decision) => match decision.validate() {
                    Ok(()) => return Ok(decision),
                    Err(err) => {
                        metrics::global().inc_profile_evolution_retry();
                        warn!(attempt, error = err, "evolution decision validation failed");
                        last_err = Some(anyhow::anyhow!(err));
                    }
                },
                Err(err) => {
                    metrics::global().inc_profile_evolution_retry();
                    warn!(attempt, error = ?err, "evolution decision parse failed");
                    last_err = Some(err);
                }
            }
        }
        if let Some(err) = last_err {
            metrics::global().inc_profile_evolution_invalid();
            return Ok(EvolutionDecision {
                action: EvolutionAction::Ignore,
                target_preference_id: None,
                new_content: None,
                reasoning: Some(format!("invalid_decision: {err}")),
            });
        }
        metrics::global().inc_profile_evolution_invalid();
        Ok(EvolutionDecision {
            action: EvolutionAction::Ignore,
            target_preference_id: None,
            new_content: None,
            reasoning: Some("invalid_decision".to_string()),
        })
    }

    pub async fn evolve(
        &self,
        agent_id: &str,
        category: PreferenceCategory,
        new_fact: &str,
    ) -> Result<EvolutionOutcome> {
        let started = std::time::Instant::now();
        let query_embedding = self.embedder.embed(new_fact).await?;
        let recalled = self.manager.search_preferences_for_evolution(
            agent_id,
            &query_embedding,
            self.recall_k,
        )?;
        let strong_match = find_strong_match_id(&recalled, new_fact);
        let prompt = build_evolution_prompt(&recalled, new_fact);
        let mut decision = self.decide_with_retry(&prompt).await?;
        if decision.action == EvolutionAction::Add {
            if let Some((match_id, score)) = strong_match.as_ref() {
                decision.action = EvolutionAction::Update;
                decision.target_preference_id = Some(match_id.clone());
                if decision
                    .new_content
                    .as_ref()
                    .map(|value| value.trim().is_empty())
                    .unwrap_or(true)
                {
                    decision.new_content = Some(new_fact.trim().to_string());
                }
                decision.reasoning = Some(append_reason(
                    decision.reasoning.clone(),
                    &format!("heuristic_update(score={score:.2})"),
                ));
            }
        }
        let mut reasoning = decision
            .reasoning
            .clone()
            .unwrap_or_else(|| "no_reasoning".to_string());

        match decision.action {
            EvolutionAction::Add => {
                let content = decision.new_content.as_deref().unwrap_or(new_fact).trim();
                let embedding = self.embedder.embed_with_metadata(content).await?;
                let preference = self.manager.add_preference_with_embedding_metadata(
                    agent_id,
                    content,
                    &embedding.embedding,
                    category,
                    now_epoch_ms(),
                    Some(&embedding.provider),
                    Some(&embedding.model),
                )?;
                let outcome = EvolutionOutcome {
                    action: EvolutionAction::Add,
                    preference_id: Some(preference.id),
                    reasoning,
                };
                metrics::global().inc_profile_evolution_decision();
                metrics::global().record_profile_evolution_latency(started.elapsed().as_millis());
                info!(
                    agent_id,
                    action = "add",
                    latency_ms = started.elapsed().as_millis(),
                    "profile evolution applied"
                );
                Ok(outcome)
            }
            EvolutionAction::Update => {
                let mut target = decision.target_preference_id.clone().unwrap_or_default();
                let target_in_recall = recalled.iter().any(|item| item.id == target);
                if !target_in_recall {
                    if let Some((match_id, score)) = strong_match.as_ref() {
                        target = match_id.clone();
                        reasoning = append_reason(
                            Some(reasoning),
                            &format!("heuristic_target(score={score:.2})"),
                        );
                    } else {
                        let outcome = EvolutionOutcome {
                            action: EvolutionAction::Ignore,
                            preference_id: None,
                            reasoning: format!("{reasoning}; target_not_found"),
                        };
                        metrics::global().inc_profile_evolution_decision();
                        metrics::global()
                            .record_profile_evolution_latency(started.elapsed().as_millis());
                        info!(
                            agent_id,
                            action = "ignore",
                            latency_ms = started.elapsed().as_millis(),
                            "profile evolution applied"
                        );
                        return Ok(outcome);
                    }
                }
                let content = decision.new_content.as_deref().unwrap_or(new_fact).trim();
                let embedding = self.embedder.embed_with_metadata(content).await?;
                self.manager.update_preference_with_embedding_metadata(
                    &target,
                    content,
                    &embedding.embedding,
                    now_epoch_ms(),
                    Some(&embedding.provider),
                    Some(&embedding.model),
                )?;
                let outcome = EvolutionOutcome {
                    action: EvolutionAction::Update,
                    preference_id: Some(target),
                    reasoning,
                };
                metrics::global().inc_profile_evolution_decision();
                metrics::global().record_profile_evolution_latency(started.elapsed().as_millis());
                info!(
                    agent_id,
                    action = "update",
                    latency_ms = started.elapsed().as_millis(),
                    "profile evolution applied"
                );
                Ok(outcome)
            }
            EvolutionAction::Ignore => {
                let outcome = EvolutionOutcome {
                    action: EvolutionAction::Ignore,
                    preference_id: None,
                    reasoning,
                };
                metrics::global().inc_profile_evolution_decision();
                metrics::global().record_profile_evolution_latency(started.elapsed().as_millis());
                info!(
                    agent_id,
                    action = "ignore",
                    latency_ms = started.elapsed().as_millis(),
                    "profile evolution applied"
                );
                Ok(outcome)
            }
        }
    }
}

fn append_reason(existing: Option<String>, suffix: &str) -> String {
    let base = existing.unwrap_or_else(|| "no_reasoning".to_string());
    if base.contains(suffix) {
        base
    } else {
        format!("{base}; {suffix}")
    }
}

fn normalize_text(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if ch.is_whitespace() {
            out.push(' ');
        }
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn token_set(text: &str) -> BTreeSet<String> {
    text.split_whitespace()
        .map(|value| value.to_string())
        .collect()
}

fn jaccard_score(left: &BTreeSet<String>, right: &BTreeSet<String>) -> f32 {
    if left.is_empty() || right.is_empty() {
        return 0.0;
    }
    let intersection = left.intersection(right).count();
    let union = left.len() + right.len() - intersection;
    if union == 0 {
        0.0
    } else {
        intersection as f32 / union as f32
    }
}

fn match_score(existing: &str, new_fact: &str) -> f32 {
    let existing_norm = normalize_text(existing);
    let new_norm = normalize_text(new_fact);
    if existing_norm.is_empty() || new_norm.is_empty() {
        return 0.0;
    }
    if existing_norm == new_norm {
        return 1.0;
    }
    let tokens_existing = token_set(&existing_norm);
    let tokens_new = token_set(&new_norm);
    let jaccard = jaccard_score(&tokens_existing, &tokens_new);
    let (shorter, longer) = if existing_norm.len() <= new_norm.len() {
        (existing_norm.as_str(), new_norm.as_str())
    } else {
        (new_norm.as_str(), existing_norm.as_str())
    };
    let substring = if longer.contains(shorter) {
        shorter.len() as f32 / longer.len() as f32
    } else {
        0.0
    };
    substring.max(jaccard)
}

fn has_min_signal(text: &str) -> bool {
    let token_count = text.split_whitespace().count();
    token_count >= MIN_MATCH_TOKENS || text.len() >= MIN_MATCH_CHARS
}

fn find_strong_match_id(recalled: &[PreferenceRecall], new_fact: &str) -> Option<(String, f32)> {
    let new_norm = normalize_text(new_fact);
    if !has_min_signal(&new_norm) {
        return None;
    }
    let mut best: Option<(String, f32, i64)> = None;
    for item in recalled {
        let score = match_score(&item.content, new_fact);
        if score < STRONG_MATCH_THRESHOLD {
            continue;
        }
        match &best {
            Some((_, best_score, best_updated)) => {
                if score > *best_score
                    || (score == *best_score && item.last_updated > *best_updated)
                {
                    best = Some((item.id.clone(), score, item.last_updated));
                }
            }
            None => best = Some((item.id.clone(), score, item.last_updated)),
        }
    }
    best.map(|(id, score, _)| (id, score))
}

pub fn build_ollama_evolution_client(base_url: &str, model: &str) -> Result<Arc<dyn LlmClient>> {
    let trimmed = model.trim();
    if trimmed.is_empty() {
        anyhow::bail!("llm model is not configured");
    }
    let client = OllamaClient::new(base_url.to_string()).context("invalid ollama base URL")?;
    Ok(Arc::new(OllamaEvolutionClient {
        client,
        model: trimmed.to_string(),
    }))
}

struct OllamaEvolutionClient {
    client: OllamaClient,
    model: String,
}

impl LlmClient for OllamaEvolutionClient {
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

fn build_evolution_prompt(recalled: &[PreferenceRecall], new_fact: &str) -> String {
    let mut lines = Vec::new();
    lines.push("You are the Memory Manager for an AI coding assistant.".to_string());
    lines.push("Current Memory State regarding topic: [".to_string());
    for item in recalled {
        let recency = format_recency(item.last_updated);
        lines.push(format!(
            "  {{ \"id\": \"{}\", \"content\": \"{}\", \"recency\": \"{}\" }}",
            item.id, item.content, recency
        ));
    }
    lines.push("]".to_string());
    lines.push(format!("New User Input: \"{}\"", new_fact.trim()));
    lines.push(String::new());
    lines.push("Determine the correct memory operation.".to_string());
    lines.push("1. ADD: The input is a new fact.".to_string());
    lines.push(
        "2. UPDATE: The input contradicts or refines an existing fact (provide target_id)."
            .to_string(),
    );
    lines.push("3. IGNORE: The input is conversational noise or already known.".to_string());
    lines.push(String::new());
    lines.push("Return ONLY a JSON object.".to_string());
    lines.join("\n")
}

fn parse_decision(raw: &str) -> Result<EvolutionDecision> {
    let cleaned = strip_code_fences(raw);
    let payload = extract_json_object(&cleaned).unwrap_or_else(|| cleaned.as_str());
    let decision: EvolutionDecision =
        serde_json::from_str(payload).context("parse evolution decision json")?;
    Ok(decision)
}

fn strip_code_fences(raw: &str) -> String {
    let mut lines = Vec::new();
    for line in raw.lines() {
        if line.trim_start().starts_with("```") {
            continue;
        }
        lines.push(line);
    }
    lines.join("\n").trim().to_string()
}

fn extract_json_object(raw: &str) -> Option<&str> {
    let start = raw.find('{')?;
    let end = raw.rfind('}')?;
    if end < start {
        return None;
    }
    Some(&raw[start..=end])
}

fn format_recency(last_updated: i64) -> String {
    let now = now_epoch_ms();
    if last_updated <= 0 || now <= last_updated {
        return "just now".to_string();
    }
    let delta_ms = now.saturating_sub(last_updated);
    let minute = 60_000i64;
    let hour = 60 * minute;
    let day = 24 * hour;
    let week = 7 * day;
    let month = 30 * day;
    if delta_ms < minute {
        "moments ago".to_string()
    } else if delta_ms < hour {
        let minutes = delta_ms / minute;
        format!("{minutes} minutes ago")
    } else if delta_ms < day {
        let hours = delta_ms / hour;
        format!("{hours} hours ago")
    } else if delta_ms < week {
        let days = delta_ms / day;
        format!("{days} days ago")
    } else if delta_ms < month {
        let weeks = delta_ms / week;
        format!("{weeks} weeks ago")
    } else {
        let months = delta_ms / month;
        format!("{months} months ago")
    }
}

fn now_epoch_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::llm::adapter::{LlmClient, LlmCompletion, LlmFuture};
    use tempfile::tempdir;

    #[test]
    fn prompt_builder_includes_memory_and_json_instruction() {
        let recalled = vec![PreferenceRecall {
            id: "pref-1".to_string(),
            content: "Prefer Vitest for unit tests".to_string(),
            last_updated: now_epoch_ms() - 86_400_000,
        }];
        let prompt = build_evolution_prompt(&recalled, "Use Vitest now");
        assert!(prompt.contains("pref-1"));
        assert!(prompt.contains("Prefer Vitest for unit tests"));
        assert!(prompt.contains("Return ONLY a JSON object."));
    }

    struct StubLlm {
        output: String,
    }

    impl LlmClient for StubLlm {
        fn generate<'a>(
            &'a self,
            _prompt: &'a str,
            _max_tokens: u32,
            _timeout: Duration,
        ) -> LlmFuture<'a> {
            let output = self.output.clone();
            Box::pin(async move {
                Ok(LlmCompletion {
                    output,
                    adapter: "stub".to_string(),
                    model: None,
                    metadata: None,
                })
            })
        }
    }

    #[tokio::test]
    async fn evolve_add_inserts_preference() -> Result<()> {
        let dir = tempdir()?;
        let manager = ProfileManager::new(dir.path(), 2)?;
        manager.create_agent("agent-add", "test", 1)?;
        let embedder = ProfileEmbedder::new_test(2, vec![0.0, 0.0])?;
        let llm = Arc::new(StubLlm {
            output: "{ \"action\": \"ADD\", \"target_preference_id\": null, \"new_content\": \"Prefer Vitest\", \"reasoning\": \"new\" }".to_string(),
        });
        let engine = EvolutionEngine::new(manager.clone(), embedder, llm);

        let outcome = engine
            .evolve("agent-add", PreferenceCategory::Style, "Use Vitest")
            .await?;
        assert_eq!(outcome.action, EvolutionAction::Add);

        let results = manager.search_preferences("agent-add", &[0.0, 0.0], 5)?;
        assert!(results
            .iter()
            .any(|item| item.preference.content == "Prefer Vitest"));
        Ok(())
    }

    #[tokio::test]
    async fn evolve_update_updates_preference() -> Result<()> {
        let dir = tempdir()?;
        let manager = ProfileManager::new(dir.path(), 2)?;
        manager.create_agent("agent-update", "test", 1)?;
        let existing = manager.add_preference(
            "agent-update",
            "Prefer Jest",
            &[0.0, 0.0],
            PreferenceCategory::Tooling,
            10,
        )?;
        let embedder = ProfileEmbedder::new_test(2, vec![0.0, 0.0])?;
        let llm = Arc::new(StubLlm {
            output: format!(
                "{{ \"action\": \"UPDATE\", \"target_preference_id\": \"{}\", \"new_content\": \"Prefer Vitest\", \"reasoning\": \"update\" }}",
                existing.id
            ),
        });
        let engine = EvolutionEngine::new(manager.clone(), embedder, llm);

        let outcome = engine
            .evolve("agent-update", PreferenceCategory::Tooling, "Use Vitest")
            .await?;
        assert_eq!(outcome.action, EvolutionAction::Update);

        let results = manager.search_preferences("agent-update", &[0.0, 0.0], 5)?;
        assert!(results
            .iter()
            .any(|item| item.preference.content == "Prefer Vitest"));
        Ok(())
    }

    #[tokio::test]
    async fn evolve_ignore_keeps_preferences() -> Result<()> {
        let dir = tempdir()?;
        let manager = ProfileManager::new(dir.path(), 2)?;
        manager.create_agent("agent-ignore", "test", 1)?;
        manager.add_preference(
            "agent-ignore",
            "Prefer Jest",
            &[0.0, 0.0],
            PreferenceCategory::Tooling,
            10,
        )?;
        let embedder = ProfileEmbedder::new_test(2, vec![0.0, 0.0])?;
        let llm = Arc::new(StubLlm {
            output: "{ \"action\": \"IGNORE\", \"target_preference_id\": null, \"new_content\": null, \"reasoning\": \"noise\" }".to_string(),
        });
        let engine = EvolutionEngine::new(manager.clone(), embedder, llm);

        let outcome = engine
            .evolve("agent-ignore", PreferenceCategory::Tooling, "Use Jest")
            .await?;
        assert_eq!(outcome.action, EvolutionAction::Ignore);

        let results = manager.search_preferences("agent-ignore", &[0.0, 0.0], 5)?;
        assert!(results
            .iter()
            .any(|item| item.preference.content == "Prefer Jest"));
        Ok(())
    }

    #[tokio::test]
    async fn evolve_add_upgraded_to_update_on_strong_match() -> Result<()> {
        let dir = tempdir()?;
        let manager = ProfileManager::new(dir.path(), 2)?;
        manager.create_agent("agent-heuristic", "test", 1)?;
        let existing = manager.add_preference(
            "agent-heuristic",
            "Prefer Jest for unit tests",
            &[0.0, 0.0],
            PreferenceCategory::Tooling,
            10,
        )?;
        let embedder = ProfileEmbedder::new_test(2, vec![0.0, 0.0])?;
        let llm = Arc::new(StubLlm {
            output: "{ \"action\": \"ADD\", \"target_preference_id\": null, \"new_content\": \"Prefer Jest for unit tests\", \"reasoning\": \"new\" }".to_string(),
        });
        let engine = EvolutionEngine::new(manager.clone(), embedder, llm);

        let outcome = engine
            .evolve(
                "agent-heuristic",
                PreferenceCategory::Tooling,
                "Prefer Jest for unit tests",
            )
            .await?;
        assert_eq!(outcome.action, EvolutionAction::Update);
        assert_eq!(outcome.preference_id, Some(existing.id));
        let prefs = manager.list_preferences(Some("agent-heuristic"))?;
        assert_eq!(prefs.len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn invalid_json_defaults_to_ignore() -> Result<()> {
        let dir = tempdir()?;
        let manager = ProfileManager::new(dir.path(), 2)?;
        manager.create_agent("agent-invalid", "test", 1)?;
        let embedder = ProfileEmbedder::new_test(2, vec![0.0, 0.0])?;
        let llm = Arc::new(StubLlm {
            output: "not json".to_string(),
        });
        let mut engine = EvolutionEngine::new(manager, embedder, llm);
        engine.retries = 1;

        let outcome = engine
            .evolve("agent-invalid", PreferenceCategory::Style, "Use Vitest")
            .await?;
        assert_eq!(outcome.action, EvolutionAction::Ignore);
        Ok(())
    }
}

impl EvolutionDecision {
    pub fn validate(&self) -> Result<(), &'static str> {
        match self.action {
            EvolutionAction::Add => {
                if self
                    .new_content
                    .as_ref()
                    .map(|v| v.trim().is_empty())
                    .unwrap_or(true)
                {
                    return Err("new_content_required");
                }
            }
            EvolutionAction::Update => {
                if self
                    .target_preference_id
                    .as_ref()
                    .map(|v| v.trim().is_empty())
                    .unwrap_or(true)
                {
                    return Err("target_preference_id_required");
                }
                if self
                    .new_content
                    .as_ref()
                    .map(|v| v.trim().is_empty())
                    .unwrap_or(true)
                {
                    return Err("new_content_required");
                }
            }
            EvolutionAction::Ignore => {}
        }
        Ok(())
    }
}
