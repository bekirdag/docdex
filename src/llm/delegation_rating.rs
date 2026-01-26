use crate::llm::delegation::TaskType;
use chrono::DateTime;
use serde_json::Value;

const DEFAULT_REVIEW_PROMPT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/prompts/delegation/agent_rating.txt"
));
const COMPLEXITY_COOLDOWN_SECONDS: i64 = 60 * 60 * 24;

#[derive(Debug, Clone, Copy)]
pub struct RatingBudgets {
    pub cost_usd: f64,
    pub duration_seconds: f64,
    pub iterations: f64,
}

#[derive(Debug, Clone, Copy)]
pub struct RatingWeights {
    pub quality: f64,
    pub cost: f64,
    pub time: f64,
    pub iterations: f64,
}

#[derive(Debug, Clone, Copy)]
pub struct RunScoreInput {
    pub quality_score: f64,
    pub total_cost: f64,
    pub duration_seconds: f64,
    pub iterations: f64,
    pub budgets: Option<RatingBudgets>,
    pub weights: Option<RatingWeights>,
}

#[derive(Debug, Clone)]
pub struct ReviewOutcome {
    pub quality_score: f64,
    pub raw_json: Option<Value>,
    pub reasoning: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AgentRatingState {
    pub rating: Option<f64>,
    pub reasoning_rating: Option<f64>,
    pub rating_samples: Option<i64>,
    pub max_complexity: Option<i64>,
    pub complexity_samples: Option<i64>,
    pub complexity_updated_at: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AgentRatingUpdate {
    pub rating: f64,
    pub reasoning_rating: f64,
    pub rating_samples: i64,
    pub rating_last_score: f64,
    pub rating_updated_at: String,
    pub max_complexity: i64,
    pub complexity_samples: i64,
    pub complexity_updated_at: Option<String>,
}

pub const DEFAULT_RATING_WEIGHTS: RatingWeights = RatingWeights {
    quality: 1.0,
    cost: 0.15,
    time: 0.1,
    iterations: 0.2,
};

pub const DEFAULT_RATING_BUDGETS: RatingBudgets = RatingBudgets {
    cost_usd: 0.05,
    duration_seconds: 600.0,
    iterations: 2.0,
};

fn clamp(value: f64, min: f64, max: f64) -> f64 {
    value.max(min).min(max)
}

fn clamp_i64(value: i64, min: i64, max: i64) -> i64 {
    value.max(min).min(max)
}

fn safe_divide(value: f64, denom: f64) -> f64 {
    if !value.is_finite() || !denom.is_finite() || denom <= 0.0 {
        return 0.0;
    }
    value / denom
}

fn normalize_score(value: f64, max_value: f64) -> f64 {
    clamp(safe_divide(value, max_value), 0.0, 1.0)
}

fn normalize_budget(value: f64, budget: f64) -> f64 {
    clamp(safe_divide(value, budget), 0.0, 1.0)
}

pub fn compute_run_score(input: RunScoreInput) -> f64 {
    let weights = input.weights.unwrap_or(DEFAULT_RATING_WEIGHTS);
    let budgets = input.budgets.unwrap_or(DEFAULT_RATING_BUDGETS);
    let quality_norm = normalize_score(input.quality_score, 10.0);
    let cost_norm = normalize_budget(input.total_cost, budgets.cost_usd);
    let time_norm = normalize_budget(input.duration_seconds, budgets.duration_seconds);
    let iter_norm = normalize_budget(input.iterations, budgets.iterations);
    let weighted = weights.quality * quality_norm
        - weights.cost * cost_norm
        - weights.time * time_norm
        - weights.iterations * iter_norm;
    let clamped = clamp(weighted, 0.0, 1.0);
    (clamped * 1000.0).round() / 100.0
}

pub fn update_ema_rating(current: f64, score: f64, alpha: f64) -> f64 {
    if !current.is_finite() {
        return score;
    }
    if !score.is_finite() {
        return current;
    }
    let safe_alpha = clamp(alpha, 0.0, 1.0);
    let next = current + safe_alpha * (score - current);
    (next * 100.0).round() / 100.0
}

pub fn compute_alpha(window_size: u32) -> f64 {
    let size = window_size.max(1) as f64;
    2.0 / (size + 1.0)
}

pub fn compute_budgets(complexity: i64) -> RatingBudgets {
    let complexity = clamp_i64(complexity, 1, 10) as f64;
    let factor = clamp(complexity / 5.0, 0.5, 2.0);
    RatingBudgets {
        cost_usd: DEFAULT_RATING_BUDGETS.cost_usd * factor,
        duration_seconds: DEFAULT_RATING_BUDGETS.duration_seconds * factor,
        iterations: (DEFAULT_RATING_BUDGETS.iterations + complexity / 3.0)
            .round()
            .max(1.0),
    }
}

pub fn reviewer_prompt() -> &'static str {
    DEFAULT_REVIEW_PROMPT
}

pub fn extract_review_json(raw: &str) -> Option<Value> {
    if raw.trim().is_empty() {
        return None;
    }
    let mut candidate = raw;
    if let Some(start) = raw.find("```json") {
        let after = &raw[start + "```json".len()..];
        if let Some(end) = after.find("```") {
            candidate = &after[..end];
        }
    }
    let start = candidate.find('{')?;
    let end = candidate.rfind('}')?;
    if end <= start {
        return None;
    }
    serde_json::from_str(&candidate[start..=end]).ok()
}

pub fn fallback_quality_score(warnings: &[String]) -> f64 {
    let penalty = warnings.len() as f64 * 0.5;
    clamp(7.0 - penalty, 0.0, 10.0)
}

pub fn review_from_output(raw: &str, fallback_quality: f64) -> ReviewOutcome {
    let parsed = extract_review_json(raw);
    let quality_raw = parsed
        .as_ref()
        .and_then(|value| value.get("quality_score"))
        .and_then(|value| value.as_f64());
    let quality_score = clamp(quality_raw.unwrap_or(fallback_quality), 0.0, 10.0);
    let reasoning = parsed
        .as_ref()
        .and_then(|value| value.get("reasoning"))
        .and_then(|value| value.as_str())
        .map(|value| value.to_string());
    ReviewOutcome {
        quality_score,
        raw_json: parsed,
        reasoning,
    }
}

pub fn estimate_complexity(task_type: TaskType, context_chars: usize) -> i64 {
    let mut score = match task_type {
        TaskType::FormatCode => 2,
        TaskType::WriteDocstring => 3,
        TaskType::ScaffoldBoilerplate => 4,
        TaskType::RefactorSimple => 6,
        TaskType::GenerateTests => 6,
    };
    if context_chars > 12_000 {
        score += 3;
    } else if context_chars > 8_000 {
        score += 2;
    } else if context_chars > 4_000 {
        score += 1;
    }
    clamp_i64(score, 1, 10)
}

fn parse_timestamp_ms(value: &str) -> Option<i64> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|dt| dt.timestamp_millis())
}

pub fn compute_agent_update(
    state: &AgentRatingState,
    run_score: f64,
    quality_score: f64,
    complexity: i64,
    now: &str,
    rating_window: u32,
) -> AgentRatingUpdate {
    let alpha = compute_alpha(rating_window);
    let base_rating = state.rating.unwrap_or(run_score);
    let updated_rating = update_ema_rating(base_rating, run_score, alpha);
    let base_reasoning = state.reasoning_rating.unwrap_or(base_rating);
    let updated_reasoning = update_ema_rating(base_reasoning, run_score, alpha);
    let updated_samples = state.rating_samples.unwrap_or(0) + 1;

    let mut max_complexity = state.max_complexity.unwrap_or(5);
    let mut complexity_samples = state.complexity_samples.unwrap_or(0);
    let mut complexity_updated_at = state.complexity_updated_at.clone();
    let promote_threshold = 7.5;
    let demote_threshold = 4.0;
    let last_update = state
        .complexity_updated_at
        .as_deref()
        .and_then(parse_timestamp_ms);
    let now_ms = parse_timestamp_ms(now).unwrap_or(0);
    let can_adjust = last_update
        .map(|value| now_ms - value >= COMPLEXITY_COOLDOWN_SECONDS * 1000)
        .unwrap_or(true);
    if can_adjust {
        if run_score >= promote_threshold && quality_score >= 7.0 && complexity >= max_complexity {
            max_complexity = clamp_i64(max_complexity + 1, 1, 10);
            complexity_samples += 1;
            complexity_updated_at = Some(now.to_string());
        } else if run_score <= demote_threshold && complexity <= max_complexity {
            max_complexity = clamp_i64(max_complexity - 1, 1, 10);
            complexity_samples += 1;
            complexity_updated_at = Some(now.to_string());
        }
    }

    AgentRatingUpdate {
        rating: updated_rating,
        reasoning_rating: updated_reasoning,
        rating_samples: updated_samples,
        rating_last_score: run_score,
        rating_updated_at: now.to_string(),
        max_complexity,
        complexity_samples,
        complexity_updated_at,
    }
}
