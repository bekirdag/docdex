use crate::hardware::{self, HardwareProfile, ModelTier};
use anyhow::{Context, Result};
use serde::Deserialize;
use std::cmp::Ordering;
use std::sync::OnceLock;

pub mod adapter;
pub mod delegation;
pub mod delegation_rating;
pub mod local_library;

const LLMLIST_JSON: &str = include_str!("../docs/llm_list.json");
const EXPENSIVE_MODELS_JSON: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/docs/expensive_models.json"
));

#[derive(Clone, Deserialize)]
pub struct LlmModel {
    pub id: String,
    #[serde(rename = "displayName")]
    pub display_name: String,
    #[serde(rename = "minRamGb")]
    pub min_ram_gb: f64,
    #[serde(default)]
    pub requires_gpu: bool,
    pub description: String,
}

#[derive(Clone, Deserialize)]
struct ExpensiveModelLibrary {
    #[serde(default)]
    model_ids: Vec<String>,
    #[serde(default)]
    model_prefixes: Vec<String>,
    #[serde(default)]
    agent_ids: Vec<String>,
    #[serde(default)]
    agent_slugs: Vec<String>,
    #[serde(default)]
    adapter_types: Vec<String>,
}

pub fn load_catalog() -> Result<Vec<LlmModel>> {
    let mut models: Vec<LlmModel> =
        serde_json::from_str(LLMLIST_JSON).context("parse embedded llm catalog")?;
    models.sort_by(|a, b| {
        a.min_ram_gb
            .partial_cmp(&b.min_ram_gb)
            .unwrap_or(Ordering::Equal)
    });
    Ok(models)
}

fn expensive_model_library() -> &'static ExpensiveModelLibrary {
    static LIBRARY: OnceLock<ExpensiveModelLibrary> = OnceLock::new();
    LIBRARY.get_or_init(|| {
        serde_json::from_str(EXPENSIVE_MODELS_JSON)
            .expect("parse docs/expensive_models.json for expensive model library")
    })
}

fn normalized_match_value(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_ascii_lowercase())
    }
}

fn matches_exact_value(candidate: Option<&str>, patterns: &[String]) -> bool {
    let Some(candidate) = candidate.and_then(normalized_match_value) else {
        return false;
    };
    patterns.iter().any(|pattern| {
        normalized_match_value(pattern)
            .map(|value| value == candidate)
            .unwrap_or(false)
    })
}

fn matches_prefixed_value(candidate: Option<&str>, patterns: &[String]) -> bool {
    let Some(candidate) = candidate.and_then(normalized_match_value) else {
        return false;
    };
    patterns.iter().any(|pattern| {
        normalized_match_value(pattern)
            .map(|value| candidate.starts_with(&value))
            .unwrap_or(false)
    })
}

pub(crate) fn matches_expensive_delegation_target(
    agent_id: Option<&str>,
    agent_slug: Option<&str>,
    model: Option<&str>,
    adapter_type: Option<&str>,
) -> bool {
    let library = expensive_model_library();
    matches_exact_value(agent_id, &library.agent_ids)
        || matches_exact_value(agent_slug, &library.agent_slugs)
        || matches_exact_value(model, &library.model_ids)
        || matches_prefixed_value(model, &library.model_prefixes)
        || matches_exact_value(adapter_type, &library.adapter_types)
}

fn bytes_from_gb(gb: f64) -> u64 {
    (gb * 1024.0 * 1024.0 * 1024.0) as u64
}

fn has_gpu(profile: &HardwareProfile) -> bool {
    profile
        .graphics
        .iter()
        .any(|card| card.memory_total_bytes > 0)
}

pub fn supports(profile: &HardwareProfile, model: &LlmModel) -> bool {
    profile.total_memory_bytes >= bytes_from_gb(model.min_ram_gb)
        && (!model.requires_gpu || has_gpu(profile))
}

pub fn filter_catalog<'a>(profile: &HardwareProfile, catalog: &'a [LlmModel]) -> Vec<&'a LlmModel> {
    catalog
        .iter()
        .filter(|model| supports(profile, model))
        .collect()
}

pub fn recommended_model<'a>(
    profile: &HardwareProfile,
    catalog: &'a [LlmModel],
) -> Option<&'a LlmModel> {
    let tier = hardware::recommend_model(profile);
    if let Some(model) = find_by_tier(catalog, tier) {
        return Some(model);
    }
    catalog
        .iter()
        .filter(|model| supports(profile, model))
        .max_by(|a, b| {
            a.min_ram_gb
                .partial_cmp(&b.min_ram_gb)
                .unwrap_or(Ordering::Equal)
        })
}

fn find_by_tier<'a>(catalog: &'a [LlmModel], tier: ModelTier) -> Option<&'a LlmModel> {
    let id = tier.label();
    catalog.iter().find(|model| model.id == id)
}

#[cfg(test)]
mod tests;
