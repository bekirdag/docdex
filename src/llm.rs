use crate::hardware::HardwareProfile;
use anyhow::{Context, Result};
use serde::Deserialize;
use std::cmp::Ordering;
use std::fs;
use std::path::PathBuf;

const LLMLIST_JSON: &str = "docs/llm_list.json";

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

fn catalog_file() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(LLMLIST_JSON)
}

pub fn load_catalog() -> Result<Vec<LlmModel>> {
    let raw = fs::read_to_string(catalog_file()).context("read llm catalog")?;
    let mut models: Vec<LlmModel> =
        serde_json::from_str(&raw).context("parse docs/llm_list.json for llm catalog")?;
    models.sort_by(|a, b| {
        a.min_ram_gb
            .partial_cmp(&b.min_ram_gb)
            .unwrap_or(Ordering::Equal)
    });
    Ok(models)
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

pub fn recommended_model<'a>(
    profile: &HardwareProfile,
    catalog: &'a [LlmModel],
) -> Option<&'a LlmModel> {
    catalog
        .iter()
        .filter(|model| supports(profile, model))
        .max_by(|a, b| {
            a.min_ram_gb
                .partial_cmp(&b.min_ram_gb)
                .unwrap_or(Ordering::Equal)
        })
}
