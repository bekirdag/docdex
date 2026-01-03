use std::fmt;

use sysinfo::System;

const MEMORY_GB: u64 = 1024 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct GraphicsInfo {
    pub name: String,
    pub memory_total_bytes: u64,
}

#[derive(Debug, Clone)]
pub struct HardwareProfile {
    pub total_memory_bytes: u64,
    pub graphics: Vec<GraphicsInfo>,
}

#[derive(Debug, Clone, Copy)]
pub enum ModelTier {
    UltraLight,
    Llama8b,
    Llama70b,
}

impl ModelTier {
    pub fn label(self) -> &'static str {
        match self {
            ModelTier::UltraLight => "ultra-light",
            ModelTier::Llama8b => "phi3.5:3.8b",
            ModelTier::Llama70b => "llama3.1:70b",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            ModelTier::UltraLight => "suitable for <8GB RAM hosts",
            ModelTier::Llama8b => "recommended default for ≥16GB RAM hosts (smaller model)",
            ModelTier::Llama70b => "use when ≥32GB RAM and GPU memory are available",
        }
    }
}

impl fmt::Display for ModelTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.label(), self.description())
    }
}

impl HardwareProfile {
    pub fn total_memory_gb(&self) -> f64 {
        (self.total_memory_bytes as f64) / (MEMORY_GB as f64)
    }

    pub fn recommended_tier(&self) -> ModelTier {
        recommend_model(self)
    }
}

pub fn detect_hardware() -> HardwareProfile {
    let mut sys = System::new_all();
    sys.refresh_memory();
    let total_memory_bytes = sys.total_memory();
    let graphics = Vec::new();
    HardwareProfile {
        total_memory_bytes,
        graphics,
    }
}

pub fn recommend_model(profile: &HardwareProfile) -> ModelTier {
    let has_gpu = profile
        .graphics
        .iter()
        .any(|card| card.memory_total_bytes > 0);
    if profile.total_memory_bytes >= 32 * MEMORY_GB && has_gpu {
        ModelTier::Llama70b
    } else if profile.total_memory_bytes >= 16 * MEMORY_GB {
        ModelTier::Llama8b
    } else {
        ModelTier::UltraLight
    }
}

pub fn format_hardware_summary(profile: &HardwareProfile) -> String {
    let mut lines = Vec::new();
    lines.push(format!("total RAM: {:.1} GB", profile.total_memory_gb()));
    if profile.graphics.is_empty() {
        lines.push("no GPUs detected".to_string());
    } else {
        for card in &profile.graphics {
            lines.push(format!(
                "GPU {} – {} MB",
                card.name,
                card.memory_total_bytes / (1024 * 1024)
            ));
        }
    }
    lines.join("; ")
}
