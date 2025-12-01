use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize)]
pub struct LlmModel {
    pub id: String,
    #[serde(default)]
    pub quantization: Option<String>,
    #[serde(default)]
    pub min_ram_gb: Option<u64>,
    #[serde(default)]
    pub min_vram_gb: Option<u64>,
    #[serde(default)]
    pub suitability: Option<String>,
}

#[derive(Debug)]
pub struct HardwareInfo {
    pub ram_gb: Option<u64>,
    pub vram_gb: Option<u64>,
    pub vram_note: Option<String>,
}

#[derive(Debug)]
pub struct Catalog {
    pub models: Vec<LlmModel>,
    pub source: CatalogSource,
    pub warning: Option<String>,
}

#[derive(Debug)]
pub enum CatalogSource {
    File(PathBuf),
    BuiltIn,
}

#[derive(Debug)]
pub struct Recommendation {
    pub id: String,
    pub quantization: String,
    pub reason: String,
}

const DEFAULT_CATALOG_JSON: &str = r#"
[
  { "id": "qwen:0.5b", "quantization": "Q4_K_M", "min_ram_gb": 4, "suitability": "fits low RAM for quick replies" },
  { "id": "llama3.2:1b", "quantization": "Q4_K_M", "min_ram_gb": 8, "suitability": "lightweight general chat" },
  { "id": "mistral:7b", "quantization": "Q4_K_M", "min_ram_gb": 16, "suitability": "balanced quality on CPU or modest GPU" },
  { "id": "llama3.1:8b", "quantization": "Q4_K_M", "min_ram_gb": 16, "min_vram_gb": 8, "suitability": "good quality when a midrange GPU is present" }
]
"#;

pub fn detect_hardware() -> HardwareInfo {
    HardwareInfo {
        ram_gb: read_ram_total_gb(),
        vram_gb: None,
        vram_note: Some("VRAM not detected; GPU probing disabled".to_string()),
    }
}

pub fn load_catalog(path: Option<&Path>) -> Catalog {
    let fallback = built_in_models();
    if let Some(path) = path {
        return load_from_path(path, fallback);
    }
    let default_path = Path::new("llm_list.json");
    if default_path.exists() {
        return load_from_path(default_path, fallback);
    }
    Catalog {
        models: fallback,
        source: CatalogSource::BuiltIn,
        warning: None,
    }
}

pub fn recommended_with_reasons(
    models: &[LlmModel],
    hardware: &HardwareInfo,
) -> Vec<Recommendation> {
    models
        .iter()
        .filter_map(|model| {
            if !meets_requirements(model, hardware) {
                return None;
            }
            let reason = build_reason(model, hardware);
            Some(Recommendation {
                id: model.id.clone(),
                quantization: model
                    .quantization
                    .clone()
                    .unwrap_or_else(|| "-".to_string()),
                reason,
            })
        })
        .collect()
}

pub fn format_detection_summary(hardware: &HardwareInfo) -> String {
    let ram = match hardware.ram_gb {
        Some(gb) => format!("{gb}GB RAM detected"),
        None => "RAM not detected".to_string(),
    };
    let vram = match (hardware.vram_gb, hardware.vram_note.as_deref()) {
        (Some(gb), _) => format!("{gb}GB VRAM detected"),
        (None, Some(note)) => note.to_string(),
        (None, None) => "VRAM not detected".to_string(),
    };
    format!("Detected: {ram}; {vram}")
}

pub fn render_recommendations(recs: &[Recommendation]) -> String {
    if recs.is_empty() {
        return "No recommended models matched the detected hardware.".to_string();
    }
    let model_width = recs
        .iter()
        .map(|r| r.id.len())
        .max()
        .unwrap_or(5)
        .max("Model".len())
        + 2;
    let quant_width = recs
        .iter()
        .map(|r| r.quantization.len())
        .max()
        .unwrap_or(5)
        .max("Quant".len())
        + 2;
    let mut lines = Vec::new();
    lines.push(format!(
        "{:<model_width$}{:<quant_width$}{}",
        "Model",
        "Quant",
        "Reason",
        model_width = model_width,
        quant_width = quant_width
    ));
    for rec in recs {
        lines.push(format!(
            "{:<model_width$}{:<quant_width$}{}",
            rec.id,
            rec.quantization,
            rec.reason,
            model_width = model_width,
            quant_width = quant_width
        ));
    }
    lines.join("\n")
}

fn load_from_path(path: &Path, fallback: Vec<LlmModel>) -> Catalog {
    let data = match fs::read_to_string(path) {
        Ok(data) => data,
        Err(err) => {
            return Catalog {
                models: fallback,
                source: CatalogSource::BuiltIn,
                warning: Some(format!("failed to read {}: {err}", path.display())),
            }
        }
    };
    match serde_json::from_str::<Vec<LlmModel>>(&data) {
        Ok(models) => Catalog {
            models,
            source: CatalogSource::File(path.to_path_buf()),
            warning: None,
        },
        Err(err) => Catalog {
            models: fallback,
            source: CatalogSource::BuiltIn,
            warning: Some(format!("failed to parse {}: {err}", path.display())),
        },
    }
}

fn built_in_models() -> Vec<LlmModel> {
    serde_json::from_str(DEFAULT_CATALOG_JSON).expect("built-in catalog JSON is valid")
}

fn read_ram_total_gb() -> Option<u64> {
    let contents = fs::read_to_string("/proc/meminfo").ok()?;
    for line in contents.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            let kb_str = rest.split_whitespace().next()?;
            if let Ok(kb) = kb_str.parse::<u64>() {
                return Some(kb_to_gb(kb));
            }
        }
    }
    None
}

fn kb_to_gb(kb: u64) -> u64 {
    (kb + 1_048_575) / 1_048_576
}

fn meets_requirements(model: &LlmModel, hardware: &HardwareInfo) -> bool {
    let ram_ok = match (model.min_ram_gb, hardware.ram_gb) {
        (Some(required), Some(detected)) => detected >= required,
        (Some(_), None) => true,
        (None, _) => true,
    };
    let vram_ok = match (model.min_vram_gb, hardware.vram_gb) {
        (Some(required), Some(detected)) => detected >= required,
        (Some(_), None) => true,
        (None, _) => true,
    };
    ram_ok && vram_ok
}

fn build_reason(model: &LlmModel, hardware: &HardwareInfo) -> String {
    let mut parts = Vec::new();
    if let Some(required) = model.min_ram_gb {
        match hardware.ram_gb {
            Some(detected) => parts.push(format!("fits RAM {detected}GB (needs ≥{required}GB)")),
            None => parts.push(format!("requires ≥{required}GB RAM")),
        }
    }
    if let Some(required) = model.min_vram_gb {
        match hardware.vram_gb {
            Some(detected) => parts.push(format!("fits VRAM {detected}GB (needs ≥{required}GB)")),
            None => parts.push(format!("requires ≥{required}GB VRAM")),
        }
    }
    if let Some(q) = model.quantization.as_deref() {
        parts.push(format!("quant {q}"));
    }
    if let Some(note) = model.suitability.as_deref() {
        parts.push(note.to_string());
    }
    parts.join("; ")
}
