use super::{load_catalog, recommended_model, supports, LlmModel};
use crate::hardware::{GraphicsInfo, HardwareProfile};

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
