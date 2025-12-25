use crate::config;
use crate::hardware;
use crate::llm;
use crate::util;
use anyhow::Result;
use std::path::PathBuf;
use std::process::Command as StdCommand;
use which::which;

pub fn run_list() -> Result<()> {
    util::init_logging("warn")?;
    let profile = hardware::detect_hardware();
    let models = llm::load_catalog()?;
    let filtered = llm::filter_catalog(&profile, &models);
    println!(
        "hardware summary: {}",
        hardware::format_hardware_summary(&profile)
    );
    if let Some(model) = llm::recommended_model(&profile, &models) {
        println!(
            "recommended model: {} ({})",
            model.display_name, model.description
        );
    } else {
        println!("recommended model: none (hardware does not meet catalog minimums)");
    }
    println!("\navailable models (hardware filtered):");
    if filtered.is_empty() {
        println!("(none)");
    } else {
        for model in &filtered {
            println!(
                "- {} (min RAM: {} GB{}): {}",
                model.display_name,
                model.min_ram_gb,
                if model.requires_gpu { ", GPU" } else { "" },
                model.description
            );
        }
        if filtered.len() != models.len() {
            println!(
                "filtered out {} model(s) that exceed detected hardware thresholds",
                models.len() - filtered.len()
            );
        }
    }
    Ok(())
}

pub fn run_setup(ollama_path: Option<PathBuf>) -> Result<()> {
    util::init_logging("warn")?;
    let profile = hardware::detect_hardware();
    let models = llm::load_catalog()?;
    println!(
        "hardware summary: {}",
        hardware::format_hardware_summary(&profile)
    );
    if let Some(model) = llm::recommended_model(&profile, &models) {
        println!(
            "recommended model: {} ({})",
            model.display_name, model.description
        );
    } else {
        println!("recommended model: none (hardware does not meet catalog minimums)");
    }
    if let Some(recommended) = llm::recommended_model(&profile, &models) {
        if let Ok(config_path) = config::default_config_path() {
            if config_path.exists() {
                let mut config_data = config::load_config_from_path(&config_path)?;
                if config_data.llm.default_model != recommended.id {
                    let previous = config_data.llm.default_model.clone();
                    config_data.llm.default_model = recommended.id.clone();
                    config::write_config(&config_path, &config_data)?;
                    println!(
                        "updated config default model: {} -> {} ({})",
                        previous, recommended.id, config_path.display()
                    );
                }
            }
        }
    }
    let binary = ollama_path.or_else(|| which("ollama").ok());
    if let Some(bin) = binary {
        match StdCommand::new(&bin).arg("--version").output() {
            Ok(output) if output.status.success() => {
                let version = String::from_utf8_lossy(&output.stdout);
                println!(
                    "ollama available at {} (version {})",
                    bin.display(),
                    version.trim()
                );
            }
            Ok(output) => {
                println!(
                    "ollama binary at {} returned non-zero (stderr: {})",
                    bin.display(),
                    String::from_utf8_lossy(&output.stderr).trim()
                );
            }
            Err(err) => {
                println!("failed to run ollama at {}: {}", bin.display(), err);
            }
        }
    } else {
        println!(
            "ollama binary not found; install Ollama (https://ollama.ai) or set --ollama-path."
        );
    }
    Ok(())
}
