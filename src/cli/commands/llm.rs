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
    println!("\navailable models:");
    for model in &models {
        let supported = llm::supports(&profile, model);
        let status = if supported {
            "supported"
        } else {
            "requires more RAM/GPU"
        };
        println!(
            "- {} (min RAM: {} GB{}): {} [{}]",
            model.display_name,
            model.min_ram_gb,
            if model.requires_gpu { ", GPU" } else { "" },
            model.description,
            status
        );
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
