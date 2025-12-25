use crate::config;
use crate::hardware;
use crate::llm;
use crate::util;
use anyhow::Result;
use std::collections::HashSet;
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
    let binary = ollama_path.or_else(|| which("ollama").ok());
    let Some(bin) = binary else {
        return Err(anyhow::anyhow!(
            "ollama binary not found; install Ollama (https://ollama.ai) or set --ollama-path"
        ));
    };
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
            return Err(anyhow::anyhow!(
                "ollama binary at {} returned non-zero (stderr: {})",
                bin.display(),
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        Err(err) => {
            return Err(anyhow::anyhow!(
                "failed to run ollama at {}: {}",
                bin.display(),
                err
            ));
        }
    }

    let config_path = config::default_config_path()?;
    let mut config_data = config::load_config_from_path(&config_path)?;
    let provider = config_data.llm.provider.trim();
    if !provider.eq_ignore_ascii_case("ollama") {
        return Err(anyhow::anyhow!(
            "unsupported llm provider `{provider}`; set [llm].provider = \"ollama\" in {}",
            config_path.display()
        ));
    }

    if let Some(recommended) = llm::recommended_model(&profile, &models) {
        if config_data.llm.default_model != recommended.id {
            let previous = config_data.llm.default_model.clone();
            config_data.llm.default_model = recommended.id.clone();
            config::write_config(&config_path, &config_data)?;
            println!(
                "updated config default model: {} -> {} ({})",
                previous,
                recommended.id,
                config_path.display()
            );
        }
    } else {
        println!(
            "no recommended model fits detected hardware; keeping existing config defaults"
        );
    }

    let installed = list_installed_models(&bin)?;
    let chat_model = config_data.llm.default_model.trim();
    if chat_model.is_empty() {
        println!("chat model is not configured; set [llm].default_model in config");
    } else if installed.contains(chat_model) {
        println!("chat model available: {chat_model}");
    } else {
        println!("chat model missing: {chat_model}");
        println!("to install: ollama pull {chat_model}");
    }
    let embed_model = config_data.llm.embedding_model.trim();
    if embed_model.is_empty() {
        println!("embedding model is not configured; set [llm].embedding_model in config");
    } else if installed.contains(embed_model) {
        println!("embedding model available: {embed_model}");
    } else {
        println!("embedding model missing: {embed_model}");
        println!("to install: ollama pull {embed_model}");
    }
    Ok(())
}

fn list_installed_models(bin: &PathBuf) -> Result<HashSet<String>> {
    let output = StdCommand::new(bin).arg("list").output()?;
    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "ollama list failed: {} (ensure the ollama daemon is running; try `ollama serve`)",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut models = HashSet::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("NAME") {
            continue;
        }
        if let Some(name) = trimmed.split_whitespace().next() {
            models.insert(name.to_string());
        }
    }
    if models.is_empty() {
        println!("ollama list returned no models; pull one to get started");
    }
    Ok(models)
}
