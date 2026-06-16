use crate::cli::LlmCommand;
use crate::config;
use crate::hardware;
use crate::llm;
use crate::llm::local_library::{
    detect_local_service_report, load_local_library, local_library_diagnostics,
    refresh_local_library_if_stale, service_probe_timeout, LocalDefaultCandidate,
};
use crate::setup::ollama as setup_ollama;
use crate::util;
use anyhow::{Context, Result};
use std::collections::HashSet;
use std::path::PathBuf;
use std::process::Command as StdCommand;
use which::which;

pub(crate) async fn run_command(command: LlmCommand) -> Result<()> {
    match command {
        LlmCommand::List => run_list(),
        LlmCommand::Detect { json } => run_detect(json).await,
        LlmCommand::Diagnostics { json } => run_diagnostics(json).await,
    }
}

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

pub async fn run_detect(json: bool) -> Result<()> {
    util::init_logging("warn")?;
    let config_data = config::AppConfig::load_default()?;
    let report =
        detect_local_service_report(None, &config_data.llm, service_probe_timeout()).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }
    println!("local LLM service detection:");
    for probe in &report.probes {
        let provider = probe
            .display_name
            .as_deref()
            .unwrap_or_else(|| probe.provider.as_str());
        let health = serde_json::to_string(&probe.health)
            .unwrap_or_else(|_| "\"unknown\"".to_string())
            .trim_matches('"')
            .to_string();
        let binary_count = probe.found_binaries.len();
        println!(
            "- {provider}: health={health}, models={}, binaries_found={binary_count}",
            probe.model_count
        );
        if let Some(notes) = probe.notes.as_deref() {
            println!("  notes: {notes}");
        }
    }
    println!(
        "detected services: {}, models: {}, mcoda agents: {}",
        report.library.services.len(),
        report.library.models.len(),
        report.library.agents.len()
    );
    Ok(())
}

pub async fn run_diagnostics(json: bool) -> Result<()> {
    util::init_logging("warn")?;
    let config_data = config::AppConfig::load_default()?;
    let library = match refresh_local_library_if_stale(None, &config_data.llm, false).await {
        Ok(library) => library,
        Err(err) => {
            eprintln!("local model library refresh failed: {err}; using cached library");
            load_local_library(None).context("load cached local model library")?
        }
    };
    let diagnostics = local_library_diagnostics(&library, &config_data.llm);
    if json {
        println!("{}", serde_json::to_string_pretty(&diagnostics)?);
        return Ok(());
    }

    println!("local LLM diagnostics:");
    println!(
        "detected services: {}, models: {}, mcoda agents: {}",
        diagnostics.services_detected, diagnostics.models_detected, diagnostics.agents_detected
    );
    println!(
        "library updated_at_ms: {} (ttl_ms={}, stale={})",
        diagnostics.updated_at_ms, diagnostics.ttl_ms, diagnostics.stale
    );
    println!(
        "embedding default: {}",
        diagnostics
            .defaults
            .embedding
            .selected
            .as_ref()
            .map(format_candidate)
            .unwrap_or_else(|| "none".to_string())
    );
    println!(
        "delegation default: {}",
        diagnostics
            .defaults
            .delegation
            .selected
            .as_ref()
            .map(format_candidate)
            .unwrap_or_else(|| "none".to_string())
    );
    if diagnostics.status_messages.is_empty() {
        println!("status messages: none");
    } else {
        println!("status messages:");
        for status in diagnostics.status_messages {
            println!(
                "- [{}] {}: {}",
                status.severity, status.code, status.message
            );
        }
    }
    Ok(())
}

fn format_candidate(candidate: &LocalDefaultCandidate) -> String {
    if let Some(agent_slug) = candidate
        .agent_slug
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return format!("agent:{agent_slug}");
    }
    if let Some(agent_id) = candidate
        .agent_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return format!("agent:{agent_id}");
    }
    let model = candidate
        .raw_model
        .as_deref()
        .or(candidate.model.as_deref())
        .unwrap_or("unknown");
    match candidate.provider.as_ref() {
        Some(provider) => format!("{}:{model}", provider.as_str()),
        None => model.to_string(),
    }
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
    let bin = ensure_ollama_installed(ollama_path)?;
    setup_ollama::ensure_ollama_daemon(&bin)?;
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
        println!("no recommended model fits detected hardware; keeping existing config defaults");
    }

    let installed = match list_installed_models(&bin) {
        Ok(models) => Some(models),
        Err(err) => {
            println!("ollama list failed: {err}");
            println!("continuing with direct model pulls");
            None
        }
    };
    let chat_model = config_data.llm.default_model.trim();
    let embed_model = config_data.llm.embedding_model.trim();
    let mut to_install = HashSet::new();
    if chat_model.is_empty() {
        println!("chat model is not configured; set [llm].default_model in config");
    } else if installed
        .as_ref()
        .is_some_and(|models| models.contains(chat_model))
    {
        println!("chat model available: {chat_model}");
    } else {
        println!("chat model missing: {chat_model}");
        to_install.insert(chat_model.to_string());
    }
    if embed_model.is_empty() {
        println!("embedding model is not configured; set [llm].embedding_model in config");
    } else if installed
        .as_ref()
        .is_some_and(|models| models.contains(embed_model))
    {
        println!("embedding model available: {embed_model}");
    } else {
        println!("embedding model missing: {embed_model}");
        to_install.insert(embed_model.to_string());
    }
    if !to_install.is_empty() {
        println!("installing required models via ollama pull...");
        for model in to_install {
            pull_model(&bin, &model)?;
        }
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

fn pull_model(bin: &PathBuf, model: &str) -> Result<()> {
    let output = StdCommand::new(bin)
        .arg("pull")
        .arg(model)
        .output()
        .with_context(|| format!("run ollama pull {model}"))?;
    if output.status.success() {
        println!("installed model: {model}");
        return Ok(());
    }
    Err(anyhow::anyhow!(
        "ollama pull {model} failed (stdout: {}, stderr: {})",
        String::from_utf8_lossy(&output.stdout).trim(),
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}

fn ensure_ollama_installed(ollama_path: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(path) = setup_ollama::resolve_ollama_path(ollama_path) {
        return Ok(path);
    }
    install_ollama()?;
    if let Some(path) = setup_ollama::resolve_ollama_path(None) {
        return Ok(path);
    }
    let hint = if cfg!(target_os = "windows") {
        "ollama installed but not found on PATH; add %LOCALAPPDATA%\\Programs\\Ollama to PATH or pass --ollama-path"
    } else {
        "ollama installed but not found on PATH; restart your shell or pass --ollama-path"
    };
    Err(anyhow::anyhow!(hint))
}

fn install_ollama() -> Result<()> {
    if cfg!(target_os = "macos") {
        install_ollama_macos()
    } else if cfg!(target_os = "linux") {
        install_ollama_linux()
    } else if cfg!(target_os = "windows") {
        install_ollama_windows()
    } else {
        Err(anyhow::anyhow!(
            "unsupported platform; install ollama from https://ollama.com/download"
        ))
    }
}

fn install_ollama_macos() -> Result<()> {
    if which("brew").is_ok() {
        run_install_command(
            "brew",
            &["install", "ollama"],
            "installing ollama with Homebrew",
        )?;
        return Ok(());
    }
    Err(anyhow::anyhow!(
        "ollama not found; install with Homebrew (`brew install ollama`) or download from https://ollama.com/download"
    ))
}

fn install_ollama_linux() -> Result<()> {
    if which("curl").is_ok() {
        return run_install_command(
            "sh",
            &["-c", "curl -fsSL https://ollama.com/install.sh | sh"],
            "installing ollama via curl",
        );
    }
    if which("wget").is_ok() {
        return run_install_command(
            "sh",
            &["-c", "wget -qO- https://ollama.com/install.sh | sh"],
            "installing ollama via wget",
        );
    }
    Err(anyhow::anyhow!(
        "ollama not found; install from https://ollama.com/download (requires curl or wget)"
    ))
}

fn install_ollama_windows() -> Result<()> {
    if which("winget").is_ok() {
        return run_install_command(
            "winget",
            &[
                "install",
                "-e",
                "--id",
                "Ollama.Ollama",
                "--accept-package-agreements",
                "--accept-source-agreements",
            ],
            "installing ollama with winget",
        );
    }
    Err(anyhow::anyhow!(
        "ollama not found; install from https://ollama.com/download (or `winget install Ollama.Ollama`)"
    ))
}

fn run_install_command(command: &str, args: &[&str], context: &str) -> Result<()> {
    let output = StdCommand::new(command)
        .args(args)
        .output()
        .with_context(|| format!("{context} ({command} {})", args.join(" ")))?;
    if output.status.success() {
        return Ok(());
    }
    Err(anyhow::anyhow!(
        "{context} failed (stdout: {}, stderr: {})",
        String::from_utf8_lossy(&output.stdout).trim(),
        String::from_utf8_lossy(&output.stderr).trim()
    ))
}
