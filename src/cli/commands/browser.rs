use crate::config;
use crate::util::{self, BrowserCandidate, BrowserKind};
use crate::web::browser_install;
use anyhow::{Context, Result};
use serde::Serialize;

pub(crate) async fn run(command: crate::cli::BrowserCommand) -> Result<()> {
    match command {
        crate::cli::BrowserCommand::List => run_list().await,
        crate::cli::BrowserCommand::Setup => run_setup().await,
        crate::cli::BrowserCommand::Install => run_install().await,
    }
}

#[derive(Serialize)]
struct BrowserCandidateOutput {
    name: String,
    kind: String,
    source: String,
    path: String,
    priority: u32,
}

#[derive(Serialize)]
struct BrowserListResponse {
    selected: Option<BrowserCandidateOutput>,
    candidates: Vec<BrowserCandidateOutput>,
    auto_install_enabled: bool,
}

#[derive(Serialize)]
struct BrowserSetupResponse {
    selected: Option<BrowserCandidateOutput>,
    config_path: String,
    auto_install_enabled: bool,
}

#[derive(Serialize)]
struct BrowserInstallResponse {
    installed: bool,
    path: Option<String>,
    version: Option<String>,
    config_path: String,
}

async fn run_list() -> Result<()> {
    let config = config::AppConfig::load_default()?;
    let mut candidates = chromium_candidates(&config);
    candidates.sort_by_key(|candidate| candidate.priority);
    let selected =
        resolve_selected_candidate(&candidates, config.web.scraper.browser_kind.as_deref());
    let response = BrowserListResponse {
        selected: selected.map(candidate_output),
        candidates: candidates.into_iter().map(candidate_output).collect(),
        auto_install_enabled: resolve_auto_install_enabled(&config),
    };
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn run_setup() -> Result<()> {
    let config = config::AppConfig::load_default()?;
    let candidates = chromium_candidates(&config);
    let selected =
        resolve_selected_candidate(&candidates, config.web.scraper.browser_kind.as_deref());
    let config_path = config::default_config_path()?.to_string_lossy().to_string();
    let response = BrowserSetupResponse {
        selected: selected.map(candidate_output),
        config_path,
        auto_install_enabled: resolve_auto_install_enabled(&config),
    };
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

async fn run_install() -> Result<()> {
    let mut config = config::AppConfig::load_default()?;
    let config_path = config::default_config_path()?.to_string_lossy().to_string();
    let install_result = browser_install::install_if_missing(true)?;
    if let Some(result) = install_result.as_ref() {
        config.web.scraper.chrome_binary_path = Some(result.path.clone());
        config.web.scraper.browser_kind = Some("chromium".to_string());
        if !config
            .web
            .scraper
            .engine
            .trim()
            .eq_ignore_ascii_case("chromium")
        {
            config.web.scraper.engine = "chromium".to_string();
        }
        config::write_config(
            &config::default_config_path().context("resolve config path")?,
            &config,
        )?;
    }
    let response = BrowserInstallResponse {
        installed: install_result.is_some(),
        path: install_result
            .as_ref()
            .map(|result| result.path.to_string_lossy().to_string()),
        version: install_result.map(|result| result.version),
        config_path,
    };
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

fn candidate_output(candidate: BrowserCandidate) -> BrowserCandidateOutput {
    BrowserCandidateOutput {
        name: candidate.name,
        kind: candidate.kind.as_str().to_string(),
        source: candidate.source.as_str().to_string(),
        path: candidate.path.to_string_lossy().to_string(),
        priority: candidate.priority,
    }
}

fn chromium_candidates(config: &config::AppConfig) -> Vec<BrowserCandidate> {
    let mut candidates = util::detect_browser_candidates(config.web.scraper.chrome_binary_path.as_deref());
    candidates.retain(|candidate| matches!(candidate.kind, BrowserKind::Chromium | BrowserKind::Custom));
    candidates
}

fn resolve_selected_candidate(
    candidates: &[BrowserCandidate],
    desired: Option<&str>,
) -> Option<BrowserCandidate> {
    let desired = desired
        .map(|value| value.trim())
        .filter(|value| !value.is_empty());
    if let Some(name) = desired {
        if let Some(candidate) = candidates
            .iter()
            .find(|candidate| candidate.name.eq_ignore_ascii_case(name))
        {
            return Some(candidate.clone());
        }
    }
    candidates.first().cloned()
}

fn resolve_auto_install_enabled(config: &config::AppConfig) -> bool {
    env_boolish("DOCDEX_BROWSER_AUTO_INSTALL").unwrap_or(config.web.scraper.auto_install)
}

fn env_boolish(key: &str) -> Option<bool> {
    let raw = std::env::var(key).ok()?;
    let trimmed = raw.trim().to_ascii_lowercase();
    match trimmed.as_str() {
        "1" | "true" | "t" | "yes" | "y" | "on" => Some(true),
        "0" | "false" | "f" | "no" | "n" | "off" => Some(false),
        _ => None,
    }
}
