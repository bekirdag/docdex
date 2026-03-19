use anyhow::{anyhow, Result};
use crossterm::{
    cursor,
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
    Terminal,
};
use std::fmt::Write;
use std::io::Write as IoWrite;
use std::io::{self, Stdout};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use super::config;
use super::model::{CHAT_MODEL, CHAT_MODEL_SIZE_GIB, EMBED_MODEL};
use super::ollama;
use super::state::{SetupContext, SetupOutcome, SetupState, StepKey, StepSnapshot, StepStatus};
use super::SetupSummary;
use crate::config as app_config;
use crate::util;
use crate::web::browser_install;
use std::env;

const MSWARM_TERMS: &str = include_str!("../../docs/mswarm-data-collection-terms.md");
const MENU_STEPS: [StepKey; 5] = [
    StepKey::Ollama,
    StepKey::EmbedModel,
    StepKey::ChatModel,
    StepKey::Browser,
    StepKey::WebProviders,
];

pub(crate) struct MenuDetails {
    ollama: String,
    embed: String,
    chat: String,
    browser: String,
    web_providers: String,
    embed_options: Option<MenuOptions>,
    chat_options: Option<MenuOptions>,
    browsers: Vec<BrowserStatus>,
}

impl MenuDetails {
    fn body_for(&self, step: StepKey) -> &str {
        match step {
            StepKey::Ollama => &self.ollama,
            StepKey::EmbedModel => &self.embed,
            StepKey::ChatModel => &self.chat,
            StepKey::Browser => &self.browser,
            StepKey::WebProviders => &self.web_providers,
            _ => "Select a section to configure.",
        }
    }

    fn options_for(&self, step: StepKey) -> Option<&MenuOptions> {
        match step {
            StepKey::EmbedModel => self.embed_options.as_ref(),
            StepKey::ChatModel => self.chat_options.as_ref(),
            _ => None,
        }
    }

    fn browsers(&self) -> &[BrowserStatus] {
        &self.browsers
    }
}

#[derive(Clone)]
struct MenuOptions {
    choices: Vec<ModelChoice>,
    default_index: usize,
}

pub trait WizardServices {
    fn resolve_ollama_path(
        &self,
        explicit: Option<std::path::PathBuf>,
    ) -> Option<std::path::PathBuf>;
    fn install_ollama(&self) -> Result<()>;
    fn ensure_ollama_service(&self, bin: &Path) -> Result<ollama::OllamaDaemonStatus>;
    fn list_models(&self, bin: &Path) -> Result<Vec<String>>;
    fn list_models_if_running(&self, bin: &Path) -> Result<Option<Vec<String>>>;
    fn pull_model(&self, bin: &Path, model: &str) -> Result<()>;
    fn set_default_model(&self, model: &str) -> Result<()>;
    fn set_embedding_model(&self, model: &str) -> Result<()>;
    fn chromium_install_status(&self) -> browser_install::ChromiumInstallStatus;
    fn install_chromium(&self) -> Result<browser_install::BrowserInstallResult>;
    fn set_browser_path(&self, path: &Path, kind: &str) -> Result<()>;
    fn set_web_provider_keys(&self, update: config::WebProviderKeysUpdate) -> Result<bool>;
    fn set_mswarm_config(&self, update: config::MswarmConfigUpdate) -> Result<bool>;
    fn ensure_mswarm_consent(
        &self,
        accepted_at_ms: u128,
    ) -> Result<config::MswarmTelemetryConsentStatus>;
}

pub struct RealServices;

impl WizardServices for RealServices {
    fn resolve_ollama_path(
        &self,
        explicit: Option<std::path::PathBuf>,
    ) -> Option<std::path::PathBuf> {
        ollama::resolve_ollama_path(explicit)
    }

    fn install_ollama(&self) -> Result<()> {
        ollama::install_ollama()
    }

    fn ensure_ollama_service(&self, bin: &Path) -> Result<ollama::OllamaDaemonStatus> {
        ollama::ensure_ollama_daemon(bin)
    }

    fn list_models(&self, bin: &Path) -> Result<Vec<String>> {
        ollama::list_models(bin)
    }

    fn list_models_if_running(&self, bin: &Path) -> Result<Option<Vec<String>>> {
        ollama::list_models_if_running(bin)
    }

    fn pull_model(&self, bin: &Path, model: &str) -> Result<()> {
        ollama::pull_model(bin, model)
    }

    fn set_default_model(&self, model: &str) -> Result<()> {
        config::set_default_model(model).map(|_| ())
    }

    fn set_embedding_model(&self, model: &str) -> Result<()> {
        config::set_embedding_model(model).map(|_| ())
    }

    fn chromium_install_status(&self) -> browser_install::ChromiumInstallStatus {
        browser_install::chromium_install_status()
    }

    fn install_chromium(&self) -> Result<browser_install::BrowserInstallResult> {
        browser_install::install_chromium()
    }

    fn set_browser_path(&self, path: &Path, kind: &str) -> Result<()> {
        config::set_browser_path(path, kind).map(|_| ())
    }

    fn set_web_provider_keys(&self, update: config::WebProviderKeysUpdate) -> Result<bool> {
        config::set_web_provider_keys(update)
    }

    fn set_mswarm_config(&self, update: config::MswarmConfigUpdate) -> Result<bool> {
        config::set_mswarm_config(update)
    }

    fn ensure_mswarm_consent(
        &self,
        accepted_at_ms: u128,
    ) -> Result<config::MswarmTelemetryConsentStatus> {
        config::ensure_mswarm_telemetry_consent(accepted_at_ms)
    }
}

pub trait WizardInput {
    fn select_menu(
        &mut self,
        state: &SetupState,
        steps: &[StepKey],
        details: &MenuDetails,
    ) -> Result<MenuAction>;
    fn confirm(&mut self, state: &SetupState, prompt: &str, default_yes: bool) -> Result<bool>;
    fn select_model(
        &mut self,
        state: &SetupState,
        models: &[ModelChoice],
        default_index: usize,
    ) -> Result<Option<String>>;
    fn prompt_text(
        &mut self,
        state: &SetupState,
        prompt: &str,
        current: Option<&str>,
        secret: bool,
    ) -> Result<Option<String>>;
    fn info(&mut self, state: &SetupState, message: &str) -> Result<()>;
    fn with_suspended_terminal<T, F: FnOnce() -> Result<T>>(&mut self, op: F) -> Result<T>;
    fn with_progress<T, F: FnOnce() -> Result<T>>(
        &mut self,
        state: &SetupState,
        message: &str,
        op: F,
    ) -> Result<T> {
        self.info(state, message)?;
        self.with_suspended_terminal(op)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MenuAction {
    SelectSection(StepKey),
    SelectDefault { step: StepKey, value: String },
    Exit,
}

pub fn run_wizard(context: SetupContext) -> Result<SetupSummary> {
    let mut input = TuiInput::new()?;
    let services = RealServices;
    run_wizard_with_input(context, &mut input, &services)
}

pub fn run_wizard_with_input<I: WizardInput, S: WizardServices>(
    context: SetupContext,
    input: &mut I,
    services: &S,
) -> Result<SetupSummary> {
    let mut state = SetupState::new();
    let mut installed = Vec::new();
    let mut models = Vec::new();
    let mut default_model: Option<String> = None;
    let mut ollama_path = context.ollama_path.clone();
    let mut ollama_status: Option<ollama::OllamaDaemonStatus> = None;
    let mut abort_error: Option<String> = None;

    if let Some(err) = configure_consent_section(&mut state, input, services)? {
        abort_error = Some(err);
    }

    if abort_error.is_none() {
        state.set_current(StepKey::Ollama);
        input.info(
            &state,
            &format!(
                "Hardware: {:.1} GB RAM, {} CPU(s), free disk: {:.1} GiB (tier: {})",
                context.hardware.total_memory_gb,
                context.hardware.cpu_count,
                context.hardware.free_disk_bytes as f64 / 1024.0 / 1024.0 / 1024.0,
                context.hardware.recommended_class()
            ),
        )?;
    }

    while abort_error.is_none() {
        let menu_details = build_menu_details(&mut state, services, &mut ollama_path, &mut models);
        let action = input.select_menu(&state, &MENU_STEPS, &menu_details)?;
        let step = match action {
            MenuAction::Exit => break,
            MenuAction::SelectSection(step) => step,
            MenuAction::SelectDefault { step, value } => {
                if let Err(err) = apply_quick_default(
                    step,
                    &value,
                    services,
                    &mut state,
                    &models,
                    menu_details.browsers(),
                    &mut default_model,
                ) {
                    abort_error = Some(err.to_string());
                    break;
                }
                continue;
            }
        };
        let result = match step {
            StepKey::Ollama => configure_ollama_section(
                &mut state,
                input,
                services,
                &mut ollama_path,
                &mut ollama_status,
            ),
            StepKey::EmbedModel => configure_embedding_section(
                &mut state,
                input,
                services,
                &mut ollama_path,
                &mut ollama_status,
                &mut models,
                &mut installed,
            ),
            StepKey::ChatModel => configure_chat_section(
                &context,
                &mut state,
                input,
                services,
                &mut ollama_path,
                &mut ollama_status,
                &mut models,
                &mut installed,
                &mut default_model,
            ),
            StepKey::Browser => configure_browser_section(&mut state, input, services),
            StepKey::WebProviders => configure_web_providers_section(&mut state, input, services),
            _ => Ok(None),
        }?;
        if let Some(err) = result {
            abort_error = Some(err);
            break;
        }
    }

    if let Some(err) = abort_error {
        state.mark_failed(err);
    }

    let outcome = derive_outcome(&state);
    state.outcome = outcome;
    let message = match outcome {
        SetupOutcome::Failed => {
            let err = state
                .error
                .clone()
                .unwrap_or_else(|| "unknown error".to_string());
            format!("Setup failed: {err}")
        }
        SetupOutcome::Deferred => "Setup deferred. Run `docdex setup` later.".to_string(),
        _ => format_completion_message(
            &models,
            default_model.as_deref(),
            ollama_status.as_ref(),
            installed.as_slice(),
        ),
    };

    Ok(summary_from_state(
        &state,
        message,
        installed,
        default_model,
    ))
}

fn configure_consent_section<I: WizardInput, S: WizardServices>(
    state: &mut SetupState,
    input: &mut I,
    services: &S,
) -> Result<Option<String>> {
    state.set_current(StepKey::Consent);
    let prompt = format!(
        "{MSWARM_TERMS}\n\nDocdex requires consent to data collection and telemetry before setup can continue.\nAccept these terms and continue?"
    );
    if !input.confirm(state, &prompt, false)? {
        let message = "mswarm data collection consent is required to use Docdex.".to_string();
        state.update_step(
            StepKey::Consent,
            StepStatus::Failed,
            Some("declined".to_string()),
        );
        return Ok(Some(message));
    }

    match services.ensure_mswarm_consent(now_ms()) {
        Ok(status) => {
            let detail = format!(
                "{} {} ({}, consent_token={})",
                status.client_type,
                status.client_id,
                status.policy_version,
                if status.consent_token_set {
                    "set"
                } else {
                    "missing"
                }
            );
            state.update_step(StepKey::Consent, StepStatus::Done, Some(detail));
            Ok(None)
        }
        Err(err) => {
            let detail = err.to_string();
            state.update_step(StepKey::Consent, StepStatus::Failed, Some(detail.clone()));
            Ok(Some(detail))
        }
    }
}

fn build_menu_details<S: WizardServices>(
    state: &mut SetupState,
    services: &S,
    ollama_path: &mut Option<PathBuf>,
    models: &mut Vec<String>,
) -> MenuDetails {
    let resolved_path = if ollama_path.is_some() {
        ollama_path.clone()
    } else {
        services.resolve_ollama_path(None)
    };
    if ollama_path.is_none() {
        *ollama_path = resolved_path.clone();
    }

    let mut running_models = Vec::new();
    let mut ollama_running: Option<bool> = None;
    let mut ollama_err: Option<String> = None;
    if let Some(path) = resolved_path.as_ref() {
        match services.list_models_if_running(path) {
            Ok(Some(list)) => {
                running_models = list;
                ollama_running = Some(true);
            }
            Ok(None) => {
                ollama_running = Some(false);
            }
            Err(err) => {
                ollama_err = Some(err.to_string());
            }
        }
    }
    let cached_models = if running_models.is_empty() {
        models.clone()
    } else {
        running_models.clone()
    };
    if !running_models.is_empty() {
        *models = running_models.clone();
    }

    let config_embed = resolve_config_embedding_model();
    let config_default = resolve_config_default_model();
    let embed_models = filter_embedding_models(&cached_models);
    let chat_models = filter_chat_models(&cached_models);
    let embed_installed = model_installed(&cached_models, &config_embed);
    let chat_installed = config_default
        .as_deref()
        .map(|model| model_installed(&cached_models, model))
        .unwrap_or(false);

    let (ollama_status, ollama_detail) =
        match (resolved_path.as_ref(), ollama_running, ollama_err.as_ref()) {
            (_, _, Some(err)) => (StepStatus::Failed, Some(err.to_string())),
            (None, _, None) => (StepStatus::Pending, Some("not installed".to_string())),
            (Some(_), Some(true), None) => (StepStatus::Done, Some("active".to_string())),
            (Some(_), Some(false), None) => (StepStatus::Pending, Some("not running".to_string())),
            (Some(_), None, None) => (StepStatus::Pending, Some("unknown".to_string())),
        };
    state.update_step(StepKey::Ollama, ollama_status, ollama_detail);

    let embed_status = if resolved_path.is_none() {
        StepStatus::Pending
    } else if embed_installed {
        StepStatus::Done
    } else {
        StepStatus::Pending
    };
    state.update_step(
        StepKey::EmbedModel,
        embed_status,
        Some(config_embed.clone()),
    );

    let chat_status = if resolved_path.is_none() {
        StepStatus::Pending
    } else if chat_installed {
        StepStatus::Done
    } else {
        StepStatus::Pending
    };
    state.update_step(StepKey::ChatModel, chat_status, config_default.clone());

    let chromium_status = services.chromium_install_status();
    let browser_status = if chromium_status.installed {
        StepStatus::Done
    } else {
        StepStatus::Pending
    };
    let browser_detail = if chromium_status.installed {
        Some(chromium_detail(&chromium_status))
    } else {
        Some("not installed".to_string())
    };
    state.update_step(StepKey::Browser, browser_status, browser_detail);

    let browsers = list_chromium_browsers();
    let config_browser = resolve_config_browser_kind();
    let config = load_summary_config();
    let provider_status = resolve_web_provider_status(config.as_ref());
    let provider_count = provider_status.configured_count();
    let providers_detail = Some(format!("{provider_count}/4 configured"));
    let providers_status = if provider_count > 0 {
        StepStatus::Done
    } else {
        StepStatus::Pending
    };
    state.update_step(StepKey::WebProviders, providers_status, providers_detail);

    let mut ollama_body = String::new();
    if let Some(path) = resolved_path.as_ref() {
        let _ = writeln!(ollama_body, "Ollama path: {}", path.display());
        match (ollama_running, ollama_err.as_ref()) {
            (Some(true), _) => {
                let _ = writeln!(ollama_body, "Status: running");
                let _ = writeln!(
                    ollama_body,
                    "Installed models: {}",
                    format_model_list(&cached_models)
                );
            }
            (Some(false), _) => {
                let _ = writeln!(ollama_body, "Status: installed but not running");
                if !cached_models.is_empty() {
                    let _ = writeln!(
                        ollama_body,
                        "Cached models: {}",
                        format_model_list(&cached_models)
                    );
                }
            }
            (None, Some(err)) => {
                let _ = writeln!(ollama_body, "Status: error ({err})");
            }
            _ => {
                let _ = writeln!(ollama_body, "Status: unknown");
            }
        }
    } else {
        ollama_body.push_str("Ollama not detected.\nSelect this section to install.");
    }

    let mut embed_body = String::new();
    if resolved_path.is_none() {
        embed_body.push_str("Ollama not detected.\nInstall Ollama to configure embedding models.");
    } else if ollama_running == Some(false) {
        embed_body
            .push_str("Ollama detected but not running.\nStart Ollama to list embedding models.");
    } else if let Some(err) = ollama_err.as_ref() {
        let _ = writeln!(embed_body, "Ollama error: {err}");
    } else {
        let _ = writeln!(
            embed_body,
            "Installed embedding models: {}",
            format_model_list(&embed_models)
        );
        let status = if embed_installed {
            "installed"
        } else {
            "missing"
        };
        let _ = writeln!(
            embed_body,
            "Configured embedding model: {config_embed} ({status})"
        );
    }

    let mut chat_body = String::new();
    if resolved_path.is_none() {
        chat_body.push_str("Ollama not detected.\nInstall Ollama to configure chat models.");
    } else if ollama_running == Some(false) {
        chat_body.push_str("Ollama detected but not running.\nStart Ollama to list chat models.");
    } else if let Some(err) = ollama_err.as_ref() {
        let _ = writeln!(chat_body, "Ollama error: {err}");
    } else {
        let _ = writeln!(
            chat_body,
            "Installed chat models: {}",
            format_model_list(&chat_models)
        );
        let status = match config_default.as_deref() {
            Some(model) if model_installed(&running_models, model) => "installed",
            Some(_) => "missing",
            None => "not set",
        };
        let _ = writeln!(
            chat_body,
            "Configured default chat model: {} ({status})",
            config_default.as_deref().unwrap_or("not set")
        );
    }

    let mut browser_body = String::new();
    let installed_list = format_browser_list(&browsers);
    let _ = writeln!(browser_body, "Chromium status:");
    let _ = writeln!(browser_body, "{installed_list}");
    let _ = writeln!(
        browser_body,
        "Configured browser: {}",
        config_browser.as_deref().unwrap_or("chromium")
    );
    if !chromium_status.installed {
        browser_body.push_str("\nSelect this section to download Chromium.");
    }

    let mut web_body = String::new();
    let _ = writeln!(web_body, "Web search API keys:");
    let _ = writeln!(
        web_body,
        "- Brave Search: {}",
        format_key_status(&provider_status.brave)
    );
    let _ = writeln!(
        web_body,
        "- Google CSE: key {}, cx {}",
        format_key_status(&provider_status.google_cse_key),
        format_key_status(&provider_status.google_cse_cx)
    );
    let _ = writeln!(
        web_body,
        "- Bing Web Search: {}",
        format_key_status(&provider_status.bing)
    );
    let mswarm_base_url = current_key_display(&provider_status.mswarm_base_url, false)
        .unwrap_or_else(app_config::default_mswarm_base_url);
    let _ = writeln!(
        web_body,
        "- mswarm: key {}, base URL {}, primary {}",
        format_key_status(&provider_status.mswarm_api_key),
        mswarm_base_url,
        if provider_status.mswarm_selected_for_web {
            "yes"
        } else {
            "no"
        }
    );
    web_body.push_str("\nSelect this section to add or update API keys.");

    let embed_options = if embed_models.is_empty() {
        None
    } else {
        let (choices, default_index) = build_model_choices(&embed_models, Some(&config_embed));
        let default_index = default_index.unwrap_or(0);
        Some(MenuOptions {
            choices,
            default_index,
        })
    };

    let chat_options = if chat_models.is_empty() {
        None
    } else {
        let (choices, default_index) = build_model_choices(&chat_models, config_default.as_deref());
        let default_index = default_index.unwrap_or(0);
        Some(MenuOptions {
            choices,
            default_index,
        })
    };

    MenuDetails {
        ollama: ollama_body.trim_end().to_string(),
        embed: embed_body.trim_end().to_string(),
        chat: chat_body.trim_end().to_string(),
        browser: browser_body.trim_end().to_string(),
        web_providers: web_body.trim_end().to_string(),
        embed_options,
        chat_options,
        browsers,
    }
}

fn apply_quick_default<S: WizardServices>(
    step: StepKey,
    value: &str,
    services: &S,
    state: &mut SetupState,
    models: &[String],
    browsers: &[BrowserStatus],
    default_model: &mut Option<String>,
) -> Result<()> {
    match step {
        StepKey::EmbedModel => {
            if !model_installed(models, value) {
                return Err(anyhow!("embedding model not found: {value}"));
            }
            services.set_embedding_model(value)?;
            state.update_step(
                StepKey::EmbedModel,
                StepStatus::Done,
                Some(value.to_string()),
            );
        }
        StepKey::ChatModel => {
            if !model_installed(models, value) {
                return Err(anyhow!("chat model not found: {value}"));
            }
            services.set_default_model(value)?;
            *default_model = Some(value.to_string());
            state.update_step(
                StepKey::ChatModel,
                StepStatus::Done,
                Some(value.to_string()),
            );
        }
        StepKey::Browser => {
            let browser = browsers
                .iter()
                .find(|browser| browser.name.eq_ignore_ascii_case(value))
                .ok_or_else(|| anyhow!("browser not found: {value}"))?;
            if !browser.installed {
                return Err(anyhow!("browser not installed: {value}"));
            }
            let path = browser
                .path
                .as_ref()
                .ok_or_else(|| anyhow!("browser path missing: {value}"))?;
            services.set_browser_path(path, "chromium")?;
            state.update_step(
                StepKey::Browser,
                StepStatus::Done,
                Some("chromium".to_string()),
            );
        }
        _ => {}
    }
    Ok(())
}

fn derive_outcome(state: &SetupState) -> SetupOutcome {
    let mut any_done = false;
    let mut any_skipped = false;
    let mut any_failed = false;
    for step in &state.steps {
        match step.status {
            StepStatus::Done => any_done = true,
            StepStatus::Skipped => any_skipped = true,
            StepStatus::Failed => any_failed = true,
            StepStatus::Active | StepStatus::Pending => {}
        }
    }
    if state.outcome == SetupOutcome::Failed || any_failed {
        SetupOutcome::Failed
    } else if state.outcome == SetupOutcome::Deferred {
        SetupOutcome::Deferred
    } else if any_done || any_skipped {
        SetupOutcome::Complete
    } else {
        SetupOutcome::Deferred
    }
}

fn configure_ollama_section<I: WizardInput, S: WizardServices>(
    state: &mut SetupState,
    input: &mut I,
    services: &S,
    ollama_path: &mut Option<PathBuf>,
    ollama_status: &mut Option<ollama::OllamaDaemonStatus>,
) -> Result<Option<String>> {
    state.set_current(StepKey::Ollama);
    if let Err(err) = ensure_ollama_ready(state, input, services, ollama_path, ollama_status) {
        return Ok(Some(err.to_string()));
    }
    if ollama_path.is_none() {
        state.update_step(
            StepKey::Ollama,
            StepStatus::Skipped,
            Some("not installed".to_string()),
        );
    } else {
        let detail = if ollama_status
            .as_ref()
            .map(|status| status.running)
            .unwrap_or(false)
        {
            "active".to_string()
        } else {
            "installed".to_string()
        };
        state.update_step(StepKey::Ollama, StepStatus::Done, Some(detail));
    }
    Ok(None)
}

fn configure_embedding_section<I: WizardInput, S: WizardServices>(
    state: &mut SetupState,
    input: &mut I,
    services: &S,
    ollama_path: &mut Option<PathBuf>,
    ollama_status: &mut Option<ollama::OllamaDaemonStatus>,
    models: &mut Vec<String>,
    installed: &mut Vec<String>,
) -> Result<Option<String>> {
    state.set_current(StepKey::EmbedModel);
    let path = match ensure_ollama_ready(state, input, services, ollama_path, ollama_status) {
        Ok(Some(path)) => path,
        Ok(None) => {
            state.update_step(
                StepKey::EmbedModel,
                StepStatus::Skipped,
                Some("ollama missing".to_string()),
            );
            return Ok(None);
        }
        Err(err) => return Ok(Some(err.to_string())),
    };

    let mut current_models = services.list_models(&path).unwrap_or_default();
    *models = current_models.clone();
    let config_embed = resolve_config_embedding_model();
    let embed_installed = model_installed(&current_models, &config_embed);
    let embed_list = format_model_list(&filter_embedding_models(&current_models));
    let embed_status = if embed_installed {
        "installed"
    } else {
        "missing"
    };
    input.info(
        state,
        &format!(
            "Installed embedding models: {embed_list}\nConfigured embedding model: {config_embed} ({embed_status})"
        ),
    )?;

    let model_prompt_override = env_bool("DOCDEX_OLLAMA_MODEL_PROMPT");
    let assume_yes = env_bool("DOCDEX_OLLAMA_MODEL_ASSUME_Y").unwrap_or(false);
    let prompt_models = model_prompt_override.unwrap_or(true);
    if !prompt_models {
        state.update_step(
            StepKey::EmbedModel,
            if embed_installed {
                StepStatus::Done
            } else {
                StepStatus::Skipped
            },
            Some(config_embed),
        );
        input.info(
            state,
            "Model prompts disabled; skipping embedding model selection.",
        )?;
        return Ok(None);
    }

    if !model_installed(&current_models, EMBED_MODEL)
        && (assume_yes
            || input.confirm(
                state,
                &format!("Install embedding model {EMBED_MODEL}?"),
                true,
            )?)
    {
        loop {
            let pull = input.with_progress(state, "Pulling embedding model...", || {
                services.pull_model(&path, EMBED_MODEL)
            });
            match pull {
                Ok(()) => {
                    installed.push(EMBED_MODEL.to_string());
                    current_models = services
                        .list_models(&path)
                        .unwrap_or_else(|_| current_models.clone());
                    *models = current_models.clone();
                    break;
                }
                Err(err) => {
                    let err = err.to_string();
                    state.update_step(StepKey::EmbedModel, StepStatus::Failed, Some(err.clone()));
                    if !prompt_retry(input, state, "Embedding model install failed. Retry?")? {
                        return Ok(Some(err));
                    }
                }
            }
        }
    }

    let embed_models = filter_embedding_models(&current_models);
    if embed_models.is_empty() {
        state.update_step(
            StepKey::EmbedModel,
            StepStatus::Skipped,
            Some("no embedding models".to_string()),
        );
        return Ok(None);
    }

    let (choices, default_index) = build_model_choices(&embed_models, Some(&config_embed));
    let Some(default_index) = default_index else {
        state.update_step(
            StepKey::EmbedModel,
            StepStatus::Skipped,
            Some("no embedding models".to_string()),
        );
        return Ok(None);
    };
    let selected = input.select_model(state, &choices, default_index)?;
    if let Some(model) = selected.as_deref() {
        services.set_embedding_model(model)?;
    }
    let chosen = selected.or_else(|| {
        if model_installed(&current_models, &config_embed) {
            Some(config_embed.clone())
        } else {
            None
        }
    });
    if let Some(model) = chosen {
        state.update_step(StepKey::EmbedModel, StepStatus::Done, Some(model));
    } else {
        state.update_step(StepKey::EmbedModel, StepStatus::Skipped, None);
    }
    Ok(None)
}

fn configure_chat_section<I: WizardInput, S: WizardServices>(
    context: &SetupContext,
    state: &mut SetupState,
    input: &mut I,
    services: &S,
    ollama_path: &mut Option<PathBuf>,
    ollama_status: &mut Option<ollama::OllamaDaemonStatus>,
    models: &mut Vec<String>,
    installed: &mut Vec<String>,
    default_model: &mut Option<String>,
) -> Result<Option<String>> {
    state.set_current(StepKey::ChatModel);
    let path = match ensure_ollama_ready(state, input, services, ollama_path, ollama_status) {
        Ok(Some(path)) => path,
        Ok(None) => {
            state.update_step(
                StepKey::ChatModel,
                StepStatus::Skipped,
                Some("ollama missing".to_string()),
            );
            return Ok(None);
        }
        Err(err) => return Ok(Some(err.to_string())),
    };

    let mut current_models = services.list_models(&path).unwrap_or_default();
    *models = current_models.clone();
    let config_default = resolve_config_default_model();
    let chat_models = filter_chat_models(&current_models);
    let chat_list = format_model_list(&chat_models);
    let chat_default_status = match config_default.as_deref() {
        Some(model) if model_installed(&current_models, model) => "installed",
        Some(_) => "missing",
        None => "not set",
    };
    input.info(
        state,
        &format!(
            "Installed chat models: {chat_list}\nConfigured default chat model: {} ({chat_default_status})",
            config_default.as_deref().unwrap_or("not set")
        ),
    )?;

    let model_prompt_override = env_bool("DOCDEX_OLLAMA_MODEL_PROMPT");
    let assume_yes = env_bool("DOCDEX_OLLAMA_MODEL_ASSUME_Y").unwrap_or(false);
    let prompt_models = model_prompt_override.unwrap_or(true);
    if prompt_models && context.hardware.recommend_phi() {
        if !model_installed(&current_models, CHAT_MODEL)
            && (assume_yes
                || input.confirm(
                    state,
                    &format!("Install chat model {CHAT_MODEL} (~{CHAT_MODEL_SIZE_GIB:.1} GiB)?"),
                    true,
                )?)
        {
            loop {
                let pull = input.with_progress(state, "Pulling chat model...", || {
                    services.pull_model(&path, CHAT_MODEL)
                });
                match pull {
                    Ok(()) => {
                        installed.push(CHAT_MODEL.to_string());
                        current_models = services
                            .list_models(&path)
                            .unwrap_or_else(|_| current_models.clone());
                        *models = current_models.clone();
                        break;
                    }
                    Err(err) => {
                        let err = err.to_string();
                        state.update_step(
                            StepKey::ChatModel,
                            StepStatus::Failed,
                            Some(err.clone()),
                        );
                        if !prompt_retry(input, state, "Chat model install failed. Retry?")? {
                            return Ok(Some(err));
                        }
                    }
                }
            }
        }
    } else if !prompt_models {
        input.info(
            state,
            "Model prompts disabled; skipping chat model selection.",
        )?;
        state.update_step(
            StepKey::ChatModel,
            if config_default
                .as_deref()
                .map(|model| model_installed(&current_models, model))
                .unwrap_or(false)
            {
                StepStatus::Done
            } else {
                StepStatus::Skipped
            },
            config_default.clone(),
        );
        return Ok(None);
    }

    let chat_models = filter_chat_models(&current_models);
    if chat_models.is_empty() {
        state.update_step(
            StepKey::ChatModel,
            StepStatus::Skipped,
            Some("no chat models".to_string()),
        );
        return Ok(None);
    }

    let (choices, default_index) = build_model_choices(&chat_models, config_default.as_deref());
    let Some(default_index) = default_index else {
        state.update_step(
            StepKey::ChatModel,
            StepStatus::Skipped,
            Some("no chat models".to_string()),
        );
        return Ok(None);
    };
    let selected = input.select_model(state, &choices, default_index)?;
    if let Some(model) = selected.as_deref() {
        services.set_default_model(model)?;
        *default_model = Some(model.to_string());
    }
    let chosen = selected.or_else(|| {
        config_default
            .clone()
            .filter(|model| model_installed(&current_models, model))
    });
    if let Some(model) = chosen {
        state.update_step(StepKey::ChatModel, StepStatus::Done, Some(model));
    } else {
        state.update_step(StepKey::ChatModel, StepStatus::Skipped, None);
    }
    Ok(None)
}

fn configure_browser_section<I: WizardInput, S: WizardServices>(
    state: &mut SetupState,
    input: &mut I,
    services: &S,
) -> Result<Option<String>> {
    state.set_current(StepKey::Browser);
    let status = services.chromium_install_status();
    if status.installed {
        if let Some(path) = status.path.as_ref() {
            services.set_browser_path(path, "chromium")?;
            state.update_step(
                StepKey::Browser,
                StepStatus::Done,
                Some(chromium_detail(&status)),
            );
            return Ok(None);
        }
    }

    let install_override = resolve_browser_install_preference()?;
    let consent = match install_override {
        Some(true) => true,
        Some(false) => false,
        None => input.confirm(
            state,
            "Chromium not detected. Do you want to download it now?",
            true,
        )?,
    };
    if !consent {
        state.update_step(
            StepKey::Browser,
            StepStatus::Skipped,
            Some("not installed".to_string()),
        );
        state.outcome = SetupOutcome::Deferred;
        return Ok(None);
    }

    loop {
        let install = input.with_progress(state, "Downloading Chromium...", || {
            services.install_chromium()
        });
        match install {
            Ok(result) => {
                services.set_browser_path(&result.path, "chromium")?;
                let detail = format!("v{}", result.version);
                state.update_step(StepKey::Browser, StepStatus::Done, Some(detail));
                break;
            }
            Err(err) => {
                let err = err.to_string();
                state.update_step(StepKey::Browser, StepStatus::Failed, Some(err.clone()));
                if !prompt_retry(input, state, "Chromium install failed. Retry?")? {
                    return Ok(Some(err));
                }
            }
        }
    }
    Ok(None)
}

fn configure_web_providers_section<I: WizardInput, S: WizardServices>(
    state: &mut SetupState,
    input: &mut I,
    services: &S,
) -> Result<Option<String>> {
    state.set_current(StepKey::WebProviders);
    let config = load_summary_config();
    let current = resolve_web_provider_status(config.as_ref());
    let current_detail = format!("{}/4 configured", current.configured_count());

    let brave_current = current_key_display(&current.brave, true);
    let google_api_current = current_key_display(&current.google_cse_key, true);
    let google_cse_current = current_key_display(&current.google_cse_cx, false);
    let bing_current = current_key_display(&current.bing, true);
    let mswarm_key_current = current_key_display(&current.mswarm_api_key, true);
    let mswarm_base_url_current = current_key_display(&current.mswarm_base_url, false);
    let brave_key = input.prompt_text(
        state,
        "Brave Search API key (X-Subscription-Token)",
        brave_current.as_deref(),
        true,
    )?;
    let google_api_key = input.prompt_text(
        state,
        "Google CSE API key",
        google_api_current.as_deref(),
        true,
    )?;
    let google_cse_cx = input.prompt_text(
        state,
        "Google CSE Search Engine ID (cx)",
        google_cse_current.as_deref(),
        false,
    )?;
    let bing_key = input.prompt_text(
        state,
        "Bing Web Search API key",
        bing_current.as_deref(),
        true,
    )?;
    let mswarm_api_key = input.prompt_text(
        state,
        "mswarm API key (x-api-key)",
        mswarm_key_current.as_deref(),
        true,
    )?;
    let mswarm_base_url = input.prompt_text(
        state,
        "mswarm base URL (leave blank for default)",
        mswarm_base_url_current.as_deref(),
        false,
    )?;
    let use_mswarm_for_web = input.confirm(
        state,
        "Use mswarm as the primary Docdex web search provider?",
        current.mswarm_selected_for_web,
    )?;

    if brave_key.is_none()
        && google_api_key.is_none()
        && google_cse_cx.is_none()
        && bing_key.is_none()
        && mswarm_api_key.is_none()
        && mswarm_base_url.is_none()
        && use_mswarm_for_web == current.mswarm_selected_for_web
    {
        let status = if current.configured_count() > 0 {
            StepStatus::Done
        } else {
            StepStatus::Pending
        };
        state.update_step(StepKey::WebProviders, status, Some(current_detail));
        return Ok(None);
    }

    services.set_web_provider_keys(config::WebProviderKeysUpdate {
        brave_api_key: brave_key.clone(),
        google_cse_api_key: google_api_key.clone(),
        google_cse_cx: google_cse_cx.clone(),
        bing_api_key: bing_key.clone(),
    })?;
    services.set_mswarm_config(config::MswarmConfigUpdate {
        api_key: mswarm_api_key.clone(),
        base_url: mswarm_base_url.clone(),
        use_for_web_search: Some(use_mswarm_for_web),
    })?;
    let refreshed = resolve_web_provider_status(load_summary_config().as_ref());
    let configured_detail = format!("{}/4 configured", refreshed.configured_count());
    let status = if refreshed.configured_count() > 0 {
        StepStatus::Done
    } else {
        StepStatus::Pending
    };
    state.update_step(StepKey::WebProviders, status, Some(configured_detail));
    Ok(None)
}

fn ensure_ollama_ready<I: WizardInput, S: WizardServices>(
    state: &mut SetupState,
    input: &mut I,
    services: &S,
    ollama_path: &mut Option<PathBuf>,
    ollama_status: &mut Option<ollama::OllamaDaemonStatus>,
) -> Result<Option<PathBuf>> {
    if ollama_path.is_none() {
        let install_override = env_bool("DOCDEX_OLLAMA_INSTALL");
        let consent = match install_override {
            Some(true) => true,
            Some(false) => false,
            None => input.confirm(
                state,
                "Ollama not detected. Do you want to download Ollama?",
                true,
            )?,
        };
        if !consent {
            state.update_step(
                StepKey::Ollama,
                StepStatus::Skipped,
                Some("not installed".to_string()),
            );
            state.outcome = SetupOutcome::Deferred;
            return Ok(None);
        }
        loop {
            input.info(state, "Installing Ollama...")?;
            let install = input.with_suspended_terminal(|| services.install_ollama());
            match install {
                Ok(()) => {
                    if let Some(path) = services.resolve_ollama_path(None) {
                        *ollama_path = Some(path);
                        break;
                    }
                    let err = "ollama installed but not found on PATH".to_string();
                    state.update_step(StepKey::Ollama, StepStatus::Failed, Some(err.clone()));
                    if !prompt_retry(input, state, "Ollama install failed. Retry?")? {
                        return Err(anyhow!(err));
                    }
                }
                Err(err) => {
                    let err = err.to_string();
                    state.update_step(StepKey::Ollama, StepStatus::Failed, Some(err.clone()));
                    if !prompt_retry(input, state, "Ollama install failed. Retry?")? {
                        return Err(anyhow!(err));
                    }
                }
            }
        }
    }

    let path = match ollama_path.clone() {
        Some(path) => path,
        None => return Ok(None),
    };
    loop {
        input.info(state, "Ensuring Ollama is running...")?;
        let ensure = input.with_suspended_terminal(|| services.ensure_ollama_service(&path));
        match ensure {
            Ok(status) => {
                *ollama_status = Some(status);
                state.update_step(
                    StepKey::Ollama,
                    StepStatus::Done,
                    Some("active".to_string()),
                );
                return Ok(Some(path));
            }
            Err(err) => {
                let err = err.to_string();
                state.update_step(StepKey::Ollama, StepStatus::Failed, Some(err.clone()));
                if !prompt_retry(input, state, "Ollama daemon failed to start. Retry?")? {
                    return Err(anyhow!(err));
                }
            }
        }
    }
}

#[derive(Clone, Debug)]
struct BrowserStatus {
    name: String,
    installed: bool,
    version: Option<String>,
    path: Option<PathBuf>,
}

#[derive(Clone, Debug)]
pub struct ModelChoice {
    pub label: String,
    pub value: String,
    pub selectable: bool,
    pub style: Option<Style>,
}

fn is_embedding_model_name(model: &str) -> bool {
    let trimmed = model.trim();
    if trimmed.is_empty() {
        return false;
    }
    let base = trimmed.split(':').next().unwrap_or(trimmed);
    let base_lower = base.to_ascii_lowercase();
    let embed_lower = EMBED_MODEL.to_ascii_lowercase();
    if base_lower.contains("embed") || base_lower.contains("embedding") {
        return true;
    }
    base_lower == embed_lower || base_lower.starts_with(&format!("{embed_lower}-"))
}

fn filter_embedding_models(models: &[String]) -> Vec<String> {
    models
        .iter()
        .filter(|model| is_embedding_model_name(model))
        .cloned()
        .collect()
}

fn filter_chat_models(models: &[String]) -> Vec<String> {
    models
        .iter()
        .filter(|model| !is_embedding_model_name(model))
        .cloned()
        .collect()
}

fn model_installed(models: &[String], model: &str) -> bool {
    let trimmed = model.trim();
    if trimmed.is_empty() {
        return false;
    }
    models
        .iter()
        .any(|candidate| candidate.eq_ignore_ascii_case(trimmed))
}

fn format_model_list(models: &[String]) -> String {
    if models.is_empty() {
        "none".to_string()
    } else {
        models.join(", ")
    }
}

fn build_model_choices(
    models: &[String],
    current_default: Option<&str>,
) -> (Vec<ModelChoice>, Option<usize>) {
    let mut choices = Vec::new();
    let mut default_index = None;
    for (idx, model) in models.iter().enumerate() {
        if default_index.is_none() {
            if let Some(default_model) = current_default {
                if model.eq_ignore_ascii_case(default_model) {
                    default_index = Some(idx);
                }
            }
        }
        choices.push(ModelChoice {
            label: model.clone(),
            value: model.clone(),
            selectable: true,
            style: None,
        });
    }
    if default_index.is_none() && !choices.is_empty() {
        default_index = Some(0);
    }
    (choices, default_index)
}

fn resolve_browser_install_preference() -> Result<Option<bool>> {
    let raw = match env::var("DOCDEX_BROWSER_INSTALL") {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(Some(false));
    }
    let lowered = trimmed.to_ascii_lowercase();
    match lowered.as_str() {
        "1" | "true" | "yes" | "y" | "on" | "chromium" => Ok(Some(true)),
        "0" | "false" | "no" | "n" | "off" | "none" | "skip" => Ok(Some(false)),
        _ => Err(anyhow!(
            "unsupported value for DOCDEX_BROWSER_INSTALL: {lowered}"
        )),
    }
}

fn resolve_config_embedding_model() -> String {
    load_summary_config()
        .and_then(|cfg| {
            let trimmed = cfg.llm.embedding_model.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        })
        .unwrap_or_else(|| EMBED_MODEL.to_string())
}

fn resolve_config_default_model() -> Option<String> {
    load_summary_config().and_then(|cfg| {
        let trimmed = cfg.llm.default_model.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn resolve_config_browser_kind() -> Option<String> {
    load_summary_config().and_then(|cfg| {
        cfg.web.scraper.browser_kind.and_then(|kind| {
            let trimmed = kind.trim();
            if trimmed.is_empty() {
                None
            } else if trimmed.eq_ignore_ascii_case("chromium")
                || trimmed.eq_ignore_ascii_case("chrome")
            {
                Some("chromium".to_string())
            } else {
                None
            }
        })
    })
}

fn list_chromium_browsers() -> Vec<BrowserStatus> {
    let mut browser = BrowserStatus {
        name: "chromium".to_string(),
        installed: false,
        version: None,
        path: None,
    };

    if let Some(manifest) = util::read_chromium_manifest() {
        if manifest.path.is_file() {
            browser.installed = true;
            browser.version = manifest.version;
            browser.path = Some(manifest.path);
        }
    }

    vec![browser]
}

fn browser_label(name: &str) -> String {
    if name.trim().eq_ignore_ascii_case("chromium") {
        "Chromium".to_string()
    } else {
        name.to_string()
    }
}

fn chromium_detail(status: &browser_install::ChromiumInstallStatus) -> String {
    if let Some(version) = status.version.as_deref().map(|value| value.trim()) {
        if !version.is_empty() {
            return format!("v{version}");
        }
    }
    if status.installed {
        "installed".to_string()
    } else {
        "missing".to_string()
    }
}

fn format_browser_status(browser: &BrowserStatus) -> String {
    let label = browser_label(&browser.name);
    if browser.installed {
        match browser.version.as_ref().map(|value| value.trim()) {
            Some(value) if !value.is_empty() => format!("- {label}: installed ({value})"),
            _ => format!("- {label}: installed"),
        }
    } else {
        format!("- {label}: uninstalled")
    }
}

fn format_browser_list(browsers: &[BrowserStatus]) -> String {
    if browsers.is_empty() {
        "none".to_string()
    } else {
        browsers
            .iter()
            .map(format_browser_status)
            .collect::<Vec<_>>()
            .join("\n")
    }
}

fn format_completion_message(
    models: &[String],
    default_model: Option<&str>,
    ollama_status: Option<&ollama::OllamaDaemonStatus>,
    installed_models: &[String],
) -> String {
    let config = load_summary_config();
    let config_default = config.as_ref().and_then(|cfg| {
        let trimmed = cfg.llm.default_model.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    });
    let config_embed = config
        .as_ref()
        .and_then(|cfg| {
            let trimmed = cfg.llm.embedding_model.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        })
        .unwrap_or_else(|| EMBED_MODEL.to_string());

    let ollama_running = ollama_status.map(|status| status.running).unwrap_or(false);
    let service_line = match ollama_status {
        Some(status) if status.service_enabled => {
            let service = status.service.as_deref().unwrap_or("service");
            format!("Ollama service: enabled via {service}")
        }
        Some(status) if status.service.is_some() => {
            format!(
                "Ollama service: running via {} (not registered for restart)",
                status.service.as_deref().unwrap_or("launch")
            )
        }
        _ => "Ollama service: not detected; using background process".to_string(),
    };
    let embed_installed = models.iter().any(|m| m.eq_ignore_ascii_case(&config_embed));
    let embed_line = if embed_installed {
        format!("Embedding model: {config_embed} (installed)")
    } else {
        format!("Embedding model: {config_embed} (missing)")
    };
    let default_present = default_model.is_some() || config_default.is_some();
    let default_line = match default_model
        .map(|value| value.to_string())
        .or(config_default)
    {
        Some(model) => format!("Default chat model: {model}"),
        None => "Default chat model: not set".to_string(),
    };

    let browser_info = config
        .as_ref()
        .and_then(resolve_browser_summary_from_config)
        .or_else(resolve_browser_summary_from_detection);
    let browser_ready = browser_info.is_some();
    let browser_line = match browser_info {
        Some(info) => format!("Web browser: {info}"),
        None => "Web browser: not configured".to_string(),
    };

    let fully_functional = ollama_running && embed_installed && default_present && browser_ready;
    let status_line = if fully_functional {
        "Docdex status: fully functional".to_string()
    } else {
        "Docdex status: partially configured".to_string()
    };

    let mut lines = vec![
        "Setup complete.".to_string(),
        format!(
            "Ollama: {}",
            if ollama_running {
                "running"
            } else {
                "not running"
            }
        ),
        service_line,
        embed_line,
        default_line,
        browser_line,
        status_line,
    ];

    if !installed_models.is_empty() {
        lines.push(format!(
            "Models installed this run: {}",
            installed_models.join(", ")
        ));
    }

    lines.push("Now you can safely close this window.".to_string());

    lines.join("\n")
}

fn load_summary_config() -> Option<app_config::AppConfig> {
    let path = app_config::default_config_path().ok()?;
    let previous = env::var("DOCDEX_BROWSER_AUTO_INSTALL").ok();
    env::set_var("DOCDEX_BROWSER_AUTO_INSTALL", "0");
    let config = app_config::load_config_from_path(&path).ok();
    match previous {
        Some(value) => env::set_var("DOCDEX_BROWSER_AUTO_INSTALL", value),
        None => env::remove_var("DOCDEX_BROWSER_AUTO_INSTALL"),
    }
    config
}

fn resolve_browser_summary_from_config(config: &app_config::AppConfig) -> Option<String> {
    let kind = config.web.scraper.browser_kind.as_deref()?;
    if !kind.eq_ignore_ascii_case("chromium") && !kind.eq_ignore_ascii_case("chrome") {
        return None;
    }
    let label = browser_label("chromium");
    if let Some(path) = config.web.scraper.chrome_binary_path.as_ref() {
        return Some(format!("{label} ({})", path.display()));
    }
    let browsers = list_chromium_browsers();
    browsers
        .iter()
        .find(|browser| browser.installed)
        .and_then(|browser| {
            browser
                .path
                .as_ref()
                .map(|path| format!("{label} ({})", path.display()))
        })
}

fn resolve_browser_summary_from_detection() -> Option<String> {
    let browsers = list_chromium_browsers();
    browsers
        .iter()
        .find(|browser| browser.installed)
        .and_then(|browser| {
            browser
                .path
                .as_ref()
                .map(|path| format!("{} ({})", browser_label(&browser.name), path.display()))
        })
}

#[derive(Clone, Default)]
struct ProviderKeyStatus {
    configured: bool,
    from_env: bool,
    value: Option<String>,
}

#[derive(Clone, Default)]
struct WebProviderStatus {
    brave: ProviderKeyStatus,
    google_cse_key: ProviderKeyStatus,
    google_cse_cx: ProviderKeyStatus,
    bing: ProviderKeyStatus,
    mswarm_api_key: ProviderKeyStatus,
    mswarm_base_url: ProviderKeyStatus,
    mswarm_selected_for_web: bool,
}

impl WebProviderStatus {
    fn configured_count(&self) -> usize {
        let mut count = 0;
        if self.brave.configured {
            count += 1;
        }
        if self.google_cse_key.configured && self.google_cse_cx.configured {
            count += 1;
        }
        if self.bing.configured {
            count += 1;
        }
        if self.mswarm_api_key.configured {
            count += 1;
        }
        count
    }
}

fn resolve_web_provider_status(config: Option<&app_config::AppConfig>) -> WebProviderStatus {
    WebProviderStatus {
        brave: resolve_key_status(config, "DOCDEX_BRAVE_API_KEY", |cfg| {
            cfg.web.providers.brave_api_key.as_ref()
        }),
        google_cse_key: resolve_key_status(config, "DOCDEX_GOOGLE_CSE_API_KEY", |cfg| {
            cfg.web.providers.google_cse_api_key.as_ref()
        }),
        google_cse_cx: resolve_key_status(config, "DOCDEX_GOOGLE_CSE_CX", |cfg| {
            cfg.web.providers.google_cse_cx.as_ref()
        }),
        bing: resolve_key_status(config, "DOCDEX_BING_API_KEY", |cfg| {
            cfg.web.providers.bing_api_key.as_ref()
        }),
        mswarm_api_key: resolve_key_status(config, "DOCDEX_MSWARM_API_KEY", |cfg| {
            cfg.integrations.mswarm.api_key.as_ref()
        }),
        mswarm_base_url: resolve_key_status(config, "DOCDEX_MSWARM_BASE_URL", |cfg| {
            Some(&cfg.integrations.mswarm.base_url)
        }),
        mswarm_selected_for_web: resolve_discovery_provider(config).eq_ignore_ascii_case("mswarm"),
    }
}

fn resolve_discovery_provider(config: Option<&app_config::AppConfig>) -> String {
    env::var("DOCDEX_WEB_DISCOVERY_PROVIDER")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .or_else(|| {
            config
                .map(|cfg| cfg.web.discovery_provider.trim().to_string())
                .filter(|value| !value.is_empty())
        })
        .unwrap_or_else(app_config::default_discovery_provider)
}

fn resolve_key_status(
    config: Option<&app_config::AppConfig>,
    env_key: &str,
    extract: impl FnOnce(&app_config::AppConfig) -> Option<&String>,
) -> ProviderKeyStatus {
    let env_value = env::var(env_key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let config_value = config
        .and_then(extract)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    match (env_value, config_value) {
        (Some(value), _) => ProviderKeyStatus {
            configured: true,
            from_env: true,
            value: Some(value),
        },
        (None, Some(value)) => ProviderKeyStatus {
            configured: true,
            from_env: false,
            value: Some(value),
        },
        (None, None) => ProviderKeyStatus {
            configured: false,
            from_env: false,
            value: None,
        },
    }
}

fn format_key_status(status: &ProviderKeyStatus) -> &'static str {
    if status.configured {
        if status.from_env {
            "set (env)"
        } else {
            "set"
        }
    } else {
        "missing"
    }
}

fn mask_secret_value(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let chars: Vec<char> = trimmed.chars().collect();
    if chars.len() <= 6 {
        let prefix_len = chars.len().min(2);
        let prefix: String = chars[..prefix_len].iter().collect();
        return format!("{prefix}***");
    }
    let prefix: String = chars[..4].iter().collect();
    let suffix: String = chars[chars.len().saturating_sub(3)..].iter().collect();
    format!("{prefix}***{suffix}")
}

fn current_key_display(status: &ProviderKeyStatus, secret: bool) -> Option<String> {
    if !status.configured {
        return None;
    }
    let value = status
        .value
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .map(|value| {
            if secret {
                mask_secret_value(value)
            } else {
                value.to_string()
            }
        })
        .unwrap_or_else(|| format_key_status(status).to_string());
    let suffix = if status.from_env { " (env)" } else { "" };
    Some(format!("{value}{suffix}"))
}

fn prompt_retry<I: WizardInput>(input: &mut I, state: &SetupState, message: &str) -> Result<bool> {
    input.confirm(state, message, false)
}

fn summary_from_state(
    state: &SetupState,
    message: String,
    mut models_installed: Vec<String>,
    default_model: Option<String>,
) -> SetupSummary {
    models_installed.sort();
    models_installed.dedup();
    SetupSummary {
        status: state.outcome.as_str().to_string(),
        message,
        models_installed,
        default_model,
        timestamp_ms: now_ms(),
        error: state.error.clone(),
        steps: state.steps.clone(),
    }
}

fn env_bool(key: &str) -> Option<bool> {
    std::env::var(key)
        .ok()
        .and_then(|value| match value.trim().to_ascii_lowercase().as_str() {
            "1" | "true" | "yes" | "y" | "on" => Some(true),
            "0" | "false" | "no" | "n" | "off" => Some(false),
            _ => None,
        })
}

fn now_ms() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
}

struct TuiInput {
    terminal: Terminal<CrosstermBackend<Stdout>>,
    selected_index: usize,
    menu_index: usize,
    menu_focus: MenuFocus,
    option_index: usize,
    option_step: Option<StepKey>,
}

impl TuiInput {
    fn new() -> Result<Self> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, cursor::Hide)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;
        terminal.clear()?;
        Ok(Self {
            terminal,
            selected_index: 0,
            menu_index: 0,
            menu_focus: MenuFocus::Menu,
            option_index: 0,
            option_step: None,
        })
    }

    fn draw_prompt(
        &mut self,
        state: &SetupState,
        body: &str,
        hint: &str,
        list: Option<(&[ModelChoice], usize)>,
        selected: StepKey,
    ) -> Result<()> {
        self.terminal.draw(|frame| {
            let layout = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(3), Constraint::Length(2)])
                .split(frame.size());

            let content = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Length(28), Constraint::Min(10)])
                .split(layout[0]);

            render_status_list(frame, content[0], &state.steps, selected);
            render_body(frame, content[1], body, list);

            let hints = Paragraph::new(hint)
                .block(Block::default().borders(Borders::TOP))
                .wrap(Wrap { trim: true });
            frame.render_widget(hints, layout[1]);
        })?;
        Ok(())
    }

    fn read_key(&self) -> Result<KeyCode> {
        loop {
            if let Event::Key(key) = event::read()? {
                if matches!(key.kind, KeyEventKind::Press | KeyEventKind::Repeat) {
                    return Ok(key.code);
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MenuFocus {
    Menu,
    Options,
}

impl WizardInput for TuiInput {
    fn select_menu(
        &mut self,
        state: &SetupState,
        steps: &[StepKey],
        details: &MenuDetails,
    ) -> Result<MenuAction> {
        if steps.is_empty() {
            return Ok(MenuAction::Exit);
        }
        if self.menu_index >= steps.len() {
            self.menu_index = 0;
        }
        loop {
            let selected = steps[self.menu_index];
            let options = details.options_for(selected);
            if options.is_none() && self.menu_focus == MenuFocus::Options {
                self.menu_focus = MenuFocus::Menu;
            }
            if self.option_step != Some(selected) {
                self.option_step = Some(selected);
                self.option_index = options
                    .map(|entry| {
                        entry
                            .default_index
                            .min(entry.choices.len().saturating_sub(1))
                    })
                    .unwrap_or(0);
            }
            let hint = match self.menu_focus {
                MenuFocus::Menu => {
                    if options.is_some() {
                        "Up/Down=move, Right/Tab=options, Enter=open, Esc=finish"
                    } else {
                        "Up/Down=move, Enter=open, Esc=finish"
                    }
                }
                MenuFocus::Options => {
                    "Up/Down=select, Left/Tab=menu, Enter=set default, Esc=finish"
                }
            };
            self.draw_prompt(
                state,
                details.body_for(selected),
                hint,
                options.map(|entry| (entry.choices.as_slice(), self.option_index)),
                selected,
            )?;
            match self.read_key()? {
                KeyCode::Tab | KeyCode::Right | KeyCode::Char('l') | KeyCode::Char('L') => {
                    if options.is_some() {
                        self.menu_focus = MenuFocus::Options;
                    }
                }
                KeyCode::BackTab | KeyCode::Left | KeyCode::Char('h') | KeyCode::Char('H') => {
                    self.menu_focus = MenuFocus::Menu;
                }
                KeyCode::Up | KeyCode::Char('k') | KeyCode::Char('K') => match self.menu_focus {
                    MenuFocus::Menu => {
                        if self.menu_index == 0 {
                            self.menu_index = steps.len() - 1;
                        } else {
                            self.menu_index = self.menu_index.saturating_sub(1);
                        }
                    }
                    MenuFocus::Options => {
                        if let Some(entry) = options {
                            if let Some(next) =
                                next_selectable_index(&entry.choices, self.option_index, -1)
                            {
                                self.option_index = next;
                            }
                        }
                    }
                },
                KeyCode::Down | KeyCode::Char('j') | KeyCode::Char('J') => match self.menu_focus {
                    MenuFocus::Menu => {
                        self.menu_index = (self.menu_index + 1) % steps.len();
                    }
                    MenuFocus::Options => {
                        if let Some(entry) = options {
                            if let Some(next) =
                                next_selectable_index(&entry.choices, self.option_index, 1)
                            {
                                self.option_index = next;
                            }
                        }
                    }
                },
                KeyCode::Enter => match self.menu_focus {
                    MenuFocus::Menu => return Ok(MenuAction::SelectSection(selected)),
                    MenuFocus::Options => {
                        if let Some(entry) = options {
                            if let Some(choice) = entry.choices.get(self.option_index) {
                                if choice.selectable {
                                    return Ok(MenuAction::SelectDefault {
                                        step: selected,
                                        value: choice.value.clone(),
                                    });
                                }
                            }
                        } else {
                            return Ok(MenuAction::SelectSection(selected));
                        }
                    }
                },
                KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('Q') => {
                    return Ok(MenuAction::Exit)
                }
                _ => {}
            }
        }
    }

    fn confirm(&mut self, state: &SetupState, prompt: &str, default_yes: bool) -> Result<bool> {
        let hint = if default_yes {
            "Y=yes, N=no, Enter=Yes, Esc=No"
        } else {
            "Y=yes, N=no, Enter=No, Esc=No"
        };
        loop {
            self.draw_prompt(state, prompt, hint, None, state.current)?;
            match self.read_key()? {
                KeyCode::Char('y') | KeyCode::Char('Y') => return Ok(true),
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => return Ok(false),
                KeyCode::Enter => return Ok(default_yes),
                _ => {}
            }
        }
    }

    fn select_model(
        &mut self,
        state: &SetupState,
        models: &[ModelChoice],
        default_index: usize,
    ) -> Result<Option<String>> {
        let hint = "Up/Down=move, Enter=select, Esc=skip";
        let body = match state.current {
            StepKey::ChatModel => "Select default chat model",
            StepKey::EmbedModel => "Select default embedding model",
            StepKey::Browser => "Select Chromium browser",
            _ => "Select option",
        };
        self.selected_index = default_index.min(models.len().saturating_sub(1));
        loop {
            self.draw_prompt(
                state,
                body,
                hint,
                Some((models, self.selected_index)),
                state.current,
            )?;
            match self.read_key()? {
                KeyCode::Up | KeyCode::Char('k') | KeyCode::Char('K') => {
                    if let Some(next) = next_selectable_index(models, self.selected_index, -1) {
                        self.selected_index = next;
                    }
                }
                KeyCode::Down | KeyCode::Char('j') | KeyCode::Char('J') => {
                    if let Some(next) = next_selectable_index(models, self.selected_index, 1) {
                        self.selected_index = next;
                    }
                }
                KeyCode::Enter => {
                    if let Some(choice) = models.get(self.selected_index) {
                        if choice.selectable {
                            return Ok(Some(choice.value.clone()));
                        }
                    }
                }
                KeyCode::Esc => return Ok(None),
                _ => {}
            }
        }
    }

    fn prompt_text(
        &mut self,
        state: &SetupState,
        prompt: &str,
        current: Option<&str>,
        secret: bool,
    ) -> Result<Option<String>> {
        let mut buffer = String::new();
        let hint = if secret {
            "Type to set, Enter=save, Esc=skip, Backspace=delete (input hidden)"
        } else {
            "Type to set, Enter=save, Esc=skip, Backspace=delete"
        };
        loop {
            let current_label = current
                .map(|value| value.trim())
                .filter(|value| !value.is_empty())
                .unwrap_or("not set");
            let displayed = if buffer.is_empty() {
                "<leave unchanged>".to_string()
            } else if secret {
                "*".repeat(buffer.chars().count())
            } else {
                buffer.clone()
            };
            let current_field = format!("[ {current_label} ]");
            let input_field = format!("[ {displayed} ]");
            let body = format!("{prompt}\nCurrent: {current_field}\nInput:   {input_field}");
            self.draw_prompt(state, &body, hint, None, state.current)?;
            match self.read_key()? {
                KeyCode::Char(c) => {
                    if !c.is_control() {
                        buffer.push(c);
                    }
                }
                KeyCode::Backspace => {
                    buffer.pop();
                }
                KeyCode::Enter => {
                    if buffer.is_empty() {
                        return Ok(None);
                    }
                    return Ok(Some(buffer.clone()));
                }
                KeyCode::Esc => return Ok(None),
                _ => {}
            }
        }
    }

    fn info(&mut self, state: &SetupState, message: &str) -> Result<()> {
        self.draw_prompt(state, message, "", None, state.current)
    }

    fn with_suspended_terminal<T, F: FnOnce() -> Result<T>>(&mut self, op: F) -> Result<T> {
        disable_raw_mode()?;
        execute!(
            self.terminal.backend_mut(),
            LeaveAlternateScreen,
            cursor::Show
        )?;
        let result = op();
        execute!(
            self.terminal.backend_mut(),
            EnterAlternateScreen,
            cursor::Hide
        )?;
        enable_raw_mode()?;
        self.terminal.clear()?;
        result
    }

    fn with_progress<T, F: FnOnce() -> Result<T>>(
        &mut self,
        _state: &SetupState,
        message: &str,
        op: F,
    ) -> Result<T> {
        disable_raw_mode()?;
        execute!(
            self.terminal.backend_mut(),
            LeaveAlternateScreen,
            cursor::Show
        )?;
        let mut spinner = ProgressSpinner::start(message);
        let result = op();
        spinner.stop();
        execute!(
            self.terminal.backend_mut(),
            EnterAlternateScreen,
            cursor::Hide
        )?;
        enable_raw_mode()?;
        self.terminal.clear()?;
        result
    }
}

impl Drop for TuiInput {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(
            self.terminal.backend_mut(),
            LeaveAlternateScreen,
            cursor::Show
        );
    }
}

fn render_status_list(
    frame: &mut ratatui::Frame,
    area: Rect,
    steps: &[StepSnapshot],
    current: StepKey,
) {
    let mut selected_index = 0usize;
    let items: Vec<ListItem> = MENU_STEPS
        .iter()
        .filter_map(|key| steps.iter().find(|step| step.key == *key))
        .enumerate()
        .map(|(idx, step)| {
            if step.key == current {
                selected_index = idx;
            }
            let status = step.status.label();
            let label = match step.detail.as_ref().map(|value| value.trim()) {
                Some(detail) if !detail.is_empty() => {
                    format!("{}: {} ({detail})", step.key.label(), status)
                }
                _ => format!("{}: {}", step.key.label(), status),
            };
            let style = match step.status {
                StepStatus::Done => Style::default().fg(Color::Green),
                StepStatus::Failed => Style::default().fg(Color::Red),
                StepStatus::Active => Style::default().fg(Color::Yellow),
                StepStatus::Skipped => Style::default().fg(Color::DarkGray),
                StepStatus::Pending => Style::default().fg(Color::Gray),
            };
            ListItem::new(Line::from(Span::styled(label, style)))
        })
        .collect();

    let mut state = ListState::default();
    if !items.is_empty() {
        state.select(Some(selected_index.min(items.len() - 1)));
    }
    let list = List::new(items)
        .block(Block::default().title("Setup").borders(Borders::ALL))
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
    frame.render_stateful_widget(list, area, &mut state);
}

fn render_body(
    frame: &mut ratatui::Frame,
    area: Rect,
    body: &str,
    list: Option<(&[ModelChoice], usize)>,
) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Min(3)])
        .split(area);

    let paragraph = Paragraph::new(body)
        .block(Block::default().title("Details").borders(Borders::ALL))
        .wrap(Wrap { trim: true });
    frame.render_widget(paragraph, chunks[0]);

    if let Some((items, selected)) = list {
        let list_items: Vec<ListItem> = items
            .iter()
            .map(|item| {
                let mut style = item.style.unwrap_or_default();
                if !item.selectable && item.style.is_none() {
                    style = style.fg(Color::DarkGray);
                }
                ListItem::new(Line::from(Span::styled(item.label.clone(), style)))
            })
            .collect();
        let mut state = ListState::default();
        state.select(Some(selected));
        let list = List::new(list_items)
            .block(Block::default().title("Options").borders(Borders::ALL))
            .highlight_style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            );
        frame.render_stateful_widget(list, chunks[1], &mut state);
    }
}

fn next_selectable_index(
    models: &[ModelChoice],
    current: usize,
    direction: isize,
) -> Option<usize> {
    if models.is_empty() {
        return None;
    }
    let mut index = current as isize;
    loop {
        index += direction;
        if index < 0 || index >= models.len() as isize {
            return None;
        }
        let idx = index as usize;
        if models[idx].selectable {
            return Some(idx);
        }
    }
}

struct ProgressSpinner {
    message: String,
    running: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl ProgressSpinner {
    fn start(message: &str) -> Self {
        let running = Arc::new(AtomicBool::new(true));
        let running_thread = Arc::clone(&running);
        let message_owned = message.to_string();
        let thread_message = message_owned.clone();
        let handle = std::thread::spawn(move || {
            let mut tick = 0usize;
            let mut stdout = io::stdout();
            let mut first = true;
            while running_thread.load(Ordering::Relaxed) {
                if first {
                    let _ = writeln!(stdout);
                    let _ = stdout.flush();
                    first = false;
                }
                let bar = progress_bar(tick, 20);
                let _ = write!(stdout, "\r{} {}", thread_message, bar);
                let _ = stdout.flush();
                tick = tick.wrapping_add(1);
                std::thread::sleep(Duration::from_millis(120));
            }
        });
        Self {
            message: message_owned,
            running,
            handle: Some(handle),
        }
    }

    fn stop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        let mut stdout = io::stdout();
        let clear_width = self.message.len().saturating_add(32);
        let _ = write!(stdout, "\r{:width$}\r", "", width = clear_width);
        let _ = stdout.flush();
    }
}

fn progress_bar(tick: usize, width: usize) -> String {
    let width = width.max(4);
    let pos = tick % width;
    let mut bar = String::with_capacity(width + 2);
    bar.push('[');
    for idx in 0..width {
        if idx == pos {
            bar.push('>');
        } else if idx < pos {
            bar.push('=');
        } else {
            bar.push(' ');
        }
    }
    bar.push(']');
    bar
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup::test_support::ENV_LOCK;
    use ratatui::backend::TestBackend;
    use std::path::{Path, PathBuf};
    use tempfile::TempDir;

    struct EnvGuard {
        key: &'static str,
        previous: Option<String>,
    }

    impl EnvGuard {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self { key, previous }
        }

        fn clear(key: &'static str) -> Self {
            let previous = std::env::var(key).ok();
            std::env::remove_var(key);
            Self { key, previous }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.previous {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }

    struct ScriptedInput {
        answers: Vec<ScriptedAnswer>,
        index: usize,
    }

    #[derive(Clone)]
    enum ScriptedAnswer {
        Confirm(bool),
        Select(Option<usize>),
        Menu(Option<StepKey>),
        Text(Option<String>),
    }

    impl ScriptedInput {
        fn new(answers: Vec<ScriptedAnswer>) -> Self {
            Self { answers, index: 0 }
        }

        fn next(&mut self) -> ScriptedAnswer {
            if self.index >= self.answers.len() {
                return ScriptedAnswer::Menu(None);
            }
            let answer = self.answers[self.index].clone();
            self.index += 1;
            answer
        }
    }

    impl WizardInput for ScriptedInput {
        fn select_menu(
            &mut self,
            _state: &SetupState,
            steps: &[StepKey],
            _details: &MenuDetails,
        ) -> Result<MenuAction> {
            match self.next() {
                ScriptedAnswer::Menu(Some(choice)) => Ok(MenuAction::SelectSection(choice)),
                ScriptedAnswer::Menu(None) => Ok(MenuAction::Exit),
                _ => Ok(MenuAction::SelectSection(
                    steps.first().copied().unwrap_or(StepKey::Ollama),
                )),
            }
        }

        fn confirm(
            &mut self,
            _state: &SetupState,
            _prompt: &str,
            default_yes: bool,
        ) -> Result<bool> {
            match self.next() {
                ScriptedAnswer::Confirm(value) => Ok(value),
                _ => Ok(default_yes),
            }
        }

        fn select_model(
            &mut self,
            _state: &SetupState,
            models: &[ModelChoice],
            default_index: usize,
        ) -> Result<Option<String>> {
            match self.next() {
                ScriptedAnswer::Select(Some(idx)) => Ok(models
                    .get(idx)
                    .filter(|choice| choice.selectable)
                    .map(|choice| choice.value.clone())),
                ScriptedAnswer::Select(None) => Ok(None),
                _ => Ok(models
                    .get(default_index)
                    .filter(|choice| choice.selectable)
                    .map(|choice| choice.value.clone())),
            }
        }

        fn prompt_text(
            &mut self,
            _state: &SetupState,
            _prompt: &str,
            _current: Option<&str>,
            _secret: bool,
        ) -> Result<Option<String>> {
            match self.next() {
                ScriptedAnswer::Text(value) => Ok(value),
                _ => Ok(None),
            }
        }

        fn info(&mut self, _state: &SetupState, _message: &str) -> Result<()> {
            Ok(())
        }

        fn with_suspended_terminal<T, F: FnOnce() -> Result<T>>(&mut self, op: F) -> Result<T> {
            op()
        }
    }

    struct FakeServices {
        models: Vec<String>,
        ollama_path: Option<PathBuf>,
        chromium_installed: bool,
        chromium_path: Option<PathBuf>,
    }

    impl WizardServices for FakeServices {
        fn resolve_ollama_path(&self, _explicit: Option<PathBuf>) -> Option<PathBuf> {
            self.ollama_path.clone()
        }

        fn install_ollama(&self) -> Result<()> {
            Ok(())
        }

        fn ensure_ollama_service(&self, _bin: &Path) -> Result<ollama::OllamaDaemonStatus> {
            Ok(ollama::OllamaDaemonStatus {
                running: true,
                service: Some("test".to_string()),
                service_enabled: true,
            })
        }

        fn list_models(&self, _bin: &Path) -> Result<Vec<String>> {
            Ok(self.models.clone())
        }

        fn list_models_if_running(&self, _bin: &Path) -> Result<Option<Vec<String>>> {
            Ok(Some(self.models.clone()))
        }

        fn pull_model(&self, _bin: &Path, _model: &str) -> Result<()> {
            Ok(())
        }

        fn set_default_model(&self, _model: &str) -> Result<()> {
            Ok(())
        }

        fn set_embedding_model(&self, _model: &str) -> Result<()> {
            Ok(())
        }

        fn chromium_install_status(&self) -> browser_install::ChromiumInstallStatus {
            browser_install::ChromiumInstallStatus {
                installed: self.chromium_installed,
                version: self.chromium_installed.then(|| "test".to_string()),
                path: self
                    .chromium_installed
                    .then(|| self.chromium_path.clone())
                    .flatten(),
            }
        }

        fn install_chromium(&self) -> Result<browser_install::BrowserInstallResult> {
            let path = self
                .chromium_path
                .clone()
                .unwrap_or_else(|| PathBuf::from("/tmp/chromium"));
            Ok(browser_install::BrowserInstallResult {
                path,
                version: "test".to_string(),
            })
        }

        fn set_browser_path(&self, _path: &Path, _kind: &str) -> Result<()> {
            Ok(())
        }

        fn set_web_provider_keys(&self, _update: config::WebProviderKeysUpdate) -> Result<bool> {
            Ok(false)
        }

        fn set_mswarm_config(&self, _update: config::MswarmConfigUpdate) -> Result<bool> {
            Ok(false)
        }

        fn ensure_mswarm_consent(
            &self,
            _accepted_at_ms: u128,
        ) -> Result<config::MswarmTelemetryConsentStatus> {
            Ok(config::MswarmTelemetryConsentStatus {
                client_id: "client-1".to_string(),
                client_type: "free_docdex_client".to_string(),
                policy_version: "2026-03-18".to_string(),
                consent_token_set: true,
            })
        }
    }

    #[test]
    fn scripted_input_prompt_text_returns_value() -> Result<()> {
        let mut input = ScriptedInput::new(vec![ScriptedAnswer::Text(Some("hello".to_string()))]);
        let state = SetupState::new();
        let value = input.prompt_text(&state, "Prompt", None, false)?;
        assert_eq!(value.as_deref(), Some("hello"));
        Ok(())
    }

    #[test]
    fn wizard_decline_records_deferred() -> Result<()> {
        let _guard = ENV_LOCK.lock();
        let temp = TempDir::new()?;
        let temp_home = temp.path().to_string_lossy();
        let _home = EnvGuard::set("HOME", &temp_home);
        let _user = EnvGuard::set("USERPROFILE", &temp_home);
        let _appdata = EnvGuard::set(
            "APPDATA",
            &temp
                .path()
                .join("AppData")
                .join("Roaming")
                .to_string_lossy(),
        );
        let _config = EnvGuard::set(
            "DOCDEX_CONFIG_PATH",
            &temp.path().join("config.toml").to_string_lossy(),
        );
        let _ollama_install = EnvGuard::clear("DOCDEX_OLLAMA_INSTALL");
        let _ollama_prompt = EnvGuard::clear("DOCDEX_OLLAMA_MODEL_PROMPT");
        let _ollama_assume = EnvGuard::clear("DOCDEX_OLLAMA_MODEL_ASSUME_Y");
        let _browser_install = EnvGuard::clear("DOCDEX_BROWSER_INSTALL");
        let mut input = ScriptedInput::new(vec![
            ScriptedAnswer::Confirm(true),
            ScriptedAnswer::Menu(Some(StepKey::Ollama)),
            ScriptedAnswer::Confirm(false),
            ScriptedAnswer::Menu(None),
        ]);
        let services = FakeServices {
            models: vec![],
            ollama_path: None,
            chromium_installed: false,
            chromium_path: None,
        };
        let context = SetupContext {
            hardware: super::super::hardware::SetupHardware {
                total_memory_gb: 16.0,
                free_disk_bytes: 10 * 1024 * 1024 * 1024,
                cpu_count: 8,
            },
            ollama_path: None,
        };
        let summary = run_wizard_with_input(context, &mut input, &services)?;
        assert_eq!(summary.status, "deferred");
        Ok(())
    }

    #[test]
    fn derive_outcome_keeps_explicit_deferred_with_completed_steps() {
        let mut state = SetupState::new();
        state.update_step(
            StepKey::Consent,
            StepStatus::Done,
            Some("accepted".to_string()),
        );
        state.update_step(
            StepKey::Ollama,
            StepStatus::Skipped,
            Some("not installed".to_string()),
        );
        state.outcome = SetupOutcome::Deferred;

        assert_eq!(derive_outcome(&state), SetupOutcome::Deferred);
    }

    #[test]
    fn wizard_declining_consent_fails() -> Result<()> {
        let _guard = ENV_LOCK.lock();
        let mut input = ScriptedInput::new(vec![ScriptedAnswer::Confirm(false)]);
        let services = FakeServices {
            models: vec![],
            ollama_path: None,
            chromium_installed: false,
            chromium_path: None,
        };
        let context = SetupContext {
            hardware: super::super::hardware::SetupHardware {
                total_memory_gb: 16.0,
                free_disk_bytes: 10 * 1024 * 1024 * 1024,
                cpu_count: 8,
            },
            ollama_path: None,
        };
        let summary = run_wizard_with_input(context, &mut input, &services)?;
        assert_eq!(summary.status, "failed");
        assert!(summary.message.contains("consent"));
        Ok(())
    }

    #[test]
    fn wizard_completes_with_default_model() -> Result<()> {
        let _guard = ENV_LOCK.lock();
        std::env::remove_var("DOCDEX_OLLAMA_INSTALL");
        std::env::remove_var("DOCDEX_OLLAMA_MODEL_PROMPT");
        std::env::remove_var("DOCDEX_OLLAMA_MODEL_ASSUME_Y");
        std::env::remove_var("DOCDEX_BROWSER_INSTALL");
        let mut input = ScriptedInput::new(vec![
            ScriptedAnswer::Confirm(true),
            ScriptedAnswer::Menu(Some(StepKey::ChatModel)),
            ScriptedAnswer::Select(Some(0)),
            ScriptedAnswer::Menu(None),
        ]);
        let services = FakeServices {
            models: vec![EMBED_MODEL.to_string(), CHAT_MODEL.to_string()],
            ollama_path: Some(PathBuf::from("/tmp/ollama")),
            chromium_installed: false,
            chromium_path: None,
        };
        let context = SetupContext {
            hardware: super::super::hardware::SetupHardware {
                total_memory_gb: 32.0,
                free_disk_bytes: 10 * 1024 * 1024 * 1024,
                cpu_count: 8,
            },
            ollama_path: Some(PathBuf::from("/tmp/ollama")),
        };
        let summary = run_wizard_with_input(context, &mut input, &services)?;
        assert_eq!(summary.status, "complete");
        assert_eq!(summary.default_model.as_deref(), Some(CHAT_MODEL));
        Ok(())
    }

    #[test]
    fn wizard_skips_default_selection_when_prompts_disabled() -> Result<()> {
        let _guard = ENV_LOCK.lock();
        let temp = TempDir::new()?;
        let temp_home = temp.path().to_string_lossy();
        let _home = EnvGuard::set("HOME", &temp_home);
        let _user = EnvGuard::set("USERPROFILE", &temp_home);
        let _appdata = EnvGuard::set(
            "APPDATA",
            &temp
                .path()
                .join("AppData")
                .join("Roaming")
                .to_string_lossy(),
        );
        let _config = EnvGuard::set(
            "DOCDEX_CONFIG_PATH",
            &temp.path().join("config.toml").to_string_lossy(),
        );
        let _ollama_install = EnvGuard::clear("DOCDEX_OLLAMA_INSTALL");
        let _ollama_prompt = EnvGuard::set("DOCDEX_OLLAMA_MODEL_PROMPT", "0");
        let _ollama_assume = EnvGuard::clear("DOCDEX_OLLAMA_MODEL_ASSUME_Y");
        let _browser_install = EnvGuard::clear("DOCDEX_BROWSER_INSTALL");
        let mut input = ScriptedInput::new(vec![
            ScriptedAnswer::Confirm(true),
            ScriptedAnswer::Menu(Some(StepKey::ChatModel)),
            ScriptedAnswer::Menu(None),
        ]);
        let services = FakeServices {
            models: vec![EMBED_MODEL.to_string()],
            ollama_path: Some(PathBuf::from("/tmp/ollama")),
            chromium_installed: false,
            chromium_path: None,
        };
        let context = SetupContext {
            hardware: super::super::hardware::SetupHardware {
                total_memory_gb: 32.0,
                free_disk_bytes: 10 * 1024 * 1024 * 1024,
                cpu_count: 8,
            },
            ollama_path: Some(PathBuf::from("/tmp/ollama")),
        };
        let summary = run_wizard_with_input(context, &mut input, &services)?;
        assert_eq!(summary.status, "complete");
        assert!(summary.default_model.is_none());
        Ok(())
    }

    #[test]
    fn build_model_choices_filters_embedding_models_from_chat() {
        let models = vec![
            "nomic-embed-text:latest".to_string(),
            "nomic-embed-text-v1.5".to_string(),
            "phi3.5:3.8b".to_string(),
        ];
        let chat_models = filter_chat_models(&models);
        let (choices, default_index) = build_model_choices(&chat_models, None);
        assert_eq!(choices.len(), 1);
        assert_eq!(choices[0].value, "phi3.5:3.8b");
        assert_eq!(default_index, Some(0));
    }

    #[test]
    fn build_model_choices_filters_chat_models_from_embedding() {
        let models = vec![
            "nomic-embed-text-v1.5".to_string(),
            "phi3.5:3.8b".to_string(),
        ];
        let embed_models = filter_embedding_models(&models);
        let (choices, default_index) = build_model_choices(&embed_models, None);
        assert_eq!(choices.len(), 1);
        assert_eq!(choices[0].value, "nomic-embed-text-v1.5");
        assert_eq!(default_index, Some(0));
    }

    #[test]
    fn list_chromium_browsers_includes_default() -> Result<()> {
        let _guard = ENV_LOCK.lock();
        let temp = TempDir::new()?;
        let temp_home = temp.path().to_string_lossy();
        let _home = EnvGuard::set("HOME", &temp_home);
        let _user = EnvGuard::set("USERPROFILE", &temp_home);
        let browsers = list_chromium_browsers();
        assert_eq!(browsers.len(), 1);
        assert!(browsers[0].name.eq_ignore_ascii_case("chromium"));
        assert!(!browsers[0].installed);
        Ok(())
    }

    #[test]
    fn tui_render_does_not_panic() {
        let mut state = SetupState::new();
        let backend = TestBackend::new(80, 20);
        let mut terminal = Terminal::new(backend).unwrap();
        for step in [
            StepKey::Consent,
            StepKey::Ollama,
            StepKey::EmbedModel,
            StepKey::ChatModel,
            StepKey::DefaultModel,
            StepKey::EmbedDefault,
            StepKey::Browser,
            StepKey::WebProviders,
            StepKey::Summary,
        ] {
            state.current = step;
            terminal
                .draw(|frame| {
                    let area = frame.size();
                    render_status_list(frame, area, &state.steps, step);
                })
                .unwrap();
        }
    }
}
