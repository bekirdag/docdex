use anyhow::Result;
use crossterm::{
    cursor,
    event::{self, Event, KeyCode},
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
use std::io::{self, Stdout};
use std::path::Path;

use super::config;
use super::model::{CHAT_MODEL, CHAT_MODEL_SIZE_GIB, EMBED_MODEL};
use super::ollama;
use super::state::{SetupContext, SetupEvent, SetupState, StepKey, StepSnapshot, StepStatus};
use super::SetupSummary;
use crate::config as app_config;
use crate::util;
use std::env;

pub trait WizardServices {
    fn resolve_ollama_path(&self, explicit: Option<std::path::PathBuf>) -> Option<std::path::PathBuf>;
    fn install_ollama(&self) -> Result<()>;
    fn ensure_ollama_service(&self, bin: &Path) -> Result<ollama::OllamaDaemonStatus>;
    fn list_models(&self, bin: &Path) -> Result<Vec<String>>;
    fn pull_model(&self, bin: &Path, model: &str) -> Result<()>;
    fn set_default_model(&self, model: &str) -> Result<()>;
}

pub struct RealServices;

impl WizardServices for RealServices {
    fn resolve_ollama_path(&self, explicit: Option<std::path::PathBuf>) -> Option<std::path::PathBuf> {
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

    fn pull_model(&self, bin: &Path, model: &str) -> Result<()> {
        ollama::pull_model(bin, model)
    }

    fn set_default_model(&self, model: &str) -> Result<()> {
        config::set_default_model(model).map(|_| ())
    }
}

pub trait WizardInput {
    fn confirm(&mut self, state: &SetupState, prompt: &str, default_yes: bool) -> Result<bool>;
    fn select_model(
        &mut self,
        state: &SetupState,
        models: &[ModelChoice],
        default_index: usize,
    ) -> Result<Option<String>>;
    fn info(&mut self, state: &SetupState, message: &str) -> Result<()>;
    fn with_suspended_terminal<T, F: FnOnce() -> Result<T>>(&mut self, op: F) -> Result<T>;
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

    let install_override = env_bool("DOCDEX_OLLAMA_INSTALL");
    let consent = match install_override {
        Some(true) => true,
        Some(false) => false,
        None => input.confirm(
            &state,
            "Install Ollama and models now?",
            true,
        )?,
    };
    if !consent {
        state.apply(SetupEvent::ConsentDeclined);
        return Ok(summary_from_state(
            &state,
            match install_override {
                Some(false) => "Setup deferred (DOCDEX_OLLAMA_INSTALL=0).".to_string(),
                _ => "Setup deferred. Run `docdex setup` later.".to_string(),
            },
            Vec::new(),
            None,
        ));
    }

    state.apply(SetupEvent::ConsentAccepted);
    let ollama_path = if context.ollama_path.is_none() {
        loop {
            input.info(&state, "Installing Ollama...")?;
            let install = input.with_suspended_terminal(|| services.install_ollama());
            match install {
                Ok(()) => {
                    if let Some(path) = services.resolve_ollama_path(None) {
                        state.apply(SetupEvent::OllamaReady);
                        break path;
                    }
                    let err = "ollama installed but not found on PATH".to_string();
                    state.apply(SetupEvent::OllamaFailed(err.clone()));
                    if !prompt_retry(input, &state, "Ollama install failed. Retry?")? {
                        state.mark_failed(err.clone());
                        return Ok(summary_from_state(
                            &state,
                            format!("Setup failed: {err}"),
                            Vec::new(),
                            None,
                        ));
                    }
                    state.apply(SetupEvent::OllamaRetry);
                }
                Err(err) => {
                    let err = err.to_string();
                    state.apply(SetupEvent::OllamaFailed(err.clone()));
                    if !prompt_retry(input, &state, "Ollama install failed. Retry?")? {
                        state.mark_failed(err.clone());
                        return Ok(summary_from_state(
                            &state,
                            format!("Setup failed: {err}"),
                            Vec::new(),
                            None,
                        ));
                    }
                    state.apply(SetupEvent::OllamaRetry);
                }
            }
        }
    } else {
        state.apply(SetupEvent::OllamaReady);
        context.ollama_path.clone().unwrap()
    };

    let ollama_status = loop {
        input.info(&state, "Ensuring Ollama is running...")?;
        let ensure = input.with_suspended_terminal(|| services.ensure_ollama_service(&ollama_path));
        match ensure {
            Ok(status) => break Some(status),
            Err(err) => {
                let err = err.to_string();
                state.apply(SetupEvent::OllamaFailed(err.clone()));
                if !prompt_retry(input, &state, "Ollama daemon failed to start. Retry?")? {
                    state.mark_failed(err.clone());
                    return Ok(summary_from_state(
                        &state,
                        format!("Setup failed: {err}"),
                        Vec::new(),
                        None,
                    ));
                }
                state.apply(SetupEvent::OllamaRetry);
            }
        }
    };

    let mut models = services.list_models(&ollama_path).unwrap_or_default();
    let mut installed = Vec::new();
    let model_prompt_override = env_bool("DOCDEX_OLLAMA_MODEL_PROMPT");
    let assume_yes = env_bool("DOCDEX_OLLAMA_MODEL_ASSUME_Y").unwrap_or(false);
    let prompt_models = model_prompt_override.unwrap_or(true);

    if models.iter().any(|m| m.eq_ignore_ascii_case(EMBED_MODEL)) {
        state.apply(SetupEvent::EmbedSkipped);
    } else if !prompt_models {
        state.apply(SetupEvent::EmbedSkipped);
        input.info(&state, "Model prompts disabled; skipping embedding model install.")?;
    } else if assume_yes
        || input.confirm(
            &state,
            &format!("Install embedding model {EMBED_MODEL}?"),
            true,
        )?
    {
        loop {
            input.info(&state, "Pulling embedding model...")?;
            let pull = input.with_suspended_terminal(|| services.pull_model(&ollama_path, EMBED_MODEL));
            match pull {
                Ok(()) => {
                    installed.push(EMBED_MODEL.to_string());
                    models = services.list_models(&ollama_path).unwrap_or_else(|_| models.clone());
                    state.apply(SetupEvent::EmbedInstalled);
                    break;
                }
                Err(err) => {
                    let err = err.to_string();
                    state.apply(SetupEvent::EmbedFailed(err.clone()));
                    if !prompt_retry(input, &state, "Embedding model install failed. Retry?")? {
                        state.mark_failed(err.clone());
                        return Ok(summary_from_state(
                            &state,
                            format!("Setup failed: {err}"),
                            installed,
                            None,
                        ));
                    }
                    state.apply(SetupEvent::EmbedRetry);
                }
            }
        }
    } else {
        state.apply(SetupEvent::EmbedSkipped);
    }

    if !context.hardware.recommend_phi() {
        state.apply(SetupEvent::ChatSkipped);
        input.info(
            &state,
            "Chat model not recommended: low RAM or free disk. Skipping.",
        )?;
    } else if models.iter().any(|m| m.eq_ignore_ascii_case(CHAT_MODEL)) {
        state.apply(SetupEvent::ChatSkipped);
    } else if !prompt_models {
        state.apply(SetupEvent::ChatSkipped);
        input.info(&state, "Model prompts disabled; skipping chat model install.")?;
    } else if assume_yes
        || input.confirm(
            &state,
            &format!(
                "Install chat model {CHAT_MODEL} (~{CHAT_MODEL_SIZE_GIB:.1} GiB)?"
            ),
            true,
        )?
    {
        loop {
            input.info(&state, "Pulling chat model...")?;
            let pull = input.with_suspended_terminal(|| services.pull_model(&ollama_path, CHAT_MODEL));
            match pull {
                Ok(()) => {
                    installed.push(CHAT_MODEL.to_string());
                    models = services.list_models(&ollama_path).unwrap_or_else(|_| models.clone());
                    state.apply(SetupEvent::ChatInstalled);
                    break;
                }
                Err(err) => {
                    let err = err.to_string();
                    state.apply(SetupEvent::ChatFailed(err.clone()));
                    if !prompt_retry(input, &state, "Chat model install failed. Retry?")? {
                        state.mark_failed(err.clone());
                        return Ok(summary_from_state(
                            &state,
                            format!("Setup failed: {err}"),
                            installed,
                            None,
                        ));
                    }
                    state.apply(SetupEvent::ChatRetry);
                }
            }
        }
    } else {
        state.apply(SetupEvent::ChatSkipped);
    }

    let default_model = if models.is_empty() {
        state.apply(SetupEvent::DefaultSelected(None));
        None
    } else if !prompt_models {
        state.apply(SetupEvent::DefaultSelected(None));
        input.info(&state, "Model prompts disabled; skipping default model selection.")?;
        None
    } else {
        let (choices, default_index) = build_model_choices(&models);
        match default_index {
            None => {
                state.apply(SetupEvent::DefaultSelected(None));
                input.info(&state, "No selectable chat models found; keeping existing default.")?;
                None
            }
            Some(default_index) => {
                let selected = input.select_model(&state, &choices, default_index)?;
                state.apply(SetupEvent::DefaultSelected(selected.clone()));
                if let Some(ref model) = selected {
                    services.set_default_model(model)?;
                }
                selected
            }
        }
    };

    Ok(summary_from_state(
        &state,
        format_completion_message(
            &models,
            default_model.as_deref(),
            ollama_status.as_ref(),
            installed.as_slice(),
        ),
        installed,
        default_model,
    ))
}

#[derive(Clone, Debug)]
pub struct ModelChoice {
    pub label: String,
    pub value: String,
    pub selectable: bool,
}

fn build_model_choices(models: &[String]) -> (Vec<ModelChoice>, Option<usize>) {
    let mut choices = Vec::new();
    let mut default_index = None;
    for model in models {
        let selectable = !model.eq_ignore_ascii_case(EMBED_MODEL);
        let label = if selectable {
            model.clone()
        } else {
            format!("{model} (embedding only)")
        };
        if selectable && default_index.is_none() {
            default_index = Some(choices.len());
        }
        choices.push(ModelChoice {
            label,
            value: model.clone(),
            selectable,
        });
    }
    (choices, default_index)
}

fn format_completion_message(
    models: &[String],
    default_model: Option<&str>,
    ollama_status: Option<&ollama::OllamaDaemonStatus>,
    installed_models: &[String],
) -> String {
    let config = load_summary_config();
    let config_default = config
        .as_ref()
        .and_then(|cfg| {
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
    let embed_installed = models
        .iter()
        .any(|m| m.eq_ignore_ascii_case(&config_embed));
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
        format!("Ollama: {}", if ollama_running { "running" } else { "not running" }),
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
    config
        .web
        .scraper
        .chrome_binary_path
        .as_ref()
        .map(|path| {
            let kind = config
                .web
                .scraper
                .browser_kind
                .as_deref()
                .unwrap_or("chrome");
            format!("{kind} ({})", path.display())
        })
}

fn resolve_browser_summary_from_detection() -> Option<String> {
    util::detect_browser_binary(None).map(|candidate| {
        format!("{} ({})", candidate.kind.as_str(), candidate.path.display())
    })
}

fn prompt_retry<I: WizardInput>(input: &mut I, state: &SetupState, message: &str) -> Result<bool> {
    input.confirm(state, message, false)
}

fn summary_from_state(
    state: &SetupState,
    message: String,
    models_installed: Vec<String>,
    default_model: Option<String>,
) -> SetupSummary {
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
        })
    }

    fn draw_prompt(
        &mut self,
        state: &SetupState,
        body: &str,
        hint: &str,
        list: Option<(&[ModelChoice], usize)>,
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

            render_status_list(frame, content[0], &state.steps, state.current);
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
                return Ok(key.code);
            }
        }
    }
}

impl WizardInput for TuiInput {
    fn confirm(&mut self, state: &SetupState, prompt: &str, default_yes: bool) -> Result<bool> {
        let hint = if default_yes {
            "Y=yes, N=no, Enter=Yes, Esc=No"
        } else {
            "Y=yes, N=no, Enter=No, Esc=No"
        };
        loop {
            self.draw_prompt(state, prompt, hint, None)?;
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
        self.selected_index = default_index.min(models.len().saturating_sub(1));
        loop {
            self.draw_prompt(
                state,
                "Select default model",
                hint,
                Some((models, self.selected_index)),
            )?;
            match self.read_key()? {
                KeyCode::Up => {
                    if let Some(next) = next_selectable_index(models, self.selected_index, -1) {
                        self.selected_index = next;
                    }
                }
                KeyCode::Down => {
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

    fn info(&mut self, state: &SetupState, message: &str) -> Result<()> {
        self.draw_prompt(state, message, "", None)
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

fn render_status_list(frame: &mut ratatui::Frame, area: Rect, steps: &[StepSnapshot], current: StepKey) {
    let items: Vec<ListItem> = steps
        .iter()
        .map(|step| {
            let status = step.status.label();
            let label = format!("{}: {}", step.key.label(), status);
            let mut style = match step.status {
                StepStatus::Done => Style::default().fg(Color::Green),
                StepStatus::Failed => Style::default().fg(Color::Red),
                StepStatus::Active => Style::default().fg(Color::Yellow),
                StepStatus::Skipped => Style::default().fg(Color::DarkGray),
                StepStatus::Pending => Style::default().fg(Color::Gray),
            };
            if step.key == current {
                style = style.add_modifier(Modifier::BOLD);
            }
            ListItem::new(Line::from(Span::styled(label, style)))
        })
        .collect();

    let list = List::new(items)
        .block(Block::default().title("Setup").borders(Borders::ALL));
    frame.render_widget(list, area);
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
                let mut style = Style::default();
                if !item.selectable {
                    style = style.fg(Color::DarkGray);
                }
                ListItem::new(Line::from(Span::styled(item.label.clone(), style)))
            })
            .collect();
        let mut state = ListState::default();
        state.select(Some(selected));
        let list = List::new(list_items)
            .block(Block::default().title("Models").borders(Borders::ALL))
            .highlight_style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD));
        frame.render_stateful_widget(list, chunks[1], &mut state);
    }
}

fn next_selectable_index(models: &[ModelChoice], current: usize, direction: isize) -> Option<usize> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup::test_support::ENV_LOCK;
    use ratatui::backend::TestBackend;
    use std::path::PathBuf;

    struct ScriptedInput {
        answers: Vec<ScriptedAnswer>,
        index: usize,
    }

    #[derive(Clone)]
    enum ScriptedAnswer {
        Confirm(bool),
        Select(Option<usize>),
    }

    impl ScriptedInput {
        fn new(answers: Vec<ScriptedAnswer>) -> Self {
            Self { answers, index: 0 }
        }

        fn next(&mut self) -> ScriptedAnswer {
            if self.index >= self.answers.len() {
                return ScriptedAnswer::Confirm(false);
            }
            let answer = self.answers[self.index].clone();
            self.index += 1;
            answer
        }
    }

    impl WizardInput for ScriptedInput {
        fn confirm(&mut self, _state: &SetupState, _prompt: &str, default_yes: bool) -> Result<bool> {
            match self.next() {
                ScriptedAnswer::Confirm(value) => Ok(value),
                ScriptedAnswer::Select(_) => Ok(default_yes),
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
                ScriptedAnswer::Confirm(_) => Ok(models
                    .get(default_index)
                    .filter(|choice| choice.selectable)
                    .map(|choice| choice.value.clone())),
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
    }

    impl WizardServices for FakeServices {
        fn resolve_ollama_path(&self, _explicit: Option<PathBuf>) -> Option<PathBuf> {
            Some(PathBuf::from("/tmp/ollama"))
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

        fn pull_model(&self, _bin: &Path, _model: &str) -> Result<()> {
            Ok(())
        }

        fn set_default_model(&self, _model: &str) -> Result<()> {
            Ok(())
        }
    }

    #[test]
    fn wizard_decline_records_deferred() -> Result<()> {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var("DOCDEX_OLLAMA_INSTALL");
        std::env::remove_var("DOCDEX_OLLAMA_MODEL_PROMPT");
        std::env::remove_var("DOCDEX_OLLAMA_MODEL_ASSUME_Y");
        let mut input = ScriptedInput::new(vec![ScriptedAnswer::Confirm(false)]);
        let services = FakeServices { models: vec![] };
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
    fn wizard_completes_with_default_model() -> Result<()> {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var("DOCDEX_OLLAMA_INSTALL");
        std::env::remove_var("DOCDEX_OLLAMA_MODEL_PROMPT");
        std::env::remove_var("DOCDEX_OLLAMA_MODEL_ASSUME_Y");
        let mut input = ScriptedInput::new(vec![
            ScriptedAnswer::Confirm(true),
            ScriptedAnswer::Confirm(false),
            ScriptedAnswer::Confirm(false),
            ScriptedAnswer::Select(Some(1)),
        ]);
        let services = FakeServices {
            models: vec![EMBED_MODEL.to_string(), CHAT_MODEL.to_string()],
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
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::remove_var("DOCDEX_OLLAMA_INSTALL");
        std::env::set_var("DOCDEX_OLLAMA_MODEL_PROMPT", "0");
        std::env::remove_var("DOCDEX_OLLAMA_MODEL_ASSUME_Y");
        let mut input = ScriptedInput::new(vec![ScriptedAnswer::Confirm(true)]);
        let services = FakeServices {
            models: vec![EMBED_MODEL.to_string()],
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
        std::env::remove_var("DOCDEX_OLLAMA_MODEL_PROMPT");
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
