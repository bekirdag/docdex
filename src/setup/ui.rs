use anyhow::{anyhow, Result};
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

pub trait WizardServices {
    fn resolve_ollama_path(&self, explicit: Option<std::path::PathBuf>) -> Option<std::path::PathBuf>;
    fn install_ollama(&self) -> Result<()>;
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
        models: &[String],
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
        let selected = input.select_model(&state, &models, 0)?;
        state.apply(SetupEvent::DefaultSelected(selected.clone()));
        if let Some(ref model) = selected {
            services.set_default_model(model)?;
        }
        selected
    };

    Ok(summary_from_state(
        &state,
        "Setup complete.".to_string(),
        installed,
        default_model,
    ))
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
        list: Option<(&[String], usize)>,
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
        models: &[String],
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
                    if self.selected_index > 0 {
                        self.selected_index -= 1;
                    }
                }
                KeyCode::Down => {
                    if self.selected_index + 1 < models.len() {
                        self.selected_index += 1;
                    }
                }
                KeyCode::Enter => {
                    return models
                        .get(self.selected_index)
                        .cloned()
                        .map(Some)
                        .ok_or_else(|| anyhow!("no model selected"));
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
    list: Option<(&[String], usize)>,
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
            .map(|item| ListItem::new(item.clone()))
            .collect();
        let mut state = ListState::default();
        state.select(Some(selected));
        let list = List::new(list_items)
            .block(Block::default().title("Models").borders(Borders::ALL))
            .highlight_style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD));
        frame.render_stateful_widget(list, chunks[1], &mut state);
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
            models: &[String],
            default_index: usize,
        ) -> Result<Option<String>> {
            match self.next() {
                ScriptedAnswer::Select(Some(idx)) => Ok(models.get(idx).cloned()),
                ScriptedAnswer::Select(None) => Ok(None),
                ScriptedAnswer::Confirm(_) => Ok(models.get(default_index).cloned()),
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
            ScriptedAnswer::Select(Some(0)),
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
        assert_eq!(summary.default_model.as_deref(), Some(EMBED_MODEL));
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
