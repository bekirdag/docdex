use anyhow::Result;
use serde::Serialize;
use std::path::PathBuf;

use super::hardware::{self, SetupHardware};
use super::ollama;

#[derive(Debug, Clone)]
pub struct SetupContext {
    pub hardware: SetupHardware,
    pub ollama_path: Option<PathBuf>,
}

impl SetupContext {
    pub fn new(ollama_path: Option<PathBuf>) -> Result<Self> {
        let hardware = hardware::detect();
        let resolved = ollama::resolve_ollama_path(ollama_path);
        Ok(Self {
            hardware,
            ollama_path: resolved,
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StepKey {
    Consent,
    Ollama,
    EmbedModel,
    ChatModel,
    DefaultModel,
    Summary,
}

impl StepKey {
    pub fn label(&self) -> &'static str {
        match self {
            StepKey::Consent => "Consent",
            StepKey::Ollama => "Ollama",
            StepKey::EmbedModel => "Embedding Model",
            StepKey::ChatModel => "Chat Model",
            StepKey::DefaultModel => "Default Model",
            StepKey::Summary => "Summary",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StepStatus {
    Pending,
    Active,
    Done,
    Skipped,
    Failed,
}

impl StepStatus {
    pub fn label(&self) -> &'static str {
        match self {
            StepStatus::Pending => "pending",
            StepStatus::Active => "active",
            StepStatus::Done => "done",
            StepStatus::Skipped => "skipped",
            StepStatus::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct StepSnapshot {
    pub key: StepKey,
    pub status: StepStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SetupOutcome {
    InProgress,
    Complete,
    Deferred,
    Failed,
}

impl SetupOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            SetupOutcome::InProgress => "in_progress",
            SetupOutcome::Complete => "complete",
            SetupOutcome::Deferred => "deferred",
            SetupOutcome::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone)]
pub enum SetupEvent {
    ConsentAccepted,
    ConsentDeclined,
    OllamaReady,
    OllamaFailed(String),
    OllamaRetry,
    EmbedInstalled,
    EmbedSkipped,
    EmbedFailed(String),
    EmbedRetry,
    ChatInstalled,
    ChatSkipped,
    ChatFailed(String),
    ChatRetry,
    DefaultSelected(Option<String>),
}

#[derive(Debug, Clone, Serialize)]
pub struct SetupState {
    pub current: StepKey,
    pub outcome: SetupOutcome,
    pub steps: Vec<StepSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl SetupState {
    pub fn new() -> Self {
        let mut steps = vec![
            StepSnapshot {
                key: StepKey::Consent,
                status: StepStatus::Active,
                detail: None,
            },
            StepSnapshot {
                key: StepKey::Ollama,
                status: StepStatus::Pending,
                detail: None,
            },
            StepSnapshot {
                key: StepKey::EmbedModel,
                status: StepStatus::Pending,
                detail: None,
            },
            StepSnapshot {
                key: StepKey::ChatModel,
                status: StepStatus::Pending,
                detail: None,
            },
            StepSnapshot {
                key: StepKey::DefaultModel,
                status: StepStatus::Pending,
                detail: None,
            },
            StepSnapshot {
                key: StepKey::Summary,
                status: StepStatus::Pending,
                detail: None,
            },
        ];
        Self {
            current: StepKey::Consent,
            outcome: SetupOutcome::InProgress,
            steps: std::mem::take(&mut steps),
            error: None,
        }
    }

    pub fn apply(&mut self, event: SetupEvent) {
        match event {
            SetupEvent::ConsentAccepted => {
                self.set_step_status(StepKey::Consent, StepStatus::Done, None);
                self.advance_to(StepKey::Ollama);
            }
            SetupEvent::ConsentDeclined => {
                self.set_step_status(
                    StepKey::Consent,
                    StepStatus::Skipped,
                    Some("declined".to_string()),
                );
                self.outcome = SetupOutcome::Deferred;
                self.advance_to(StepKey::Summary);
            }
            SetupEvent::OllamaReady => {
                self.set_step_status(StepKey::Ollama, StepStatus::Done, None);
                self.advance_to(StepKey::EmbedModel);
            }
            SetupEvent::OllamaFailed(err) => {
                self.set_step_status(
                    StepKey::Ollama,
                    StepStatus::Failed,
                    Some(err.clone()),
                );
                self.error = Some(err);
            }
            SetupEvent::OllamaRetry => {
                self.set_step_status(StepKey::Ollama, StepStatus::Active, None);
                self.error = None;
            }
            SetupEvent::EmbedInstalled => {
                self.set_step_status(StepKey::EmbedModel, StepStatus::Done, None);
                self.advance_to(StepKey::ChatModel);
            }
            SetupEvent::EmbedSkipped => {
                self.set_step_status(StepKey::EmbedModel, StepStatus::Skipped, None);
                self.advance_to(StepKey::ChatModel);
            }
            SetupEvent::EmbedFailed(err) => {
                self.set_step_status(
                    StepKey::EmbedModel,
                    StepStatus::Failed,
                    Some(err.clone()),
                );
                self.error = Some(err);
            }
            SetupEvent::EmbedRetry => {
                self.set_step_status(StepKey::EmbedModel, StepStatus::Active, None);
                self.error = None;
            }
            SetupEvent::ChatInstalled => {
                self.set_step_status(StepKey::ChatModel, StepStatus::Done, None);
                self.advance_to(StepKey::DefaultModel);
            }
            SetupEvent::ChatSkipped => {
                self.set_step_status(StepKey::ChatModel, StepStatus::Skipped, None);
                self.advance_to(StepKey::DefaultModel);
            }
            SetupEvent::ChatFailed(err) => {
                self.set_step_status(
                    StepKey::ChatModel,
                    StepStatus::Failed,
                    Some(err.clone()),
                );
                self.error = Some(err);
            }
            SetupEvent::ChatRetry => {
                self.set_step_status(StepKey::ChatModel, StepStatus::Active, None);
                self.error = None;
            }
            SetupEvent::DefaultSelected(model) => {
                if model.is_some() {
                    self.set_step_status(StepKey::DefaultModel, StepStatus::Done, model);
                } else {
                    self.set_step_status(StepKey::DefaultModel, StepStatus::Skipped, None);
                }
                self.outcome = SetupOutcome::Complete;
                self.advance_to(StepKey::Summary);
            }
        }
    }

    pub fn mark_failed(&mut self, message: String) {
        self.error = Some(message);
        self.outcome = SetupOutcome::Failed;
    }

    fn advance_to(&mut self, step: StepKey) {
        for item in &mut self.steps {
            if item.key == step {
                if item.status == StepStatus::Pending {
                    item.status = StepStatus::Active;
                }
            } else if item.status == StepStatus::Active {
                item.status = StepStatus::Done;
            }
        }
        self.current = step;
    }

    fn set_step_status(&mut self, key: StepKey, status: StepStatus, detail: Option<String>) {
        for item in &mut self.steps {
            if item.key == key {
                item.status = status;
                item.detail = detail;
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transitions_cover_decline_and_complete() {
        let mut state = SetupState::new();
        assert_eq!(state.current, StepKey::Consent);
        state.apply(SetupEvent::ConsentDeclined);
        assert_eq!(state.outcome, SetupOutcome::Deferred);
        assert_eq!(state.current, StepKey::Summary);

        let mut state = SetupState::new();
        state.apply(SetupEvent::ConsentAccepted);
        assert_eq!(state.current, StepKey::Ollama);
        state.apply(SetupEvent::OllamaReady);
        state.apply(SetupEvent::EmbedInstalled);
        state.apply(SetupEvent::ChatSkipped);
        state.apply(SetupEvent::DefaultSelected(Some("phi3.5:3.8b".to_string())));
        assert_eq!(state.outcome, SetupOutcome::Complete);
        assert_eq!(state.current, StepKey::Summary);
    }

    #[test]
    fn retry_clears_failed_state() {
        let mut state = SetupState::new();
        state.apply(SetupEvent::ConsentAccepted);
        state.apply(SetupEvent::OllamaFailed("oops".to_string()));
        assert_eq!(state.error.as_deref(), Some("oops"));
        state.apply(SetupEvent::OllamaRetry);
        assert_eq!(state.error, None);
        let step = state.steps.iter().find(|s| s.key == StepKey::Ollama).unwrap();
        assert_eq!(step.status, StepStatus::Active);
    }
}
