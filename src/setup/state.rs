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
    EmbedDefault,
    Browser,
    Summary,
}

impl StepKey {
    pub fn label(&self) -> &'static str {
        match self {
            StepKey::Consent => "Consent",
            StepKey::Ollama => "Ollama",
            StepKey::EmbedModel => "Embedding Model",
            StepKey::ChatModel => "Chat Model",
            StepKey::DefaultModel => "Default Chat Model",
            StepKey::EmbedDefault => "Default Embedding Model",
            StepKey::Browser => "Browser",
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
                key: StepKey::EmbedDefault,
                status: StepStatus::Pending,
                detail: None,
            },
            StepSnapshot {
                key: StepKey::Browser,
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

    pub fn set_current(&mut self, step: StepKey) {
        self.current = step;
    }

    pub fn update_step(&mut self, key: StepKey, status: StepStatus, detail: Option<String>) {
        self.set_step_status(key, status, detail);
    }

    pub fn mark_failed(&mut self, message: String) {
        self.error = Some(message);
        self.outcome = SetupOutcome::Failed;
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
