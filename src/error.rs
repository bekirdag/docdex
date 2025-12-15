use std::error::Error;
use std::fmt;

#[derive(Debug, Clone)]
pub struct StartupError {
    pub code: &'static str,
    pub message: String,
    pub hint: Option<String>,
    pub remediation: Option<Vec<String>>,
}

impl StartupError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            hint: None,
            remediation: None,
        }
    }

    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    pub fn with_remediation(mut self, steps: Vec<String>) -> Self {
        if !steps.is_empty() {
            self.remediation = Some(steps);
        }
        self
    }
}

impl fmt::Display for StartupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl Error for StartupError {}
