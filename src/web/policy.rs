use crate::error::{AppError, ERR_BACKOFF_REQUIRED};
use chrono::{Duration as ChronoDuration, Utc};
use serde_json::json;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex;

#[derive(Clone, Debug)]
pub struct SpacingBackoffPolicy {
    pub min_spacing: Duration,
    pub jitter_ms: u64,
    pub max_attempts: usize,
    pub base_backoff: Duration,
    pub backoff_multiplier: f64,
    pub max_backoff: Duration,
    pub max_consecutive_failures: usize,
    pub cooldown: Duration,
}

#[derive(Clone)]
pub struct SpacingBackoff {
    policy: SpacingBackoffPolicy,
    state: Arc<Mutex<SpacingBackoffState>>,
}

#[derive(Debug, Default)]
struct SpacingBackoffState {
    last_request_at: Option<Instant>,
    consecutive_failures: usize,
    cooldown_until: Option<Instant>,
}

impl SpacingBackoff {
    pub fn new(policy: SpacingBackoffPolicy) -> Self {
        Self {
            policy,
            state: Arc::new(Mutex::new(SpacingBackoffState::default())),
        }
    }

    pub fn policy(&self) -> &SpacingBackoffPolicy {
        &self.policy
    }

    pub async fn wait_for_slot(&self) -> Result<(), AppError> {
        let mut state = self.state.lock().await;
        let now = Instant::now();
        if let Some(until) = state.cooldown_until {
            if now < until {
                let retry_after = until.saturating_duration_since(now);
                return Err(backoff_error("web discovery backoff required", retry_after));
            }
        }

        let mut wait = Duration::ZERO;
        if let Some(last) = state.last_request_at {
            let next = last + self.policy.min_spacing;
            if next > now {
                wait = next.duration_since(now);
            }
        }

        let jitter = self.jitter();
        let wait = wait + jitter;
        state.last_request_at = Some(now + wait);
        drop(state);

        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
        Ok(())
    }

    pub async fn register_success(&self) {
        let mut state = self.state.lock().await;
        state.consecutive_failures = 0;
        state.cooldown_until = None;
    }

    pub async fn register_failure(&self) -> Option<AppError> {
        let mut state = self.state.lock().await;
        state.consecutive_failures = state.consecutive_failures.saturating_add(1);
        if self.policy.max_consecutive_failures == 0 {
            return None;
        }
        if state.consecutive_failures >= self.policy.max_consecutive_failures {
            if !self.policy.cooldown.is_zero() {
                let now = Instant::now();
                state.cooldown_until = Some(now + self.policy.cooldown);
                return Some(backoff_error(
                    "web discovery backoff required",
                    self.policy.cooldown,
                ));
            }
        }
        None
    }

    pub fn backoff_delay(&self, attempt: usize) -> Duration {
        let attempt = attempt.max(1) as u32;
        let base_ms = self
            .policy
            .base_backoff
            .as_millis()
            .min(u128::from(u64::MAX)) as f64;
        let mut delay_ms = base_ms
            * self
                .policy
                .backoff_multiplier
                .powi(attempt.saturating_sub(1) as i32);
        if delay_ms.is_nan() || delay_ms.is_infinite() {
            delay_ms = base_ms;
        }
        let max_ms = self
            .policy
            .max_backoff
            .as_millis()
            .min(u128::from(u64::MAX)) as f64;
        if delay_ms > max_ms {
            delay_ms = max_ms;
        }
        let jitter_ms = self.jitter().as_millis().min(u128::from(u64::MAX)) as f64;
        Duration::from_millis((delay_ms + jitter_ms).round() as u64)
    }

    fn jitter(&self) -> Duration {
        if self.policy.jitter_ms == 0 {
            return Duration::ZERO;
        }
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos() as u64;
        Duration::from_millis(nanos % (self.policy.jitter_ms + 1))
    }
}

pub fn backoff_error(message: impl Into<String>, retry_after: Duration) -> AppError {
    let retry_after_ms = retry_after.as_millis().min(u128::from(u64::MAX)) as u64;
    let retry_at = ChronoDuration::from_std(retry_after)
        .ok()
        .map(|delta| (Utc::now() + delta).to_rfc3339());
    let mut details = json!({
        "retry_after_ms": retry_after_ms,
    });
    if let Some(retry_at) = retry_at {
        if let Some(obj) = details.as_object_mut() {
            obj.insert("retry_at".to_string(), json!(retry_at));
        }
    }
    AppError::new(ERR_BACKOFF_REQUIRED, message).with_details(details)
}
