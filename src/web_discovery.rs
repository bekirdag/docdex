#![allow(dead_code)]

use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WebDiscoveryStatus {
    Ok,
    Skipped,
    Blocked,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WebDiscoveryStopReason {
    MaxAttempts,
    MaxElapsed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WebDiscoveryFailureKind {
    Blocked,
    HttpError,
    TransportError,
    ParseError,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebDiscoveryFailure {
    pub kind: WebDiscoveryFailureKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
}

impl WebDiscoveryFailure {
    pub fn blocked(status: Option<u16>, message: Option<String>) -> Self {
        Self {
            kind: WebDiscoveryFailureKind::Blocked,
            message,
            http_status: status,
        }
    }

    pub fn http_error(status: u16, message: Option<String>) -> Self {
        Self {
            kind: WebDiscoveryFailureKind::HttpError,
            message,
            http_status: Some(status),
        }
    }

    pub fn transport_error(message: impl Into<String>) -> Self {
        Self {
            kind: WebDiscoveryFailureKind::TransportError,
            message: Some(message.into()),
            http_status: None,
        }
    }

    pub fn parse_error(message: impl Into<String>) -> Self {
        Self {
            kind: WebDiscoveryFailureKind::ParseError,
            message: Some(message.into()),
            http_status: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebDiscoveryOutcome {
    pub status: WebDiscoveryStatus,
    pub stop_reason: WebDiscoveryStopReason,
    pub attempts: u32,
    pub elapsed_ms: u64,
    pub failure: WebDiscoveryFailure,
}

#[derive(Debug, Clone)]
pub struct WebDiscoveryBackoffPolicy {
    pub base_delay: Duration,
    pub max_delay: Duration,
    pub max_attempts: u32,
    pub max_elapsed: Duration,
    pub jitter_ratio: f64,
}

impl WebDiscoveryBackoffPolicy {
    pub fn new(
        base_delay: Duration,
        max_delay: Duration,
        max_attempts: u32,
        max_elapsed: Duration,
        jitter_ratio: f64,
    ) -> Self {
        let base_delay = if base_delay.is_zero() {
            Duration::from_millis(1)
        } else {
            base_delay
        };
        let max_delay = if max_delay < base_delay {
            base_delay
        } else {
            max_delay
        };
        Self {
            base_delay,
            max_delay,
            max_attempts: max_attempts.max(1),
            max_elapsed,
            jitter_ratio: jitter_ratio.clamp(0.0, 1.0),
        }
    }

    fn next_delay(&self, attempt: u32, rng_state: &mut u64) -> Duration {
        let attempt = attempt.max(1);
        let base_ms = self.base_delay.as_millis().max(1);
        let max_ms = self.max_delay.as_millis().max(base_ms);
        let exp = attempt.saturating_sub(1).min(31);
        let mut delay_ms = base_ms.saturating_mul(1u128 << exp).min(max_ms);
        if self.jitter_ratio > 0.0 && delay_ms > 0 {
            let jitter_span = (delay_ms as f64 * self.jitter_ratio).round() as i128;
            if jitter_span > 0 {
                let range = (jitter_span as u128)
                    .saturating_mul(2)
                    .saturating_add(1);
                let offset = (next_u64(rng_state) as u128 % range) as i128 - jitter_span;
                delay_ms = (delay_ms as i128 + offset).max(0) as u128;
            }
        }
        delay_ms = delay_ms.min(max_ms).max(1);
        Duration::from_millis(delay_ms as u64)
    }

    fn stop_reason(
        &self,
        attempts: u32,
        elapsed: Duration,
        next_delay: Duration,
    ) -> Option<WebDiscoveryStopReason> {
        if attempts >= self.max_attempts {
            return Some(WebDiscoveryStopReason::MaxAttempts);
        }
        if self.max_elapsed.is_zero() {
            return Some(WebDiscoveryStopReason::MaxElapsed);
        }
        if elapsed >= self.max_elapsed {
            return Some(WebDiscoveryStopReason::MaxElapsed);
        }
        if elapsed.saturating_add(next_delay) > self.max_elapsed {
            return Some(WebDiscoveryStopReason::MaxElapsed);
        }
        None
    }
}

#[derive(Debug, Clone)]
pub struct WebDiscoveryBackoff {
    policy: WebDiscoveryBackoffPolicy,
    started_at: Instant,
    attempts: u32,
    rng_state: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebDiscoveryDecision {
    Retry { delay: Duration, failure: WebDiscoveryFailure },
    Stop { outcome: WebDiscoveryOutcome },
}

impl WebDiscoveryBackoff {
    pub fn new(policy: WebDiscoveryBackoffPolicy) -> Self {
        Self::new_with_seed_and_start(policy, None, Instant::now())
    }

    pub fn new_with_seed_and_start(
        policy: WebDiscoveryBackoffPolicy,
        seed: Option<u64>,
        started_at: Instant,
    ) -> Self {
        let seed = seed.unwrap_or_else(seed_from_time);
        let seed = if seed == 0 { 0x9e3779b97f4a7c15 } else { seed };
        Self {
            policy,
            started_at,
            attempts: 0,
            rng_state: seed,
        }
    }

    pub fn attempts(&self) -> u32 {
        self.attempts
    }

    pub fn register_failure(&mut self, failure: WebDiscoveryFailure) -> WebDiscoveryDecision {
        self.register_failure_at(failure, Instant::now())
    }

    pub fn register_failure_at(
        &mut self,
        failure: WebDiscoveryFailure,
        now: Instant,
    ) -> WebDiscoveryDecision {
        self.attempts = self.attempts.saturating_add(1);
        let elapsed = now.duration_since(self.started_at);
        let next_delay = self.policy.next_delay(self.attempts, &mut self.rng_state);
        if let Some(reason) = self.policy.stop_reason(self.attempts, elapsed, next_delay) {
            return WebDiscoveryDecision::Stop {
                outcome: WebDiscoveryOutcome {
                    status: status_from_failure(&failure),
                    stop_reason: reason,
                    attempts: self.attempts,
                    elapsed_ms: duration_ms(elapsed),
                    failure,
                },
            };
        }
        WebDiscoveryDecision::Retry {
            delay: next_delay,
            failure,
        }
    }
}

pub fn classify_ddg_html_failure(status: u16, body: &str) -> Option<WebDiscoveryFailure> {
    if is_ddg_blocked_status(status) || ddg_blocked_body(body) {
        return Some(WebDiscoveryFailure::blocked(
            Some(status),
            Some("ddg_blocked".to_string()),
        ));
    }
    if status >= 400 {
        return Some(WebDiscoveryFailure::http_error(
            status,
            Some("ddg_http_error".to_string()),
        ));
    }
    None
}

fn is_ddg_blocked_status(status: u16) -> bool {
    matches!(status, 403 | 429 | 451)
}

static DDG_BLOCK_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new("(?i)(captcha|unusual traffic|access denied|verify you are a human|robot check|blocked)")
        .expect("valid ddg block regex")
});

fn ddg_blocked_body(body: &str) -> bool {
    DDG_BLOCK_RE.is_match(body)
}

fn status_from_failure(failure: &WebDiscoveryFailure) -> WebDiscoveryStatus {
    match failure.kind {
        WebDiscoveryFailureKind::Blocked => WebDiscoveryStatus::Blocked,
        WebDiscoveryFailureKind::HttpError
        | WebDiscoveryFailureKind::TransportError
        | WebDiscoveryFailureKind::ParseError => WebDiscoveryStatus::Failed,
    }
}

fn duration_ms(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}

fn seed_from_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_nanos() as u64)
        .unwrap_or(0x9e3779b97f4a7c15)
}

fn next_u64(state: &mut u64) -> u64 {
    let mut x = *state;
    if x == 0 {
        x = 0x9e3779b97f4a7c15;
    }
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    let next = x.wrapping_mul(0x2545_f491_4f6c_dd1d);
    *state = next;
    next
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ddg_blocked_status_is_detected() {
        let failure = classify_ddg_html_failure(429, "ok").expect("blocked failure");
        assert_eq!(failure.kind, WebDiscoveryFailureKind::Blocked);
        assert_eq!(failure.http_status, Some(429));
    }

    #[test]
    fn ddg_blocked_body_is_detected() {
        let failure = classify_ddg_html_failure(200, "Please solve the captcha")
            .expect("blocked failure");
        assert_eq!(failure.kind, WebDiscoveryFailureKind::Blocked);
        assert_eq!(failure.http_status, Some(200));
    }

    #[test]
    fn backoff_retries_then_stops_on_max_attempts() {
        let policy = WebDiscoveryBackoffPolicy::new(
            Duration::from_millis(100),
            Duration::from_millis(400),
            3,
            Duration::from_secs(10),
            0.0,
        );
        let start = Instant::now();
        let mut backoff =
            WebDiscoveryBackoff::new_with_seed_and_start(policy, Some(1), start);
        let failure = WebDiscoveryFailure::http_error(500, None);

        match backoff.register_failure_at(failure.clone(), start) {
            WebDiscoveryDecision::Retry { delay, .. } => {
                assert_eq!(delay, Duration::from_millis(100));
            }
            _ => panic!("expected retry on first failure"),
        }

        match backoff.register_failure_at(failure.clone(), start + Duration::from_millis(10)) {
            WebDiscoveryDecision::Retry { delay, .. } => {
                assert_eq!(delay, Duration::from_millis(200));
            }
            _ => panic!("expected retry on second failure"),
        }

        match backoff.register_failure_at(failure, start + Duration::from_millis(20)) {
            WebDiscoveryDecision::Stop { outcome } => {
                assert_eq!(outcome.stop_reason, WebDiscoveryStopReason::MaxAttempts);
                assert_eq!(outcome.attempts, 3);
                assert_eq!(outcome.status, WebDiscoveryStatus::Failed);
            }
            _ => panic!("expected stop on third failure"),
        }
    }

    #[test]
    fn backoff_stops_when_elapsed_exceeds_limit() {
        let policy = WebDiscoveryBackoffPolicy::new(
            Duration::from_millis(100),
            Duration::from_millis(400),
            5,
            Duration::from_millis(150),
            0.0,
        );
        let start = Instant::now();
        let mut backoff =
            WebDiscoveryBackoff::new_with_seed_and_start(policy, Some(7), start);
        let failure = WebDiscoveryFailure::http_error(500, None);

        match backoff.register_failure_at(failure, start + Duration::from_millis(100)) {
            WebDiscoveryDecision::Stop { outcome } => {
                assert_eq!(outcome.stop_reason, WebDiscoveryStopReason::MaxElapsed);
                assert_eq!(outcome.attempts, 1);
            }
            _ => panic!("expected stop on elapsed limit"),
        }
    }
}
