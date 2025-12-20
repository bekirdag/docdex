use std::time::{Duration, Instant};

use crate::error::BackoffRequired;

pub const DDG_DISCOVERY_LIMIT_KEY: &str = "ddg_discovery";
pub const DDG_DISCOVERY_SCOPE: &str = "global";

#[derive(Clone, Debug)]
pub struct DdgDiscoveryPolicyConfig {
    pub min_spacing: Duration,
    pub base_backoff: Duration,
    pub max_backoff: Duration,
    pub max_consecutive_failures: u32,
    pub stop_backoff: Duration,
}

impl Default for DdgDiscoveryPolicyConfig {
    fn default() -> Self {
        Self {
            min_spacing: Duration::from_millis(2_000),
            base_backoff: Duration::from_millis(2_000),
            max_backoff: Duration::from_millis(30_000),
            max_consecutive_failures: 5,
            stop_backoff: Duration::from_millis(120_000),
        }
    }
}

impl DdgDiscoveryPolicyConfig {
    fn normalized(mut self) -> Self {
        if self.max_consecutive_failures == 0 {
            self.max_consecutive_failures = 1;
        }
        if self.max_backoff < self.base_backoff {
            self.max_backoff = self.base_backoff;
        }
        self
    }
}

#[derive(Debug)]
pub struct DdgDiscoveryPacer {
    config: DdgDiscoveryPolicyConfig,
    last_attempt_at: Option<Instant>,
    backoff_until: Option<Instant>,
    consecutive_failures: u32,
}

impl DdgDiscoveryPacer {
    pub fn new(config: DdgDiscoveryPolicyConfig) -> Self {
        Self {
            config: config.normalized(),
            last_attempt_at: None,
            backoff_until: None,
            consecutive_failures: 0,
        }
    }

    pub fn config(&self) -> &DdgDiscoveryPolicyConfig {
        &self.config
    }

    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }

    pub fn check_or_backoff(&mut self) -> Result<(), BackoffRequired> {
        self.check_or_backoff_at(Instant::now())
    }

    pub fn check_or_backoff_at(&mut self, now: Instant) -> Result<(), BackoffRequired> {
        if let Some(next) = self.next_allowed_at() {
            if now < next {
                return Err(self.backoff_error(next.duration_since(now)));
            }
        }
        self.last_attempt_at = Some(now);
        Ok(())
    }

    pub fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.backoff_until = None;
    }

    pub fn record_failure(&mut self) -> BackoffRequired {
        self.record_failure_at(Instant::now())
    }

    pub fn record_failure_at(&mut self, now: Instant) -> BackoffRequired {
        self.consecutive_failures = self.consecutive_failures.saturating_add(1);
        let capped_failures = self
            .consecutive_failures
            .min(self.config.max_consecutive_failures);
        let mut next = now + self.backoff_duration(capped_failures);
        if self.consecutive_failures >= self.config.max_consecutive_failures
            && !self.config.stop_backoff.is_zero()
        {
            let stop_until = now + self.config.stop_backoff;
            if stop_until > next {
                next = stop_until;
            }
        }
        self.backoff_until = Some(next);
        self.backoff_error(next.duration_since(now))
    }

    fn next_allowed_at(&self) -> Option<Instant> {
        let spacing_ready = self
            .last_attempt_at
            .map(|at| at + self.config.min_spacing);
        match (spacing_ready, self.backoff_until) {
            (Some(spacing), Some(backoff)) => Some(spacing.max(backoff)),
            (Some(spacing), None) => Some(spacing),
            (None, Some(backoff)) => Some(backoff),
            (None, None) => None,
        }
    }

    fn backoff_duration(&self, failures: u32) -> Duration {
        if failures == 0 {
            return Duration::ZERO;
        }
        let base_ms = self
            .config
            .base_backoff
            .as_millis()
            .min(u128::from(u64::MAX)) as u64;
        if base_ms == 0 {
            return Duration::ZERO;
        }
        let max_ms = self
            .config
            .max_backoff
            .as_millis()
            .max(base_ms as u128)
            .min(u128::from(u64::MAX)) as u64;
        let exponent = failures.saturating_sub(1).min(30);
        let multiplier = 1u64.checked_shl(exponent).unwrap_or(u64::MAX);
        let delay_ms = base_ms.saturating_mul(multiplier).min(max_ms);
        Duration::from_millis(delay_ms)
    }

    fn backoff_error(&self, retry_after: Duration) -> BackoffRequired {
        BackoffRequired::new(
            retry_after,
            DDG_DISCOVERY_LIMIT_KEY.to_string(),
            DDG_DISCOVERY_SCOPE.to_string(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enforces_min_spacing_between_attempts() {
        let config = DdgDiscoveryPolicyConfig {
            min_spacing: Duration::from_millis(500),
            base_backoff: Duration::from_millis(1_000),
            max_backoff: Duration::from_millis(5_000),
            max_consecutive_failures: 3,
            stop_backoff: Duration::from_millis(0),
        };
        let mut pacer = DdgDiscoveryPacer::new(config);
        let start = Instant::now();

        assert!(pacer.check_or_backoff_at(start).is_ok());

        let err = pacer
            .check_or_backoff_at(start + Duration::from_millis(200))
            .expect_err("should enforce spacing");
        assert_eq!(err.retry_after_ms, 300);

        assert!(pacer
            .check_or_backoff_at(start + Duration::from_millis(500))
            .is_ok());
    }

    #[test]
    fn applies_exponential_backoff_and_stop_window() {
        let config = DdgDiscoveryPolicyConfig {
            min_spacing: Duration::from_millis(0),
            base_backoff: Duration::from_millis(1_000),
            max_backoff: Duration::from_millis(4_000),
            max_consecutive_failures: 3,
            stop_backoff: Duration::from_millis(10_000),
        };
        let mut pacer = DdgDiscoveryPacer::new(config);
        let now = Instant::now();

        let err1 = pacer.record_failure_at(now);
        assert_eq!(err1.retry_after_ms, 1_000);

        let err2 = pacer.record_failure_at(now);
        assert_eq!(err2.retry_after_ms, 2_000);

        let err3 = pacer.record_failure_at(now);
        assert_eq!(err3.retry_after_ms, 10_000);
    }

    #[test]
    fn resets_after_success() {
        let mut pacer = DdgDiscoveryPacer::new(DdgDiscoveryPolicyConfig::default());
        let now = Instant::now();

        pacer.record_failure_at(now);
        assert_eq!(pacer.consecutive_failures(), 1);
        pacer.record_success();
        assert_eq!(pacer.consecutive_failures(), 0);
    }
}
