use crate::error::RateLimited;
use crate::metrics;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const DDG_DISCOVERY_LIMIT_KEY: &str = "ddg_discovery";

#[derive(Clone)]
pub struct RateLimiter<K>
where
    K: Eq + Hash,
{
    inner: Arc<Mutex<HashMap<K, RateBucket>>>,
    refill_per_sec: f64,
    capacity: f64,
}

#[derive(Clone, Copy)]
struct RateBucket {
    tokens: f64,
    last: Instant,
    last_allowed: Option<Instant>,
    deny_streak: u64,
    total_denies: u64,
}

#[derive(Clone, Copy)]
struct RateLimitOutcome {
    allowed: bool,
    elapsed: Duration,
    retry_after: Duration,
    deny_streak: u64,
    total_denies: u64,
    allowed_gap: Option<Duration>,
}

impl<K> RateLimiter<K>
where
    K: Eq + Hash,
{
    pub fn new(per_minute: u32, burst: u32) -> Self {
        let capacity = if burst == 0 {
            per_minute as f64
        } else {
            burst as f64
        }
        .max(1.0);
        let refill_per_sec = per_minute as f64 / 60.0;
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            refill_per_sec,
            capacity,
        }
    }

    pub fn per_minute(&self) -> u32 {
        (self.refill_per_sec * 60.0).round().max(0.0) as u32
    }

    pub fn check(&self, key: K) -> Result<(), Duration>
    where
        K: Clone,
    {
        let outcome = self.check_with_outcome(key);
        if outcome.allowed {
            Ok(())
        } else {
            Err(outcome.retry_after)
        }
    }

    pub fn check_or_rate_limited(
        &self,
        key: K,
        limit_key: impl Into<String>,
        scope: impl Into<String>,
    ) -> Result<(), RateLimited>
    where
        K: Clone,
    {
        let limit_key = limit_key.into();
        let scope = scope.into();
        let outcome = self.check_with_outcome(key);
        if outcome.allowed {
            if is_ddg_limit(&limit_key) {
                let spacing_ms = duration_ms(outcome.allowed_gap.unwrap_or_default());
                metrics::global().inc_ddg_discovery_spacing(spacing_ms);
                tracing::info!(
                    target: "docdexd_web_discovery",
                    event = "ddg_discovery_spacing",
                    limit_key = %limit_key,
                    scope = %scope,
                    spacing_ms,
                    first = outcome.allowed_gap.is_none(),
                    "ddg discovery spacing observed"
                );
            }
            Ok(())
        } else {
            let retry_after_ms = duration_ms(outcome.retry_after);
            if is_ddg_limit(&limit_key) {
                metrics::global().inc_ddg_discovery_backoff(retry_after_ms);
                metrics::global().inc_ddg_discovery_retry();
                metrics::global().inc_ddg_discovery_stop();
                tracing::warn!(
                    target: "docdexd_web_discovery",
                    event = "ddg_discovery_backoff",
                    limit_key = %limit_key,
                    scope = %scope,
                    retry_after_ms,
                    retry_count = outcome.deny_streak,
                    total_denies = outcome.total_denies,
                    outcome = "stop",
                    "ddg discovery backoff required"
                );
            }
            Err(RateLimited::new(outcome.retry_after, limit_key, scope))
        }
    }

    fn check_with_outcome(&self, key: K) -> RateLimitOutcome
    where
        K: Clone,
    {
        let mut guard = self.inner.lock();
        let now = Instant::now();
        let bucket = guard.entry(key).or_insert(RateBucket {
            tokens: self.capacity,
            last: now,
            last_allowed: None,
            deny_streak: 0,
            total_denies: 0,
        });
        let elapsed = now.duration_since(bucket.last);
        bucket.tokens = (bucket.tokens + elapsed.as_secs_f64() * self.refill_per_sec)
            .min(self.capacity);
        bucket.last = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            bucket.deny_streak = 0;
            let allowed_gap = bucket.last_allowed.map(|prev| now.duration_since(prev));
            bucket.last_allowed = Some(now);
            RateLimitOutcome {
                allowed: true,
                elapsed,
                retry_after: Duration::default(),
                deny_streak: bucket.deny_streak,
                total_denies: bucket.total_denies,
                allowed_gap,
            }
        } else {
            bucket.deny_streak = bucket.deny_streak.saturating_add(1);
            bucket.total_denies = bucket.total_denies.saturating_add(1);
            let retry_after = if self.refill_per_sec <= 0.0 {
                Duration::from_secs(60)
            } else {
                let missing = (1.0 - bucket.tokens).max(0.0);
                let seconds = (missing / self.refill_per_sec).max(0.0);
                Duration::from_secs_f64(seconds)
            };
            RateLimitOutcome {
                allowed: false,
                elapsed,
                retry_after,
                deny_streak: bucket.deny_streak,
                total_denies: bucket.total_denies,
                allowed_gap: None,
            }
        }
    }
}

fn is_ddg_limit(limit_key: &str) -> bool {
    limit_key == DDG_DISCOVERY_LIMIT_KEY
}

fn duration_ms(duration: Duration) -> u64 {
    duration
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}
