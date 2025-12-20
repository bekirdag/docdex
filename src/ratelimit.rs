use crate::error::{RateLimited, StartupError};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct RateLimiter<K>
where
    K: Eq + Hash,
{
    inner: Arc<Mutex<HashMap<K, RateBucket>>>,
    refill_per_sec: f64,
    capacity: f64,
}

#[derive(Clone, Copy, Debug)]
pub struct RateLimitConfig {
    per_minute: u32,
    burst: u32,
}

impl RateLimitConfig {
    pub fn for_http(per_minute: u32, burst: u32, secure_mode: bool) -> Result<Self, StartupError> {
        let effective_per_minute = if secure_mode && per_minute == 0 {
            DEFAULT_SECURE_PER_MINUTE
        } else {
            per_minute
        };
        if !secure_mode && per_minute == 0 && burst > 0 {
            return Err(StartupError::new(
                "startup_config_invalid",
                "invalid HTTP rate limit config: burst set without a per-minute limit",
            )
            .with_hint(
                "Set --rate-limit-per-min (or DOCDEX_RATE_LIMIT_PER_MIN) to enable the limiter, or set --rate-limit-burst=0 to disable it.",
            ));
        }
        Ok(Self::new(effective_per_minute, burst))
    }

    pub fn for_mcp(per_minute: u32, burst: u32) -> Result<Self, StartupError> {
        if per_minute == 0 && burst > 0 {
            return Err(StartupError::new(
                "startup_config_invalid",
                "invalid MCP rate limit config: burst set without a per-minute limit",
            )
            .with_hint(
                "Set --rate-limit-per-min (or DOCDEX_MCP_RATE_LIMIT_PER_MIN) to enable the limiter, or set --rate-limit-burst=0 to disable it.",
            ));
        }
        Ok(Self::new(per_minute, burst))
    }

    fn new(per_minute: u32, burst: u32) -> Self {
        let effective_burst = if per_minute > 0 {
            if burst == 0 { per_minute } else { burst }
        } else {
            0
        };
        Self {
            per_minute,
            burst: effective_burst,
        }
    }

    pub fn limiter<K>(&self) -> Option<RateLimiter<K>>
    where
        K: Eq + Hash,
    {
        if self.per_minute > 0 {
            Some(RateLimiter::new(self.per_minute, self.burst))
        } else {
            None
        }
    }
}

pub const DEFAULT_SECURE_PER_MINUTE: u32 = 60;

#[derive(Clone, Copy)]
struct RateBucket {
    tokens: f64,
    last: Instant,
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
        let mut guard = self.inner.lock();
        let now = Instant::now();
        let bucket = guard.entry(key).or_insert(RateBucket {
            tokens: self.capacity,
            last: now,
        });
        let elapsed = now.duration_since(bucket.last).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        bucket.last = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            Ok(())
        } else {
            // How long until the bucket refills to 1 token?
            if self.refill_per_sec <= 0.0 {
                return Err(Duration::from_secs(60));
            }
            let missing = (1.0 - bucket.tokens).max(0.0);
            let seconds = (missing / self.refill_per_sec).max(0.0);
            Err(Duration::from_secs_f64(seconds))
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
        match self.check(key) {
            Ok(()) => Ok(()),
            Err(retry_after) => Err(RateLimited::new(
                retry_after,
                limit_key.into(),
                scope.into(),
            )),
        }
    }
}

#[derive(Clone, Default)]
pub struct ResourceLimiter {
    inner: Arc<Mutex<HashMap<String, RateLimiter<()>>>>,
}

impl ResourceLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_limit(&self, resource: impl Into<String>, per_minute: u32, burst: u32) {
        if per_minute == 0 {
            return;
        }
        let resource = resource.into();
        let effective_burst = if burst == 0 { per_minute } else { burst };
        let limiter = RateLimiter::<()>::new(per_minute, effective_burst);
        self.inner.lock().insert(resource, limiter);
    }

    pub fn check_or_rate_limited(
        &self,
        resource: &str,
        scope: impl Into<String>,
    ) -> Result<(), RateLimited> {
        let limiter = { self.inner.lock().get(resource).cloned() };
        match limiter {
            Some(limiter) => limiter.check_or_rate_limited((), resource.to_string(), scope),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_limiter_shares_limits_per_key() {
        let limiter = ResourceLimiter::new();
        limiter.insert_limit("web_research", 60, 1);

        assert!(limiter
            .check_or_rate_limited("web_research", "global")
            .is_ok());

        let err = limiter
            .check_or_rate_limited("web_research", "global")
            .expect_err("second call should be rate limited");
        assert_eq!(err.limit_key, "web_research");
        assert_eq!(err.scope, "global");
    }
}
