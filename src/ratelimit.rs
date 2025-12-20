use crate::error::RateLimited;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;
use std::time::{Duration, Instant};

struct RateLimiterState<K> {
    buckets: HashMap<K, RateBucket>,
}

#[derive(Clone)]
pub struct RateLimiter<K>
where
    K: Eq + Hash,
{
    inner: Arc<Mutex<RateLimiterState<K>>>,
    refill_per_sec: f64,
    capacity: f64,
    per_minute: u32,
    burst: u32,
}

#[derive(Clone, Copy)]
struct RateBucket {
    tokens: f64,
    last: Instant,
    denied_total: u64,
}

struct RateLimitViolation {
    retry_after: Duration,
    denied_total: u64,
}

impl<K> RateLimiter<K>
where
    K: Eq + Hash,
{
    pub fn new(per_minute: u32, burst: u32) -> Self {
        let effective_burst = if burst == 0 { per_minute } else { burst }.max(1);
        let capacity = effective_burst as f64;
        let refill_per_sec = per_minute as f64 / 60.0;
        Self {
            inner: Arc::new(Mutex::new(RateLimiterState {
                buckets: HashMap::new(),
            })),
            refill_per_sec,
            capacity,
            per_minute,
            burst: effective_burst,
        }
    }

    pub fn per_minute(&self) -> u32 {
        self.per_minute
    }

    pub fn burst(&self) -> u32 {
        self.burst
    }

    pub fn check(&self, key: K) -> Result<(), RateLimitViolation>
    where
        K: Clone,
    {
        let mut guard = self.inner.lock();
        let now = Instant::now();
        let bucket = guard.buckets.entry(key).or_insert(RateBucket {
            tokens: self.capacity,
            last: now,
            denied_total: 0,
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
                bucket.denied_total = bucket.denied_total.saturating_add(1);
                return Err(RateLimitViolation {
                    retry_after: Duration::from_secs(60),
                    denied_total: bucket.denied_total,
                });
            }
            let missing = (1.0 - bucket.tokens).max(0.0);
            let seconds = (missing / self.refill_per_sec).max(0.0);
            bucket.denied_total = bucket.denied_total.saturating_add(1);
            Err(RateLimitViolation {
                retry_after: Duration::from_secs_f64(seconds),
                denied_total: bucket.denied_total,
            })
        }
    }

    pub fn check_or_rate_limited(
        &self,
        key: K,
        limit_key: impl Into<String>,
        scope: impl Into<String>,
        resource_key: impl Into<String>,
    ) -> Result<(), RateLimited>
    where
        K: Clone,
    {
        match self.check(key) {
            Ok(()) => Ok(()),
            Err(violation) => Err(RateLimited::new(
                violation.retry_after,
                limit_key.into(),
                scope.into(),
                resource_key.into(),
                self.per_minute,
                self.burst,
                violation.denied_total,
            )),
        }
    }
}
