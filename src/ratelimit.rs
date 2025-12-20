use crate::error::RateLimited;
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

#[cfg(test)]
mod latency_perf_tests {
    use super::RateLimiter;
    use std::hint::black_box;
    use std::time::Instant;

    fn percentile(sorted: &[u128], p: f64) -> u128 {
        if sorted.is_empty() {
            return 0;
        }
        let p = p.clamp(0.0, 1.0);
        let idx = ((p * ((sorted.len() - 1) as f64)).ceil() as usize).min(sorted.len() - 1);
        sorted[idx]
    }

    fn summarize(mut samples_ns: Vec<u128>) -> (u128, u128, u128) {
        samples_ns.sort_unstable();
        let p50 = percentile(&samples_ns, 0.50);
        let p95 = percentile(&samples_ns, 0.95);
        let max = *samples_ns.last().unwrap_or(&0);
        (p50, p95, max)
    }

    /// NFR check: rate-limiter fast path should remain negligible for non-rate-limited tool calls.
    #[test]
    #[ignore]
    fn mcp_rate_limiter_fast_path_p95_under_50us() {
        let limiter = RateLimiter::<()>::new(10_000_000, 10_000_000);
        for _ in 0..10_000 {
            let _ = limiter.check_or_rate_limited((), "mcp_tools", "global");
        }

        const BATCH: usize = 10_000;
        const BATCHES: usize = 200;
        let mut samples_ns = Vec::with_capacity(BATCHES);
        for _ in 0..BATCHES {
            let start = Instant::now();
            for _ in 0..BATCH {
                black_box(
                    limiter
                        .check_or_rate_limited((), "mcp_tools", "global")
                        .expect("should not rate limit"),
                );
            }
            samples_ns.push(start.elapsed().as_nanos() / (BATCH as u128));
        }

        let (p50, p95, max) = summarize(samples_ns);
        eprintln!(
            "rate limiter fast-path check: p50={}ns p95={}ns max={}ns (batched)",
            p50, p95, max
        );

        if cfg!(debug_assertions) {
            eprintln!(
                "note: perf assertions are enforced in release builds; re-run with `cargo test --release ... -- --ignored --nocapture`"
            );
            return;
        }

        assert!(
            p95 < 50_000,
            "rate limiter fast-path p95 {}ns exceeds 50us",
            p95
        );
    }
}
