#![allow(dead_code)]

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::browser_session::BrowserSessionError;
use crate::error::RateLimited;
use crate::metrics;

pub const ERR_TIER2_UNAVAILABLE: &str = "tier2_unavailable";
pub const LIMIT_KEY_BROWSER_CONCURRENCY: &str = "browser_concurrency";
const DEFAULT_BROWSER_CONCURRENCY_RETRY_AFTER: Duration = Duration::from_secs(1);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Tier2UnavailableReason {
    StartupFailed,
    Overload,
    Timeout,
    Crashed,
    Disabled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Tier2Unavailable {
    pub code: &'static str,
    pub reason: Tier2UnavailableReason,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
}

impl Tier2Unavailable {
    pub fn new(reason: Tier2UnavailableReason, message: impl Into<String>) -> Self {
        Self {
            code: ERR_TIER2_UNAVAILABLE,
            reason,
            message: message.into(),
            correlation_id: None,
        }
    }

    pub fn with_correlation_id(mut self, correlation_id: impl Into<String>) -> Self {
        self.correlation_id = Some(correlation_id.into());
        self
    }
}

impl fmt::Display for Tier2Unavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({:?})", self.message, self.reason)
    }
}

#[derive(Clone, Debug, Default)]
pub struct Tier2Config {
    pub enabled: bool,
}

impl Tier2Config {
    pub fn enabled() -> Self {
        Self { enabled: true }
    }
}

#[derive(Clone)]
pub struct Tier2Limiter {
    semaphore: Arc<Semaphore>,
    queue_timeout: Duration,
    max_concurrent_sessions: usize,
}

impl Tier2Limiter {
    pub fn new(max_concurrent_sessions: usize, queue_timeout: Duration) -> Self {
        let max = max_concurrent_sessions.max(1);
        Self {
            semaphore: Arc::new(Semaphore::new(max)),
            queue_timeout,
            max_concurrent_sessions: max,
        }
    }

    pub fn max_concurrent_sessions(&self) -> usize {
        self.max_concurrent_sessions
    }

    pub fn queue_timeout(&self) -> Duration {
        self.queue_timeout
    }

    pub fn available_permits(&self) -> usize {
        self.semaphore.available_permits()
    }

    pub async fn acquire_browser_permit(&self) -> Result<Tier2Permit, RateLimited> {
        self.acquire_or_rate_limited(LIMIT_KEY_BROWSER_CONCURRENCY, "global")
            .await
    }

    pub async fn acquire_or_rate_limited(
        &self,
        limit_key: impl Into<String>,
        scope: impl Into<String>,
    ) -> Result<Tier2Permit, RateLimited> {
        let limit_key = limit_key.into();
        let scope = scope.into();
        let retry_after = self.retry_after_hint();
        let make_err = || {
            RateLimited::new(retry_after, limit_key.clone(), scope.clone())
                .with_message("concurrency limit reached")
        };

        if self.queue_timeout.is_zero() {
            return self
                .semaphore
                .clone()
                .try_acquire_owned()
                .map(Tier2Permit::new)
                .map_err(|_| {
                    metrics::global().inc_tier2_overload_rejection();
                    make_err()
                });
        }

        tokio::time::timeout(self.queue_timeout, self.semaphore.clone().acquire_owned())
            .await
            .map_err(|_| {
                metrics::global().inc_tier2_overload_rejection();
                make_err()
            })?
            .map(Tier2Permit::new)
            .map_err(|_| {
                metrics::global().inc_tier2_overload_rejection();
                make_err()
            })
    }

    pub async fn acquire(&self) -> Result<Tier2Permit, Tier2Unavailable> {
        if self.queue_timeout.is_zero() {
            return self
                .semaphore
                .clone()
                .try_acquire_owned()
                .map(Tier2Permit::new)
                .map_err(|_| {
                    metrics::global().inc_tier2_overload_rejection();
                    Tier2Unavailable::new(
                        Tier2UnavailableReason::Overload,
                        "tier 2 browser capacity exhausted",
                    )
                });
        }

        tokio::time::timeout(self.queue_timeout, self.semaphore.clone().acquire_owned())
            .await
            .map_err(|_| {
                metrics::global().inc_tier2_overload_rejection();
                Tier2Unavailable::new(
                    Tier2UnavailableReason::Overload,
                    "tier 2 browser capacity exhausted",
                )
            })?
            .map(Tier2Permit::new)
            .map_err(|_| {
                metrics::global().inc_tier2_overload_rejection();
                Tier2Unavailable::new(
                    Tier2UnavailableReason::Overload,
                    "tier 2 browser capacity exhausted",
                )
            })
    }

    fn retry_after_hint(&self) -> Duration {
        if self.queue_timeout.is_zero() {
            DEFAULT_BROWSER_CONCURRENCY_RETRY_AFTER
        } else {
            self.queue_timeout
        }
    }
}

pub struct Tier2Permit {
    _permit: OwnedSemaphorePermit,
}

impl Tier2Permit {
    fn new(permit: OwnedSemaphorePermit) -> Self {
        metrics::global().inc_tier2_permits_in_use();
        Self { _permit: permit }
    }
}

impl Drop for Tier2Permit {
    fn drop(&mut self) {
        metrics::global().dec_tier2_permits_in_use();
    }
}

pub fn classify_browser_session_failure(err: &BrowserSessionError) -> Option<Tier2Unavailable> {
    match err {
        BrowserSessionError::LaunchFailed(_) => Some(Tier2Unavailable::new(
            Tier2UnavailableReason::StartupFailed,
            "tier 2 browser startup failed",
        )),
        BrowserSessionError::TimedOut(timeout) => Some(Tier2Unavailable::new(
            Tier2UnavailableReason::Timeout,
            format!("tier 2 browser timed out after {}ms", timeout.as_millis()),
        )),
        BrowserSessionError::WorkFailed(_) | BrowserSessionError::CleanupFailed(_) => {
            Some(Tier2Unavailable::new(
                Tier2UnavailableReason::Crashed,
                "tier 2 browser crashed or became unavailable",
            ))
        }
        BrowserSessionError::Cancelled => None,
    }
}

pub fn classify_tier2_unavailable(err: &anyhow::Error) -> Option<Tier2Unavailable> {
    err.downcast_ref::<BrowserSessionError>()
        .and_then(classify_browser_session_failure)
}

#[derive(Debug)]
pub struct Tier2RunResult<T> {
    pub value: T,
    pub tier2_unavailable: Option<Tier2Unavailable>,
}

pub async fn run_with_fallback<T, Tier2Future, Tier3Future>(
    request_id: &str,
    config: Tier2Config,
    limiter: Option<&Tier2Limiter>,
    tier2: impl FnOnce() -> Tier2Future,
    tier3: impl FnOnce() -> Tier3Future,
) -> Result<Tier2RunResult<T>, anyhow::Error>
where
    Tier2Future: std::future::Future<Output = Result<T, anyhow::Error>>,
    Tier3Future: std::future::Future<Output = Result<T, anyhow::Error>>,
{
    if !config.enabled {
        let unavailable =
            Tier2Unavailable::new(Tier2UnavailableReason::Disabled, "tier 2 is disabled")
                .with_correlation_id(request_id);
        tracing::info!(
            target: "docdexd_tier2",
            event = "tier2_disabled_fallback",
            request_id = %request_id,
            reason = ?unavailable.reason,
            "tier2 fallback (disabled)"
        );
        return Ok(Tier2RunResult {
            value: tier3().await?,
            tier2_unavailable: Some(unavailable),
        });
    }

    let _permit: Option<Tier2Permit> = match limiter {
        None => None,
        Some(limiter) => match limiter.acquire().await {
            Ok(permit) => Some(permit),
            Err(unavailable) => {
                let unavailable = unavailable.with_correlation_id(request_id);
                tracing::warn!(
                    target: "docdexd_tier2",
                    event = "tier2_overload_fallback",
                    request_id = %request_id,
                    reason = ?unavailable.reason,
                    message = %unavailable.message,
                    max_concurrent_sessions = limiter.max_concurrent_sessions(),
                    available_permits = limiter.available_permits(),
                    queue_timeout_ms = limiter.queue_timeout().as_millis() as u64,
                    "tier2 fallback (overload)"
                );
                return Ok(Tier2RunResult {
                    value: tier3().await?,
                    tier2_unavailable: Some(unavailable),
                });
            }
        },
    };

    match tier2().await {
        Ok(value) => Ok(Tier2RunResult {
            value,
            tier2_unavailable: None,
        }),
        Err(err) => {
            let Some(unavailable) = classify_tier2_unavailable(&err) else {
                return Err(err);
            };
            let unavailable = unavailable.with_correlation_id(request_id);
            tracing::warn!(
                target: "docdexd_tier2",
                event = "tier2_unavailable_fallback",
                request_id = %request_id,
                reason = ?unavailable.reason,
                message = %unavailable.message,
                error = %err,
                "tier2 fallback (unavailable)"
            );
            Ok(Tier2RunResult {
                value: tier3().await?,
                tier2_unavailable: Some(unavailable),
            })
        }
    }
}

#[cfg(test)]
mod observability_tests {
    use super::*;
    use crate::metrics::Metrics;
    use std::collections::BTreeMap;
    use std::sync::Mutex;
    use tracing::Subscriber;
    use tracing_subscriber::layer::{Context, Layer};
    use tracing_subscriber::prelude::*;
    use tracing_subscriber::{registry::LookupSpan, Registry};

    #[derive(Default)]
    struct Captured {
        events: Mutex<Vec<BTreeMap<String, String>>>,
    }

    struct CaptureLayer(std::sync::Arc<Captured>);

    impl<S> Layer<S> for CaptureLayer
    where
        S: Subscriber + for<'a> LookupSpan<'a>,
    {
        fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
            let mut fields = BTreeMap::new();
            fields.insert("target".to_string(), event.metadata().target().to_string());
            struct Visitor<'a>(&'a mut BTreeMap<String, String>);
            impl tracing::field::Visit for Visitor<'_> {
                fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                    self.0.insert(field.name().to_string(), value.to_string());
                }

                fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
                    self.0
                        .insert(field.name().to_string(), value.to_string());
                }

                fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
                    self.0
                        .insert(field.name().to_string(), value.to_string());
                }

                fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
                    self.0
                        .insert(field.name().to_string(), value.to_string());
                }

                fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                    self.0
                        .insert(field.name().to_string(), format!("{value:?}"));
                }
            }
            event.record(&mut Visitor(&mut fields));
            self.0.events.lock().unwrap().push(fields);
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn emits_structured_overload_fallback_log() {
        let captured = std::sync::Arc::new(Captured::default());
        let subscriber = Registry::default().with(CaptureLayer(captured.clone()));
        let _guard = tracing::subscriber::set_default(subscriber);

        let limiter = Tier2Limiter::new(1, Duration::from_millis(0));
        let _hold = limiter.acquire().await.expect("hold permit");

        let _ = run_with_fallback(
            "req-overload-obs",
            Tier2Config::enabled(),
            Some(&limiter),
            || async { Ok::<_, anyhow::Error>("tier2".to_string()) },
            || async { Ok::<_, anyhow::Error>("tier3".to_string()) },
        )
        .await
        .expect("run");

        let events = captured.events.lock().unwrap();
        let found = events.iter().any(|fields| {
            fields
                .get("event")
                .is_some_and(|v| v.contains("tier2_overload_fallback"))
                && fields
                    .get("request_id")
                    .is_some_and(|v| v.contains("req-overload-obs"))
                && fields.get("max_concurrent_sessions").is_some()
        });
        assert!(found, "expected structured tier2 overload log");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn metrics_increment_on_permit_and_overload() {
        let before = metrics::global().render_prometheus();

        let limiter = Tier2Limiter::new(1, Duration::from_millis(0));
        let _hold = limiter.acquire().await.expect("hold permit");

        let _ = run_with_fallback(
            "req-overload-metrics",
            Tier2Config::enabled(),
            Some(&limiter),
            || async { Ok::<_, anyhow::Error>("tier2".to_string()) },
            || async { Ok::<_, anyhow::Error>("tier3".to_string()) },
        )
        .await
        .expect("run");

        let after = metrics::global().render_prometheus();
        assert!(
            after.contains("docdex_tier2_permits_acquired_total")
                && after.contains("docdex_tier2_overload_rejections_total")
        );
        assert_ne!(before, after, "expected metrics to change");

        // Silence unused warning if this test module is compiled with cfgs that
        // don't exercise other metrics; the type stays referenced for doctest tooling.
        let _ = Metrics::default();
    }
}

#[cfg(test)]
mod rate_limit_tests {
    use super::*;
    use crate::error::ERR_RATE_LIMITED;

    #[tokio::test(flavor = "current_thread")]
    async fn overload_maps_to_rate_limited_with_retry_hint() {
        let limiter = Tier2Limiter::new(1, Duration::from_millis(0));
        let _hold = limiter.acquire().await.expect("hold permit");

        let err = limiter
            .acquire_browser_permit()
            .await
            .expect_err("expected rate limit");

        assert_eq!(err.code, ERR_RATE_LIMITED);
        assert_eq!(err.limit_key, LIMIT_KEY_BROWSER_CONCURRENCY);
        assert_eq!(err.scope, "global");
        assert!(
            err.retry_after_ms > 0,
            "retry_after_ms should provide a backoff hint"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn overload_retry_hint_tracks_queue_timeout() {
        let limiter = Tier2Limiter::new(1, Duration::from_millis(10));
        let _hold = limiter.acquire().await.expect("hold permit");

        let err = limiter
            .acquire_browser_permit()
            .await
            .expect_err("expected rate limit");

        assert_eq!(err.retry_after_ms, 10);
    }
}
