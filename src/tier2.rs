#![allow(dead_code)]

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::browser_session::BrowserSessionError;
<<<<<<< HEAD
use crate::error::BackoffRequired;
=======
use crate::error::ERR_TIER2_UNAVAILABLE;
>>>>>>> mcoda/task/bck-05-us-09-t21
use crate::metrics;
use crate::waterfall_trace::{WaterfallGateInput, WaterfallOutcome, WaterfallTier, WaterfallTrace};

<<<<<<< HEAD
pub const ERR_TIER2_UNAVAILABLE: &str = "tier2_unavailable";
const TRACE_DECISION_ATTEMPT: &str = "attempt";
const TRACE_DECISION_FALLBACK: &str = "fallback";
const TRACE_DECISION_EXECUTE: &str = "execute";
const TRACE_DECISION_SKIP: &str = "skip";
const TRACE_DECISION_ABORT: &str = "abort";

const TRACE_REASON_TIER2_ENABLED: &str = "tier2_enabled";
const TRACE_REASON_TIER2_DISABLED: &str = "tier2_disabled";
const TRACE_REASON_TIER2_OVERLOAD: &str = "tier2_overload";
const TRACE_REASON_TIER2_UNAVAILABLE: &str = "tier2_unavailable";
const TRACE_REASON_TIER2_ERROR: &str = "tier2_error";
const TRACE_REASON_TIER3_FALLBACK: &str = "tier3_fallback";
const TRACE_REASON_TIER3_ERROR: &str = "tier3_error";
const TRACE_REASON_TIER3_SKIPPED: &str = "tier3_skipped";

=======
>>>>>>> mcoda/task/bck-05-us-09-t21
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Tier2UnavailableReason {
    StartupFailed,
    Overload,
    Timeout,
    Crashed,
    Disabled,
}

impl Tier2UnavailableReason {
<<<<<<< HEAD
    fn as_trace_detail(&self) -> &'static str {
        match self {
            Tier2UnavailableReason::StartupFailed => "startup_failed",
            Tier2UnavailableReason::Overload => "overload",
            Tier2UnavailableReason::Timeout => "timeout",
            Tier2UnavailableReason::Crashed => "crashed",
            Tier2UnavailableReason::Disabled => "disabled",
=======
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::StartupFailed => "startup_failed",
            Self::Overload => "overload",
            Self::Timeout => "timeout",
            Self::Crashed => "crashed",
            Self::Disabled => "disabled",
>>>>>>> mcoda/task/bck-05-us-09-t21
        }
    }
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

impl std::error::Error for Tier2Unavailable {}

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

    fn overload_backoff(&self) -> BackoffRequired {
        BackoffRequired::new(
            self.queue_timeout,
            "chrome_concurrency".to_string(),
            "tier2".to_string(),
        )
        .with_message("tier 2 browser capacity exhausted")
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
        BrowserSessionError::RateLimited(_) => None,
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
    mut trace: Option<&mut WaterfallTrace>,
    tier2: impl FnOnce() -> Tier2Future,
    tier3: impl FnOnce() -> Tier3Future,
) -> Result<Tier2RunResult<T>, anyhow::Error>
where
    Tier2Future: std::future::Future<Output = Result<T, anyhow::Error>>,
    Tier3Future: std::future::Future<Output = Result<T, anyhow::Error>>,
{
    fn record_gate(
        trace: &mut WaterfallTrace,
        tier: WaterfallTier,
        outcome: WaterfallOutcome,
        decision: &'static str,
        reason: &'static str,
        detail: Option<&'static str>,
    ) {
        trace.record(
            tier,
            outcome,
            Some(WaterfallGateInput {
                decision,
                reason,
                detail,
            }),
        );
    }

    if !config.enabled {
        let unavailable =
            Tier2Unavailable::new(Tier2UnavailableReason::Disabled, "tier 2 is disabled")
                .with_correlation_id(request_id);
        if let Some(trace) = trace.as_deref_mut() {
            record_gate(
                trace,
                WaterfallTier::Tier2,
                WaterfallOutcome::Skipped,
                TRACE_DECISION_FALLBACK,
                TRACE_REASON_TIER2_DISABLED,
                Some("disabled"),
            );
            record_gate(
                trace,
                WaterfallTier::Tier3,
                WaterfallOutcome::Started,
                TRACE_DECISION_EXECUTE,
                TRACE_REASON_TIER3_FALLBACK,
                Some(TRACE_REASON_TIER2_DISABLED),
            );
        }
        tracing::info!(
            target: "docdexd_tier2",
            event = "tier2_disabled_fallback",
            request_id = %request_id,
            reason = ?unavailable.reason,
            "tier2 fallback (disabled)"
        );
        let value = match tier3().await {
            Ok(value) => {
                if let Some(trace) = trace.as_deref_mut() {
                    trace.record(WaterfallTier::Tier3, WaterfallOutcome::Succeeded, None);
                }
                value
            }
            Err(err) => {
                if let Some(trace) = trace.as_deref_mut() {
                    record_gate(
                        trace,
                        WaterfallTier::Tier3,
                        WaterfallOutcome::Failed,
                        TRACE_DECISION_ABORT,
                        TRACE_REASON_TIER3_ERROR,
                        None,
                    );
                }
                return Err(err);
            }
        };
        return Ok(Tier2RunResult {
            value,
            tier2_unavailable: Some(unavailable),
        });
    }

    let _permit: Option<Tier2Permit> = match limiter {
        None => None,
        Some(limiter) => match limiter.acquire().await {
            Ok(permit) => Some(permit),
            Err(unavailable) => {
                let unavailable = unavailable.with_correlation_id(request_id);
<<<<<<< HEAD
                if let Some(trace) = trace.as_deref_mut() {
                    record_gate(
                        trace,
                        WaterfallTier::Tier2,
                        WaterfallOutcome::Skipped,
                        TRACE_DECISION_FALLBACK,
                        TRACE_REASON_TIER2_OVERLOAD,
                        Some("capacity_exhausted"),
                    );
                    record_gate(
                        trace,
                        WaterfallTier::Tier3,
                        WaterfallOutcome::Started,
                        TRACE_DECISION_EXECUTE,
                        TRACE_REASON_TIER3_FALLBACK,
                        Some(TRACE_REASON_TIER2_OVERLOAD),
                    );
                }
=======
                let backoff = limiter.overload_backoff();
>>>>>>> mcoda/task/bck-05-us-09-t22
                tracing::warn!(
                    target: "docdexd_tier2",
                    event = "tier2_overload_fallback",
                    request_id = %request_id,
                    reason = ?unavailable.reason,
                    message = %unavailable.message,
                    backoff_code = %backoff.code,
                    retry_after_ms = backoff.retry_after_ms,
                    limit_key = %backoff.limit_key,
                    scope = %backoff.scope,
                    max_concurrent_sessions = limiter.max_concurrent_sessions(),
                    available_permits = limiter.available_permits(),
                    queue_timeout_ms = limiter.queue_timeout().as_millis() as u64,
                    "tier2 fallback (overload)"
                );
                let value = match tier3().await {
                    Ok(value) => {
                        if let Some(trace) = trace.as_deref_mut() {
                            trace.record(WaterfallTier::Tier3, WaterfallOutcome::Succeeded, None);
                        }
                        value
                    }
                    Err(err) => {
                        if let Some(trace) = trace.as_deref_mut() {
                            record_gate(
                                trace,
                                WaterfallTier::Tier3,
                                WaterfallOutcome::Failed,
                                TRACE_DECISION_ABORT,
                                TRACE_REASON_TIER3_ERROR,
                                None,
                            );
                        }
                        return Err(err);
                    }
                };
                return Ok(Tier2RunResult {
                    value,
                    tier2_unavailable: Some(unavailable),
                });
            }
        },
    };

    if let Some(trace) = trace.as_deref_mut() {
        record_gate(
            trace,
            WaterfallTier::Tier2,
            WaterfallOutcome::Started,
            TRACE_DECISION_ATTEMPT,
            TRACE_REASON_TIER2_ENABLED,
            None,
        );
    }

    match tier2().await {
        Ok(value) => {
            if let Some(trace) = trace.as_deref_mut() {
                trace.record(WaterfallTier::Tier2, WaterfallOutcome::Succeeded, None);
                record_gate(
                    trace,
                    WaterfallTier::Tier3,
                    WaterfallOutcome::Skipped,
                    TRACE_DECISION_SKIP,
                    TRACE_REASON_TIER3_SKIPPED,
                    Some("tier2_succeeded"),
                );
            }
            Ok(Tier2RunResult {
                value,
                tier2_unavailable: None,
            })
        }
        Err(err) => {
            let Some(unavailable) = classify_tier2_unavailable(&err) else {
                if let Some(trace) = trace.as_deref_mut() {
                    record_gate(
                        trace,
                        WaterfallTier::Tier2,
                        WaterfallOutcome::Failed,
                        TRACE_DECISION_ABORT,
                        TRACE_REASON_TIER2_ERROR,
                        None,
                    );
                }
                return Err(err);
            };
            let unavailable = unavailable.with_correlation_id(request_id);
            if let Some(trace) = trace.as_deref_mut() {
                trace.record(
                    WaterfallTier::Tier2,
                    WaterfallOutcome::Failed,
                    Some(WaterfallGateInput {
                        decision: TRACE_DECISION_FALLBACK,
                        reason: TRACE_REASON_TIER2_UNAVAILABLE,
                        detail: Some(unavailable.reason.as_trace_detail()),
                    }),
                );
                record_gate(
                    trace,
                    WaterfallTier::Tier3,
                    WaterfallOutcome::Started,
                    TRACE_DECISION_EXECUTE,
                    TRACE_REASON_TIER3_FALLBACK,
                    Some(TRACE_REASON_TIER2_UNAVAILABLE),
                );
            }
            tracing::warn!(
                target: "docdexd_tier2",
                event = "tier2_unavailable_fallback",
                request_id = %request_id,
                reason = ?unavailable.reason,
                message = %unavailable.message,
                error = %err,
                "tier2 fallback (unavailable)"
            );
            let value = match tier3().await {
                Ok(value) => {
                    if let Some(trace) = trace.as_deref_mut() {
                        trace.record(WaterfallTier::Tier3, WaterfallOutcome::Succeeded, None);
                    }
                    value
                }
                Err(err) => {
                    if let Some(trace) = trace.as_deref_mut() {
                        record_gate(
                            trace,
                            WaterfallTier::Tier3,
                            WaterfallOutcome::Failed,
                            TRACE_DECISION_ABORT,
                            TRACE_REASON_TIER3_ERROR,
                            None,
                        );
                    }
                    return Err(err);
                }
            };
            Ok(Tier2RunResult {
                value,
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
            None,
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
                && fields
                    .get("backoff_code")
                    .is_some_and(|v| v.contains("backoff_required"))
                && fields.get("retry_after_ms").is_some()
                && fields.get("limit_key").is_some()
                && fields.get("scope").is_some()
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
            None,
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

    #[tokio::test(flavor = "current_thread")]
    async fn records_bounded_tier_trace_for_fallbacks() {
        let mut trace = WaterfallTrace::new();
        let result = run_with_fallback(
            "req-trace-disabled",
            Tier2Config { enabled: false },
            None,
            Some(&mut trace),
            || async { Ok::<_, anyhow::Error>("tier2".to_string()) },
            || async { Ok::<_, anyhow::Error>("tier3".to_string()) },
        )
        .await
        .expect("run");
        assert_eq!(result.value, "tier3");
        assert!(
            trace.events.iter().any(|e| {
                e.tier == WaterfallTier::Tier2
                    && e.outcome == WaterfallOutcome::Skipped
                    && e.gate
                        .as_ref()
                        .is_some_and(|g| g.reason == "tier2_disabled" && g.decision == "fallback")
            }),
            "expected tier2 disabled gating event"
        );
        assert!(
            trace.events.iter().any(|e| {
                e.tier == WaterfallTier::Tier3
                    && e.outcome == WaterfallOutcome::Started
                    && e.gate.as_ref().is_some_and(|g| {
                        g.decision == TRACE_DECISION_EXECUTE
                            && g.reason == TRACE_REASON_TIER3_FALLBACK
                            && g.detail.as_deref() == Some(TRACE_REASON_TIER2_DISABLED)
                    })
            }),
            "expected tier3 started fallback gating event"
        );
        assert!(
            trace.events
                .iter()
                .any(|e| e.tier == WaterfallTier::Tier3 && e.outcome == WaterfallOutcome::Succeeded),
            "expected tier3 success event"
        );
        assert!(trace.events.len() <= 48, "trace should be bounded");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn records_tier2_started_and_tier3_skipped_when_tier2_succeeds() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let mut trace = WaterfallTrace::new();
        let tier3_called = std::sync::Arc::new(AtomicBool::new(false));
        let tier3_called_inner = tier3_called.clone();

        let result = run_with_fallback(
            "req-trace-success",
            Tier2Config::enabled(),
            None,
            Some(&mut trace),
            || async { Ok::<_, anyhow::Error>("tier2".to_string()) },
            move || {
                let tier3_called_inner = tier3_called_inner.clone();
                async move {
                    tier3_called_inner.store(true, Ordering::SeqCst);
                    Ok::<_, anyhow::Error>("tier3".to_string())
                }
            },
        )
        .await
        .expect("run");

        assert_eq!(result.value, "tier2");
        assert!(
            !tier3_called.load(Ordering::SeqCst),
            "tier3 should not run when tier2 succeeds"
        );

        assert_eq!(trace.events.len(), 3, "expected fixed trace event count");
        assert_eq!(trace.events[0].seq, 1);
        assert_eq!(trace.events[0].tier, WaterfallTier::Tier2);
        assert_eq!(trace.events[0].outcome, WaterfallOutcome::Started);
        assert!(
            trace.events[0].gate.as_ref().is_some_and(|g| {
                g.decision == TRACE_DECISION_ATTEMPT && g.reason == TRACE_REASON_TIER2_ENABLED
            }),
            "expected tier2 start gating"
        );
        assert_eq!(trace.events[1].seq, 2);
        assert_eq!(trace.events[1].tier, WaterfallTier::Tier2);
        assert_eq!(trace.events[1].outcome, WaterfallOutcome::Succeeded);
        assert_eq!(trace.events[2].seq, 3);
        assert_eq!(trace.events[2].tier, WaterfallTier::Tier3);
        assert_eq!(trace.events[2].outcome, WaterfallOutcome::Skipped);
        assert!(
            trace.events[2].gate.as_ref().is_some_and(|g| {
                g.decision == TRACE_DECISION_SKIP
                    && g.reason == TRACE_REASON_TIER3_SKIPPED
                    && g.detail.as_deref() == Some("tier2_succeeded")
            }),
            "expected tier3 skipped gating event"
        );
    }
}
