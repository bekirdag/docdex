#![allow(dead_code)]

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::browser_session::BrowserSessionError;

pub const ERR_TIER2_UNAVAILABLE: &str = "tier2_unavailable";

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
}

impl Tier2Limiter {
    pub fn new(max_concurrent_sessions: usize, queue_timeout: Duration) -> Self {
        let max = max_concurrent_sessions.max(1);
        Self {
            semaphore: Arc::new(Semaphore::new(max)),
            queue_timeout,
        }
    }

    pub async fn acquire(&self) -> Result<OwnedSemaphorePermit, Tier2Unavailable> {
        if self.queue_timeout.is_zero() {
            return self.semaphore.clone().try_acquire_owned().map_err(|_| {
                Tier2Unavailable::new(
                    Tier2UnavailableReason::Overload,
                    "tier 2 browser capacity exhausted",
                )
            });
        }

        tokio::time::timeout(self.queue_timeout, self.semaphore.clone().acquire_owned())
            .await
            .map_err(|_| {
                Tier2Unavailable::new(
                    Tier2UnavailableReason::Overload,
                    "tier 2 browser capacity exhausted",
                )
            })?
            .map_err(|_| {
                Tier2Unavailable::new(
                    Tier2UnavailableReason::Overload,
                    "tier 2 browser capacity exhausted",
                )
            })
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
            request_id = %request_id,
            reason = ?unavailable.reason,
            "tier2_disabled_fallback"
        );
        return Ok(Tier2RunResult {
            value: tier3().await?,
            tier2_unavailable: Some(unavailable),
        });
    }

    let _permit: Option<OwnedSemaphorePermit> = match limiter {
        None => None,
        Some(limiter) => match limiter.acquire().await {
            Ok(permit) => Some(permit),
            Err(unavailable) => {
                let unavailable = unavailable.with_correlation_id(request_id);
                tracing::warn!(
                    target: "docdexd_tier2",
                    request_id = %request_id,
                    reason = ?unavailable.reason,
                    message = %unavailable.message,
                    "tier2_overload_fallback"
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
                request_id = %request_id,
                reason = ?unavailable.reason,
                message = %unavailable.message,
                error = %err,
                "tier2_unavailable_fallback"
            );
            Ok(Tier2RunResult {
                value: tier3().await?,
                tier2_unavailable: Some(unavailable),
            })
        }
    }
}
