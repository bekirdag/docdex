use hdrhistogram::Histogram;
use once_cell::sync::Lazy;
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;

const HTTP_LATENCY_MAX_MS: u64 = 60_000;

#[derive(Default)]
pub struct DelegationMetrics {
    delegate_requests: AtomicU64,
    delegate_offloaded_total: AtomicU64,
    delegate_fallbacks: AtomicU64,
    delegate_failed_total: AtomicU64,
    delegate_latency_ms_total: AtomicU64,
    delegate_latency_count: AtomicU64,
    delegate_token_estimate_total: AtomicU64,
    delegate_local_tokens_total: AtomicU64,
    delegate_primary_tokens_total: AtomicU64,
    delegate_token_savings_total: AtomicU64,
    delegate_local_cost_micros_total: AtomicU64,
    delegate_primary_cost_micros_total: AtomicU64,
    delegate_cost_savings_micros_total: AtomicU64,
    delegate_local_enforced_failures_total: AtomicU64,
}

impl DelegationMetrics {
    pub fn inc_delegate_request(&self) {
        self.delegate_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_delegate_offloaded(&self) {
        self.delegate_offloaded_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_delegate_fallback(&self) {
        self.delegate_fallbacks.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_delegate_failed(&self) {
        self.delegate_failed_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_delegate_latency(&self, latency_ms: u128) {
        self.delegate_latency_ms_total
            .fetch_add(latency_ms as u64, Ordering::Relaxed);
        self.delegate_latency_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_delegate_token_estimate(&self, tokens: u64) {
        self.delegate_token_estimate_total
            .fetch_add(tokens, Ordering::Relaxed);
    }

    pub fn record_delegate_local_tokens(&self, tokens: u64) {
        self.delegate_local_tokens_total
            .fetch_add(tokens, Ordering::Relaxed);
    }

    pub fn record_delegate_primary_tokens(&self, tokens: u64) {
        self.delegate_primary_tokens_total
            .fetch_add(tokens, Ordering::Relaxed);
    }

    pub fn record_delegate_token_savings(&self, tokens: u64) {
        self.delegate_token_savings_total
            .fetch_add(tokens, Ordering::Relaxed);
    }

    pub fn record_delegate_local_cost_micros(&self, micros: u64) {
        self.delegate_local_cost_micros_total
            .fetch_add(micros, Ordering::Relaxed);
    }

    pub fn record_delegate_primary_cost_micros(&self, micros: u64) {
        self.delegate_primary_cost_micros_total
            .fetch_add(micros, Ordering::Relaxed);
    }

    pub fn record_delegate_cost_savings_micros(&self, micros: u64) {
        self.delegate_cost_savings_micros_total
            .fetch_add(micros, Ordering::Relaxed);
    }

    pub fn inc_delegate_local_enforced_failure(&self) {
        self.delegate_local_enforced_failures_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn delegate_requests_total(&self) -> u64 {
        self.delegate_requests.load(Ordering::Relaxed)
    }

    pub fn delegate_offloaded_total(&self) -> u64 {
        self.delegate_offloaded_total.load(Ordering::Relaxed)
    }

    pub fn delegate_fallbacks_total(&self) -> u64 {
        self.delegate_fallbacks.load(Ordering::Relaxed)
    }

    pub fn delegate_failed_total(&self) -> u64 {
        self.delegate_failed_total.load(Ordering::Relaxed)
    }

    pub fn delegate_token_estimate_total(&self) -> u64 {
        self.delegate_token_estimate_total.load(Ordering::Relaxed)
    }

    pub fn delegate_local_tokens_total(&self) -> u64 {
        self.delegate_local_tokens_total.load(Ordering::Relaxed)
    }

    pub fn delegate_primary_tokens_total(&self) -> u64 {
        self.delegate_primary_tokens_total.load(Ordering::Relaxed)
    }

    pub fn delegate_token_savings_total(&self) -> u64 {
        self.delegate_token_savings_total.load(Ordering::Relaxed)
    }

    pub fn delegate_local_cost_micros_total(&self) -> u64 {
        self.delegate_local_cost_micros_total
            .load(Ordering::Relaxed)
    }

    pub fn delegate_primary_cost_micros_total(&self) -> u64 {
        self.delegate_primary_cost_micros_total
            .load(Ordering::Relaxed)
    }

    pub fn delegate_cost_savings_micros_total(&self) -> u64 {
        self.delegate_cost_savings_micros_total
            .load(Ordering::Relaxed)
    }

    pub fn delegate_local_enforced_failures_total(&self) -> u64 {
        self.delegate_local_enforced_failures_total
            .load(Ordering::Relaxed)
    }

    pub fn snapshot(&self) -> DelegationTelemetrySnapshot {
        DelegationTelemetrySnapshot::from_delegation_metrics(self)
    }

    pub fn apply_snapshot(&self, snapshot: DelegationTelemetrySnapshot) {
        self.delegate_requests
            .store(snapshot.delegate_requests_total, Ordering::Relaxed);
        self.delegate_offloaded_total
            .store(snapshot.delegate_offloaded_total, Ordering::Relaxed);
        self.delegate_fallbacks
            .store(snapshot.delegate_fallbacks_total, Ordering::Relaxed);
        self.delegate_failed_total
            .store(snapshot.delegate_failed_total, Ordering::Relaxed);
        self.delegate_token_estimate_total
            .store(snapshot.delegate_token_estimate_total, Ordering::Relaxed);
        self.delegate_local_tokens_total
            .store(snapshot.delegate_local_tokens_total, Ordering::Relaxed);
        self.delegate_primary_tokens_total
            .store(snapshot.delegate_primary_tokens_total, Ordering::Relaxed);
        self.delegate_token_savings_total
            .store(snapshot.delegate_token_savings_total, Ordering::Relaxed);
        self.delegate_local_cost_micros_total
            .store(snapshot.delegate_local_cost_micros_total, Ordering::Relaxed);
        self.delegate_primary_cost_micros_total.store(
            snapshot.delegate_primary_cost_micros_total,
            Ordering::Relaxed,
        );
        self.delegate_cost_savings_micros_total.store(
            snapshot.delegate_cost_savings_micros_total,
            Ordering::Relaxed,
        );
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DelegationTelemetrySnapshot {
    pub delegate_requests_total: u64,
    pub delegate_offloaded_total: u64,
    pub delegate_fallbacks_total: u64,
    pub delegate_failed_total: u64,
    pub delegate_token_estimate_total: u64,
    pub delegate_local_tokens_total: u64,
    pub delegate_primary_tokens_total: u64,
    pub delegate_token_savings_total: u64,
    pub delegate_local_cost_micros_total: u64,
    pub delegate_primary_cost_micros_total: u64,
    pub delegate_cost_savings_micros_total: u64,
}

impl DelegationTelemetrySnapshot {
    pub fn from_delegation_metrics(metrics: &DelegationMetrics) -> Self {
        Self {
            delegate_requests_total: metrics.delegate_requests_total(),
            delegate_offloaded_total: metrics.delegate_offloaded_total(),
            delegate_fallbacks_total: metrics.delegate_fallbacks_total(),
            delegate_failed_total: metrics.delegate_failed_total(),
            delegate_token_estimate_total: metrics.delegate_token_estimate_total(),
            delegate_local_tokens_total: metrics.delegate_local_tokens_total(),
            delegate_primary_tokens_total: metrics.delegate_primary_tokens_total(),
            delegate_token_savings_total: metrics.delegate_token_savings_total(),
            delegate_local_cost_micros_total: metrics.delegate_local_cost_micros_total(),
            delegate_primary_cost_micros_total: metrics.delegate_primary_cost_micros_total(),
            delegate_cost_savings_micros_total: metrics.delegate_cost_savings_micros_total(),
        }
    }

    pub fn from_metrics(metrics: &Metrics) -> Self {
        Self {
            delegate_requests_total: metrics.delegate_requests_total(),
            delegate_offloaded_total: metrics.delegate_offloaded_total(),
            delegate_fallbacks_total: metrics.delegate_fallbacks_total(),
            delegate_failed_total: metrics.delegate_failed_total(),
            delegate_token_estimate_total: metrics.delegate_token_estimate_total(),
            delegate_local_tokens_total: metrics.delegate_local_tokens_total(),
            delegate_primary_tokens_total: metrics.delegate_primary_tokens_total(),
            delegate_token_savings_total: metrics.delegate_token_savings_total(),
            delegate_local_cost_micros_total: metrics.delegate_local_cost_micros_total(),
            delegate_primary_cost_micros_total: metrics.delegate_primary_cost_micros_total(),
            delegate_cost_savings_micros_total: metrics.delegate_cost_savings_micros_total(),
        }
    }

    pub fn merge(&mut self, other: Self) {
        self.delegate_requests_total = self
            .delegate_requests_total
            .saturating_add(other.delegate_requests_total);
        self.delegate_offloaded_total = self
            .delegate_offloaded_total
            .saturating_add(other.delegate_offloaded_total);
        self.delegate_fallbacks_total = self
            .delegate_fallbacks_total
            .saturating_add(other.delegate_fallbacks_total);
        self.delegate_failed_total = self
            .delegate_failed_total
            .saturating_add(other.delegate_failed_total);
        self.delegate_token_estimate_total = self
            .delegate_token_estimate_total
            .saturating_add(other.delegate_token_estimate_total);
        self.delegate_local_tokens_total = self
            .delegate_local_tokens_total
            .saturating_add(other.delegate_local_tokens_total);
        self.delegate_primary_tokens_total = self
            .delegate_primary_tokens_total
            .saturating_add(other.delegate_primary_tokens_total);
        self.delegate_token_savings_total = self
            .delegate_token_savings_total
            .saturating_add(other.delegate_token_savings_total);
        self.delegate_local_cost_micros_total = self
            .delegate_local_cost_micros_total
            .saturating_add(other.delegate_local_cost_micros_total);
        self.delegate_primary_cost_micros_total = self
            .delegate_primary_cost_micros_total
            .saturating_add(other.delegate_primary_cost_micros_total);
        self.delegate_cost_savings_micros_total = self
            .delegate_cost_savings_micros_total
            .saturating_add(other.delegate_cost_savings_micros_total);
    }

    pub fn is_zero(&self) -> bool {
        self == &Self::default()
    }

    pub fn avoided_primary_cost_micros_total(&self) -> u64 {
        self.delegate_local_cost_micros_total
            .saturating_add(self.delegate_cost_savings_micros_total)
    }

    pub fn effective_avoided_primary_usd_per_million_tokens(&self) -> Option<f64> {
        effective_cost_per_million(
            self.avoided_primary_cost_micros_total(),
            self.delegate_token_savings_total,
        )
    }
}

fn effective_cost_per_million(cost_micros: u64, tokens: u64) -> Option<f64> {
    if tokens == 0 {
        None
    } else {
        Some(cost_micros as f64 / tokens as f64)
    }
}

pub struct Metrics {
    rate_limit_denies: AtomicU64,
    auth_denies: AtomicU64,
    error_count: AtomicU64,

    browser_sessions_active: AtomicI64,
    browser_session_launch_failures: AtomicU64,
    browser_session_cleanup_failures: AtomicU64,

    tier2_permits_in_use: AtomicI64,
    tier2_permits_acquired_total: AtomicU64,
    tier2_overload_rejections: AtomicU64,

    waterfall_tier2_attempts: AtomicU64,
    waterfall_tier2_skipped: AtomicU64,
    waterfall_tier2_served: AtomicU64,
    waterfall_tier2_unavailable: AtomicU64,

    waterfall_memory_context_requests: AtomicU64,
    waterfall_memory_context_candidates: AtomicU64,
    waterfall_memory_context_kept: AtomicU64,
    waterfall_memory_context_dropped: AtomicU64,
    memory_repo_mismatch_total: AtomicU64,
    profile_recall_requests: AtomicU64,
    profile_recall_candidates: AtomicU64,
    profile_recall_kept: AtomicU64,
    profile_recall_dropped: AtomicU64,
    profile_recall_latency_ms_total: AtomicU64,
    profile_recall_latency_count: AtomicU64,
    profile_budget_drops: AtomicU64,

    profile_evolution_decisions: AtomicU64,
    profile_evolution_retries: AtomicU64,
    profile_evolution_invalid: AtomicU64,
    profile_evolution_latency_ms_total: AtomicU64,
    profile_evolution_latency_count: AtomicU64,

    hook_checks: AtomicU64,
    hook_failures: AtomicU64,
    hook_latency_ms_total: AtomicU64,
    hook_latency_count: AtomicU64,

    delegate_requests: AtomicU64,
    delegate_offloaded_total: AtomicU64,
    delegate_fallbacks: AtomicU64,
    delegate_failed_total: AtomicU64,
    delegate_latency_ms_total: AtomicU64,
    delegate_latency_count: AtomicU64,
    delegate_token_estimate_total: AtomicU64,
    delegate_local_tokens_total: AtomicU64,
    delegate_primary_tokens_total: AtomicU64,
    delegate_token_savings_total: AtomicU64,
    delegate_local_cost_micros_total: AtomicU64,
    delegate_primary_cost_micros_total: AtomicU64,
    delegate_cost_savings_micros_total: AtomicU64,
    delegate_local_enforced_failures_total: AtomicU64,

    project_map_cache_hits: AtomicU64,
    project_map_cache_misses: AtomicU64,

    chrome_watchdog_reap_attempts: AtomicU64,
    chrome_watchdog_reaped: AtomicU64,
    chrome_watchdog_reap_failures: AtomicU64,

    http_requests_total: AtomicU64,
    http_error_responses_total: AtomicU64,
    http_request_latency_ms_total: AtomicU64,
    http_request_latency_count: AtomicU64,
    http_latency_hist: Mutex<Histogram<u64>>,
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            rate_limit_denies: AtomicU64::new(0),
            auth_denies: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
            browser_sessions_active: AtomicI64::new(0),
            browser_session_launch_failures: AtomicU64::new(0),
            browser_session_cleanup_failures: AtomicU64::new(0),
            tier2_permits_in_use: AtomicI64::new(0),
            tier2_permits_acquired_total: AtomicU64::new(0),
            tier2_overload_rejections: AtomicU64::new(0),
            waterfall_tier2_attempts: AtomicU64::new(0),
            waterfall_tier2_skipped: AtomicU64::new(0),
            waterfall_tier2_served: AtomicU64::new(0),
            waterfall_tier2_unavailable: AtomicU64::new(0),
            waterfall_memory_context_requests: AtomicU64::new(0),
            waterfall_memory_context_candidates: AtomicU64::new(0),
            waterfall_memory_context_kept: AtomicU64::new(0),
            waterfall_memory_context_dropped: AtomicU64::new(0),
            memory_repo_mismatch_total: AtomicU64::new(0),
            profile_recall_requests: AtomicU64::new(0),
            profile_recall_candidates: AtomicU64::new(0),
            profile_recall_kept: AtomicU64::new(0),
            profile_recall_dropped: AtomicU64::new(0),
            profile_recall_latency_ms_total: AtomicU64::new(0),
            profile_recall_latency_count: AtomicU64::new(0),
            profile_budget_drops: AtomicU64::new(0),
            profile_evolution_decisions: AtomicU64::new(0),
            profile_evolution_retries: AtomicU64::new(0),
            profile_evolution_invalid: AtomicU64::new(0),
            profile_evolution_latency_ms_total: AtomicU64::new(0),
            profile_evolution_latency_count: AtomicU64::new(0),
            hook_checks: AtomicU64::new(0),
            hook_failures: AtomicU64::new(0),
            hook_latency_ms_total: AtomicU64::new(0),
            hook_latency_count: AtomicU64::new(0),
            delegate_requests: AtomicU64::new(0),
            delegate_offloaded_total: AtomicU64::new(0),
            delegate_fallbacks: AtomicU64::new(0),
            delegate_failed_total: AtomicU64::new(0),
            delegate_latency_ms_total: AtomicU64::new(0),
            delegate_latency_count: AtomicU64::new(0),
            delegate_token_estimate_total: AtomicU64::new(0),
            delegate_local_tokens_total: AtomicU64::new(0),
            delegate_primary_tokens_total: AtomicU64::new(0),
            delegate_token_savings_total: AtomicU64::new(0),
            delegate_local_cost_micros_total: AtomicU64::new(0),
            delegate_primary_cost_micros_total: AtomicU64::new(0),
            delegate_cost_savings_micros_total: AtomicU64::new(0),
            delegate_local_enforced_failures_total: AtomicU64::new(0),
            project_map_cache_hits: AtomicU64::new(0),
            project_map_cache_misses: AtomicU64::new(0),
            chrome_watchdog_reap_attempts: AtomicU64::new(0),
            chrome_watchdog_reaped: AtomicU64::new(0),
            chrome_watchdog_reap_failures: AtomicU64::new(0),
            http_requests_total: AtomicU64::new(0),
            http_error_responses_total: AtomicU64::new(0),
            http_request_latency_ms_total: AtomicU64::new(0),
            http_request_latency_count: AtomicU64::new(0),
            http_latency_hist: Mutex::new(
                Histogram::new_with_bounds(1, HTTP_LATENCY_MAX_MS, 3)
                    .expect("http latency histogram"),
            ),
        }
    }
}

impl Metrics {
    pub fn inc_rate_limit(&self) {
        self.rate_limit_denies.fetch_add(1, Ordering::Relaxed);
    }

    pub fn rate_limit_denies(&self) -> u64 {
        self.rate_limit_denies.load(Ordering::Relaxed)
    }

    pub fn inc_auth_deny(&self) {
        self.auth_denies.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_error(&self) {
        self.error_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_browser_session_active(&self) {
        self.browser_sessions_active.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_browser_session_active(&self) {
        dec_saturating(&self.browser_sessions_active);
    }

    pub fn inc_browser_session_launch_failure(&self) {
        self.browser_session_launch_failures
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_browser_session_cleanup_failure(&self) {
        self.browser_session_cleanup_failures
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_tier2_permits_in_use(&self) {
        self.tier2_permits_in_use.fetch_add(1, Ordering::Relaxed);
        self.tier2_permits_acquired_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_tier2_permits_in_use(&self) {
        dec_saturating(&self.tier2_permits_in_use);
    }

    pub fn inc_tier2_overload_rejection(&self) {
        self.tier2_overload_rejections
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_waterfall_tier2_attempt(&self) {
        self.waterfall_tier2_attempts
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_waterfall_tier2_skipped(&self) {
        self.waterfall_tier2_skipped.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_waterfall_tier2_served(&self) {
        self.waterfall_tier2_served.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_waterfall_tier2_unavailable(&self) {
        self.waterfall_tier2_unavailable
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_waterfall_memory_context(&self, candidates: usize, kept: usize, dropped: usize) {
        self.waterfall_memory_context_requests
            .fetch_add(1, Ordering::Relaxed);
        self.waterfall_memory_context_candidates
            .fetch_add(candidates as u64, Ordering::Relaxed);
        self.waterfall_memory_context_kept
            .fetch_add(kept as u64, Ordering::Relaxed);
        self.waterfall_memory_context_dropped
            .fetch_add(dropped as u64, Ordering::Relaxed);
    }

    pub fn inc_memory_repo_mismatch(&self, dropped: u64) {
        self.memory_repo_mismatch_total
            .fetch_add(dropped, Ordering::Relaxed);
    }

    pub fn record_profile_recall(
        &self,
        candidates: usize,
        kept: usize,
        dropped: usize,
        latency_ms: u128,
    ) {
        self.profile_recall_requests.fetch_add(1, Ordering::Relaxed);
        self.profile_recall_candidates
            .fetch_add(candidates as u64, Ordering::Relaxed);
        self.profile_recall_kept
            .fetch_add(kept as u64, Ordering::Relaxed);
        self.profile_recall_dropped
            .fetch_add(dropped as u64, Ordering::Relaxed);
        self.profile_recall_latency_ms_total
            .fetch_add(latency_ms as u64, Ordering::Relaxed);
        self.profile_recall_latency_count
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_profile_budget_drop(&self, count: usize) {
        if count == 0 {
            return;
        }
        self.profile_budget_drops
            .fetch_add(count as u64, Ordering::Relaxed);
    }

    pub fn inc_profile_evolution_decision(&self) {
        self.profile_evolution_decisions
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_profile_evolution_retry(&self) {
        self.profile_evolution_retries
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_profile_evolution_invalid(&self) {
        self.profile_evolution_invalid
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_profile_evolution_latency(&self, latency_ms: u128) {
        self.profile_evolution_latency_ms_total
            .fetch_add(latency_ms as u64, Ordering::Relaxed);
        self.profile_evolution_latency_count
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_hook_check(&self) {
        self.hook_checks.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_hook_failure(&self) {
        self.hook_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_hook_latency(&self, latency_ms: u128) {
        self.hook_latency_ms_total
            .fetch_add(latency_ms as u64, Ordering::Relaxed);
        self.hook_latency_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_delegate_request(&self) {
        self.delegate_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_delegate_offloaded(&self) {
        self.delegate_offloaded_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_delegate_fallback(&self) {
        self.delegate_fallbacks.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_delegate_failed(&self) {
        self.delegate_failed_total.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_delegate_latency(&self, latency_ms: u128) {
        self.delegate_latency_ms_total
            .fetch_add(latency_ms as u64, Ordering::Relaxed);
        self.delegate_latency_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_delegate_token_estimate(&self, tokens: u64) {
        self.delegate_token_estimate_total
            .fetch_add(tokens, Ordering::Relaxed);
    }

    pub fn record_delegate_local_tokens(&self, tokens: u64) {
        self.delegate_local_tokens_total
            .fetch_add(tokens, Ordering::Relaxed);
    }

    pub fn record_delegate_primary_tokens(&self, tokens: u64) {
        self.delegate_primary_tokens_total
            .fetch_add(tokens, Ordering::Relaxed);
    }

    pub fn record_delegate_token_savings(&self, tokens: u64) {
        self.delegate_token_savings_total
            .fetch_add(tokens, Ordering::Relaxed);
    }

    pub fn record_delegate_local_cost_micros(&self, micros: u64) {
        self.delegate_local_cost_micros_total
            .fetch_add(micros, Ordering::Relaxed);
    }

    pub fn record_delegate_primary_cost_micros(&self, micros: u64) {
        self.delegate_primary_cost_micros_total
            .fetch_add(micros, Ordering::Relaxed);
    }

    pub fn record_delegate_cost_savings_micros(&self, micros: u64) {
        self.delegate_cost_savings_micros_total
            .fetch_add(micros, Ordering::Relaxed);
    }

    pub fn inc_delegate_local_enforced_failure(&self) {
        self.delegate_local_enforced_failures_total
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn delegate_requests_total(&self) -> u64 {
        self.delegate_requests.load(Ordering::Relaxed)
    }

    pub fn delegate_offloaded_total(&self) -> u64 {
        self.delegate_offloaded_total.load(Ordering::Relaxed)
    }

    pub fn delegate_fallbacks_total(&self) -> u64 {
        self.delegate_fallbacks.load(Ordering::Relaxed)
    }

    pub fn delegate_failed_total(&self) -> u64 {
        self.delegate_failed_total.load(Ordering::Relaxed)
    }

    pub fn delegate_token_estimate_total(&self) -> u64 {
        self.delegate_token_estimate_total.load(Ordering::Relaxed)
    }

    pub fn delegate_local_tokens_total(&self) -> u64 {
        self.delegate_local_tokens_total.load(Ordering::Relaxed)
    }

    pub fn delegate_primary_tokens_total(&self) -> u64 {
        self.delegate_primary_tokens_total.load(Ordering::Relaxed)
    }

    pub fn delegate_token_savings_total(&self) -> u64 {
        self.delegate_token_savings_total.load(Ordering::Relaxed)
    }

    pub fn delegate_local_cost_micros_total(&self) -> u64 {
        self.delegate_local_cost_micros_total
            .load(Ordering::Relaxed)
    }

    pub fn delegate_primary_cost_micros_total(&self) -> u64 {
        self.delegate_primary_cost_micros_total
            .load(Ordering::Relaxed)
    }

    pub fn delegate_cost_savings_micros_total(&self) -> u64 {
        self.delegate_cost_savings_micros_total
            .load(Ordering::Relaxed)
    }

    pub fn delegate_local_enforced_failures_total(&self) -> u64 {
        self.delegate_local_enforced_failures_total
            .load(Ordering::Relaxed)
    }

    pub fn delegation_snapshot(&self) -> DelegationTelemetrySnapshot {
        DelegationTelemetrySnapshot::from_metrics(self)
    }

    pub fn apply_delegation_snapshot(&self, snapshot: DelegationTelemetrySnapshot) {
        self.delegate_requests
            .store(snapshot.delegate_requests_total, Ordering::Relaxed);
        self.delegate_offloaded_total
            .store(snapshot.delegate_offloaded_total, Ordering::Relaxed);
        self.delegate_fallbacks
            .store(snapshot.delegate_fallbacks_total, Ordering::Relaxed);
        self.delegate_failed_total
            .store(snapshot.delegate_failed_total, Ordering::Relaxed);
        self.delegate_token_estimate_total
            .store(snapshot.delegate_token_estimate_total, Ordering::Relaxed);
        self.delegate_local_tokens_total
            .store(snapshot.delegate_local_tokens_total, Ordering::Relaxed);
        self.delegate_primary_tokens_total
            .store(snapshot.delegate_primary_tokens_total, Ordering::Relaxed);
        self.delegate_token_savings_total
            .store(snapshot.delegate_token_savings_total, Ordering::Relaxed);
        self.delegate_local_cost_micros_total
            .store(snapshot.delegate_local_cost_micros_total, Ordering::Relaxed);
        self.delegate_primary_cost_micros_total.store(
            snapshot.delegate_primary_cost_micros_total,
            Ordering::Relaxed,
        );
        self.delegate_cost_savings_micros_total.store(
            snapshot.delegate_cost_savings_micros_total,
            Ordering::Relaxed,
        );
    }

    pub fn inc_project_map_cache_hit(&self) {
        self.project_map_cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_project_map_cache_miss(&self) {
        self.project_map_cache_misses
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_chrome_watchdog_reap_attempt(&self) {
        self.chrome_watchdog_reap_attempts
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_chrome_watchdog_reaped(&self) {
        self.chrome_watchdog_reaped.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_chrome_watchdog_reap_failure(&self) {
        self.chrome_watchdog_reap_failures
            .fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_http_request(&self, latency_ms: u128, status: u16) {
        self.http_requests_total.fetch_add(1, Ordering::Relaxed);
        if status >= 400 {
            self.http_error_responses_total
                .fetch_add(1, Ordering::Relaxed);
        }
        let latency_total = latency_ms.min(u128::from(u64::MAX)) as u64;
        self.http_request_latency_ms_total
            .fetch_add(latency_total, Ordering::Relaxed);
        self.http_request_latency_count
            .fetch_add(1, Ordering::Relaxed);
        let latency_bucket = latency_total.max(1).min(HTTP_LATENCY_MAX_MS);
        let mut hist = self.http_latency_hist.lock();
        let _ = hist.record(latency_bucket);
    }

    pub fn http_requests_total(&self) -> u64 {
        self.http_requests_total.load(Ordering::Relaxed)
    }

    pub fn http_error_responses_total(&self) -> u64 {
        self.http_error_responses_total.load(Ordering::Relaxed)
    }

    pub fn http_latency_avg_ms(&self) -> Option<f64> {
        let count = self.http_request_latency_count.load(Ordering::Relaxed);
        if count == 0 {
            return None;
        }
        let total = self.http_request_latency_ms_total.load(Ordering::Relaxed);
        Some(total as f64 / count as f64)
    }

    pub fn http_latency_p95_ms(&self) -> Option<u64> {
        let hist = self.http_latency_hist.lock();
        if hist.len() == 0 {
            return None;
        }
        Some(hist.value_at_quantile(0.95))
    }

    pub fn render_prometheus(&self) -> String {
        let http_latency_p95 = self.http_latency_p95_ms().unwrap_or(0);
        let http_latency_avg = self.http_latency_avg_ms().unwrap_or(0.0);
        format!(
            concat!(
                "# HELP docdex_rate_limit_denies_total Rate limit denials\n",
                "# TYPE docdex_rate_limit_denies_total counter\n",
                "docdex_rate_limit_denies_total {}\n",
                "# HELP docdex_auth_denies_total Auth denials\n",
                "# TYPE docdex_auth_denies_total counter\n",
                "docdex_auth_denies_total {}\n",
                "# HELP docdex_errors_total Handler errors\n",
                "# TYPE docdex_errors_total counter\n",
                "docdex_errors_total {}\n",
                "# HELP docdex_http_requests_total HTTP request count\n",
                "# TYPE docdex_http_requests_total counter\n",
                "docdex_http_requests_total {}\n",
                "# HELP docdex_http_error_responses_total HTTP error responses (status >= 400)\n",
                "# TYPE docdex_http_error_responses_total counter\n",
                "docdex_http_error_responses_total {}\n",
                "# HELP docdex_http_request_latency_ms_total HTTP request latency sum in ms\n",
                "# TYPE docdex_http_request_latency_ms_total counter\n",
                "docdex_http_request_latency_ms_total {}\n",
                "# HELP docdex_http_request_latency_count_total HTTP request latency samples\n",
                "# TYPE docdex_http_request_latency_count_total counter\n",
                "docdex_http_request_latency_count_total {}\n",
                "# HELP docdex_http_request_latency_p95_ms HTTP request latency p95 in ms\n",
                "# TYPE docdex_http_request_latency_p95_ms gauge\n",
                "docdex_http_request_latency_p95_ms {}\n",
                "# HELP docdex_http_request_latency_avg_ms HTTP request latency avg in ms\n",
                "# TYPE docdex_http_request_latency_avg_ms gauge\n",
                "docdex_http_request_latency_avg_ms {}\n",
                "# HELP docdex_browser_sessions_active Active browser sessions\n",
                "# TYPE docdex_browser_sessions_active gauge\n",
                "docdex_browser_sessions_active {}\n",
                "# HELP docdex_browser_session_launch_failures_total Browser session launch failures\n",
                "# TYPE docdex_browser_session_launch_failures_total counter\n",
                "docdex_browser_session_launch_failures_total {}\n",
                "# HELP docdex_browser_session_cleanup_failures_total Browser session cleanup failures\n",
                "# TYPE docdex_browser_session_cleanup_failures_total counter\n",
                "docdex_browser_session_cleanup_failures_total {}\n",
                "# HELP docdex_tier2_permits_in_use Tier2 browser permits currently held\n",
                "# TYPE docdex_tier2_permits_in_use gauge\n",
                "docdex_tier2_permits_in_use {}\n",
                "# HELP docdex_tier2_permits_acquired_total Tier2 browser permits acquired\n",
                "# TYPE docdex_tier2_permits_acquired_total counter\n",
                "docdex_tier2_permits_acquired_total {}\n",
                "# HELP docdex_tier2_overload_rejections_total Tier2 browser overload rejections\n",
                "# TYPE docdex_tier2_overload_rejections_total counter\n",
                "docdex_tier2_overload_rejections_total {}\n",
                "# HELP docdex_waterfall_tier2_attempts_total Tier2 gate attempts\n",
                "# TYPE docdex_waterfall_tier2_attempts_total counter\n",
                "docdex_waterfall_tier2_attempts_total {}\n",
                "# HELP docdex_waterfall_tier2_skipped_total Tier2 gate skips\n",
                "# TYPE docdex_waterfall_tier2_skipped_total counter\n",
                "docdex_waterfall_tier2_skipped_total {}\n",
                "# HELP docdex_waterfall_tier2_served_total Tier2 browser responses\n",
                "# TYPE docdex_waterfall_tier2_served_total counter\n",
                "docdex_waterfall_tier2_served_total {}\n",
                "# HELP docdex_waterfall_tier2_unavailable_total Tier2 fallbacks due to unavailability\n",
                "# TYPE docdex_waterfall_tier2_unavailable_total counter\n",
                "docdex_waterfall_tier2_unavailable_total {}\n",
                "# HELP docdex_waterfall_memory_context_requests_total Memory context assemblies\n",
                "# TYPE docdex_waterfall_memory_context_requests_total counter\n",
                "docdex_waterfall_memory_context_requests_total {}\n",
                "# HELP docdex_waterfall_memory_context_candidates_total Memory recall candidates considered\n",
                "# TYPE docdex_waterfall_memory_context_candidates_total counter\n",
                "docdex_waterfall_memory_context_candidates_total {}\n",
                "# HELP docdex_waterfall_memory_context_kept_total Memory context items kept\n",
                "# TYPE docdex_waterfall_memory_context_kept_total counter\n",
                "docdex_waterfall_memory_context_kept_total {}\n",
                "# HELP docdex_waterfall_memory_context_dropped_total Memory context items dropped\n",
                "# TYPE docdex_waterfall_memory_context_dropped_total counter\n",
                "docdex_waterfall_memory_context_dropped_total {}\n",
                "# HELP docdex_memory_repo_mismatch_total Memory items dropped due to repo mismatch\n",
                "# TYPE docdex_memory_repo_mismatch_total counter\n",
                "docdex_memory_repo_mismatch_total {}\n",
                "# HELP docdex_profile_recall_requests_total Profile recall requests\n",
                "# TYPE docdex_profile_recall_requests_total counter\n",
                "docdex_profile_recall_requests_total {}\n",
                "# HELP docdex_profile_recall_candidates_total Profile recall candidates\n",
                "# TYPE docdex_profile_recall_candidates_total counter\n",
                "docdex_profile_recall_candidates_total {}\n",
                "# HELP docdex_profile_recall_kept_total Profile recall items kept\n",
                "# TYPE docdex_profile_recall_kept_total counter\n",
                "docdex_profile_recall_kept_total {}\n",
                "# HELP docdex_profile_recall_dropped_total Profile recall items dropped\n",
                "# TYPE docdex_profile_recall_dropped_total counter\n",
                "docdex_profile_recall_dropped_total {}\n",
                "# HELP docdex_profile_recall_latency_ms_total Profile recall latency sum in ms\n",
                "# TYPE docdex_profile_recall_latency_ms_total counter\n",
                "docdex_profile_recall_latency_ms_total {}\n",
                "# HELP docdex_profile_recall_latency_count_total Profile recall latency samples\n",
                "# TYPE docdex_profile_recall_latency_count_total counter\n",
                "docdex_profile_recall_latency_count_total {}\n",
                "# HELP docdex_profile_budget_drops_total Profile context drops due to budget\n",
                "# TYPE docdex_profile_budget_drops_total counter\n",
                "docdex_profile_budget_drops_total {}\n",
                "# HELP docdex_profile_evolution_decisions_total Evolution decisions processed\n",
                "# TYPE docdex_profile_evolution_decisions_total counter\n",
                "docdex_profile_evolution_decisions_total {}\n",
                "# HELP docdex_profile_evolution_retries_total Evolution decision retries\n",
                "# TYPE docdex_profile_evolution_retries_total counter\n",
                "docdex_profile_evolution_retries_total {}\n",
                "# HELP docdex_profile_evolution_invalid_total Invalid evolution decisions\n",
                "# TYPE docdex_profile_evolution_invalid_total counter\n",
                "docdex_profile_evolution_invalid_total {}\n",
                "# HELP docdex_profile_evolution_latency_ms_total Evolution latency sum in ms\n",
                "# TYPE docdex_profile_evolution_latency_ms_total counter\n",
                "docdex_profile_evolution_latency_ms_total {}\n",
                "# HELP docdex_profile_evolution_latency_count_total Evolution latency samples\n",
                "# TYPE docdex_profile_evolution_latency_count_total counter\n",
                "docdex_profile_evolution_latency_count_total {}\n",
                "# HELP docdex_hook_checks_total Hook validation requests\n",
                "# TYPE docdex_hook_checks_total counter\n",
                "docdex_hook_checks_total {}\n",
                "# HELP docdex_hook_failures_total Hook validation failures\n",
                "# TYPE docdex_hook_failures_total counter\n",
                "docdex_hook_failures_total {}\n",
                "# HELP docdex_hook_latency_ms_total Hook validation latency sum in ms\n",
                "# TYPE docdex_hook_latency_ms_total counter\n",
                "docdex_hook_latency_ms_total {}\n",
                "# HELP docdex_hook_latency_count_total Hook validation latency samples\n",
                "# TYPE docdex_hook_latency_count_total counter\n",
                "docdex_hook_latency_count_total {}\n",
                "# HELP docdex_delegate_total Delegation requests\n",
                "# TYPE docdex_delegate_total counter\n",
                "docdex_delegate_total {}\n",
                "# HELP docdex_delegate_offloaded_total Delegation tasks offloaded to local\n",
                "# TYPE docdex_delegate_offloaded_total counter\n",
                "docdex_delegate_offloaded_total {}\n",
                "# HELP docdex_delegate_fallback_total Delegation fallbacks\n",
                "# TYPE docdex_delegate_fallback_total counter\n",
                "docdex_delegate_fallback_total {}\n",
                "# HELP docdex_delegate_failed_total Terminal delegation failures\n",
                "# TYPE docdex_delegate_failed_total counter\n",
                "docdex_delegate_failed_total {}\n",
                "# HELP docdex_delegate_latency_ms_total Delegation latency sum in ms\n",
                "# TYPE docdex_delegate_latency_ms_total counter\n",
                "docdex_delegate_latency_ms_total {}\n",
                "# HELP docdex_delegate_latency_count_total Delegation latency samples\n",
                "# TYPE docdex_delegate_latency_count_total counter\n",
                "docdex_delegate_latency_count_total {}\n",
                "# HELP docdex_delegate_token_estimate_total Delegation token estimate\n",
                "# TYPE docdex_delegate_token_estimate_total counter\n",
                "docdex_delegate_token_estimate_total {}\n",
                "# HELP docdex_delegate_local_tokens_total Delegation local token usage\n",
                "# TYPE docdex_delegate_local_tokens_total counter\n",
                "docdex_delegate_local_tokens_total {}\n",
                "# HELP docdex_delegate_primary_tokens_total Delegation primary token usage\n",
                "# TYPE docdex_delegate_primary_tokens_total counter\n",
                "docdex_delegate_primary_tokens_total {}\n",
                "# HELP docdex_delegate_token_savings_total Delegation token savings\n",
                "# TYPE docdex_delegate_token_savings_total counter\n",
                "docdex_delegate_token_savings_total {}\n",
                "# HELP docdex_delegate_local_cost_micros_total Delegation local cost (micros)\n",
                "# TYPE docdex_delegate_local_cost_micros_total counter\n",
                "docdex_delegate_local_cost_micros_total {}\n",
                "# HELP docdex_delegate_primary_cost_micros_total Delegation primary cost (micros)\n",
                "# TYPE docdex_delegate_primary_cost_micros_total counter\n",
                "docdex_delegate_primary_cost_micros_total {}\n",
                "# HELP docdex_delegate_cost_savings_micros_total Delegation cost savings (micros)\n",
                "# TYPE docdex_delegate_cost_savings_micros_total counter\n",
                "docdex_delegate_cost_savings_micros_total {}\n",
                "# HELP docdex_delegate_local_enforced_failures_total Delegation enforcement failures\n",
                "# TYPE docdex_delegate_local_enforced_failures_total counter\n",
                "docdex_delegate_local_enforced_failures_total {}\n",
                "# HELP docdex_project_map_cache_hits_total Project map cache hits\n",
                "# TYPE docdex_project_map_cache_hits_total counter\n",
                "docdex_project_map_cache_hits_total {}\n",
                "# HELP docdex_project_map_cache_misses_total Project map cache misses\n",
                "# TYPE docdex_project_map_cache_misses_total counter\n",
                "docdex_project_map_cache_misses_total {}\n",
            "# HELP docdex_chrome_watchdog_reap_attempts_total Chrome watchdog reap attempts\n",
            "# TYPE docdex_chrome_watchdog_reap_attempts_total counter\n",
            "docdex_chrome_watchdog_reap_attempts_total {}\n",
                "# HELP docdex_chrome_watchdog_reaped_total Chrome watchdog successful reaps\n",
                "# TYPE docdex_chrome_watchdog_reaped_total counter\n",
                "docdex_chrome_watchdog_reaped_total {}\n",
                "# HELP docdex_chrome_watchdog_reap_failures_total Chrome watchdog reap failures\n",
                "# TYPE docdex_chrome_watchdog_reap_failures_total counter\n",
                "docdex_chrome_watchdog_reap_failures_total {}\n",
            ),
            self.rate_limit_denies.load(Ordering::Relaxed),
            self.auth_denies.load(Ordering::Relaxed),
            self.error_count.load(Ordering::Relaxed),
            self.http_requests_total.load(Ordering::Relaxed),
            self.http_error_responses_total.load(Ordering::Relaxed),
            self.http_request_latency_ms_total
                .load(Ordering::Relaxed),
            self.http_request_latency_count
                .load(Ordering::Relaxed),
            http_latency_p95,
            http_latency_avg,
            self.browser_sessions_active.load(Ordering::Relaxed),
            self.browser_session_launch_failures.load(Ordering::Relaxed),
            self.browser_session_cleanup_failures.load(Ordering::Relaxed),
            self.tier2_permits_in_use.load(Ordering::Relaxed),
            self.tier2_permits_acquired_total.load(Ordering::Relaxed),
            self.tier2_overload_rejections.load(Ordering::Relaxed),
            self.waterfall_tier2_attempts.load(Ordering::Relaxed),
            self.waterfall_tier2_skipped.load(Ordering::Relaxed),
            self.waterfall_tier2_served.load(Ordering::Relaxed),
            self.waterfall_tier2_unavailable.load(Ordering::Relaxed),
            self.waterfall_memory_context_requests.load(Ordering::Relaxed),
            self.waterfall_memory_context_candidates.load(Ordering::Relaxed),
            self.waterfall_memory_context_kept.load(Ordering::Relaxed),
            self.waterfall_memory_context_dropped.load(Ordering::Relaxed),
            self.memory_repo_mismatch_total.load(Ordering::Relaxed),
            self.profile_recall_requests.load(Ordering::Relaxed),
            self.profile_recall_candidates.load(Ordering::Relaxed),
            self.profile_recall_kept.load(Ordering::Relaxed),
            self.profile_recall_dropped.load(Ordering::Relaxed),
            self.profile_recall_latency_ms_total
                .load(Ordering::Relaxed),
            self.profile_recall_latency_count.load(Ordering::Relaxed),
            self.profile_budget_drops.load(Ordering::Relaxed),
            self.profile_evolution_decisions.load(Ordering::Relaxed),
            self.profile_evolution_retries.load(Ordering::Relaxed),
            self.profile_evolution_invalid.load(Ordering::Relaxed),
            self.profile_evolution_latency_ms_total
                .load(Ordering::Relaxed),
            self.profile_evolution_latency_count
                .load(Ordering::Relaxed),
            self.hook_checks.load(Ordering::Relaxed),
            self.hook_failures.load(Ordering::Relaxed),
            self.hook_latency_ms_total.load(Ordering::Relaxed),
            self.hook_latency_count.load(Ordering::Relaxed),
            self.delegate_requests.load(Ordering::Relaxed),
            self.delegate_offloaded_total.load(Ordering::Relaxed),
            self.delegate_fallbacks.load(Ordering::Relaxed),
            self.delegate_failed_total.load(Ordering::Relaxed),
            self.delegate_latency_ms_total.load(Ordering::Relaxed),
            self.delegate_latency_count.load(Ordering::Relaxed),
            self.delegate_token_estimate_total
                .load(Ordering::Relaxed),
            self.delegate_local_tokens_total
                .load(Ordering::Relaxed),
            self.delegate_primary_tokens_total
                .load(Ordering::Relaxed),
            self.delegate_token_savings_total
                .load(Ordering::Relaxed),
            self.delegate_local_cost_micros_total
                .load(Ordering::Relaxed),
            self.delegate_primary_cost_micros_total
                .load(Ordering::Relaxed),
            self.delegate_cost_savings_micros_total
                .load(Ordering::Relaxed),
            self.delegate_local_enforced_failures_total
                .load(Ordering::Relaxed),
            self.project_map_cache_hits.load(Ordering::Relaxed),
            self.project_map_cache_misses.load(Ordering::Relaxed),
            self.chrome_watchdog_reap_attempts.load(Ordering::Relaxed),
            self.chrome_watchdog_reaped.load(Ordering::Relaxed),
            self.chrome_watchdog_reap_failures.load(Ordering::Relaxed),
        )
    }
}

fn dec_saturating(gauge: &AtomicI64) {
    let mut current = gauge.load(Ordering::Relaxed);
    loop {
        if current <= 0 {
            return;
        }
        match gauge.compare_exchange(current, current - 1, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return,
            Err(next) => current = next,
        }
    }
}

static GLOBAL_METRICS: Lazy<RwLock<Arc<Metrics>>> =
    Lazy::new(|| RwLock::new(Arc::new(Metrics::default())));

pub fn global() -> Arc<Metrics> {
    GLOBAL_METRICS.read().clone()
}

pub fn set_global(metrics: Arc<Metrics>) {
    *GLOBAL_METRICS.write() = metrics;
}

#[cfg(test)]
mod tests;
