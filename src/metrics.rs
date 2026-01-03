use hdrhistogram::Histogram;
use once_cell::sync::Lazy;
use parking_lot::{Mutex, RwLock};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;

const HTTP_LATENCY_MAX_MS: u64 = 60_000;

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
