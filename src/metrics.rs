use once_cell::sync::Lazy;
use parking_lot::RwLock;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Default)]
pub struct Metrics {
    rate_limit_denies: AtomicU64,
    auth_denies: AtomicU64,
    error_count: AtomicU64,
    mcp_error_counts: RwLock<BTreeMap<String, u64>>,

    browser_sessions_active: AtomicI64,
    browser_session_launch_failures: AtomicU64,
    browser_session_cleanup_failures: AtomicU64,

    tier2_permits_in_use: AtomicI64,
    tier2_permits_acquired_total: AtomicU64,
    tier2_overload_rejections: AtomicU64,

    chrome_watchdog_reap_attempts: AtomicU64,
    chrome_watchdog_reaped: AtomicU64,
    chrome_watchdog_reap_failures: AtomicU64,
}

impl Metrics {
    pub fn inc_rate_limit(&self) {
        self.rate_limit_denies.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_auth_deny(&self) {
        self.auth_denies.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_error(&self) {
        self.error_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_mcp_error(&self, code: &str) {
        let mut counts = self.mcp_error_counts.write();
        let entry = counts.entry(code.to_string()).or_insert(0);
        *entry = entry.saturating_add(1);
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
        self.tier2_overload_rejections.fetch_add(1, Ordering::Relaxed);
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

    pub fn render_prometheus(&self) -> String {
        let mut out = format!(
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
            self.browser_sessions_active.load(Ordering::Relaxed),
            self.browser_session_launch_failures.load(Ordering::Relaxed),
            self.browser_session_cleanup_failures.load(Ordering::Relaxed),
            self.tier2_permits_in_use.load(Ordering::Relaxed),
            self.tier2_permits_acquired_total.load(Ordering::Relaxed),
            self.tier2_overload_rejections.load(Ordering::Relaxed),
            self.chrome_watchdog_reap_attempts.load(Ordering::Relaxed),
            self.chrome_watchdog_reaped.load(Ordering::Relaxed),
            self.chrome_watchdog_reap_failures.load(Ordering::Relaxed),
        );
        out.push_str("# HELP docdex_mcp_errors_total MCP errors by code\n");
        out.push_str("# TYPE docdex_mcp_errors_total counter\n");
        let counts = self.mcp_error_counts.read();
        for (code, count) in counts.iter() {
            out.push_str(&format!(
                "docdex_mcp_errors_total{{code=\"{}\"}} {}\n",
                escape_label_value(code),
                count
            ));
        }
        out
    }
}

fn escape_label_value(value: &str) -> String {
    value.replace('\\', r"\\").replace('"', r#"\""#)
}

fn dec_saturating(gauge: &AtomicI64) {
    let mut current = gauge.load(Ordering::Relaxed);
    loop {
        if current <= 0 {
            return;
        }
        match gauge.compare_exchange(
            current,
            current - 1,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
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
