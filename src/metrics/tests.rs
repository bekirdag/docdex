use super::Metrics;

#[test]
fn render_prometheus_includes_counters() {
    let metrics = Metrics::default();
    metrics.inc_rate_limit();
    metrics.inc_error();
    metrics.inc_hook_check();
    metrics.inc_hook_failure();
    metrics.record_hook_latency(5);

    let payload = metrics.render_prometheus();
    assert!(payload.contains("docdex_rate_limit_denies_total 1"));
    assert!(payload.contains("docdex_errors_total 1"));
    assert!(payload.contains("docdex_hook_checks_total 1"));
    assert!(payload.contains("docdex_hook_failures_total 1"));
    assert!(payload.contains("docdex_hook_latency_count_total 1"));
}

#[test]
fn profile_budget_drop_is_saturating() {
    let metrics = Metrics::default();
    metrics.inc_profile_budget_drop(0);
    metrics.inc_profile_budget_drop(2);
    let payload = metrics.render_prometheus();
    assert!(payload.contains("docdex_profile_budget_drops_total 2"));
}
