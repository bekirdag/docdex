use super::Metrics;

#[test]
fn render_prometheus_includes_counters() {
    let metrics = Metrics::default();
    metrics.inc_rate_limit();
    metrics.inc_error();
    metrics.inc_hook_check();
    metrics.inc_hook_failure();
    metrics.record_hook_latency(5);
    metrics.record_http_request(12, 500);
    metrics.inc_delegate_request();
    metrics.inc_delegate_offloaded();
    metrics.record_delegate_latency(8);
    metrics.record_delegate_token_estimate(42);
    metrics.record_delegate_local_tokens(30);
    metrics.record_delegate_primary_tokens(12);
    metrics.record_delegate_token_savings(12);
    metrics.record_delegate_local_cost_micros(500);
    metrics.record_delegate_primary_cost_micros(750);
    metrics.record_delegate_cost_savings_micros(2500);
    metrics.inc_delegate_local_enforced_failure();

    let payload = metrics.render_prometheus();
    assert!(payload.contains("docdex_rate_limit_denies_total 1"));
    assert!(payload.contains("docdex_errors_total 1"));
    assert!(payload.contains("docdex_hook_checks_total 1"));
    assert!(payload.contains("docdex_hook_failures_total 1"));
    assert!(payload.contains("docdex_hook_latency_count_total 1"));
    assert!(payload.contains("docdex_delegate_total 1"));
    assert!(payload.contains("docdex_delegate_offloaded_total 1"));
    assert!(payload.contains("docdex_delegate_latency_count_total 1"));
    assert!(payload.contains("docdex_delegate_token_estimate_total 42"));
    assert!(payload.contains("docdex_delegate_local_tokens_total 30"));
    assert!(payload.contains("docdex_delegate_primary_tokens_total 12"));
    assert!(payload.contains("docdex_delegate_token_savings_total 12"));
    assert!(payload.contains("docdex_delegate_local_cost_micros_total 500"));
    assert!(payload.contains("docdex_delegate_primary_cost_micros_total 750"));
    assert!(payload.contains("docdex_delegate_cost_savings_micros_total 2500"));
    assert!(payload.contains("docdex_delegate_local_enforced_failures_total 1"));
    assert!(payload.contains("docdex_http_requests_total 1"));
    assert!(payload.contains("docdex_http_error_responses_total 1"));
}

#[test]
fn profile_budget_drop_is_saturating() {
    let metrics = Metrics::default();
    metrics.inc_profile_budget_drop(0);
    metrics.inc_profile_budget_drop(2);
    let payload = metrics.render_prometheus();
    assert!(payload.contains("docdex_profile_budget_drops_total 2"));
}
