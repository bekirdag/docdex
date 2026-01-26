use docdexd::metrics::Metrics;
use std::error::Error;

fn metric_value(body: &str, name: &str) -> Result<f64, Box<dyn Error>> {
    for line in body.lines() {
        if line.starts_with(name) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                return Ok(parts[1].parse::<f64>()?);
            }
        }
    }
    Err(format!("metric {name} not found").into())
}

#[test]
fn metrics_baseline_includes_required_counters() -> Result<(), Box<dyn Error>> {
    let metrics = Metrics::default();
    metrics.record_profile_recall(3, 2, 1, 15);
    metrics.inc_profile_budget_drop(2);
    metrics.inc_profile_evolution_decision();
    metrics.record_profile_evolution_latency(12);
    metrics.inc_hook_check();
    metrics.inc_hook_failure();
    metrics.record_hook_latency(7);
    metrics.inc_project_map_cache_hit();
    metrics.inc_project_map_cache_miss();
    metrics.record_delegate_token_estimate(100);
    metrics.inc_delegate_offloaded();
    metrics.record_delegate_local_tokens(80);
    metrics.record_delegate_primary_tokens(20);
    metrics.record_delegate_token_savings(80);
    metrics.record_delegate_local_cost_micros(1200);
    metrics.record_delegate_primary_cost_micros(300);
    metrics.record_delegate_cost_savings_micros(1500);
    metrics.inc_delegate_local_enforced_failure();

    let body = metrics.render_prometheus();
    let recall = metric_value(&body, "docdex_profile_recall_requests_total")?;
    let evolution = metric_value(&body, "docdex_profile_evolution_decisions_total")?;
    let hook_checks = metric_value(&body, "docdex_hook_checks_total")?;
    let map_hits = metric_value(&body, "docdex_project_map_cache_hits_total")?;
    let budget_drops = metric_value(&body, "docdex_profile_budget_drops_total")?;
    let delegate_tokens = metric_value(&body, "docdex_delegate_token_estimate_total")?;
    let delegate_offloaded = metric_value(&body, "docdex_delegate_offloaded_total")?;
    let delegate_local_tokens = metric_value(&body, "docdex_delegate_local_tokens_total")?;
    let delegate_primary_tokens = metric_value(&body, "docdex_delegate_primary_tokens_total")?;
    let delegate_savings = metric_value(&body, "docdex_delegate_token_savings_total")?;
    let delegate_local_cost = metric_value(&body, "docdex_delegate_local_cost_micros_total")?;
    let delegate_primary_cost =
        metric_value(&body, "docdex_delegate_primary_cost_micros_total")?;
    let delegate_cost = metric_value(&body, "docdex_delegate_cost_savings_micros_total")?;
    let delegate_enforced =
        metric_value(&body, "docdex_delegate_local_enforced_failures_total")?;

    assert!(recall > 0.0, "expected profile recall counter to increment");
    assert!(
        evolution > 0.0,
        "expected profile evolution counter to increment"
    );
    assert!(
        hook_checks > 0.0,
        "expected hook check counter to increment"
    );
    assert!(
        map_hits > 0.0,
        "expected map cache hit counter to increment"
    );
    assert!(
        budget_drops > 0.0,
        "expected profile budget drop counter to increment"
    );
    assert!(
        delegate_tokens > 0.0,
        "expected delegate token estimate counter to increment"
    );
    assert!(
        delegate_offloaded > 0.0,
        "expected delegate offloaded counter to increment"
    );
    assert!(
        delegate_local_tokens > 0.0,
        "expected delegate local tokens counter to increment"
    );
    assert!(
        delegate_primary_tokens > 0.0,
        "expected delegate primary tokens counter to increment"
    );
    assert!(
        delegate_savings > 0.0,
        "expected delegate token savings counter to increment"
    );
    assert!(
        delegate_local_cost > 0.0,
        "expected delegate local cost counter to increment"
    );
    assert!(
        delegate_primary_cost > 0.0,
        "expected delegate primary cost counter to increment"
    );
    assert!(
        delegate_cost > 0.0,
        "expected delegate cost savings counter to increment"
    );
    assert!(
        delegate_enforced > 0.0,
        "expected delegate enforcement failure counter to increment"
    );
    Ok(())
}
