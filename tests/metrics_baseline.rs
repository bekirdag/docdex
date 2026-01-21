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

    let body = metrics.render_prometheus();
    let recall = metric_value(&body, "docdex_profile_recall_requests_total")?;
    let evolution = metric_value(&body, "docdex_profile_evolution_decisions_total")?;
    let hook_checks = metric_value(&body, "docdex_hook_checks_total")?;
    let map_hits = metric_value(&body, "docdex_project_map_cache_hits_total")?;
    let budget_drops = metric_value(&body, "docdex_profile_budget_drops_total")?;
    let delegate_tokens = metric_value(&body, "docdex_delegate_token_estimate_total")?;

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
    Ok(())
}
