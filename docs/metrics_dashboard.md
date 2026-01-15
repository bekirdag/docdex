# Metrics Dashboard + Alerts

This page provides a lightweight observability setup for Docdex using the `/metrics` endpoint.
It aligns with `docs/quality_gates.md` and highlights the key latency/error/soak gates.

## Quick Prometheus scrape config

```yaml
scrape_configs:
  - job_name: docdex
    static_configs:
      - targets: ["127.0.0.1:28491"]
```

## Example dashboard panels (PromQL)

- HTTP error rate (5m):
  `rate(docdex_http_error_responses_total[5m]) / rate(docdex_http_requests_total[5m])`
- HTTP latency p95 (ms):
  `docdex_http_request_latency_p95_ms`
- HTTP latency avg (ms):
  `docdex_http_request_latency_avg_ms`
- Hook checks total:
  `rate(docdex_hook_checks_total[5m])`
- Profile recall latency avg (ms):
  `docdex_profile_recall_latency_ms_total / docdex_profile_recall_latency_count_total`
- Profile evolution latency avg (ms):
  `docdex_profile_evolution_latency_ms_total / docdex_profile_evolution_latency_count_total`
- Project map cache hit ratio:
  `rate(docdex_project_map_cache_hits_total[5m]) / (rate(docdex_project_map_cache_hits_total[5m]) + rate(docdex_project_map_cache_misses_total[5m]))`

## Alert thresholds (quality gates)

These mirror the targets in `docs/quality_gates.md`:

- HTTP error rate > 0.5% over 10m.
- HTTP latency p95 > 50ms over 10m (local search queries).
- Soak stability: no crashes during 30m soak (validate with `scripts/load_test_http.sh` and `scripts/load_test_mcp.sh`).

## Gate summary endpoint

`GET /v1/gates/status` returns a machine-readable snapshot of the gate status derived from the in-process metrics.
Use it to power a lightweight status panel or CI gate check.
