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
- Conversation wake-up usefulness ratio:
  `rate(docdex_conversation_wakeup_useful_total[5m]) / clamp_min(rate(docdex_conversation_wakeup_requests_total[5m]), 1)`
- Conversation prompt budget saved (tokens/s):
  `rate(docdex_conversation_prompt_budget_saved_tokens_total[5m])`
- Conversation wake-up token mix by lane:
  `rate(docdex_conversation_wakeup_working_memory_tokens_total[5m])`, `rate(docdex_conversation_wakeup_summary_tokens_total[5m])`, `rate(docdex_conversation_wakeup_knowledge_tokens_total[5m])`, `rate(docdex_conversation_wakeup_snippet_tokens_total[5m])`
- Conversation extraction lag avg (ms):
  `docdex_conversation_extraction_lag_ms_total / clamp_min(docdex_conversation_extraction_lag_count_total, 1)`
- Conversation hook enqueue latency avg (ms):
  `docdex_conversation_hook_enqueue_latency_ms_total / clamp_min(docdex_conversation_hook_enqueue_latency_count_total, 1)`
- Conversation transcript search latency avg (ms):
  `docdex_conversation_transcript_search_latency_ms_total / clamp_min(docdex_conversation_transcript_search_latency_count_total, 1)`
- Conversation archive size (bytes):
  `docdex_conversation_archive_size_bytes`
- Conversation compaction reclaimed bytes (5m):
  `rate(docdex_conversation_compaction_reclaimed_bytes_total[5m])`
- Profile recall latency avg (ms):
  `docdex_profile_recall_latency_ms_total / docdex_profile_recall_latency_count_total`
- Profile evolution latency avg (ms):
  `docdex_profile_evolution_latency_ms_total / docdex_profile_evolution_latency_count_total`
- Project map cache hit ratio:
  `rate(docdex_project_map_cache_hits_total[5m]) / (rate(docdex_project_map_cache_hits_total[5m]) + rate(docdex_project_map_cache_misses_total[5m]))`
- Delegation request rate:
  `rate(docdex_delegate_total[5m])`
- Delegation offloaded rate:
  `rate(docdex_delegate_offloaded_total[5m])`
- Delegation fallback rate:
  `rate(docdex_delegate_fallback_total[5m])`
- Delegation latency avg (ms):
  `docdex_delegate_latency_ms_total / docdex_delegate_latency_count_total`
- Delegation token estimate rate:
  `rate(docdex_delegate_token_estimate_total[5m])`
- Delegation local token rate:
  `rate(docdex_delegate_local_tokens_total[5m])`
- Delegation primary token rate:
  `rate(docdex_delegate_primary_tokens_total[5m])`
- Delegation token savings rate:
  `rate(docdex_delegate_token_savings_total[5m])`
- Delegation local cost (USD/s):
  `rate(docdex_delegate_local_cost_micros_total[5m]) / 1000000`
- Delegation primary cost (USD/s):
  `rate(docdex_delegate_primary_cost_micros_total[5m]) / 1000000`
- Delegation cost savings (USD/s):
  `rate(docdex_delegate_cost_savings_micros_total[5m]) / 1000000`
- Delegation enforcement failures:
  `rate(docdex_delegate_local_enforced_failures_total[5m])`

## Alert thresholds (quality gates)

These mirror the targets in `docs/quality_gates.md`:

- HTTP error rate > 0.5% over 10m.
- HTTP latency p95 > 50ms over 10m (local search queries).
- Conversation wake-up usefulness ratio < 0.2 over 30m after enabling conversation memory.
- Conversation transcript search latency avg > 100ms over 10m on local archives.
- Conversation archive size grows while `docdex_conversation_compaction_reclaimed_bytes_total` stays flat for a full retention window.
- Soak stability: no crashes during 30m soak (validate with `scripts/load_test_http.sh` and `scripts/load_test_mcp.sh`).

## Gate summary endpoint

`GET /v1/gates/status` returns a machine-readable snapshot of the gate status derived from the in-process metrics.
Use it to power a lightweight status panel or CI gate check.
