# Docdex Error Envelope + Code Taxonomy (MCP + HTTP)

Docdex uses the same machine-readable error codes across MCP, HTTP, and CLI. This document defines the canonical envelope and the stable code taxonomy.

## Error envelope

### HTTP daemon

Most HTTP endpoints return:
```json
{ "error": { "code": "<docdex_code>", "message": "<summary>", "details": { } } }
```

- `code` is the stable machine-readable identifier.
- `message` is a short human-readable summary.
- `details` is optional structured data for remediation.

### MCP JSON-RPC

MCP responses wrap Docdex errors inside JSON-RPC:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32602,
    "message": "invalid_params",
    "data": {
      "code": "invalid_params",
      "message": "missing required field: project_root",
      "details": { "field": "project_root" },
      "error": { "code": "invalid_params", "message": "..." }
    }
  }
}
```

Clients should treat `error.data.code` as the primary signal.

### CLI

CLI exits non-zero and prints the HTTP-style envelope to stderr when errors are an `AppError`/`StartupError`.

## Stable error codes

### Core repo/index failures

- `missing_repo` - repo context is required but missing.
- `missing_repo_path` - provided repo path does not exist on disk.
- `unknown_repo` - repo path does not match configured repo root.
- `repo_state_mismatch` - repo state fingerprint mismatch (fails closed).
- `missing_index` - index not present (run `docdexd index`).
- `indexing_in_progress` - index build is running; retry after it completes.
- `stale_index` - index exists but requires reindex after parser drift.
- `backoff_required` - retry later (index writer busy).

### Validation errors

- `invalid_params` - request fails schema/type validation.
- `invalid_argument` - well-formed argument but invalid value.
- `missing_query` - required query missing (HTTP /search).
- `invalid_query` - empty or invalid query text.
- `invalid_path` - unsafe or non-repo path.
- `invalid_range` - invalid line range/window.
- `max_content_exceeded` - response would exceed max payload.

### Dependencies and feature gates

- `missing_dependency` - feature disabled or unavailable (web, symbols, etc).
- `memory_disabled` - memory feature disabled.
- `embedding_timeout` - embedding request timed out.
- `embedding_model_not_found` - embedding model missing.
- `embedding_failed` - embedding call failed for other reasons.

### Startup failures

- `startup_tls_required` - non-loopback bind requires TLS.
- `startup_state_invalid` - state/identity mismatch on startup.

### Generic

- `rate_limited` - request rejected by rate limits.
- `internal_error` - unexpected server failure.

## Typical recovery steps

- `missing_index`: run `docdexd index --repo <path>`.
- `indexing_in_progress`: poll `/v1/index/status` (or retry after `retry_after_ms`).
- `repo_state_mismatch`: reindex with a fresh state dir or run `docdexd repo reassociate`.
- `missing_dependency`: enable feature or set required config.
- `startup_tls_required`: provide `--tls-cert/--tls-key` or use `--insecure` behind a trusted proxy.

## Parity behavior (MCP / HTTP / CLI)

- **MCP**: error lives in JSON-RPC `error.data.code`.
- **HTTP**: `{ "error": { "code", "message", "details" } }`.
- **CLI**: exit `1` with JSON error to stderr when applicable.

## Notes

- Error codes are stable. `details` fields may evolve.
- MCP tools clamp limits instead of erroring when possible.
- HTTP `/search` clamps `limit` to server caps.
