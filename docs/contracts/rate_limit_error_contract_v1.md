# Rate-Limit Error Contract (v1)

Scope: Docdex rate-limit signaling for MCP and HTTP surfaces. This contract defines the
stable, machine-readable fields clients use for retry/backoff behavior.

## MCP JSON-RPC error.data (rate_limited)

When tool calls are rate-limited, the MCP server returns JSON-RPC error code `-32029`
with `error.data` containing the following fields:

- `code` (string): always `rate_limited`.
- `retry_after_ms` (integer): milliseconds until retry is allowed.
- `retry_at` (string, optional): RFC3339 timestamp for the earliest retry time.
- `limit_key` (string): stable bucket identifier (truncated to 128 bytes).
- `scope` (string): rate-limit scope label (truncated to 128 bytes).

Example:

```json
{
  "code": "rate_limited",
  "retry_after_ms": 1200,
  "retry_at": "2025-01-01T12:00:01Z",
  "limit_key": "mcp_tools",
  "scope": "global"
}
```

## HTTP error body (rate_limited)

HTTP rate limits return status `429` with a JSON error body:

```json
{
  "error": {
    "code": "rate_limited",
    "message": "rate limited",
    "retry_after_ms": 1200,
    "retry_at": "2025-01-01T12:00:01Z",
    "limit_key": "http_ip",
    "scope": "ip"
  }
}
```

Field notes:

- `message` is a short, stable summary (truncated to 256 bytes).
- `retry_after_ms` is always present and numeric.
- `retry_at` is optional and omitted when unknown.

## Payload bounds

Rate-limit payloads are capped to keep responses predictable:

- MCP JSON-RPC rate-limit error payload: max 2048 bytes.
- HTTP rate-limit error payload: max 1024 bytes.
- `limit_key` and `scope` are truncated to 128 bytes to enforce caps.

## Versioning

Any schema or policy change must introduce a new contract document
`docs/contracts/rate_limit_error_contract_v2.md` and update references.
