# Rate Limiting + Backoff Config

This document summarizes Docdex rate limiting configuration and the retry/backoff hints emitted when limits are hit.

## HTTP daemon (`docdexd serve`)

**Config keys**

- `--rate-limit-per-min <n>` / `DOCDEX_RATE_LIMIT_PER_MIN`
- `--rate-limit-burst <n>` / `DOCDEX_RATE_LIMIT_BURST`
- `--secure-mode <true|false>` / `DOCDEX_SECURE_MODE`

**Defaults and overrides**

- Secure mode (`--secure-mode=true`, default):
  - `rate-limit-per-min=0` uses the secure default of 60 requests per minute.
  - `rate-limit-burst=0` defaults to the effective per-minute limit.
- Non-secure mode (`--secure-mode=false`):
  - `rate-limit-per-min=0` disables the limiter.
  - `rate-limit-burst=0` defaults to the effective per-minute limit.

**Failure modes (startup validation)**

- If `rate-limit-burst` is set while the effective per-minute limit is `0`, startup fails with `startup_config_invalid` and an actionable hint. This prevents silently disabling rate limiting and backoff signaling.

## MCP server (`docdexd mcp`)

**Config keys**

- `--rate-limit-per-min <n>` / `DOCDEX_MCP_RATE_LIMIT_PER_MIN`
- `--rate-limit-burst <n>` / `DOCDEX_MCP_RATE_LIMIT_BURST`

**Defaults and overrides**

- `rate-limit-per-min=0` disables the limiter.
- `rate-limit-burst=0` defaults to the per-minute limit when enabled.

**Failure modes (startup validation)**

- If `rate-limit-burst` is set while `rate-limit-per-min=0`, startup fails with `startup_config_invalid` and an actionable hint.

## Backoff signaling

- Rate-limited responses include machine-readable retry hints: `retry_after_ms` and (when available) `retry_at`, plus stable fields `limit_key` and `scope`.
- The `backoff_required` code is reserved for retry-later scenarios (see `docs/mcp/errors.md` for the canonical codes).
