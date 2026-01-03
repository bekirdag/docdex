# Web Discovery + DDG HTML Audit

Task: `bck-05-us-07-t14`

## Scope
Audit current web discovery implementation and DDG HTML touchpoints (requests, parsing, dedupe,
rate limiting/backoff) across CLI/HTTP/MCP surfaces.

## Sources Reviewed
- `docs/sds/sds.md` (design targets for DDG HTML discovery, spacing, backoff, cache, gating)
- `openapi/mcoda.yaml` (schema for `force_web`)
- `src/main.rs` (CLI surface)
- `src/search/mod.rs` (HTTP routes)
- `src/mcp.rs` (MCP tools)
- `src/ratelimit.rs`, `src/error.rs` (rate limiting/backoff primitives)
- `src/tier2.rs`, `src/browser_session.rs`, `src/chrome_watchdog.rs` (Tier-2/Chrome scaffolding)
- `src/repo_identity.rs` (repo identity/shared resolution)

## Findings
### DDG HTML discovery (requests/parsing/dedupe)
- No DDG/duckduckgo request code exists in `src/` (no URL builder, HTTP client, or HTML parser).
- No result parsing/deduplication logic is present.
- No discovery cache (`cache/web`) implementation exists.

### Rate limiting/backoff
- The generic rate limiter is used for HTTP/MCP request throttling only.
- `ERR_BACKOFF_REQUIRED` exists, but no web-specific backoff logic is wired.
- No DDG spacing/backoff configuration or CLI flags are present.

### Touchpoints by surface
- CLI: `docdexd` subcommands do not include `web-search`, `web-fetch`, or `web-rag`.
- HTTP: `src/search/mod.rs` exposes search/snippet/memory/impact routes only.
- MCP: `src/mcp.rs` tool list excludes web discovery/fetch.
- OpenAPI: `force_web` appears in `/v1/chat/completions` schema but has no code implementation.

### Tier-2 / browser guard scaffolding
- Tier-2 limiter and Chrome watchdog exist but are not used by any web discovery or fetch pipeline.

## Gaps vs SDS
- SDS describes DDG HTML discovery, >=2s spacing, per-domain fetch delay, bounded backoff,
  cache at `cache/web`, and confidence gating via `web_trigger_threshold`, but these are not
  implemented in current code.

## Implications for shared policy
- There are currently no DDG HTML touchpoints to align for shared spacing/backoff or gating
  between MCP and HTTP/CLI.
- Shared web policy must be introduced alongside the web discovery implementation (likely a new
  `[web]` config section + a reusable discovery module).
- Repo identity normalization is centralized in `src/repo_identity.rs`; any future web gating
  should reuse it to keep MCP/HTTP/CLI parity.
