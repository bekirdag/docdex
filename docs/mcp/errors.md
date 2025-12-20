# MCP Error Envelope + Code Taxonomy (Docdex)

Docdex’s MCP server (`docdexd mcp`) reports failures as JSON-RPC errors. The **machine-readable** error code is carried in `error.data.code` (and duplicated under `error.data.error.code`) so clients can reliably branch on it.

This document defines the **canonical MCP error envelope**, a **stable code taxonomy**, and a **parity mapping** to Docdex’s HTTP daemon responses and CLI error output.

## Canonical MCP envelope

### JSON-RPC wrapper

On failure, the MCP server returns a JSON-RPC error response:

- `error.code` (number): JSON-RPC error code.
  - `-32700` parse failure (`parse_error`)
  - `-32600` invalid request (`invalid_request`)
  - `-32601` unknown method/tool (`method_not_found`)
  - `-32602` tool failures and argument validation (`invalid_params` *and* domain failures like `missing_index`)
  - `-32000` internal server error (`internal_error`) when the MCP server fails outside tool handling
- `error.message` (string): a short, stable category message.
- `error.data` (object): Docdex error envelope (below).

### `error.data` (Docdex envelope)

`error.data` is an object with:

- `code` (string, required): machine-readable Docdex code (see taxonomy below).
- `message` (string, required): short summary message (often mirrors `error.message`).
- `reason` (string, optional): a more specific reason (typically an underlying error string).
- `tool` (string, optional): tool name (for `tools/call` failures), e.g. `docdex_search`.
- `details` (object, optional): structured context (limits, fields, expected/got, etc). For repo move/rename/mismatch errors, `details` may include `normalizedPath`, `attemptedFingerprint`, `knownCanonicalPath`, and `recoverySteps` (often including `docdexd repo inspect` for diagnostics and `docdexd repo reassociate` for moved repos under shared state dirs).
- `error` (object, required): the canonical envelope, containing the same fields as above (`code/message/reason/tool/details`).

Compatibility guidance for clients:

- Treat `error.data.code` as the primary stable signal.
- Ignore unknown fields; new `details` keys may be added without breaking changes.
- `error.data.error` is redundant; it exists for convenience where clients expect a nested `error` object.

## Code taxonomy (machine-readable)

### MCP-only protocol codes

These codes appear in `error.data.code` for JSON-RPC/MCP protocol failures (not tool/domain failures):

- `parse_error`
- `invalid_request`
- `method_not_found`

### Required, transport-stable codes

These codes are the **required** set for repo/index/dependency failures and are intended to be stable across MCP/HTTP/CLI for the same underlying failure:

- `missing_repo`: required repo context is absent (primarily relevant for multi-repo surfaces).
- `missing_repo_path`: the provided repo path does not exist on disk (often after a move/rename).
- `unknown_repo`: provided repo context does not match the server’s configured repo root.
- `repo_state_mismatch`: per-repo state cannot be safely associated (fingerprint/meta/registry mismatch); Docdex must fast-fail to prevent cross-repo mixing.
- `missing_index`: on-disk index is not present (e.g. `docdexd query` before indexing).
- `index_schema_mismatch`: on-disk index schema is incompatible with the running Docdex version; reindex required.
- `stale_index`: index exists but is known to be stale (reserved for future use).
- `missing_dependency`: a required optional feature/dependency is disabled (e.g. symbols extraction disabled).
- `rate_limited`: request rejected due to rate limiting (reserved for future use in MCP).
- `backoff_required`: retry later (e.g. indexing requested but index writer is locked/unavailable).
- `internal_error`: unexpected server failure.

### Parameter/argument validation codes

Use these codes for invalid inputs:

- `invalid_params`: request/arguments fail schema/JSON parsing (serde validation).
- `invalid_argument`: arguments are well-formed but semantically invalid (e.g. empty strings, negative values after coercion).
- `missing_query`: HTTP `/search` only — required query string is missing.
- `invalid_query`: invalid query text (empty/whitespace-only, or query parser rejects it).
- `invalid_path`: invalid or unsafe path (absolute path, parent traversal, outside repo, etc).
- `invalid_range`: invalid line window (`start_line`/`end_line` out of bounds).
- `max_content_exceeded`: response content would exceed server limits (e.g. `docdex_open` file too large).

### Feature/domain codes (currently emitted)

Docdex also uses feature-specific codes in some tools:

- `memory_disabled`
- `embedding_timeout`
- `embedding_model_not_found`
- `embedding_failed`

## Repo moved/renamed (deterministic behavior + recovery)

Docdex intentionally **fails closed** on repo identity changes to prevent cross-repo state mixing (no silent cross-association).

You may see these repo-related codes during moves/renames:

- `missing_repo_path`: the path passed as `project_root` (or otherwise used to resolve repo context) does not exist on disk.
  - Recovery: pass the repo’s current path, or omit `project_root` to use the MCP server default; restart the MCP server with `docdexd mcp --repo <repo>` if it is pointed at the wrong path.
- `unknown_repo`: `project_root` exists but does not match the MCP server’s configured `--repo` (fast-fail guardrail).
  - Recovery: restart the MCP server with `docdexd mcp --repo <repo>` matching the repo you intend to use, or omit `project_root`.
- `repo_state_mismatch`: the server cannot safely associate an existing on-disk state directory with the current repo without an explicit user action (common when using an absolute shared `--state-dir` across repos and the repo path changes).
  - Recovery: either reindex into a fresh `--state-dir`, or explicitly re-associate the moved repo to the existing shared state with `docdexd repo reassociate --repo <new_path> --state-dir <shared_state_dir> --old-path <knownCanonicalPath>` (or `--fingerprint <attemptedFingerprint>`).

Diagnostics:

- For these errors, `error.data.details` may include `normalizedPath`, `attemptedFingerprint`, `knownCanonicalPath`, and a `recoverySteps` array intended to be directly actionable in UX.

## Parity mapping (HTTP / CLI / MCP)

Docdex presents the same underlying failures in three different wrappers:

- **HTTP daemon**: JSON error body (where implemented) is `{ "error": { "code": "<docdex_code>", "message": "<string>" } }`.
- **CLI**: non-zero exit (currently always `1`) and a JSON error line to `stderr` when the error is a `StartupError`/`AppError` (same `{error:{code,message}}` shape as HTTP).
- **MCP**: JSON-RPC error with Docdex code in `error.data.code`.

### Mapping table (common failures)

| Underlying failure | Docdex code (`error.data.code`) | MCP JSON-RPC `error.code` | HTTP daemon behavior | CLI behavior |
| --- | --- | --- | --- | --- |
| Missing repo context | `missing_repo` | `-32602` | N/A for per-repo daemon (repo is configured at startup) | N/A for per-repo CLI (repo is required via `--repo`) |
| Repo path missing on disk | `missing_repo_path` | `-32602` | Daemon startup fails (stderr JSON `{error:{code:"missing_repo_path",...}}`) | Exit `1`, `stderr` JSON `{error:{code:"missing_repo_path",...}}` |
| Repo mismatch (`project_root` does not match server repo) | `unknown_repo` | `-32602` | N/A (daemon is started per-repo) | N/A (CLI always has `--repo`; mismatch is not represented) |
| Repo state mismatch (unsafe to associate state) | `repo_state_mismatch` | `-32602` | Daemon startup fails (stderr JSON `{error:{code:"repo_state_mismatch",...}}`) | Exit `1`, `stderr` JSON `{error:{code:"repo_state_mismatch",...}}` |
| Index missing (query/open without prior `index`) | `missing_index` | `-32602` | N/A in `serve` (daemon creates/opens index dir on startup) | Exit `1`, `stderr` JSON `{error:{code:"missing_index",...}}` |
| Index schema mismatch | `index_schema_mismatch` | `-32602` | Daemon startup fails (stderr JSON `{error:{code:"index_schema_mismatch",...}}`) | Exit `1`, `stderr` JSON `{error:{code:"index_schema_mismatch",...}}` |
| Index stale | `stale_index` | `-32602` | Not currently emitted by the per-repo daemon | Not currently emitted by the per-repo CLI |
| Index writer unavailable (concurrent indexing lock) | `backoff_required` | `-32602` | N/A in `serve` (daemon opens a writer at startup) | Usually surfaced as a non-JSON error string (not an `AppError`) |
| Rate limited | `rate_limited` | `-32602` | `429` (security middleware returns status-only; no JSON envelope) | Not currently emitted as an `AppError` (usually a plain error string if encountered) |
| Optional dependency disabled (e.g. symbols) | `missing_dependency` | `-32602` | N/A (no HTTP endpoint for MCP symbols) | N/A (no CLI symbols command) |
| Invalid MCP arguments (wrong JSON types / missing required fields) | `invalid_params` | `-32602` | N/A | N/A |
| Invalid path for `docdex_open` | `invalid_path` | `-32602` | N/A | N/A |
| Invalid line window for `docdex_open` | `invalid_range` | `-32602` | N/A | N/A |
| File too large for `docdex_open` | `max_content_exceeded` | `-32602` | N/A | N/A |
| Internal MCP server failure | `internal_error` | `-32000` | `500` (varies by endpoint) | Exit `1` (varies; may be JSON for `StartupError`/`AppError`) |

Notes:

- HTTP `/search` enforces `limit` by clamping to the daemon’s configured max and does not error on over-limit; MCP `docdex_search` similarly clamps `limit` to the MCP server’s `--max-results`.
- MCP `docdex_files` clamps `limit` to `<= 1000` and `offset` to `<= 50000`.
- MCP `docdex_open` enforces a hard maximum of 512 KiB for returned content; exceeding it returns `max_content_exceeded` with `details.max_bytes` and `details.actual_bytes`.
