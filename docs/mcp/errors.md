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
<<<<<<< HEAD
  - `-32029` rate limiting for MCP tool calls (`rate_limited`)
=======
  - `-32029` rate limited (`rate_limited`) when MCP tool throttling denies a request
>>>>>>> mcoda/task/bck-05-us-06-t26
  - `-32000` internal server error (`internal_error`) when the MCP server fails outside tool handling
  - `-32029` rate limiting for MCP tool calls (`rate_limited`)
- `error.message` (string): a short, stable category message.
- `error.data` (object): Docdex error envelope (below) for most errors. Rate-limited responses return a small retry-hint object instead (see "Rate-limit data shape").

### `error.data` (Docdex envelope)

`error.data` is an object with:

- `code` (string, required): machine-readable Docdex code (see taxonomy below).
- `message` (string, required): short summary message (often mirrors `error.message`).
- `reason` (string, optional): a more specific reason (typically an underlying error string).
- `tool` (string, optional): tool name (for `tools/call` failures), e.g. `docdex_search`.
<<<<<<< HEAD
- `details` (object, optional): structured context (limits, fields, expected/got, etc). For repo move/rename/mismatch errors, `details` may include `normalizedPath`, `attemptedFingerprint`, `knownCanonicalPath`, and `recoverySteps` (often including `docdexd repo inspect` for diagnostics and `docdexd repo reassociate` for moved repos under shared state dirs). For index-state errors, `details` may include `stateDir`, `repoRoot`, `staleReason`, `indexLastUpdatedEpochMs`, `repoLastModifiedEpochMs`, `hint`, and `recoverySteps`.
- `error` (object, required): the canonical envelope, containing the same fields as above (`code/message/reason/tool/details`).
=======
- `details` (object, optional): structured context (limits, fields, expected/got, etc). For repo move/rename/mismatch errors, `details` may include `normalizedPath`, `attemptedFingerprint`, `knownCanonicalPath`, and `recoverySteps` (often including `docdexd repo inspect` for diagnostics and `docdexd repo reassociate` for moved repos under shared state dirs).
- `request_id` (string, required): per-request correlation id (random UUID).
- `session_id` (string, required): MCP server session id (random UUID, stable for the MCP process lifetime).
- `tracing` (object, required): tracing indicator for correlation; currently `{ "enabled": <bool> }`.
- `error` (object, required): the canonical envelope, containing the same fields as above (`code/message/reason/tool/details/request_id/session_id/tracing`).

Privacy note: correlation ids are randomly generated and do not encode user, repo, or host data.
>>>>>>> mcoda/task/bck-05-us-06-t30

Compatibility guidance for clients:

- Treat `error.data.code` as the primary stable signal.
- Ignore unknown fields; new `details` keys may be added without breaking changes.
- `error.data.error` is redundant; it exists for convenience where clients expect a nested `error` object.

<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
Note: `rate_limited` uses a specialized `error.data` shape for retry hints (see
`docs/contracts/rate_limit_error_contract_v1.md`) and does not include the full nested envelope.
=======
### Rate-limit data shape (MCP)

When a tool call is rate-limited, the MCP server uses a custom JSON-RPC error code and a small, stable `error.data` object for retry hints.

- `error.code`: `-32029` (custom server error: rate-limited).
- `error.data` object:
  - `code`: string literal `"rate_limited"`.
  - `retry_after_ms`: integer, milliseconds to wait (>= 0).
  - `retry_at`: optional RFC3339 timestamp string.
  - `limit_key`: string identifying the limiter bucket (e.g., `"web_research"`, `"browser_concurrency"`).
  - `scope`: string identifying scope (e.g., `"global"`, `"repo"`).
>>>>>>> mcoda/task/bck-05-us-09-t32
=======
### Rate-limit/backoff retry hints (compact MCP data)

For `rate_limited` and `backoff_required`, MCP returns a compact `error.data` object so clients can
read retry hints without digging into nested envelopes. This object **does not** include the
`error.data.error` nested envelope. The JSON-RPC `error.message` remains the human-readable summary.

Stable fields in `error.data` for rate-limit/backoff:

- `code` (string): `rate_limited` or `backoff_required`
- `retry_after_ms` (integer): milliseconds to wait before retry
- `retry_at` (string, optional): RFC3339 timestamp hint
- `limit_key` (string): limiter key or resource name
- `scope` (string): limiter scope (e.g., `global`, `index`, `tier2`)
>>>>>>> mcoda/task/bck-05-us-09-t22
=======
### Retry hints (rate limiting/backoff)

Rate limiting/backoff responses include stable retry hint fields:

- **MCP `rate_limited`**: `error.data` is a compact retry-hint object: `{ "code": "rate_limited", "retry_after_ms": <int>, "retry_at"?: <RFC3339>, "limit_key": <string>, "scope": <string> }` (no nested `error` envelope).
- **MCP/CLI `backoff_required`**: retry hints appear under `error.data.details` (MCP) or `error.details` (CLI) using the same field names (`retry_after_ms`, `retry_at`, `limit_key`, `scope`).
- **HTTP 429**: JSON error body uses `{ "error": { "code": "rate_limited", "message": "...", "retry_after_ms": <int>, "retry_at"?: <RFC3339>, "limit_key": <string>, "scope": <string> } }` and includes a `Retry-After` header.
>>>>>>> mcoda/task/bck-05-us-09-t13
=======
Correlation metadata:

- MCP tool results include `request_id`, `session_id`, and `tracing` at the top level of the JSON payload returned inside `result.content[0].text`.
- `tracing.enabled` reflects whether the MCP server has tracing enabled at WARN level; when false, request/session ids are still generated but may not appear in logs.
>>>>>>> mcoda/task/bck-05-us-06-t30

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
<<<<<<< HEAD
<<<<<<< HEAD
- `stale_index`: index exists but is known to be stale (emitted when repo files are newer than the index; refresh with `docdex_index`).
=======
- `stale_index`: index exists but is stale (repo contents modified after last index, or legacy index missing index-state metadata).
>>>>>>> mcoda/task/bck-05-us-08-t01
=======
- `index_schema_mismatch`: on-disk index schema is incompatible with the running Docdex version; reindex required.
- `stale_index`: index exists but is known to be stale (reserved for future use).
<<<<<<< HEAD
>>>>>>> mcoda/task/bck-05-us-07-t09
=======
- `index_migration_required`: index schema is older than the minimum compatible version and must be migrated/rebuilt.
- `index_schema_unsupported`: index schema or manifest is newer/unsupported (upgrade Docdex or rebuild).
>>>>>>> mcoda/task/bck-05-us-07-t11
- `missing_dependency`: a required optional feature/dependency is disabled (e.g. symbols extraction disabled).
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
- `rate_limited`: request rejected due to rate limiting (see `docs/contracts/rate_limit_error_contract_v1.md`).
=======
- `rate_limited`: request rejected due to rate limiting; MCP uses JSON-RPC code `-32029` with retry hints in `error.data`.
>>>>>>> mcoda/task/bck-05-us-09-t32
=======
- `rate_limited`: request rejected due to rate limiting.
>>>>>>> mcoda/task/bck-05-us-09-t22
=======
- `rate_limited`: request rejected due to rate limiting. `error.data.details` includes `retry_after_ms`, optional `retry_at`, `limit_key`, and `scope`.
>>>>>>> mcoda/task/bck-05-us-06-t47
=======
- `rate_limited`: request rejected due to rate limiting.
>>>>>>> mcoda/task/bck-05-us-06-t29
- `backoff_required`: retry later (e.g. indexing requested but index writer is locked/unavailable).
<<<<<<< HEAD
=======
- `rate_limited`: request rejected due to rate limiting; includes stable retry hints.
- `backoff_required`: retry later (e.g. indexing requested but index writer is locked/unavailable); includes retry hints.
>>>>>>> mcoda/task/bck-05-us-09-t37
=======
- `rate_limited`: request rejected due to rate limiting; MCP emits a retry-hint object in `error.data`.
- `backoff_required`: retry later (e.g. indexing requested but index writer is locked/unavailable); retry hints live in `details`.
>>>>>>> mcoda/task/bck-05-us-09-t13
=======
- `repo_capacity_exceeded`: max-open-repos cap reached and no idle repo is available to evict (details include `maxOpenRepos`, `openRepos`, `busyRepos`, and recovery guidance).
>>>>>>> mcoda/task/bck-05-us-07-t05
- `internal_error`: unexpected server failure.

### Parameter/argument validation codes

Use these codes for invalid inputs:

- `invalid_params`: reserved for JSON-RPC layer failures (malformed `params`); MCP tool validation prefers `invalid_argument` with field issues.
- `invalid_argument`: arguments are well-formed but semantically invalid (e.g. empty strings, negative values after coercion).
- `missing_query`: required query string is missing (`/search` and MCP `docdex_search`).
- `invalid_query`: invalid query text (empty/whitespace-only, or query parser rejects it).
- `invalid_path`: invalid or unsafe path (absolute path, parent traversal, outside repo, etc).
- `invalid_range`: invalid line window (`start_line`/`end_line` out of bounds).
<<<<<<< HEAD
- `max_content_exceeded`: reserved for cases where content cannot be safely truncated (not currently emitted; MCP tools clamp/truncate content to MaxSizePolicy).
=======
- `unsupported_version`: requested schema version is outside the supported range for the tool response.
- `max_content_exceeded`: response content would exceed server limits (e.g. `docdex_open` file too large).
>>>>>>> mcoda/task/bck-05-us-10-t21

### Validation details (field-level issues)

For `invalid_argument`, `missing_query`, `invalid_query`, `invalid_path`, `invalid_range`, and `max_content_exceeded`, MCP errors include `error.data.details` with structured issues:

- `issues`: array of `{ field, code, message }`.
- `fieldErrors`: object keyed by field name with `{ code, message }` entries (grouped view).

This mirrors the HTTP invalid-argument contract used by `/v1/graph/impact`.

### Feature/domain codes (currently emitted)

Docdex also uses feature-specific codes in some tools:

- `memory_disabled`
- `embedding_timeout`
- `embedding_model_not_found`
- `embedding_failed`
- `tier2_unavailable`

## Rate-limit/backoff retry hints (stable contract)

When rate limiting or backoff is triggered, MCP uses the canonical error envelope and includes
retry hints at the top level of `error.data`:

- `retry_after_ms` (integer, required): milliseconds to wait before retrying.
- `retry_at` (string, optional): RFC3339 timestamp when retry is allowed.
- `limit_key` (string, required): stable identifier for the constrained resource.
- `scope` (string, required): scope of the limit (for example `global`, `repo`, or `ip`).

`error.data.code` is `rate_limited` or `backoff_required`. `error.data.message` is a short,
bounded string. The same retry fields are mirrored in `error.data.error.details`.

Payload bounds for retryable errors:

- `error.message` is capped at 256 bytes; `error.reason` at 768 bytes.
- `limit_key` and `scope` are capped at 64 bytes each.
- MCP rate-limit/backoff payloads are kept under 2 KiB; HTTP rate-limit payloads under 1 KiB.

## Index-state failures (missing vs stale)

Index-state errors are emitted when a tool requires an on-disk index to operate. They are always reported with the standard Docdex error envelope described above, and the **machine-readable** code is still `error.data.code` (mirrored in `error.data.error.code`).

### Distinguishing the codes

- `missing_index`: the on-disk index is absent (e.g., a repo has not been indexed yet, or the state dir was removed).
- `stale_index`: the on-disk index exists but is known to be out-of-date; Docdex fails closed to avoid serving stale/cross-repo results. (This code is reserved for future use and may not be emitted in all surfaces yet.)

### Expected envelope fields

When an index-dependent tool fails, the MCP error wrapper and Docdex envelope include:

- `error.code`: `-32602`
- `error.message`: short category string (e.g., "missing index")
- `error.data.code`: `missing_index` or `stale_index`
- `error.data.message`: short summary (often matches `error.message`)
- `error.data.reason` (optional): underlying detail string (e.g., "index not found at ...; run `docdexd index --repo <repo>` first")
- `error.data.tool` (optional): tool name (e.g., `docdex_search`, `docdex_files`, `docdex_stats`)
- `error.data.details` (optional): structured context; may be absent for index-state failures
- `error.data.error`: redundant nested envelope with the same fields as above

### Remediation (manual, no repo/code mutation)

Docdex does **not** modify your repo contents or install dependencies automatically. To resolve index-state failures, run an indexing action yourself:

- MCP: call `docdex_index` (empty `paths` for full reindex, or specific paths for targeted ingest).
- CLI: run `docdexd index --repo <repo>` (full reindex).

For `stale_index`, prefer a full reindex to ensure the index matches the current repo contents.

### Normal behavior when index is fresh

When the index is healthy, results are repo-scoped (no cross-repo content) and limits are clamped rather than erroring:

- MCP `docdex_search` clamps `limit` to the server’s `--max-results` (min 1).
- MCP `docdex_files` clamps `limit` to `<= 1000` and `offset` to `<= 50000`.
- MCP `docdex_open` enforces a 512 KiB max response (`max_content_exceeded` if exceeded).

## Repo-scoping fast-fail errors (scope mismatch / invalid root)

All repo-scoped MCP tools (`docdex_search`, `docdex_open`, `docdex_index`, etc.) **fail closed** when the repo context does not match the MCP server’s configured `--repo`. The server does not auto-fix repo selection; the client must correct the repo path or restart the server with the right repo.

### Error envelope fields (repo-scoping)

Repo-scoping failures use the shared MCP error envelope:

- `error.data.code`: **machine-readable** code (`missing_repo_path`, `unknown_repo`, etc.).
- `error.data.message`: short, stable summary (often mirrors `error.message`).
- `error.data.reason`: optional, more specific reason string.
- `error.data.details`: structured context (when available). For repo-scoping failures it may include:
  - `normalizedPath`
  - `attemptedFingerprint`
  - `knownCanonicalPath`
  - `recoverySteps` (actionable steps for UX)
- `error.data.error`: redundant nested envelope for clients that expect `{error:{...}}`.

### Codes + remediation (repo-scoping)

| Code (`error.data.code`) | When it happens | Remediation (no server-side auto-fix) |
| --- | --- | --- |
| `missing_repo` | Repo context is absent (no `project_root` and no default repo set by MCP `initialize`). | Pass `project_root` (tool args) or re-initialize with `workspace_root`/`project_root`. |
| `missing_repo_path` | `project_root` path does not exist on disk. | Pass the correct repo path; re-initialize the client if it cached a stale root; restart the MCP server with `docdexd mcp --repo <repo>` if it points at the wrong path. |
| `unknown_repo` | `project_root` exists but does not match the MCP server’s configured `--repo` (scope mismatch). | Restart the MCP server with the correct `--repo`, or pass the matching `project_root` / omit it to use the server default; re-initialize the client if needed. |
| `repo_state_mismatch` | Repo path matches but on-disk state cannot be safely associated (fingerprint/meta mismatch). | Reindex into a fresh `--state-dir`, or run `docdexd repo reassociate --repo <new_path> --state-dir <shared_state_dir> --old-path <knownCanonicalPath>` (or `--fingerprint <attemptedFingerprint>`). |

Notes:

- `initialize` scope mismatch returns JSON-RPC `error.code = -32600` (`invalid_request`) but `error.data.code = unknown_repo`; details include `{expected, got}`.
- Invalid/un-canonicalizable roots in `initialize` return `error.data.code = invalid_request` with the OS error in `error.data.reason`.

### Warning codes (non-fatal)

Warnings may be attached to successful responses (typically under `meta.warnings`) as a list of
objects `{ code, message, details }`. Clients should treat warnings as advisory and never as
hard failures.

- `repo_evicted`: a repo was evicted to enforce `max-open-repos` (details include `evictedRepo`,
  `maxOpenRepos`, `openRepos`, and `reason`).
- `repo_thrashing`: repeated evictions detected within a short window (details include
  `maxOpenRepos`, `evictionsInWindow`, and `windowMs`).

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

<<<<<<< HEAD
## Index-state errors (missing/stale)

Docdex fast-fails on missing or stale index state to avoid serving out-of-date results. These errors include actionable hints and recovery steps (no auto-fixing).

- `missing_index`: `details` includes `stateDir`, `repoRoot`, `hint`, and `recoverySteps`.
- `stale_index`: `details` includes `stateDir`, `repoRoot`, `staleReason`, optional `indexLastUpdatedEpochMs`, optional `repoLastModifiedEpochMs`, plus `hint` and `recoverySteps`.
  - `staleReason` values: `index_state_missing` (legacy index without state metadata) or `repo_modified_since_index`.
=======
For a full upgrade/migration and recovery guide, see `docs/ops/state_upgrade_migration.md`.
>>>>>>> mcoda/task/bck-05-us-07-t13

## Parity mapping (HTTP / CLI / MCP)

Docdex presents the same underlying failures in three different wrappers:

<<<<<<< HEAD
- **HTTP daemon**: JSON error body (where implemented) is `{ "error": { "code": "<docdex_code>", "message": "<string>", "details"?: { ... } } }`.
- **CLI**: non-zero exit (currently always `1`) and a JSON error line to `stderr` when the error is a `StartupError`/`AppError` (same `{error:{code,message,details?}}` shape as HTTP).
=======
- **HTTP daemon**: JSON error body (where implemented) is `{ "error": { "code": "<docdex_code>", "message": "<string>", "details": { ... } } }` (details optional).
- **CLI**: non-zero exit (currently always `1`) and a JSON error line to `stderr` when the error is a `StartupError`/`AppError` (same `{error:{code,message}}` shape as HTTP).
>>>>>>> mcoda/task/bck-05-us-07-t05
- **MCP**: JSON-RPC error with Docdex code in `error.data.code`.

### Mapping table (common failures)

| Underlying failure | Docdex code (`error.data.code`) | MCP JSON-RPC `error.code` | HTTP daemon behavior | CLI behavior |
| --- | --- | --- | --- | --- |
| Missing repo context | `missing_repo` | `-32602` | N/A for per-repo daemon (repo is configured at startup) | N/A for per-repo CLI (repo is required via `--repo`) |
| Repo path missing on disk | `missing_repo_path` | `-32602` | Daemon startup fails (stderr JSON `{error:{code:"missing_repo_path",...}}`) | Exit `1`, `stderr` JSON `{error:{code:"missing_repo_path",...}}` |
| Repo mismatch (`project_root` does not match server repo) | `unknown_repo` | `-32602` | N/A (daemon is started per-repo) | N/A (CLI always has `--repo`; mismatch is not represented) |
| Repo state mismatch (unsafe to associate state) | `repo_state_mismatch` | `-32602` | Daemon startup fails (stderr JSON `{error:{code:"repo_state_mismatch",...}}`) | Exit `1`, `stderr` JSON `{error:{code:"repo_state_mismatch",...}}` |
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
=======
| Repo capacity exceeded (no idle repo available) | `repo_capacity_exceeded` | `-32602` | `429` JSON `{error:{code:"repo_capacity_exceeded",...}}` | Exit `1`, `stderr` JSON `{error:{code:"repo_capacity_exceeded",...}}` |
>>>>>>> mcoda/task/bck-05-us-07-t05
| Index missing (query/open without prior `index`) | `missing_index` | `-32602` | N/A in `serve` (daemon creates/opens index dir on startup) | Exit `1`, `stderr` JSON `{error:{code:"missing_index",...}}` |
| Index schema mismatch | `index_schema_mismatch` | `-32602` | Daemon startup fails (stderr JSON `{error:{code:"index_schema_mismatch",...}}`) | Exit `1`, `stderr` JSON `{error:{code:"index_schema_mismatch",...}}` |
| Index stale | `stale_index` | `-32602` | Not currently emitted by the per-repo daemon | Not currently emitted by the per-repo CLI |
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
=======
| Index missing (query/open without prior `index`) | `missing_index` | `-32602` | `/search` and `/snippet` return `409` JSON `{error:{code:"missing_index",...}}` | Exit `1`, `stderr` JSON `{error:{code:"missing_index",...}}` |
| Index stale | `stale_index` | `-32602` | `/search` and `/snippet` return `409` JSON `{error:{code:"stale_index",...}}` | Exit `1`, `stderr` JSON `{error:{code:"stale_index",...}}` |
>>>>>>> mcoda/task/bck-05-us-08-t10
=======
| Index missing (query/open without prior `index`) | `missing_index` | `-32602` | N/A in `serve` (daemon creates/opens index dir on startup) | Exit `2`, `stderr` JSON `{error:{code:"missing_index",...}}` |
| Index stale | `stale_index` | `-32602` | Not currently emitted by the per-repo daemon | Exit `3`, `stderr` JSON `{error:{code:"stale_index",...}}` |
>>>>>>> mcoda/task/bck-05-us-08-t05
=======
| Index missing (query/open without prior `index`) | `missing_index` | `-32602` | `409` with JSON `{error:{code:"missing_index",message,details}}` (if index is missing) | Exit `1`, `stderr` JSON `{error:{code:"missing_index",message,details}}` |
| Index stale | `stale_index` | `-32602` | `409` with JSON `{error:{code:"stale_index",message,details}}` | Exit `1`, `stderr` JSON `{error:{code:"stale_index",message,details}}` |
>>>>>>> mcoda/task/bck-05-us-08-t01
| Index writer unavailable (concurrent indexing lock) | `backoff_required` | `-32602` | N/A in `serve` (daemon opens a writer at startup) | Usually surfaced as a non-JSON error string (not an `AppError`) |
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
| Rate limited | `rate_limited` | `-32029` | `429` with JSON error envelope + retry hints | N/A (CLI not rate limited) |
=======
| Rate limited | `rate_limited` | `-32029` | `429` with JSON `{error:{code,message,retry_after_ms,retry_at?,limit_key,scope}}` | Not currently emitted as an `AppError` (usually a plain error string if encountered) |
>>>>>>> mcoda/task/bck-05-us-09-t32
=======
| Index writer unavailable (concurrent indexing lock) | `backoff_required` | `-32602` | N/A in `serve` (daemon opens a writer at startup) | Exit `1`, `stderr` JSON `{error:{code,message,retry_after_ms,...}}` |
| Rate limited | `rate_limited` | `-32029` | `429` with JSON `{error:{code,message,retry_after_ms,...}}` | N/A (CLI does not rate-limit) |
>>>>>>> mcoda/task/bck-05-us-09-t22
=======
| Index writer unavailable (concurrent indexing lock) | `backoff_required` | `-32602` | N/A in `serve` (daemon opens a writer at startup) | Exit `1`, `stderr` JSON `{error:{code:"backoff_required",...}}` |
| Rate limited | `rate_limited` | `-32029` | `429` with JSON `{error:{code,message,retry_after_ms,limit_key,scope,...}}` and `Retry-After` | Not currently emitted as an `AppError` (usually a plain error string if encountered) |
>>>>>>> mcoda/task/bck-05-us-09-t37
=======
| Index writer unavailable (concurrent indexing lock) | `backoff_required` | `-32602` | Daemon startup fails (stderr JSON `{error:{code:"backoff_required",details:{retry_after_ms,...}}}`) | Exit `1`, `stderr` JSON `{error:{code:"backoff_required",details:{retry_after_ms,...}}}` |
| Rate limited | `rate_limited` | `-32029` | `429` with JSON error body + `Retry-After` header | N/A (CLI commands are not rate-limited) |
>>>>>>> mcoda/task/bck-05-us-09-t13
=======
| Rate limited | `rate_limited` | `-32602` | `429` (security middleware returns status-only; no JSON envelope) | MCP tools enforce a rate limiter; errors include retry details in `error.data.details`. |
>>>>>>> mcoda/task/bck-05-us-06-t47
=======
| Rate limited | `rate_limited` | `-32029` | `429` (security middleware returns status-only; no JSON envelope) | Not currently emitted as an `AppError` (usually a plain error string if encountered) |
>>>>>>> mcoda/task/bck-05-us-06-t26
| Optional dependency disabled (e.g. symbols) | `missing_dependency` | `-32602` | N/A (no HTTP endpoint for MCP symbols) | N/A (no CLI symbols command) |
| Invalid MCP arguments (wrong JSON types / missing required fields) | `invalid_argument` | `-32602` | N/A | N/A |
| Invalid path for `docdex_open` | `invalid_path` | `-32602` | N/A | N/A |
| Invalid line window for `docdex_open` | `invalid_range` | `-32602` | N/A | N/A |
| Internal MCP server failure | `internal_error` | `-32000` | `500` (varies by endpoint) | Exit `1` (varies; may be JSON for `StartupError`/`AppError`) |

## Dependency state signals (index / symbols)

Docdex uses the same reason codes across MCP and CLI:

- MCP: `error.data.code`
- CLI: `error.code` in the JSON stderr line (this is the CLI reason code)

Common dependency states:

- `missing_dependency`: optional dependency disabled (currently `docdex_symbols` when symbol extraction is off). MCP details include `dependency` and `flag` when available.
- `missing_index`: required state missing (no repo index, or no symbols record for a path). For `docdex_symbols`, MCP details include `{ "resource": "symbols", "path": "<rel_path>" }`.
- `stale_index`: reserved for future use; not currently emitted. Treat as a reindex signal.
- `backoff_required`: index writer unavailable (another `docdexd` is indexing); retry later.

Assumption: there is no dedicated corrupt-state code today; repeated `internal_error` after rebuilding is a practical signal to reset the affected state directory and rebuild it.

Notes:

- For `rate_limited` and `backoff_required`, MCP `error.data.details` includes retry hints with stable fields: `retry_after_ms` (integer milliseconds) and optional `retry_at` (RFC3339). Rate limiting also includes `limit_key` and `scope` in the same `details` object.
- HTTP `/search` enforces `limit` by clamping to the daemon’s configured max and does not error on over-limit; MCP `docdex_search` similarly clamps `limit` to the MCP server’s `--max-results`.
- MCP list-returning tools (`docdex_search`, `docdex_files`, `docdex_memory_recall`) clamp requested limits to their max and include `limit_info` with `requested`, `max`, `effective`, and `clamped` (true when the requested value is outside `[1, max]`).
- MCP `docdex_files` clamps `limit` to `<= 1000` and `offset` to `<= 50000`.
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
=======
- MCP `docdex_symbols` clamps `limit` to `<= 1000` and truncates `symbols[].signature` plus `outcome.reason`/`outcome.error_summary` to `<= 512` bytes.
>>>>>>> mcoda/task/bck-05-us-10-t07
- MCP `docdex_open` enforces a hard maximum of 512 KiB for returned content; exceeding it returns `max_content_exceeded` with `details.max_bytes` and `details.actual_bytes`.
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD

## Tool result size limits (server-scoped)

Docdex applies the same limits for every repo handled by a given MCP server process. Requests above these maxima either clamp deterministically or return a deterministic validation error, and responses keep the same JSON schema (no ad hoc fields). Limits are enforced before any per-repo caching or aggregation, so they do not vary by repo and do not allow cross-repo leakage.

| Tool | Max items returned | Max snippet/content size | Over-limit behavior |
| --- | --- | --- | --- |
| `docdex_search` | `limit` clamped to `max_results` (`--max-results` / `DOCDEX_MCP_MAX_RESULTS`, min 1) | `summary` <= 360 chars; `snippet` <= 420 chars (`snippet_truncated` may be true) | clamps `limit`; truncates summary/snippet |
| `docdex_files` | `limit` clamped to 1000; `offset` clamped to 50000 | `summary` <= 360 chars | clamps `limit`/`offset` |
| `docdex_open` | fixed single object | `content` <= 512 KiB | returns `max_content_exceeded` (with `details.max_bytes`/`details.actual_bytes`); invalid line window -> `invalid_range` |
| `docdex_stats` | fixed single object | N/A | fixed response |
| `docdex_repo_inspect` | fixed single object | N/A | fixed response |
| `docdex_index` | fixed single object; ingest returns one decision per input path | N/A | response scales with input; no server-side cap |
| `docdex_symbols` | fixed single object | no server-side truncation of stored symbols payload | response size depends on stored record |
| `docdex_memory_store` | fixed single object | no server-side truncation of stored text | response is `{id, created_at}` |
| `docdex_memory_recall` | `top_k` clamped to 50 | no server-side truncation of stored content | clamps `top_k` |
=======
- MCP `docdex_open` enforces a hard maximum of 512 KiB for returned content; exceeding it clamps the response content to the max bytes.

## MaxSizePolicy (MCP tool bounds)

Docdex enforces repo-invariant bounds on MCP tool outputs. When a client requests more than the maximum, results are clamped; schemas remain unchanged.

- `docdex_search`: `limit` clamped to `--max-results` (default 8). `summary` is capped at 360 chars and `snippet` at 420 chars.
- `docdex_files`: `limit` ≤ 1000, `offset` ≤ 50000.
- `docdex_index` (ingest mode): `paths` and `decisions` arrays are truncated to 1000 items.
- `docdex_symbols`: `symbols` array is capped at 1000 items per file.
- `docdex_memory_recall`: `top_k` ≤ 50; `content` is truncated to 512 KiB per item.
- `docdex_open`: `content` is truncated to 512 KiB.
>>>>>>> mcoda/task/bck-05-us-10-t26
=======
- MCP tool arguments may include `schema_version`; unsupported values return `unsupported_version` with `details.schema` including `name`, `requested`, and `supported` `{min,max}`.
- MCP `docdex_search` snippet text is capped at 420 characters (truncated when needed).
- MCP `docdex_memory_recall` clamps `top_k` to `<= 50`.
>>>>>>> mcoda/task/bck-05-us-10-t21
=======
- Global tool output limits policy: `docs/mcp/tool_limits.md`.
>>>>>>> mcoda/task/bck-05-us-10-t18
=======
- MCP `rate_limited` and `backoff_required` errors include a stable retry-hint payload in `error.data`: `{ "code": "<string>", "retry_after_ms": <int>, "retry_at"?: "<RFC3339>", "limit_key": "<string>", "scope": "<string>" }`.
>>>>>>> mcoda/task/bck-05-us-09-t34
=======
- MCP `docdex_open` enforces a hard maximum of 512 KiB for returned content; exceeding it returns `max_content_exceeded` with validation issues plus `details.max_bytes` and `details.actual_bytes`.
>>>>>>> mcoda/task/bck-05-us-06-t36
=======
- MCP `rate_limited` and `backoff_required` errors include retry metadata in `error.data.details` (`retry_after_ms`, optional `retry_at`); `rate_limited` additionally includes `limit_key` and `scope`.
>>>>>>> mcoda/task/bck-05-us-06-t29
=======
- MCP rate-limit errors use the canonical envelope and include retry hints under `error.data.details` (`retry_after_ms`, `retry_at`, `limit_key`, `scope`).
>>>>>>> mcoda/task/bck-05-us-06-t26
