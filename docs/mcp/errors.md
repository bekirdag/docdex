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

Note: `rate_limited` uses a specialized `error.data` shape for retry hints (see
`docs/contracts/rate_limit_error_contract_v1.md`) and does not include the full nested envelope.

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
- `stale_index`: index exists but is known to be stale (reserved for future use).
- `missing_dependency`: a required optional feature/dependency is disabled (e.g. symbols extraction disabled).
- `rate_limited`: request rejected due to rate limiting (see `docs/contracts/rate_limit_error_contract_v1.md`).
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
<<<<<<< HEAD
- `max_content_exceeded`: reserved for cases where content cannot be safely truncated (not currently emitted; MCP tools clamp/truncate content to MaxSizePolicy).
=======
- `unsupported_version`: requested schema version is outside the supported range for the tool response.
- `max_content_exceeded`: response content would exceed server limits (e.g. `docdex_open` file too large).
>>>>>>> mcoda/task/bck-05-us-10-t21

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
| Index stale | `stale_index` | `-32602` | Not currently emitted by the per-repo daemon | Not currently emitted by the per-repo CLI |
| Index writer unavailable (concurrent indexing lock) | `backoff_required` | `-32602` | N/A in `serve` (daemon opens a writer at startup) | Usually surfaced as a non-JSON error string (not an `AppError`) |
| Rate limited | `rate_limited` | `-32029` | `429` with JSON error envelope + retry hints | N/A (CLI not rate limited) |
| Optional dependency disabled (e.g. symbols) | `missing_dependency` | `-32602` | N/A (no HTTP endpoint for MCP symbols) | N/A (no CLI symbols command) |
| Invalid MCP arguments (wrong JSON types / missing required fields) | `invalid_params` | `-32602` | N/A | N/A |
| Invalid path for `docdex_open` | `invalid_path` | `-32602` | N/A | N/A |
| Invalid line window for `docdex_open` | `invalid_range` | `-32602` | N/A | N/A |
| Internal MCP server failure | `internal_error` | `-32000` | `500` (varies by endpoint) | Exit `1` (varies; may be JSON for `StartupError`/`AppError`) |

Notes:

- HTTP `/search` enforces `limit` by clamping to the daemon’s configured max and does not error on over-limit; MCP `docdex_search` similarly clamps `limit` to the MCP server’s `--max-results`.
- MCP `docdex_files` clamps `limit` to `<= 1000` and `offset` to `<= 50000`.
<<<<<<< HEAD
<<<<<<< HEAD
=======
- MCP `docdex_symbols` clamps `limit` to `<= 1000` and truncates `symbols[].signature` plus `outcome.reason`/`outcome.error_summary` to `<= 512` bytes.
>>>>>>> mcoda/task/bck-05-us-10-t07
- MCP `docdex_open` enforces a hard maximum of 512 KiB for returned content; exceeding it returns `max_content_exceeded` with `details.max_bytes` and `details.actual_bytes`.
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
