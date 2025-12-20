# Symbols store (optional code intelligence)

Docdex can optionally extract per-file **symbols** during indexing and persist them in a repo-scoped symbols store. Downstream features (e.g. MCP clients) can query this store via a documented interface.

This document describes:

- How to enable/disable symbol extraction
- Symbols store location and lifecycle
- Query interfaces (MCP + internal Rust)
- Payload schema/versioning and stable identifiers
- How `ok` / `skipped` / `failed` outcomes are represented and how failures affect indexing

## Enablement (and default behavior)

Symbol extraction is **disabled by default**.

- Enable: set `DOCDEX_ENABLE_SYMBOL_EXTRACTION=1` (also accepts `true|yes|on`) and run a fresh index build.
  - Example: `DOCDEX_ENABLE_SYMBOL_EXTRACTION=1 docdexd index --repo /path/to/repo`
- Disable: unset `DOCDEX_ENABLE_SYMBOL_EXTRACTION` (or set to `0|false`) and run Docdex normally.

When symbol extraction is disabled:

- Indexing and search work normally (no dependency on the symbols store).
- The MCP tool `docdex_symbols` returns an MCP error with Docdex code `missing_dependency` and details `{ "dependency": "DOCDEX_ENABLE_SYMBOL_EXTRACTION" }`.

## Store location and lifecycle

### State directory

The symbols store lives under Docdex’s **per-repo state root**:

<<<<<<< HEAD
- Default: `~/.docdex/state/repos/<fingerprint>`
- Override base: `--state-dir <path>` / `DOCDEX_STATE_DIR` (relative paths or in-repo absolute paths keep legacy layout)
=======
- Default (`<repo-state-root>`): `~/.docdex/state/repos/<fingerprint>/`
- Override: `--state-dir <state-root>` / `DOCDEX_STATE_DIR` (relative paths are resolved under `repo`; per-repo state root is `<state-root>/repos/<fingerprint>/`)
- Inspect: `docdexd repo inspect --repo <path>` reports `repoStateRoot` and `indexDir`.
>>>>>>> mcoda/task/ops-01-us-03-t02

### Symbols store path and layout

When enabled, the symbols store root is:

<<<<<<< HEAD
`<repo_state_dir>/symbols.db/`

Current on-disk layout:

- `<repo_state_dir>/symbols.db/files/`
=======
`<repo-state-root>/symbols.db/`

Current on-disk layout:

- `<repo-state-root>/symbols.db/files/`
>>>>>>> mcoda/task/ops-01-us-03-t02
  - One JSON file per repo-relative path: `<sha256(rel_path)>.json`

Notes:

- Despite the name `symbols.db`, the current implementation is a directory of JSON files (not SQLite).
- Writes are best-effort and atomic per file (write to a temp file, then rename).

### Lifecycle rules

- Full reindex (`docdexd index`):
<<<<<<< HEAD
  - Docdex attempts to delete `<repo_state_dir>/symbols.db/` and recreate `<repo_state_dir>/symbols.db/files/`.
=======
  - Docdex attempts to delete `<repo-state-root>/symbols.db/` and recreate `<repo-state-root>/symbols.db/files/`.
>>>>>>> mcoda/task/ops-01-us-03-t02
  - If the reset fails, indexing continues; stale symbol records may remain on disk for paths that are no longer indexed.
- Incremental ingest (`docdexd ingest` / watcher ingestion):
  - Docdex overwrites the per-file record for the ingested file.
- File delete:
  - Docdex attempts to remove the per-file record for the deleted file; failures are logged and ignored.

## Query interfaces

### MCP tool: `docdex_symbols`

Tool name aliases: `docdex_symbols` and `docdex.symbols`.

Arguments:

```json
<<<<<<< HEAD
{ "path": "path/relative/to/repo.ext", "limit": 200, "project_root": "/path/to/repo (optional)" }
=======
{ "path": "path/relative/to/repo.ext", "project_root": "/path/to/repo (optional)", "limit": 2000 }
>>>>>>> mcoda/task/bck-05-us-10-t03
```

- `limit` (optional): max symbols to return (clamped to 2000).

Return value:

- A `docdex.symbols` payload, as defined in `docs/contracts/code_intelligence_schema_v1.md`.
- The MCP response is bounded to 5000 symbols or 512 KiB; larger payloads fail with a `max_content_exceeded` error.

Bounds and determinism:

- `limit` clamps the number of returned symbols to `<= 1000` (minimum `1`); omitted means "use the max".
- Symbols are sorted by `symbol_id`, then truncated, so the cap is deterministic.
- `symbols[].signature`, `outcome.reason`, and `outcome.error_summary` are truncated to `<= 512` bytes (ellipsis added when truncated).

Failure semantics (MCP JSON-RPC errors):

- `missing_dependency`: symbol extraction disabled for the MCP server process.
- `missing_index`: no symbols record exists for that `path` (common after enabling symbols without reindexing).
- `invalid_path`: path is not a safe repo-relative path.

Bounded outputs:

- Symbols are sorted by `symbol_id`.
- Results are capped at 2000 symbols per file (deterministic truncation by `symbol_id` order).
- `outcome.error_summary` is truncated to 512 bytes.

See `docs/mcp/errors.md` for the common error envelope.

### Rust interface (internal)

Internal consumers can use the `SymbolsStore` API in `src/symbols.rs`:

- `SymbolsStore::new(repo_root, repo_state_dir) -> Result<SymbolsStore>`
- `SymbolsStore::read_symbols(rel_path) -> Result<Option<SymbolsResponseV1>>`
- `SymbolsStore::upsert_symbols(rel_path, payload) -> Result<()>`
- `SymbolsStore::delete_symbols(rel_path) -> Result<()>`

The store is repo-scoped via:

- `repo_id_for_root(repo_root) -> Result<String>`

## Payload schema and versioning

Each stored record is a `docdex.symbols` JSON payload:

- The wire contract is defined in `docs/contracts/code_intelligence_schema_v1.md`.
- The payload includes a top-level `schema` object:
  - `schema.name`: `docdex.symbols`
  - `schema.version`: currently `1`
  - `schema.compatible`: compatibility window (currently `{ "min": 1, "max": 1 }`)

`SymbolsStore::read_symbols()` is backward-tolerant for older/missing fields:

- If `repo_id` or `file` are missing/empty, it fills them from the store context and the read path.
- Symbol IDs are recomputed after normalization to stay consistent with truncated fields.
- Symbols are sorted by `symbol_id` for deterministic outputs.
- Symbols are capped at 2000 per file; `outcome.error_summary` is truncated to 512 bytes.
- If the stored `repo_id` does not match the store repo, the record is treated as missing.

<<<<<<< HEAD
## Output caps (deterministic)

To keep symbol outputs bounded and predictable across tools, Docdex enforces fixed caps:

- Max symbols per file: `1000` (extra symbols are dropped after sorting by `symbol_id`).
- Max symbols per run: `50000` (full reindex or multi-file ingest budget; once exhausted, remaining supported files record `status=skipped` with `reason=symbols_budget_exhausted`).
- Max `signature` length: `240` characters.
- Max `outcome.error_summary` length: `200` characters.

These limits are fixed (not configurable) and do not vary by repo.
=======
### Outcome metadata

`outcome` may include parser/runtime metadata:

- `outcome.parser`: `{ name, version? }` for the extractor parser (when known).
- `outcome.runtime`: `{ name, version? }` for the Docdex runtime.

### Limits and truncation

To keep payload sizes predictable, Docdex clamps symbol outputs deterministically:

- Max symbols per file: 512
- Max symbol `name`: 200 chars
- Max symbol `kind`: 32 chars
- Max symbol `signature`: 240 chars
- Max `outcome.reason`: 160 chars
- Max `outcome.error_summary`: 360 chars
- Max `outcome.parser.name`/`outcome.runtime.name`: 64 chars
- Max `outcome.parser.version`/`outcome.runtime.version`: 64 chars

Lengths are Unicode scalar chars; truncation does not add extra fields.
>>>>>>> mcoda/task/bck-05-us-10-t04

## Stable identifiers

### `repo_id`

`repo_id` is the repo fingerprint (SHA-256 of the repo identity). It is derived from the `.git` directory when present, falling back to the repo root on non-git directories.

Assumption/implication:

- Moving the same repo to a different absolute path will change `repo_id` (and thus `symbol_id` prefixes).

### `symbol_id`

`symbol_id` is deterministic and stable for a given `repo_id`, `file`, and symbol location:

`"<repo_id>:<file>#<start_line>:<start_col>-<end_line>:<end_col>:<kind>:<name>"`

All position fields are **1-based** and refer to the repo-relative `file` path.

## Outcomes and failure semantics

Symbol extraction is best-effort and **must not fail indexing**.

For every indexed file, when symbol extraction is enabled, Docdex attempts to persist a `docdex.symbols` record with:

- `symbols`: extracted symbols (may be empty)
- `outcome`: per-file status and optional metadata

### Outcome statuses

The `outcome.status` field is one of:

- `ok`: extraction ran successfully (even if zero symbols were found).
- `skipped`: extraction was intentionally not run (e.g. unsupported language).
- `failed`: extraction attempted but failed (read failure or extraction error).

### Standard reasons (current implementation)

Docdex currently uses these `outcome.reason` values:

- `unsupported_language` (status: `skipped`)
- `symbols_budget_exhausted` (status: `skipped`)
- `read_failed (<language>)` (status: `failed`)
- `extract_failed (<language>)` (status: `failed`)

`outcome.error_summary` is a bounded, best-effort string intended for debugging (no stack traces).

### Supported languages (current implementation)

Symbol extraction is attempted only for:

- Markdown (`.md`, `.markdown`, `.mdx`)
- Rust (`.rs`)
- Python (`.py`)
- TypeScript/TSX (`.ts`, `.tsx`)
- JavaScript/JSX (`.js`, `.jsx`)
- Go (`.go`)

Other extensions are recorded as `skipped` with `reason: unsupported_language`.

### Indexing behavior on symbol failures

If symbol extraction fails for a file/language:

- Docdex still indexes the file’s text (or indexes an empty body if the file could not be read).
- Docdex records a `failed` (or `skipped`) symbols `outcome` for the file.
- The overall indexing run continues; symbol extraction outcomes are per-file and do not change indexing exit status.
