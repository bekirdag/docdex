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

The symbols store lives under Docdex’s **state/index directory**:

- Default: `~/.docdex/state/repos/<repo_id>/index`
- Override: `--state-dir <path>` / `DOCDEX_STATE_DIR`
  - Relative paths are resolved under the repo root.
  - Absolute paths outside the repo are treated as shared bases and scoped under `<state-dir>/repos/<repo_id>/index`.
- Legacy in-repo state (opt-in): `--state-dir .docdex/index` or `--state-dir .gpt-creator/docdex/index`

### Symbols store path and layout

When enabled, the symbols store root is:

`<state_dir>/symbols.db/`

Current on-disk layout:

- `<state_dir>/symbols.db/files/`
  - One JSON file per repo-relative path: `<sha256(rel_path)>.json`

Notes:

- Despite the name `symbols.db`, the current implementation is a directory of JSON files (not SQLite).
- Writes are best-effort and atomic per file (write to a temp file, then rename).

### Lifecycle rules

- Full reindex (`docdexd index`):
  - Docdex attempts to delete `<state_dir>/symbols.db/` and recreate `<state_dir>/symbols.db/files/`.
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
{ "path": "path/relative/to/repo.ext", "project_root": "/path/to/repo" }
```

Return value:

- A `docdex.symbols` payload, as defined in `docs/contracts/code_intelligence_schema_v1.md`.

Failure semantics (MCP JSON-RPC errors):

- `missing_dependency`: symbol extraction disabled for the MCP server process.
- `missing_index`: no symbols record exists for that `path` (common after enabling symbols without reindexing).
- `invalid_path`: path is not a safe repo-relative path.

See `docs/mcp/errors.md` for the common error envelope.

### Rust interface (internal)

Internal consumers can use the `SymbolsStore` API in `src/symbols.rs`:

- `SymbolsStore::new(repo_root, state_dir) -> Result<SymbolsStore>`
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
- If `symbol_id` is missing/empty on any symbol, it is recomputed.
- Symbols are sorted by `symbol_id` for deterministic outputs.

## Stable identifiers

### `repo_id`

`repo_id` is a SHA-256 hex digest derived from the repo root path after canonicalization and slash normalization.

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
