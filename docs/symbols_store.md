# Symbols store (optional code intelligence)

Docdex can optionally extract per-file **symbols** during indexing and persist them in a repo-scoped symbols store. Downstream features (e.g. MCP clients) can query this store via a documented interface.

This document describes:

- How to enable/disable symbol extraction
- Symbols store location and lifecycle
- Query interfaces (MCP + internal Rust)
- Payload schema/versioning and stable identifiers
- How `ok` / `skipped` / `failed` outcomes are represented and how failures affect indexing

## Enablement (and default behavior)

Symbol extraction is **always enabled** during indexing.

- The legacy toggle `DOCDEX_ENABLE_SYMBOL_EXTRACTION` / `--enable-symbol-extraction` is deprecated and ignored (a warning is logged if set to false).
- Indexing and search always populate `symbols.db` alongside the Tantivy index.
- Impact graph extraction is tied to symbols and is always enabled as well.
- AST extraction uses the same enablement path and is always enabled for supported languages.

## Store location and lifecycle

### State directory

The symbols store lives under the **per-repo state root** (the parent of `index/`):

- Default: `~/.docdex/state/repos/<repo_id>/`
- Override: `--state-dir <path>` / `DOCDEX_STATE_DIR`
  - Relative paths are resolved under the repo root.
  - Absolute paths outside the repo are treated as shared bases and scoped under `<state-dir>/repos/<repo_id>/index`.
- Legacy in-repo state (opt-in): `--state-dir .docdex/index` or `--state-dir .gpt-creator/docdex/index`

### Symbols store path and layout

When enabled, the symbols store is a **SQLite database** at:

`<repo-state-root>/symbols.db`

Tables (v4):

- `symbols_meta (key TEXT PRIMARY KEY, value TEXT)`
  - `schema_version` is stored here.
  - `parser_versions` stores a JSON map of Tree-sitter parser crate versions.
  - `parser_versions_previous` captures the prior parser version map when drift is detected.
  - `parser_versions_changed_at_ms` records when the parser version drift was detected.
  - `symbols_invalidation_reason` is set when symbols are cleared (e.g. `parser_versions_changed`).
  - `symbols_invalidated_at_ms` records when symbols were cleared due to drift.
  - `docdex_version` records the docdexd version that last wrote the store.
- `symbols_files (file_path TEXT PRIMARY KEY, outcome_status TEXT, outcome_reason TEXT, outcome_error_summary TEXT, file_lang TEXT)`
  - Per-file extraction outcome metadata.
- `symbols (id INTEGER PRIMARY KEY AUTOINCREMENT, file_path TEXT, symbol_id TEXT, name TEXT, kind TEXT, line_start INT, start_col INT, line_end INT, end_col INT, signature TEXT)`
  - `symbol_id` is optional in storage; it is computed if missing when reading.
  - Indexed by `file_path` for fast lookup.
  - Additional indexes on `name` and `kind` plus a `symbols_files(file_lang)` index are included for deterministic migrations.
- `ast_files (file_path TEXT PRIMARY KEY, outcome_status TEXT, outcome_reason TEXT, outcome_error_summary TEXT, node_count INT, truncated INT, file_lang TEXT)`
  - Per-file AST extraction outcome metadata.
- `ast_nodes (file_path TEXT, node_id INT, parent_id INT, kind TEXT, is_named INT, line_start INT, start_col INT, line_end INT, end_col INT)`
  - Stores Tree-sitter AST nodes for each file; primary key is `(file_path, node_id)`.
  - Indexed by `file_path` (and `kind`) for fast lookup.

Legacy migration:

- If a legacy `symbols.db/` directory exists (JSON files), Docdex moves it to `symbols.db.legacy*` and imports the JSON payloads into SQLite (best-effort).

### Lifecycle rules

- Full reindex (`docdexd index`):
  - Docdex attempts to remove `<repo-state-root>/symbols.db` and recreate the SQLite schema.
  - If the reset fails, indexing continues; stale symbol records may remain on disk for paths that are no longer indexed.
- Parser version drift:
  - If the stored Tree-sitter parser versions differ from the running build, Docdex clears `symbols` and `symbols_files` and records invalidation metadata in `symbols_meta` (reindex required).
  - The `symbols_reindex_required` flag is set when drift is detected and cleared after a full reindex.
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

- `missing_index`: no symbols record exists for that `path` (common before the first index run).
- `invalid_path`: path is not a safe repo-relative path.

See `docs/mcp/errors.md` for the common error envelope.

### MCP tool: `docdex_ast`

Tool name aliases: `docdex_ast` and `docdex.ast`.

Arguments:

```json
{ "path": "path/relative/to/repo.ext", "project_root": "/path/to/repo", "max_nodes": 20000 }
```

Return value:

- A `docdex.ast` payload, as defined in `docs/contracts/code_intelligence_schema_v1.md`.

### HTTP endpoint: `GET /v1/symbols`

Query:

```
GET /v1/symbols?path=path/relative/to/repo.ext
```

Repo context may be provided via `x-docdex-repo-id` header or `repo_id` query param (optional for per-repo daemons).

Return value:

- A `docdex.symbols` payload, as defined in `docs/contracts/code_intelligence_schema_v1.md`.

Failure semantics (HTTP JSON errors):

- `invalid_argument`: `path` is missing/empty or not a safe repo-relative path.
- `missing_index`: no symbols record exists for the requested path.
- `stale_index`: parser version drift invalidated symbols/AST; reindex required.

### HTTP endpoint: `GET /v1/ast`

Query:

```
GET /v1/ast?path=path/relative/to/repo.ext&maxNodes=20000
```

Return value:

- A `docdex.ast` payload, as defined in `docs/contracts/code_intelligence_schema_v1.md`.

Failure semantics (HTTP JSON errors):

- `invalid_argument`: `path` is missing/empty or not a safe repo-relative path.
- `missing_index`: no AST record exists for the requested path.
- `stale_index`: parser version drift invalidated symbols/AST; reindex required.

### HTTP endpoint: `GET /v1/ast/search`

Query:

```
GET /v1/ast/search?kinds=function_item,struct_item&mode=all&limit=50
```

Parameters:

- `kinds`: comma-separated list of Tree-sitter node kinds to match (required).
- `mode`: `any` (default) or `all` (require all kinds per file).
- `limit`: maximum files returned (default 50, server capped).

Return value:

- A `docdex.ast_search` payload listing files and match counts.

Failure semantics (HTTP JSON errors):

- `invalid_argument`: `kinds` is missing/empty or `mode` is unsupported.
- `stale_index`: parser version drift invalidated symbols/AST; reindex required.

### HTTP endpoint: `GET /v1/symbols/status`

Query:

```
GET /v1/symbols/status
```

Repo context may be provided via `x-docdex-repo-id` header or `repo_id` query param (optional for per-repo daemons).

Return value:

- A `docdex.symbols_status` payload describing Tree-sitter parser versions and drift metadata.
  - `parser_versions_changed`: `true` if parser versions changed since the previous run.
  - `requires_reindex`: `true` if symbols were invalidated and a full reindex is required.

### CLI command: `docdexd symbols-status`

Example:

```
docdexd symbols-status --repo /path/to/repo
```

Returns the same payload as `GET /v1/symbols/status`.

### Rust interface (internal)

Internal consumers can use the `SymbolsStore` API in `src/symbols.rs`:

- `SymbolsStore::new(repo_root, state_dir) -> Result<SymbolsStore>`
- `SymbolsStore::read_symbols(rel_path) -> Result<Option<SymbolsResponseV1>>`
- `SymbolsStore::upsert_symbols(rel_path, payload) -> Result<()>`
- `SymbolsStore::delete_symbols(rel_path) -> Result<()>`

The store is repo-scoped via:

- `repo_id_for_root(repo_root) -> Result<String>`

## Payload schema and versioning

Each stored record is served as a `docdex.symbols` JSON payload:

- The wire contract is defined in `docs/contracts/code_intelligence_schema_v1.md`.
- The payload includes a top-level `schema` object:
  - `schema.name`: `docdex.symbols`
  - `schema.version`: currently `1`
  - `schema.compatible`: compatibility window (currently `{ "min": 1, "max": 1 }`)

`SymbolsStore::read_symbols()` is tolerant of older/missing fields:

- If `repo_id` or `file` are missing/empty, it fills them from the store context and the read path.
- If `symbol_id` is missing/empty on any symbol, it is recomputed.
- Symbols are sorted by `symbol_id` for deterministic outputs.

## Schema migrations (workflow)

When changing the symbols store schema:

- Bump `SYMBOLS_SCHEMA_VERSION` in `src/symbols.rs`.
- Add a new `migrate_to_vN` step and register it in `SymbolsStore::migration_steps` (even if it is a no-op).
- Add or update migration tests in `tests/symbols_schema_migration.rs` (upgrade + downgrade rejection).

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
