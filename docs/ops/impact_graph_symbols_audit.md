# Impact graph + symbols audit

## Entry points

- Impact graph extraction: `src/index/mod.rs` `add_document` -> `extract_import_edges` in `src/impact.rs`.
- Impact graph persistence: `src/index/impact.rs` uses `ImpactGraphStore::write_graph` / `update_impact_graph_for_file` / `remove_impact_edges_for_file` to write `impact_graph.json`.
- Impact graph API: `src/api/v1/graph.rs` (`/v1/graph` and `/v1/impact/diagnostics`) uses `ImpactGraphStore` and `traverse_impact`.
- CLI diagnostics surface: `docdexd impact-diagnostics` (local or via HTTP) in `src/cli/commands/impact.rs`.
- Symbols extraction: `src/index/symbols.rs` builds payloads with `doc_symbols::build_symbols_payload` / `build_ast_payload` and writes via `SymbolsStore`.
- Symbols store API: `src/symbols.rs` `SymbolsStore` (open/read/write/search, migrations, drift).
- HTTP/MCP symbols/AST: `src/api/v1/symbols.rs`, `src/api/v1/ast.rs`, `crates/mcp-server/src/lib.rs`.

## Schema/version metadata

- Impact graph schema: `IMPACT_GRAPH_SCHEMA_VERSION = 2` in `src/impact.rs`, `default_impact_schema()` embeds `name = docdex.impact_graph` + compatible range.
- Impact graph diagnostics schema: `default_impact_diagnostics_schema()` -> `docdex.impact_diagnostics` v1 (`ImpactDiagnosticsResponseV1`).
- Impact graph contract docs: `docs/contracts/code_intelligence_schema_v1.md`.
- Symbols store schema versioning: `SYMBOLS_SCHEMA_VERSION = 5`, `SYMBOLS_SCHEMA_MIN_VERSION = 1` in `src/symbols.rs`, stored in `symbols_meta.schema_version`.
- Symbols/AST response schemas: `docdex.symbols` v1, `docdex.ast` v1, `docdex.symbols_status` v1 (`src/symbols.rs`, `docs/contracts/code_intelligence_schema_v1.md`).
- Symbols store layout + versions documented in `docs/symbols_store.md`.

## Diagnostics + drift handling

- Impact graph diagnostics: unresolved imports counted in `build_edges_with_context` (`ImpactDiagnostics`), surfaced on `/v1/graph` response and `/v1/impact/diagnostics`.
- Impact graph legacy formats: `parse_store_payload` accepts edge-only / entry-only legacy formats and runs `run_impact_graph_migrations`; warns when migration is in-memory only.
- Symbols parser drift: `SymbolsStore::ensure_parser_versions` compares stored vs current parser versions, clears symbols/AST tables, sets `symbols_reindex_required`, and records `symbols_invalidated_at_ms` + `symbols_invalidation_reason`.
- Stale index surface: `/v1/symbols` and `/v1/ast` return `stale_index` when `symbols_reindex_required` is set; MCP mirrors `stale_index` (`docs/mcp/errors.md`).

## Extension points (migrations + runtime traces)

- Impact graph migrations: `run_impact_graph_migrations` + `migrate_impact_graph_v1_to_v2` in `src/impact.rs` are invoked during read; persistence happens only on index/write.
- Impact graph schema enforcement: `normalize_impact_schema` controls compatibility handling and "newer but compatible" warnings.
- Runtime import traces: `IMPORT_TRACES_FILE = docdex.import_traces.jsonl`, `IMPORT_TRACES_STATE_FILE = import_traces.jsonl`, `ImportTraceEntry`, `load_import_traces`, and `import_hints_for_repo` in `src/impact.rs`; toggled by config/env (`DOCDEX_ENABLE_IMPORT_TRACES`).
- Import map overrides: `resolve_import_map_matches` returns overrides/fallbacks; `hint_edges_for_source` suppresses auto-resolved edges when `override_edge` is set.
- Dynamic import tie-break: `resolve_unique_match` + `pick_unique_match` provides deterministic lexicographic tie-break logging for pattern imports.

## Gaps noted (for follow-up tasks)

- Impact graph migrations currently warn and require reindex to persist; there is no on-read persistence or versioned upgrade framework for `impact_graph.json` beyond in-memory normalization.
- Runtime traces are read-only from a file; no ingestion pipeline exists to merge external runtime traces into `impact_graph.json` on disk.
