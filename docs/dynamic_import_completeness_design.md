# Dynamic import completeness design

## Goals

- Make dynamic import edge generation deterministic and reproducible.
- Define runtime trace ingestion format + storage location.
- Define import-map override precedence and conflict handling.
- Define unique-match heuristics and deterministic tie-breaks.
- Surface unresolved imports explicitly in HTTP/MCP (and CLI when available).

## Non-goals

- No automatic trace collection; traces are provided externally.
- No attempt to resolve arbitrary runtime string building beyond supported patterns.
- No schema changes to `docdex.impact_graph` in this task (unless required by storage).

## Runtime trace ingestion

### Format (JSONL)

One JSON object per line, minimal required fields:

```json
{"source":"path/rel/to/repo.js","target":"path/rel/to/repo_dep.js","kind":"import"}
```

- `source` (string, required): repo-relative or absolute path; absolute must be under repo root.
- `target` (string, required): repo-relative or absolute path; absolute must be under repo root.
- `kind` (string, optional): normalized to impact edge kinds (`import`, `require`, `include`).
- Unknown fields are ignored.

Invalid lines are skipped with a warning (include path + line number); empty lines are ignored.

### Storage location

- Primary persisted store: `<repo-state-root>/import_traces.jsonl` (same root as `impact_graph.json`).
- Backwards compatibility: continue reading repo-root `docdex.import_traces.jsonl`.
- Merge both sources during edge building; de-dupe by `(source, target, kind)`.
- Prefer state-dir traces when duplicates exist; repo-root file is treated as supplemental hints.

### Ingestion mechanism

- Place `import_traces.jsonl` under the repo state root (same directory as `impact_graph.json`).
- Repo-root `docdex.import_traces.jsonl` remains supported as a supplemental hint file.
- A dedicated CLI/HTTP ingestion endpoint can be added later if needed.

## Import-map precedence + conflict rules

### Inputs

- `docdex.import_map.json` entries:
  - `edges[]` (explicit edges).
  - `mappings[]` (spec -> targets, optional expand + override).
- Runtime traces (from state-dir + repo-root files).
- Static resolver output (JS/TS/Python/Rust/Go heuristics).

### Precedence

For a given source file and import ref:

1) **Explicit edges** from import map are always added.
2) **Override mappings** are applied first; if a mapping matches and has `override: true`, its targets are used and static resolution for that import ref is skipped.
3) **Runtime trace edges** are added independently (deduped).
4) **Static resolution** runs when no override mapping matched; for patterns, unique-match runs before fallbacks.
5) **Fallback mappings** are only used when static/unique-match resolution fails.

### Conflict handling

- Track `override_targets` from explicit edges with `override: true`.
- After static resolution, drop any auto-resolved edges whose targets are in `override_targets` (mapping overrides only suppress their own import refs).
- Runtime trace edges are not suppressed by overrides (they represent observed runtime behavior); duplicates are deduped.
- Edge dedupe key is `(source, target, kind)`; output order is deterministic (lexicographic sort on key).

## Deterministic unique-match heuristic

Unique-match is only attempted when:

- The dynamic pattern is anchored and has usable static parts.
- Repo scan limits are not exceeded (`dynamic_import_scan_limit`).

### JS/TS

- Candidate set: all JS/TS files (limited by scan limit).
- Build candidate specs via existing `js_ts_candidate_specs`.
- Score by:
  1) Match via relative spec (preferred).
  2) Shorter relative spec length.
  3) Shorter target path length.
  4) Lexicographic path (deterministic tie-break).

### Python

- Candidate set: all Python files (limited by scan limit).
- Prefer module-name spec matches (`pkg.module`) over file-path specs.
- Score by:
  1) Module-name match.
  2) Shorter module name length.
  3) Shorter target path length.
  4) Lexicographic path.

Ambiguities are logged at info level with the chosen target.

## Unresolved import surfaces

- Persist `ImpactDiagnostics` per file (count + sample list) in `impact_graph.json` entries.
- `/v1/graph/impact` includes `diagnostics` for the requested file when present.
- `/v1/graph/impact/diagnostics` (and MCP `docdex_impact_diagnostics`) lists unresolved counts/samples across files.
- CLI surface: `docdexd impact-diagnostics --repo <path> [--file <path>] [--limit <n>] [--offset <n>]` returns the same `docdex.impact_diagnostics` payload.
- Logging: keep `info` logs for unresolved imports with sample list; include `count` + `file`.

## Implementation notes

- `src/impact.rs`:
  - Extend import-hints loader to read state-dir traces alongside repo-root traces.
  - Add parsing/normalization for trace entries (reuse `normalize_hint_path`).
  - Apply precedence rules in `resolve_import_ref` and `build_edges_with_context`.
  - Update `pick_unique_match` to accept a scored candidate list and apply deterministic tie-breaks.
- `src/index/impact.rs`:
  - Ensure trace ingestion updates propagate to `impact_graph.json` during reindex or explicit trace-ingest.
- Docs to update: `docs/contracts/code_intelligence_schema_v1.md`, `docs/sds/sds.md`.
