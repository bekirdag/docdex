# Code intelligence JSON schemas (v1)

This document defines **wire contracts** for symbol extraction outputs and symbol-derived impact/graph outputs.

## Schema compatibility signal

All symbol/code-intelligence outputs MUST include a top-level `schema` object so clients can detect breaking changes.

```json
{
  "schema": {
    "name": "docdex.<schema_name>",
    "version": 1,
    "compatible": { "min": 1, "max": 1 }
  }
}
```

- `schema.name`: Stable identifier for the payload family (examples below).
- `schema.version`: The payload version emitted by the server/tool.
- `schema.compatible`: The inclusive range of versions this payload is intended to be compatible with.

## Symbols response (`docdex.symbols`)

Symbol responses represent extracted symbols within a repo, scoped to a file.

**Required top-level fields**

```json
{
  "schema": { "name": "docdex.symbols", "version": 1, "compatible": { "min": 1, "max": 1 } },
  "repo_id": "<sha256 fingerprint>",
  "file": "path/relative/to/repo.ext",
  "symbols": []
}
```

**Optional top-level fields**

- `outcome` (object, optional): Per-file extraction outcome metadata.
  - `status` (string, required): `ok` | `skipped` | `failed`
  - `reason` (string, optional): Short stable reason code/message (e.g. `unsupported_language`, `read_failed (markdown)`).
  - `error_summary` (string, optional): Best-effort human-readable error summary (must be bounded; avoid stack traces).

**Symbol item fields (v1)**

- `symbol_id` (string, required): Deterministic identifier stable across runs for the same repo snapshot.
  - v1 format: `"<repo_id>:<file>#<start_line>:<start_col>-<end_line>:<end_col>:<kind>:<name>"`
- `name` (string, required)
- `kind` (string, required): Language-agnostic kind label (e.g. `function`, `class`, `method`, `variable`, `module`).
- `range` (object, required): 1-based positions within `file`.
  - `start_line`, `start_col`, `end_line`, `end_col` (integers)
- `signature` (string, optional): Language-specific display signature if available.

## AST response (`docdex.ast`)

AST responses represent Tree-sitter node ranges for a repo file.

**Required top-level fields**

```json
{
  "schema": { "name": "docdex.ast", "version": 1, "compatible": { "min": 1, "max": 1 } },
  "repo_id": "<sha256 fingerprint>",
  "file": "path/relative/to/repo.ext",
  "nodes": [],
  "total_nodes": 0,
  "truncated": false
}
```

**Optional top-level fields**

- `language` (string, optional): language identifier (e.g. `rust`, `typescript`).
- `outcome` (object, optional): per-file extraction outcome metadata.
  - `status` (string, required): `ok` | `skipped` | `failed`
  - `reason` (string, optional)
  - `error_summary` (string, optional)

**AST node fields (v1)**

- `id` (integer, required): unique per-file node id.
- `parent_id` (integer, optional): parent node id.
- `kind` (string, required): Tree-sitter node kind.
- `is_named` (boolean, required)
- `range` (object, required): 1-based positions within `file`.
  - `start_line`, `start_col`, `end_line`, `end_col` (integers)

Notes:

- `total_nodes` is the total node count for the file; responses may be truncated when a node limit is applied.

## Impact graph response (`docdex.impact_graph`)

Impact graph responses represent **directed** dependency edges between repo files.

**Required top-level fields**

```json
{
  "schema": { "name": "docdex.impact_graph", "version": 1, "compatible": { "min": 1, "max": 1 } },
  "repo_id": "<sha256 fingerprint>",
  "source": "path/relative/to/repo.ext",
  "inbound": [],
  "outbound": [],
  "edges": []
}
```

### Edge direction semantics

For each edge object `{ "source": "<path>", "target": "<path>" }`:

- `source` is the file that contains the dependency/reference (the importer / depender).
- `target` is the file being depended on (the imported / dependee).

For a request where `source = F`:

- `outbound` is the set of `target` paths for edges where `source == F`.
- `inbound` is the set of `source` paths for edges where `target == F`.

`edges[].kind` is an optional classifier such as `import`, `include`, or `require` (implementation-defined).

**Optional diagnostics**

```json
"diagnostics": {
  "unresolvedImportsTotal": 2,
  "unresolvedImportsSample": ["./dynamic/${name}.js", "importlib.import_module(VAR)"]
}
```

Diagnostics are best-effort and omitted when no unresolved imports are recorded.

### Impact graph storage and migrations

`impact_graph.json` stores a repo-scoped graph snapshot and includes schema metadata:

```json
{
  "schema": { "name": "docdex.impact_graph", "version": 1, "compatible": { "min": 1, "max": 1 } },
  "repo_id": "<sha256 fingerprint>",
  "graphs": [ ... ]
}
```

Readers must reject payloads whose schema name does not match or whose compatibility range does not include the current implementation version. Legacy files without schema metadata are accepted and migrated in-memory; reindex to persist the upgraded format. Newer schema versions may be accepted when the compatibility range explicitly includes the current version.

### Import resolution (best-effort)

Impact edges are derived from static/heuristic import resolution. Supported patterns include:

- Literal import strings (`import "./foo"`, `require("./bar")`, `from pkg import x`)
- String concatenation with literals and constant identifiers (`"./foo" + "/bar"`)
- Static path joins (`path.join("./dir", "file")`, `path.resolve("./dir", "file")`, `os.path.join("pkg", "mod")`)
- Template literals or f-strings when all substitutions resolve to static values; if the resulting pattern matches a unique repo file, emit an edge (`./dir/${name}.js`)
- Python `importlib.import_module(...)` and `importlib.util.spec_from_file_location(..., path)`
- Rust `mod`/`use` and `include!`/`include_str!`/`include_bytes!`

Unresolved dynamic imports are **skipped** (no "unknown" edges are emitted). Counts/samples are surfaced in `diagnostics` and logs.

Optional import hints:

- `docdex.import_map.json` at the repo root can provide explicit mappings or edges for dynamic imports.
- `docdex.import_traces.jsonl` can supply resolved runtime traces (one JSON object per line).

## Impact diagnostics response (`docdex.impact_diagnostics`)

Impact diagnostics responses list unresolved dynamic import diagnostics across files.

**Required top-level fields**

```json
{
  "schema": { "name": "docdex.impact_diagnostics", "version": 1, "compatible": { "min": 1, "max": 1 } },
  "repo_id": "<sha256 fingerprint>",
  "total": 0,
  "limit": 200,
  "offset": 0,
  "truncated": false,
  "diagnostics": []
}
```

**Diagnostics entry fields (v1)**

- `file` (string, required): repo-relative file path.
- `diagnostics` (object, required):
  - `unresolvedImportsTotal` (integer)
  - `unresolvedImportsSample` (string array)
