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

Docdex caps `error_summary` to 200 chars, `signature` to 240 chars, and the `symbols` array to 1000 items per file.

**Symbol item fields (v1)**

- `symbol_id` (string, required): Deterministic identifier stable across runs for the same repo snapshot.
  - v1 format: `"<repo_id>:<file>#<start_line>:<start_col>-<end_line>:<end_col>:<kind>:<name>"`
- `name` (string, required)
- `kind` (string, required): Language-agnostic kind label (e.g. `function`, `class`, `method`, `variable`, `module`).
- `range` (object, required): 1-based positions within `file`.
  - `start_line`, `start_col`, `end_line`, `end_col` (integers)
- `signature` (string, optional): Language-specific display signature if available.

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

### Output bounds (deterministic)

Impact graph responses are bounded to keep payloads predictable and repo-safe:

- `maxEdges` is hard-capped at 10,000. Requests above the cap are clamped to 10,000 and reported via `appliedLimits.maxEdges`.
- `inbound` and `outbound` arrays are capped to the applied `maxEdges` value (and therefore never exceed 10,000).
- Node path strings (`source`, `target`, `inbound`, `outbound`) are truncated to 512 bytes when needed.
- Edge label strings (`edges[].kind`, `edgeTypes`) are truncated to 128 bytes when needed.
- `truncated` is set to `true` when any clamp or truncation occurs (limits, filtering, or text truncation).

Truncation is UTF-8 safe and deterministic; it truncates at a character boundary and appends `...` when space allows.
