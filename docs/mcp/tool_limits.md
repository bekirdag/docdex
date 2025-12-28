# MCP tool output limits policy

This document defines repo-invariant output bounds and enforcement semantics for
MCP tools exposed by `docdexd mcp`. The goal is predictable payload sizes and
stable JSON schemas across all clients.

## Scope

- Applies to MCP tools exposed by `docdexd mcp`.
- Limits are server-wide and repo-invariant. Repo configuration cannot increase
  maxima.
- Tools never aggregate across repos; responses are scoped to the server repo.

## Enforcement semantics

- Clamp for count-like inputs: `limit`, `offset`, and `top_k` are clamped to the
  server max; no error is returned for over-limit requests. Effective values are
  returned via existing fields (`limit`, `offset`, `top_k`).
- Validation error for invalid inputs or oversize content: return JSON-RPC
  `-32602` with Docdex codes from `docs/mcp/errors.md` (e.g. `invalid_query`,
  `invalid_argument`, `invalid_range`, `max_content_exceeded`).
- Schema stability: limit enforcement never introduces tool-specific fields or
  ad hoc flags (no "clamped" or "truncated" fields). Use the existing response
  schema or the canonical error envelope.

## Tool bounds (current implementation)

| Tool | Max items returned | Content/snippet bounds | Enforcement notes |
| --- | --- | --- | --- |
| `docdex_search` | `limit` clamped to `[1, max_results]` (default `8`, set by `--max-results` or `DOCDEX_MCP_MAX_RESULTS`) | Summary max `360` chars, snippet max `420` chars per hit | Clamp `limit`; empty/invalid query returns `invalid_query`. |
| `docdex_web_research` | `limit` clamped to `[1, max_results]`; `web_limit` clamped to `[1, DOCDEX_WEB_MAX_HITS]` when set | Summary max `360` chars, snippet max `420` chars per hit | Clamp `limit`/`web_limit`; returns `webDiscovery` status for disabled/unavailable web. |
| `docdex_files` | `limit` clamped to `[1, 1000]`, `offset` clamped to `[0, 50000]` | Summary max `360` chars per result | Clamp `limit`/`offset`. |
| `docdex_open` | Single file slice | Content max `512 KiB` | Oversize content returns `max_content_exceeded`; invalid line window returns `invalid_range`. |
| `docdex_index` | Output arrays are bounded by input `paths` length | N/A | No server-side expansion beyond input list. |
| `docdex_stats` | N/A | N/A | Fixed shape only. |
| `docdex_repo_inspect` | N/A | N/A | Fixed shape only. |
| `docdex_symbols` | Single file record | Schema-defined payload (`docs/contracts/code_intelligence_schema_v1.md`) | No multi-file aggregation; errors per `docs/mcp/errors.md`. |
| `docdex_ast` | `max_nodes` clamped to `[1, 100000]` (default `20000`) | Schema-defined payload (`docs/contracts/code_intelligence_schema_v1.md`) | Clamp `max_nodes`; errors per `docs/mcp/errors.md`. |
| `docdex_impact_diagnostics` | `limit` clamped to `[1, 1000]` when listing all files | Diagnostics are bounded by stored impact entries | Clamp `limit`; file-scoped queries return one entry. |
| `docdex_memory_save` | Single record | N/A | Rejects empty text (`invalid_argument`). |
| `docdex_memory_store` | Alias for `docdex_memory_save` | N/A | Same limits/errors as `docdex_memory_save`. |
| `docdex_memory_recall` | `top_k` clamped to `[1, 50]` | Returns stored text as-is | Clamp `top_k`; errors per `docs/mcp/errors.md`. |

## Schema compatibility guarantees

- Response shapes and field names are stable; removing or renaming fields is a
  breaking change.
- Adding new optional fields is permitted if clients can ignore unknown fields.
- For schema-bearing payloads (e.g. `docdex.symbols`), use the `schema` object
  and compatibility window defined in `docs/contracts/code_intelligence_schema_v1.md`.
