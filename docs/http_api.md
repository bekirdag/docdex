# Docdex HTTP API

Docdex runs a per-repo HTTP server (default `127.0.0.1:3210`). Secure mode is on by default; include `Authorization: Bearer <token>` when `--auth-token` is set.

## Repo scoping

- The daemon is per-repo; `repo_id` is optional but must match the daemon repo when provided.
- Pass `repo_id` in the query/body or set `x-docdex-repo-id` for endpoints that support it.

## Endpoints

- `GET /healthz` - basic health check.
- `GET /search` - full-text search.
  - Query params: `q`, `limit`, `snippets`, `max_tokens`, `include_libs`, `force_web`, `skip_local_search`, `no_cache`, `max_web_results`, `llm_filter_local_results`, `diff_mode`, `diff_base`, `diff_head`, `diff_path`, `repo_id`.
- `GET /snippet/:doc_id` - snippet for a document.
  - Query params: `window`, `q`, `text_only`, `max_tokens`.
- `POST /v1/index/rebuild` - rebuild the repo index.
  - Body: `{ "libs_sources": "<path optional>" }`.
- `POST /v1/index/ingest` - ingest a single file.
  - Body: `{ "file": "<path>" }`.
- `POST /v1/chat/completions` - OpenAI-compatible chat completion with docdex context.
  - Optional `docdex` object (`limit`, `force_web`, `skip_local_search`, `no_cache`, `include_libs`, `max_web_results`, `llm_filter_local_results`, `compress_results`, `diff`) plus `repo_id`.
- `GET /v1/graph/impact` - impact graph edges for a file.
  - Query params: `file`, `repo_id`, `maxEdges`, `maxDepth`, `edgeTypes`.
- `GET /v1/graph/impact/diagnostics` - unresolved import diagnostics.
  - Query params: `file`, `limit`, `offset`.
- `GET /v1/symbols` - symbols for a repo-relative file.
  - Query params: `path`, `repo_id`.
- `GET /v1/symbols/status` - Tree-sitter parser drift status.
  - Query params: `repo_id`.
- `GET /v1/ast` - AST nodes for a repo-relative file.
  - Query params: `path`, `maxNodes`, `repo_id`.
- `GET /v1/ast/search` - AST search by node kinds.
  - Query params: `kinds`, `mode`, `limit`, `repo_id`.
- `POST /v1/ast/query` - structural AST query.
  - Body includes `kinds`, optional `name`, `field`, `pathPrefix`, `mode`, `limit`, `sampleLimit`, `repo_id`.
- `POST /v1/memory/store` - store a memory item (enabled by default).
  - Body: `{ "text": "<string>", "metadata": { ... } }`.
- `POST /v1/memory/recall` - recall memory items by embedding similarity.
  - Body: `{ "query": "<string>", "top_k": <int> }`.
- `POST /v1/web/search` - web discovery (requires `DOCDEX_WEB_ENABLED=1`).
- `POST /v1/web/fetch` - fetch a single web URL (requires `DOCDEX_WEB_ENABLED=1`).
- `POST /v1/web/cache/flush` - clear cached web entries.
- `GET /ai-help` - JSON quickstart for agents (endpoints, CLI commands, limits).
- `GET /metrics` - Prometheus-style metrics.

## Error envelope

Most endpoints return `{ "error": { "code": "<docdex_code>", "message": "<string>" } }` on failure (see `docs/mcp/errors.md` for shared codes).
