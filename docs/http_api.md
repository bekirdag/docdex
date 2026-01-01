# Docdex HTTP API

Docdex runs a per-repo HTTP server by default (default `127.0.0.1:3210`). Secure mode is on by default; include `Authorization: Bearer <token>` when `--auth-token` is set.

When running the singleton daemon (`docdexd daemon`), the server can mount multiple repos. Call `POST /v1/initialize` with `rootUri` to mount a repo and then pass its `repo_id` on subsequent requests.

## Repo scoping

- The daemon is per-repo by default; `repo_id` is optional but must match the daemon repo when provided.
- In singleton mode, `repo_id` selects the mounted repo returned by `/v1/initialize`.
- Pass `repo_id` in the query/body or set `x-docdex-repo-id` for endpoints that support it.
- MCP initialize (`/sse` + `/v1/mcp/message`) with `rootUri`/`workspace_root` triggers `/v1/initialize` and binds the MCP session to that repo. Per-request `project_root`/`repo_path` can override the bound repo for `/v1/mcp`.

## Endpoints

- `GET /healthz` - basic health check.
- `POST /v1/initialize` - validate repo context and return repo metadata.
  - Body: `{ "rootUri": "<file://... or absolute path optional>" }`.
  - Response: `{ "repo_id": "<sha256>", "status": "ready", "repo_root": "<path>" }`.
- `POST /v1/mcp` - MCP JSON-RPC over HTTP (single request/response).
  - Body: JSON-RPC request (`initialize`, `tools/list`, `tools/call`, ...).
- `GET /v1/mcp/sse` (alias `GET /sse`) - MCP SSE stream.
  - Response header `x-docdex-mcp-session` provides the session id.
- `POST /v1/mcp/message` - enqueue MCP JSON-RPC to an SSE session.
  - Header `x-docdex-mcp-session` or `?session_id=` required.
- `GET /search` - full-text search.
  - Query params: `q`, `limit`, `snippets`, `max_tokens`, `include_libs`, `force_web`, `skip_local_search`, `no_cache`, `max_web_results`, `llm_filter_local_results`, `diff_mode`, `diff_base`, `diff_head`, `diff_path`, `repo_id`.
- `GET /snippet/:doc_id` - snippet for a document.
  - Query params: `window`, `q`, `text_only`, `max_tokens`.
- `POST /v1/index/rebuild` - rebuild the repo index.
  - Body: `{ "libs_sources": "<path optional>" }`.
- `POST /v1/index/ingest` - ingest a single file.
  - Body: `{ "file": "<path>" }`.
- `POST /v1/libs/discover` - discover library documentation sources for a repo.
  - Body: `{ "sources_path": "<path optional>", "repo_id": "<optional>" }`.
- `POST /v1/libs/fetch` - discover + ingest library sources for a repo.
  - Body: `{ "sources_path": "<path optional>", "repo_id": "<optional>" }`.
- `POST /v1/libs/ingest` - ingest library sources from a sources file.
  - Body: `{ "sources_path": "<path>", "repo_id": "<optional>" }`.
- `POST /v1/chat/completions` - OpenAI-compatible chat completion with docdex context.
  - Optional `docdex` object (`limit`, `force_web`, `skip_local_search`, `no_cache`, `include_libs`, `max_web_results`, `llm_filter_local_results`, `compress_results`, `diff`, `agent_id`) plus `repo_id`.
  - Header `x-docdex-agent-id` overrides `docdex.agent_id`.
  - Response may include `reasoning_trace` (non-streaming) with `behavioral_truth` (style/workflow) and `technical_truth` (memory/repo/web).
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
- `GET /v1/profile/list` - list agents and preferences (global profile memory).
  - Query params: `agent_id` (optional).
- `POST /v1/profile/add` - add a profile preference (immediate write).
  - Body: `{ "agent_id": "<string>", "content": "<string>", "category": "<style|tooling|constraint|workflow>", "role": "<string optional>" }`.
- `POST /v1/profile/save` - add a preference and trigger background evolution.
  - Body: `{ "agent_id": "<string>", "content": "<string>", "category": "<style|tooling|constraint|workflow>", "role": "<string optional>" }`.
- `POST /v1/profile/search` - semantic search across preferences for an agent.
  - Body: `{ "agent_id": "<string>", "query": "<string>", "top_k": <int optional> }`.
- `POST /v1/profile/export` - export all agents/preferences to a JSON manifest.
- `POST /v1/profile/import` - import a JSON manifest with LWW merge.
- `POST /v1/hooks/validate` - semantic hook validation (pre-commit).
  - Body: `{ "files": ["<repo-relative path>", "..."] }`.
- `GET /v1/dag/export` - export a reasoning DAG trace.
  - Query params: `session_id`, `format` (`json|text|dot`), `max_nodes`, `repo_id`.
- `POST /v1/web/search` - web discovery (requires `DOCDEX_WEB_ENABLED=1`).
- `POST /v1/web/fetch` - fetch a single web URL (requires `DOCDEX_WEB_ENABLED=1`).
- `POST /v1/web/cache/flush` - clear cached web entries.
- `GET /ai-help` - JSON quickstart for agents (endpoints, CLI commands, limits).
- `GET /metrics` - Prometheus-style metrics.
- `GET /v1/gates/status` - quality gate summary (error rate, latency p95, soak status).

## Error envelope

Most endpoints return `{ "error": { "code": "<docdex_code>", "message": "<string>" } }` on failure (see `docs/mcp/errors.md` for shared codes). Some dependency failures include `details` with remediation hints (e.g., `/v1/web/fetch` when no browser is available).

## Config highlights

- `[memory.profile]` controls profile embedding config:
  - `embedding_model` (default `nomic-embed-text`)
  - `embedding_dim` (default `768`)
- `[server].default_agent_id` sets the fallback agent used when requests omit `agent_id` (also configurable via `DOCDEX_DEFAULT_AGENT_ID` / `docdexd serve --agent-id`).
- `[server].hook_socket_path` enables Unix socket transport for `/v1/hooks/validate` (HTTP remains available).
- `[web.scraper].auto_install` controls Linux auto-install of headless Chromium; `[web.scraper].chrome_binary_path` and `[web.scraper].browser_kind` store the resolved browser binary.
