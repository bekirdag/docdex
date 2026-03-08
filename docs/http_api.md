# Docdex HTTP API

Docdex exposes a local HTTP server (default `127.0.0.1:28491`). Use it directly or through MCP.

## Base URL and auth

- Default base URL: `http://127.0.0.1:28491`
- Secure mode is on by default for non-loopback binds.
- If `--auth-token` is set, include `Authorization: Bearer <token>`.

## IPC transport (local)

Docdex can serve the same HTTP endpoints over local IPC (Unix domain socket or Windows named pipe).
Use the `/v1/mcp` JSON-RPC endpoint over IPC with the same request/response payloads as HTTP.
HTTP/SSE (`/v1/mcp/sse`) remains available over TCP.

## Repo scoping

Docdex can run in two modes:

- Per-repo daemon: `repo_id` is optional but must match the daemon repo when provided.
- Singleton daemon: mount repos with `POST /v1/initialize` and pass `repo_id` on later requests. If the daemon starts without a default repo or has more than one repo mounted, `repo_id` becomes required for all repo-scoped endpoints.

Repo selection rules:

- `repo_id` can be sent in the query/body or in the header `x-docdex-repo-id`.
- MCP initialize over `/sse` + `/v1/mcp/message` must include `rootUri` when multiple repos are active.
- MCP SSE sessions bind to the repo and reuse it for subsequent tool calls.
- `/v1/mcp` requests can override the bound repo using `project_root`/`repo_path`.

## Common headers

- `Authorization: Bearer <token>`
- `x-docdex-repo-id: <sha256>`
- `x-docdex-agent-id: <agent>`

## Health and metrics

- `GET /healthz` - basic health check.
- `GET /metrics` - Prometheus counters and timers.
- `GET /v1/telemetry/delegation` - delegation savings telemetry (repo-scoped by default; add `?all=true` for daemon-global totals across all mounted repos).
- `GET /v1/gates/status` - quality gate summary.

## Repo lifecycle

### Initialize

`POST /v1/initialize`

Request body:
```json
{ "rootUri": "file:///path/to/repo" }
```

Behavior:
- Validates repo context.
- Mounts the repo in singleton mode.
- Triggers background indexing if needed.

Response:
```json
{ "repo_id": "<sha256>", "status": "ready|indexing", "repo_root": "/path" }
```

## Search and snippets

### Search

`GET /search`

Query params:
- `q` (required)
- `limit`
- `snippets`
- `max_tokens`
- `include_libs`
- `force_web`
- `async_web`
- `skip_local_search`
- `no_cache`
- `max_web_results`
- `llm_filter_local_results`
- `diff_mode`, `diff_base`, `diff_head`, `diff_path`
- `dag_session_id`
- `repo_id`

Example:
```bash
curl "http://127.0.0.1:28491/search?q=payment%20retry&limit=5"
```

Notes:
- `async_web=true` (default) returns local hits immediately and defers web discovery in the background; `web_discovery.status` returns `skipped` with reason `async_deferred`.
- If the index is missing or still building, `/search` returns HTTP 202 with `indexing_in_progress` and a `status_url` to poll.

Header:
- `x-docdex-dag-session` (optional)


### Capabilities

`GET /v1/capabilities`

Returns the optional-feature capability contract and bounded limits for retrieval enhancements.

Response fields include:
- `contract_version`
- retrieval feature flags (`score_breakdown`, `rerank`, `snippet_provenance`, `retrieval_explanation`, `batch_search`)
- MCP/HTTP feature flags
- limit values (`rerank_max_candidates`, `batch_search_max_queries`, `explanation_max_chars`)

### Rerank

`POST /v1/search/rerank`

Request body:
```json
{
  "query": "capabilities",
  "candidates": [
    {
      "doc_id": "docs/usage.md",
      "snippet": "..."
    }
  ],
  "limit": 5,
  "repo_id": "<optional>"
}
```

Response fields:
- `hits`
- `returned_count`
- `input_count`
- `limit`
- `truncated`

Notes:
- `candidates` is required and must be non-empty.
- Candidate input is deterministically truncated to the runtime maximum (`rerank_max_candidates` from `/v1/capabilities`).

### Batch search

`POST /v1/search/batch`

Request body:
```json
{
  "queries": ["auth flow", "retry policy"],
  "limit": 8,
  "include_libs": true,
  "repo_id": "<optional>"
}
```

Response fields:
- `results` (per-query search responses)
- `query_count`
- `effective_query_count`
- `limit`
- `truncated`

Notes:
- `queries` is required and must include at least one non-empty value.
- Query lists are deterministically truncated to the runtime maximum (`batch_search_max_queries` from `/v1/capabilities`).

### Snippet

`GET /snippet/:doc_id`

Query params:
- `window`
- `q`
- `text_only`
- `max_tokens`

## Chat

`POST /v1/chat/completions`

OpenAI-compatible chat with Docdex context.

Request body:
```json
{
  "model": "fake-model",
  "messages": [{ "role": "user", "content": "Where is the retry logic?" }],
  "docdex": {
    "agent_id": "agent-1",
    "limit": 6,
    "compress_results": false,
    "skip_local_search": false,
    "force_web": false,
    "include_libs": true,
    "max_web_results": 8,
    "llm_filter_local_results": false,
    "no_cache": false,
    "dag_session_id": "session-123",
    "diff": { "mode": "head" }
  }
}
```

Notes:
- `x-docdex-agent-id` overrides `docdex.agent_id`.
- `x-docdex-dag-session` overrides `docdex.dag_session_id`.
- Non-streaming responses can include `reasoning_trace` with `behavioral_truth` and `technical_truth`.

## Delegation (local completion)

`POST /v1/delegate`

Request body:
```json
{
  "task_type": "format_code",
  "instruction": "Format this code",
  "context": "let  a=1;",
  "agent": "ollama-local",
  "max_tokens": 512,
  "timeout_ms": 30000,
  "mode": "draft_only",
  "max_context_chars": 12000,
  "repo_id": "<optional>"
}
```

Response:
```json
{
  "id": "uuid",
  "adapter": "ollama",
  "model": "llama3",
  "output": "let a = 1;",
  "draft": true,
  "truncated": false,
  "warnings": []
}
```

Notes:
- Requires `[llm.delegation].enabled = true` or `auto_enable = true` with a local model/agent available.
- `task_type` must be one of: `generate_tests`, `write_docstring`, `scaffold_boilerplate`, `refactor_simple`, `format_code`.
- `mode` defaults to `[llm.delegation].mode` when omitted.
- `draft_then_refine` returns a primary-agent refinement when configured; otherwise returns the local draft with a warning.
- `agent` overrides the local agent id for this request only; otherwise Docdex selects from the local model library.

## Delegation telemetry

`GET /v1/telemetry/delegation`

Response:
```json
{
  "generated_at_epoch_ms": 1710000000000,
  "delegate_requests_total": 12,
  "delegate_offloaded_total": 10,
  "delegate_fallbacks_total": 2,
  "delegate_token_estimate_total": 4200,
  "delegate_local_tokens_total": 3100,
  "delegate_primary_tokens_total": 400,
  "delegate_tokens_total": 3500,
  "delegate_token_savings_total": 3100,
  "delegate_local_cost_micros_total": 0,
  "delegate_primary_cost_micros_total": 1200000,
  "delegate_cost_savings_micros_total": 950000,
  "delegate_cost_savings_usd": 0.95,
  "pricing": {
    "primary_usd_per_1k_tokens": 2.5,
    "local_usd_per_1k_tokens": 0.0
  }
}
```

Notes:
- The response is repo-scoped. In multi-repo daemon mode, send `repo_id` or `x-docdex-repo-id`; if more than one repo is mounted and no repo is selected, the endpoint returns `missing_repo`.
- `delegate_offloaded_total` counts requests that produced a local draft.
- Savings use actual local token usage and mcoda `cost_per_million` when available; Ollama models are treated as $0.
- `pricing` reflects `[llm.delegation]` defaults and may differ from mcoda agent costs.

## Code intelligence

Supported AST/symbols languages: Rust, Python, JavaScript, TypeScript, Go, Java, C#, C/C++, PHP, Kotlin, Swift, Ruby, Lua, Dart.

### Symbols

`GET /v1/symbols`

Query params:
- `path` (repo-relative)
- `repo_id`

### Symbols status

`GET /v1/symbols/status`

Query params:
- `repo_id`

### AST (file)

`GET /v1/ast`

Query params:
- `path` (repo-relative)
- `maxNodes`
- `repo_id`

### AST (search)

`GET /v1/ast/search`

Query params:
- `kinds`
- `mode`
- `limit`
- `repo_id`

### AST (query)

`POST /v1/ast/query`

Request body:
```json
{
  "kinds": ["function_item"],
  "name": "addressGenerator",
  "pathPrefix": "src",
  "limit": 20
}
```

Notes:
- `repo_id` may be provided in the query string or request body.
- AST kinds are tree-sitter node kinds and are language-specific (e.g. Rust: `function_item`, `struct_item`; JS/TS: `function_declaration`, `class_declaration`; Python: `function_definition`, `class_definition`).

### Impact graph

`GET /v1/graph/impact`

Query params:
- `file`
- `repo_id`
- `maxEdges`
- `maxDepth`
- `edgeTypes`

### DAG export

`GET /v1/dag/export`

Query params:
- `session_id` (required)
- `format` (optional: json/text/dot; default json)
- `max_nodes` (optional)
- `repo_id` (required when multiple repos are mounted)

`GET /v1/graph/impact/diagnostics`

Query params:
- `file`
- `limit`
- `offset`

## Indexing

- `POST /v1/index/rebuild` - rebuild the repo index.
  - Body: `{ "libs_sources": "<path optional>" }`
- `POST /v1/index/ingest` - ingest a single file.
  - Body: `{ "file": "<path>" }`
- `GET /v1/index/status` - report index readiness, docs count, and last updated timestamp.
  - Query: `repo_id`

## Folder tree

Folder tree rendering is exposed via the CLI (`docdexd tree`) and the MCP tool `docdex_tree` (no HTTP endpoint).

## Library docs

- `POST /v1/libs/discover` - discover library sources.
- `POST /v1/libs/fetch` - discover + ingest library sources.
- `POST /v1/libs/ingest` - ingest from a sources file.

Each accepts `sources_path` and optional `repo_id`.

## Repo memory

- `POST /v1/memory/store`
  - Body: `{ "text": "...", "metadata": { ... } }`
- `POST /v1/memory/recall`
  - Body: `{ "query": "...", "top_k": 5 }`

## Agent memory (profiles)

- `GET /v1/profile/list`
- `POST /v1/profile/add`
- `POST /v1/profile/save`
- `POST /v1/profile/search`
- `POST /v1/profile/export`
- `POST /v1/profile/import`

## Hooks

`POST /v1/hooks/validate`

Body:
```json
{ "files": ["src/main.rs", "README.md"] }
```

## Web (optional)

Web discovery requires `DOCDEX_WEB_ENABLED=1` (daemon enables it by default).

- `POST /v1/web/search`
- `POST /v1/web/fetch`
- `POST /v1/web/cache/flush`

`POST /v1/web/search` body:
```json
{ "query": "...", "limit": 8, "dag_session_id": "session-123" }
```
Header:
- `x-docdex-dag-session` (optional)

## MCP transport

- `POST /v1/mcp` - MCP JSON-RPC over HTTP.
- `GET /v1/mcp/sse` or `GET /sse` - MCP SSE stream.
  - Response header `x-docdex-mcp-session` contains the session id.
- `POST /v1/mcp/message` - send MCP JSON-RPC to a session.
  - Use `x-docdex-mcp-session` header or `?session_id=` query.

## Errors

Most endpoints return:
```json
{ "error": { "code": "<docdex_code>", "message": "..." } }
```

See `docs/mcp/errors.md` for shared error codes.

## Config highlights

- `[memory.profile]` controls profile embedding config.
  - `embedding_model` (default `nomic-embed-text`)
  - `embedding_dim` (default `768`)
- `[server].default_agent_id` sets the fallback agent for requests without `agent_id`.
- `[server].hook_socket_path` enables a Unix socket transport for hooks.
- `[web.scraper]` stores browser detection and Linux auto-install settings.
