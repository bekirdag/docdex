# Docdex HTTP API

Docdex exposes a local HTTP server (default `127.0.0.1:3210`). Use it directly or through MCP.

## Base URL and auth

- Default base URL: `http://127.0.0.1:3210`
- Secure mode is on by default for non-loopback binds.
- If `--auth-token` is set, include `Authorization: Bearer <token>`.

## Repo scoping

Docdex can run in two modes:

- Per-repo daemon: `repo_id` is optional but must match the daemon repo when provided.
- Singleton daemon: mount repos with `POST /v1/initialize` and pass `repo_id` on later requests.

Repo selection rules:

- `repo_id` can be sent in the query/body or in the header `x-docdex-repo-id`.
- MCP initialize over `/sse` + `/v1/mcp/message` binds the session to a repo.
- `/v1/mcp` requests can override the bound repo using `project_root`/`repo_path`.

## Common headers

- `Authorization: Bearer <token>`
- `x-docdex-repo-id: <sha256>`
- `x-docdex-agent-id: <agent>`

## Health and metrics

- `GET /healthz` - basic health check.
- `GET /metrics` - Prometheus counters and timers.
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
- `skip_local_search`
- `no_cache`
- `max_web_results`
- `llm_filter_local_results`
- `diff_mode`, `diff_base`, `diff_head`, `diff_path`
- `repo_id`

Example:
```bash
curl "http://127.0.0.1:3210/search?q=payment%20retry&limit=5"
```

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
    "diff": { "mode": "head" }
  }
}
```

Notes:
- `x-docdex-agent-id` overrides `docdex.agent_id`.
- Non-streaming responses can include `reasoning_trace` with `behavioral_truth` and `technical_truth`.

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
  "kinds": ["function_definition"],
  "name": "addressGenerator",
  "pathPrefix": "src",
  "limit": 20
}
```

### Impact graph

`GET /v1/graph/impact`

Query params:
- `file`
- `repo_id`
- `maxEdges`
- `maxDepth`
- `edgeTypes`

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
