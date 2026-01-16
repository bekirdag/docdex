# Docdex — Agent Prompt

You are interacting with Docdex, a local-first indexer/search daemon for docs and source code. It keeps a per-repo index on disk and serves search, chat, and code intelligence results over HTTP, CLI, or MCP. No external services or uploads are required.

## What Docdex does
- Builds a Tantivy-based index under `~/.docdex/state/repos/<fingerprint>/index` (docs + common code extensions).
- Serves HTTP endpoints: `/search`, `/snippet`, `/v1/chat/completions`, `/v1/symbols`, `/v1/ast`, `/v1/graph/impact`, `/healthz`.
- CLI commands mirror the API: `docdexd index|serve|chat|ingest|self-check` (chat includes a REPL when `--query` is omitted).
- MCP endpoint (HTTP/SSE) exposes `docdex_search`, `docdex_web_research`, `docdex_index`, `docdex_files`, `docdex_open`, `docdex_stats`, `docdex_repo_inspect`, `docdex_symbols`, `docdex_ast`, `docdex_impact_diagnostics`, `docdex_memory_store/recall`.
- Watches files while serving to keep the index fresh; memory is enabled by default and web fallback is gated (disabled unless `DOCDEX_WEB_ENABLED=1`).

## How to use
- Install via npm: `npm i -g docdex` (or `npx docdex --version`).
- Build an index: `docdexd index --repo /path/to/repo`.
- Serve API: `docdexd serve --repo /path/to/repo --host 127.0.0.1 --port 28491 --log info` (use `--expose --auth-token <token>` for non-loopback binds).
- Query via CLI: `docdexd chat --repo /path/to/repo --query "term" --limit 5` (omit `--query` for REPL).
- Web fallback: set `DOCDEX_WEB_ENABLED=1` (otherwise web is disabled).
- Health: `GET /healthz` should return `ok`.

## Security/constraints
- Defaults bind to `127.0.0.1`; non-loopback binds require `--expose` and `--auth-token`. Secure mode is on by default and enables default rate limiting.
- Index stays on disk; do not upload corpus or snippets externally.
- Respect rate limits and request size defaults (`max_query_bytes`, `max_request_bytes`, `max_limit`).

## Paths and binaries
- Binary name: `docdexd` (`docdex` alias via npm).
- Index path: `~/.docdex/state/repos/<fingerprint>/index` (or `DOCDEX_STATE_DIR` as a base override).
- Supported published platforms: macOS (arm64/x64), Linux glibc (arm64/x64), Linux musl (x64), Windows (x64).
- Unpublished/unsupported (fails gracefully): Linux musl (arm64), Windows (arm64).

## Environment overrides (common)
- `DOCDEX_STATE_DIR` — override state base directory.
- `DOCDEX_HTTP_BASE_URL` — point CLI to a running daemon.
- `DOCDEX_ENABLE_MEMORY` — enable/disable memory endpoints (default enabled via config).
- `DOCDEX_WEB_ENABLED` / `DOCDEX_OFFLINE` — enable web fallback or force offline.
- `DOCDEX_AUTH_TOKEN` — bearer token for HTTP/MCP auth when required.
- `DOCDEX_DOWNLOAD_REPO` — owner/repo for release assets (npm installer).
- `DOCDEX_GITHUB_TOKEN` — authenticated downloads of release assets (avoids rate limits/private releases).

## Agent guidance
- Keep queries concise; prefer summary-only when possible (`snippets=false`), then fetch snippets for selected docs.
- Avoid sending sensitive content elsewhere; Docdex is local—keep data local.
- When returning snippets, include `rel_path` so humans can navigate the source.
- If your client supports MCP, use `docdex_search` for repo context, `docdex_web_research` for web fallback, `docdex_index` when results look stale, and `docdex_open` to read files; use symbols/AST/impact tools for code intelligence when needed.
- When integrating Docdex into a new repo, add `.docdex/` to `.gitignore` only if you opt into an in-repo `--state-dir`.
- MCP client setup: register a server named `docdex` that points to `http://localhost:28491/v1/mcp/sse` (Codex uses `http://localhost:28491/v1/mcp`). Use the Docdex helper to auto-add wherever possible: `docdex mcp-add --repo <repo>` (add `--all` to attempt every supported client, or `--remove` to uninstall). Then use the MCP tools instead of shelling out.
