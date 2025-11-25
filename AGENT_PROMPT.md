# Docdex — Agent Prompt

You are interacting with Docdex, a local documentation indexer/search daemon. It keeps a per-repo index of Markdown/text files on disk and serves search/snippet results over HTTP and CLI. No external services are used; all data stays local.

## What Docdex does
- Builds a tantivy-based index under `<repo>/.docdex/index`.
- Serves HTTP endpoints: `/search`, `/snippet`, `/healthz`.
- CLI commands mirror the API: `docdexd index|serve|query|ingest|self-check`.
- Optional MCP mode (stdio) exposes `docdex.search` and `docdex.index` tools for MCP-aware clients.
- Watches files while serving to keep the index fresh.

## How to use
- Install via npm: `npm i -g docdex` (or `npx docdex --version`).
- Build an index: `docdexd index --repo /path/to/repo`.
- Serve API: `docdexd serve --repo /path/to/repo --host 127.0.0.1 --port 46137 --log info --auth-token <token>` (or add `--secure-mode=false` for token-free local use).
- Query via CLI: `docdexd query --repo /path/to/repo --query "term" --limit 5`.
- Health: `GET /healthz` should return `ok`.

## Security/constraints
- Defaults bind to `127.0.0.1`; secure mode is on by default and requires an auth token, loopback-only allowlist, and default rate limiting. Add `--secure-mode=false` (and set `--allow-ip`/`--rate-limit-per-min`) when you need broader access. Respect local-only behavior unless configured otherwise.
- Index stays on disk; do not upload corpus or snippets externally.
- Respect rate limits and request size defaults (`max_query_bytes`, `max_request_bytes`, `max_limit`).

## Paths and binaries
- Binary name: `docdexd` (`docdex` alias via npm).
- Index path: `<repo>/.docdex/index` (or `DOCDEX_STATE_DIR`).
- Supported platforms: macOS (arm64/x64), Linux glibc (arm64/x64), Linux musl (arm64/x64), Windows (x64/arm64) with matching release artifacts.

## Environment overrides (common)
- `DOCDEX_STATE_DIR` — override index location.
- `DOCDEX_DOWNLOAD_REPO` — owner/repo for release assets (npm installer).
- `DOCDEX_LIBC` — force `gnu` or `musl` on Linux.
- `DOCDEX_GITHUB_TOKEN` — authenticated downloads of release assets (avoids rate limits/private releases).

## Agent guidance
- Keep queries concise; prefer summary-only when possible (`snippets=false`), then fetch snippets for selected docs.
- Avoid sending sensitive content elsewhere; Docdex is local—keep data local.
- When returning snippets, include `rel_path` so humans can navigate the source.
- If your client supports MCP, use `docdex.search` (concise queries, low `limit`) for repo-specific context, `docdex.index` when results look stale, `docdex.files` to list indexed docs, and `docdex.stats` to confirm doc counts/recency; otherwise keep using HTTP/CLI.
- When integrating Docdex into a new repo, ensure `.docdex/` (especially `.docdex/index/`) is listed in `.gitignore` so index artifacts are never committed.
- MCP client setup: register a server named `docdex` that runs `docdexd mcp --repo <repo> --log warn --max-results 8` (or `docdex mcp ...` from npm). Then use the MCP tools instead of shelling out.
