# Docdex

Docdex is a lightweight, local documentation indexer/search daemon. It runs per-project, keeps an on-disk index of your markdown/text docs, and serves top-k snippets over HTTP or CLI for any coding assistant or tool—no external services or uploads required.

## Install via npm
- Requires Node.js >= 18.
- Install: `npm i -g docdex` (or run `npx docdex --version` to verify).
- Commands: `docdex` (alias `docdexd`) downloads the right binary for your platform from the matching GitHub release.
- Supported targets: macOS (arm64, x64), Linux glibc (arm64, x64), Linux musl (arm64, x64), Windows (x64, arm64); installer fetches the matching platform release asset.
- If you publish from a fork, set `DOCDEX_DOWNLOAD_REPO=<owner/repo>` before installing so the downloader fetches your release assets.
- Distribution: binaries stay in GitHub Releases (small npm package); postinstall fetches `docdexd-<platform>.tar.gz` matching the npm version.
- Publishing uses npm Trusted Publishing (OIDC) — no NPM token needed; see `.github/workflows/release.yml`.

## Features at a glance
- Per-repo, local indexing of Markdown/text files (tantivy-backed; no network calls).
- HTTP API (`/search`, `/snippet`, `/healthz`) and CLI (`query`, `ingest`, `self-check`) share the same index.
- Live file watching while serving for incremental updates.
- Security knobs: TLS (manual certs or Certbot), auth token required by default (disable with `--secure-mode=false`), loopback-only allowlist by default, default rate limiting, request-size limits, strict state-dir perms, audit log, chroot/privilege drop/unshare net (Unix).
- Output ready for coding assistants: summaries, snippets, and doc metadata.
- AI-friendly: `GET /ai-help` returns a JSON playbook (endpoints, CLI commands, limits, best practices) for agents.

## What it does
- Indexes Markdown/text docs inside a repo and stores them locally (tantivy-based index under `<repo>/.docdex/index` by default).
- Serves the same index over HTTP (`/search`, `/snippet`, `/healthz`) and via CLI (`query`, `ingest`, `self-check`), so automation and interactive use share one dataset.
- Watches files while serving to incrementally ingest changes.
- Hardened defaults: loopback binding, TLS enforcement on non-loopback, auth token required by default (disable with `--secure-mode=false`), loopback-only allowlist and default rate limit (60 req/min) in secure mode, audit log enabled, and strict state-dir perms.

## How it works
1) `docdexd index` builds the on-disk index for your repo (or reuses a legacy `.gpt-creator/docdex/index` if present).  
2) `docdexd serve` loads that index, starts a file watcher for incremental updates, and exposes the HTTP API.  
3) HTTP clients or the CLI (`docdexd query`) read from the same index; `ingest` can update a single file without full reindexing.  
4) Optional TLS/auth/rate-limit settings secure remote access; audit logging can record access actions.

## Quick start
```bash
# install (npm)
npm i -g docdex
# or use once
npx docdex --version

# full index for a repo/workspace
docdexd index --repo /path/to/repo

# serve HTTP API with live file watching (secure mode requires an auth token)
docdexd serve --repo /path/to/repo --host 127.0.0.1 --port 46137 --log info --auth-token <token>
# for local, token-free use, add --secure-mode=false
# docdexd serve --repo /path/to/repo --host 127.0.0.1 --port 46137 --log info --secure-mode=false

# ad-hoc search via CLI (JSON)
docdexd query --repo /path/to/repo --query "otp flow" --limit 5
```

## TL;DR for agents
- Use Docdex for repo docs: run `docdexd index --repo .` once, then either `docdexd serve --repo . --host 127.0.0.1 --port 46137` for HTTP, or `docdexd mcp --repo . --log warn` for MCP.
- Add `.docdex/` to `.gitignore` so indexes aren’t committed.
- When MCP-aware, register a server named `docdex` that runs `docdexd mcp --repo . --log warn --max-results 8`, then call `docdex.search` before coding and `docdex.index` when stale.
- Prefer summary-first (snippets=false), fetch specific snippets only when needed, keep queries short, and respect token estimates.

## Usage cheat sheet
- Build index: `docdexd index --repo <path>` (add `--exclude-*` to skip paths).
- Serve with watcher: `docdexd serve --repo <path> --host 127.0.0.1 --port 46137 --log warn --auth-token <token>` (secure mode also allowlists loopback and rate-limits by default; add `--allow-ip`/`--secure-mode=false`/`--rate-limit-per-min` as needed for remote use).
- Secure serving: add `--auth-token <token>` (required by default); use TLS with `--tls-cert/--tls-key` or `--certbot-domain <domain>`.
- Single-file ingest: `docdexd ingest --repo <path> --file docs/new.md` (honors excludes).
- Query via CLI: `docdexd query --repo <path> --query "term" --limit 4`.
- Git hygiene: add `.docdex/` (and especially `.docdex/index/`) to your repo’s `.gitignore` so index artifacts never get committed.
- Health check: `curl http://127.0.0.1:46137/healthz`.
- Summary-only search responses: `curl "http://127.0.0.1:46137/search?q=foo&snippets=false"`; fetch snippets only for top hits.
- Token budgets: `curl "http://127.0.0.1:46137/search?q=foo&max_tokens=800"` to drop hits that would exceed your prompt budget; pair with `snippets=false` then fetch 1–2 snippets you keep.
- Text-only snippets: append `text_only=true` to `/snippet/:doc_id` or start `serve` with `--strip-snippet-html` (or `--disable-snippet-text` to return metadata only).
- Keep requests compact: defaults enforce `max_query_bytes=4096` and `max_request_bytes=16384`; keep queries short and leave `--max-limit` low (default 8) to avoid oversized responses.
- Prompt hygiene: in agent prompts, normalize whitespace and include only `rel_path`, `summary`, and trimmed `snippet` (omit `score`/`token_estimate`/`doc_id`).
- Trim noise early: use `--exclude-dir` and `--exclude-prefix` to keep vendor/build/cache/secrets out of the index so snippets stay relevant and short.
- Quiet logging for agents: run `docdexd serve --log warn --access-log=false` if you marshal responses elsewhere to cut log overhead.
- Cache hits client-side: store `doc_id` ↔ `rel_path` ↔ `summary` to avoid repeat snippet calls; fetch snippets only for new doc_ids.
- Agent help: `curl http://127.0.0.1:46137/ai-help` (requires auth if configured; include `Authorization: Bearer <token>` when you’ve set `--auth-token`).

## Versioning
- Semantic versioning with tagged releases (`vX.Y.Z`). The Rust crate and npm package share the same version.
- Conventional Commits drive release notes via Release Please; it opens release PRs that bump `Cargo.toml` and `npm/package.json`, update changelogs, and creates the tag/release on merge.
- Pin to a released version when integrating (e.g., in scripts or Dockerfiles) so upgrades are explicit and reversible.
- If you build from source, the version comes from `Cargo.toml` in this repo; the npm wrapper uses the matching version to fetch binaries.

## Paths and defaults
- State/index directory: `<repo>/.docdex/index` (if missing but legacy `<repo>/.gpt-creator/docdex/index` exists, Docdex will reuse it and warn). The directory is created with `0700` permissions by default.
- HTTP API: defaults to `127.0.0.1:46137` when serving.
- Docdex data and logs stay inside the repo; no external services.

## Configuration knobs
- `--repo <path>`: workspace root to index (defaults to `.`).
- `--state-dir <path>` / `DOCDEX_STATE_DIR`: override index storage path (relative paths are resolved under `repo`).
- `--exclude-prefix a,b,c` / `DOCDEX_EXCLUDE_PREFIXES`: extra relative prefixes to skip.
- `--exclude-dir a,b,c` / `DOCDEX_EXCLUDE_DIRS`: extra directory names to skip anywhere in the tree.
- `--auth-token <token>` / `DOCDEX_AUTH_TOKEN`: bearer token required in secure mode (default); omit only when starting with `--secure-mode=false`.
- `--secure-mode <true|false>` / `DOCDEX_SECURE_MODE`: default `true`; when enabled, requires an auth token, loopback allowlist by default, and default rate limiting (60 req/min).
- `--allow-ip a,b,c` / `DOCDEX_ALLOW_IPS`: optional comma-separated IPs/CIDRs allowed to reach the HTTP API (default: loopback-only in secure mode; allow all when secure mode is disabled).
- `--tls-cert` / `DOCDEX_TLS_CERT` and `--tls-key` / `DOCDEX_TLS_KEY`: serve HTTPS with the provided cert/key. With TLS enforcement on, non-loopback binds must use HTTPS unless you explicitly opt out.
- `--certbot-domain <domain>` / `DOCDEX_CERTBOT_DOMAIN`: point TLS at `/etc/letsencrypt/live/<domain>/{fullchain.pem,privkey.pem}` (Certbot). Conflicts with manual `--tls-*`.
- `--certbot-live-dir <path>` / `DOCDEX_CERTBOT_LIVE_DIR`: use a specific Certbot live dir containing `fullchain.pem` and `privkey.pem`.
- `--require-tls <true|false>` / `DOCDEX_REQUIRE_TLS`: default `true`. Enforce TLS for non-loopback binds; set to `false` when TLS is already terminated by a trusted proxy.
- `--insecure` / `DOCDEX_INSECURE_HTTP=true`: allow plain HTTP on non-loopback binds even when TLS is enforced (only use behind a trusted proxy).
- `--max-limit <n>` / `DOCDEX_MAX_LIMIT`: clamp HTTP `limit` to at most `n` (default: 8).
- `--max-query-bytes <n>` / `DOCDEX_MAX_QUERY_BYTES`: reject requests whose query string exceeds `n` bytes (default: 4096).
- `--max-request-bytes <n>` / `DOCDEX_MAX_REQUEST_BYTES`: reject requests whose Content-Length or size hint exceeds `n` bytes (default: 16384).
- `--rate-limit-per-min <n>` / `DOCDEX_RATE_LIMIT_PER_MIN`: per-IP request budget per minute (default 60 in secure mode when unset/0; 0 disables when secure mode is off).
- `--rate-limit-burst <n>` / `DOCDEX_RATE_LIMIT_BURST`: optional burst capacity for the rate limiter (defaults to per-minute limit when 0).
- `--audit-log-path <path>` / `DOCDEX_AUDIT_LOG_PATH`: write audit log JSONL to this path (default: `<state-dir>/audit.log`).
- `--audit-max-bytes <n>` / `DOCDEX_AUDIT_MAX_BYTES`: rotate audit log after this many bytes (default: 5_000_000).
- `--audit-max-files <n>` / `DOCDEX_AUDIT_MAX_FILES`: keep at most this many rotated audit files (default: 5).
- `--audit-disable` / `DOCDEX_AUDIT_DISABLE=true`: disable audit logging entirely.
- `--strip-snippet-html` / `DOCDEX_STRIP_SNIPPET_HTML=true`: omit `snippet.html` in responses to force text-only snippets (HTML is sanitized by default when present).
- `--disable-snippet-text` / `DOCDEX_DISABLE_SNIPPET_TEXT=true`: omit snippet text/html in responses entirely (only doc metadata is returned).
- `--access-log <true|false>` / `DOCDEX_ACCESS_LOG`: emit minimal structured access logs with query values redacted (default: true).
- `--run-as-uid` / `DOCDEX_RUN_AS_UID`, `--run-as-gid` / `DOCDEX_RUN_AS_GID`: (Unix) drop privileges to the provided UID/GID after startup prep.
- `--chroot <path>` / `DOCDEX_CHROOT`: (Unix) chroot into `path` before serving; repo/state paths must exist inside that jail.
- `--unshare-net` / `DOCDEX_UNSHARE_NET=true`: (Linux only) unshare the network namespace before serving (requires CAP_SYS_ADMIN/root); no-op on other platforms.
- Logging: `--log <level>` on `serve` (defaults to `info`), or `RUST_LOG=docdexd=debug` style filters.
- Secure mode defaults: when `--secure-mode=true` (default), docdex requires an auth token, allows only loopback IPs unless overridden, and applies a 60 req/min rate limit. Set `--secure-mode=false` to opt out for local dev and adjust `--allow-ip`/rate limits as needed.

## Indexing rules (see `index/mod.rs`)
- File types: `.md`, `.markdown`, `.mdx`, `.txt` (extend `DEFAULT_EXTENSIONS` to add more).
- Skipped directories: broad VCS/build/cache/vendor folders across ecosystems (e.g., `.git`, `.hg`, `.svn`, `node_modules`, `.pnpm-store`, `.yarn*`, `.nx`, `.rollup-cache`, `.webpack-cache`, `.tsbuildinfo`, `.next`, `.nuxt`, `.svelte-kit`, `.mypy_cache`, `.ruff_cache`, `.venv`, `target`, `go-build`, `.gradle`, `.mvn`, `pods`, `.dart_tool`, `.android`, `.serverless`, `.vercel`, `.netlify`, `_build`, `_opam`, `.stack-work`, `elm-stuff`, `library`, `intermediate`, `.godot`, etc.; see `DEFAULT_EXCLUDED_DIR_NAMES` for the full list).
- Skipped relative prefixes: `logs/`, `.docdex/`, `.docdex/logs/`, `.docdex/tmp/`, `.gpt-creator/logs/`, `.gpt-creator/tmp/`, `.mastercoda/logs/`, `.mastercoda/tmp/`, `docker/.data/`, `docker-data/`, `.docker/`.
- Snippet sizing: summaries ~360 chars (up to 4 segments); snippets ~420 chars.

## HTTP API
- `GET /healthz` — returns `ok`; this endpoint is unauthenticated and not rate-limited (IP allowlist still applies).
- `GET /search?q=<text>&limit=<n>&snippets=<bool>&max_tokens=<u64>` — returns `{ hits: [...] }` with doc id, rel path, summary, snippet, score, token estimate. Set `snippets=false` for summary-only responses; set `max_tokens` to drop hits above your budget.
- `GET /snippet/:doc_id?window=<lines>&q=<query>&text_only=<bool>&max_tokens=<u64>` — returns `{ doc, snippet }` with optional highlighted snippet; falls back to preview when query highlighting is empty (default window: 40 lines). Set `text_only=true` to drop HTML and shrink payloads; set `max_tokens` to omit the snippet if the doc exceeds your budget.
- `GET /ai-help` — returns a JSON quickstart for agents (endpoints, CLI commands, limits, best practices).
- `GET /metrics` — returns Prometheus-style counters for rate-limit/auth/error metrics.
- If `--auth-token` is set, include `Authorization: Bearer <token>` on HTTP calls (including `/ai-help`).

## CLI commands
- `serve --repo <path> [--host 127.0.0.1] [--port 46137] [--log info]` — start HTTP API with file watching for incremental updates.
- `index --repo <path>` — rebuild the entire index.
- `ingest --repo <path> --file <file>` — reindex a single file.
- `query --repo <path> --query "<text>" [--limit 8]` — run a search and print JSON hits.
- `self-check --repo <path> --terms "foo,bar" [--limit 5]` — scan the index for sensitive terms before enabling access (fails with non-zero exit if any are found; reports sample hits and if more exist). Includes built-in token/password patterns by default; disable with `--include-default-patterns=false` if you only want your provided terms.

## Help and command discovery
- List all commands/flags: `docdexd --help`.
- Dump help for every subcommand: `docdexd help-all`.
- See `serve` options (TLS, auth, rate limits, watcher): `docdexd serve --help`.
- Indexing options: `docdexd index --help` (exclude paths, custom state dir).
- Ad-hoc queries: `docdexd query --help`.
- Self-check scanner options: `docdexd self-check --help`.
- Agent help endpoint: `curl http://127.0.0.1:46137/ai-help` (include `Authorization: Bearer <token>` if `--auth-token` is set) for a JSON listing of endpoints, limits, and best practices.
- Environment variables mirror the flags (e.g., `DOCDEX_AUTH_TOKEN`, `DOCDEX_TLS_CERT`, `DOCDEX_MAX_LIMIT`).
- Command overview (same as `docdexd --help`):
  - `serve` — run HTTP API with watcher and security knobs.
  - `index` — build or rebuild the whole index.
  - `ingest` — reindex a single file.
  - `query` — run an ad-hoc search, JSON to stdout.
  - `self-check` — scan index for sensitive terms with report.
  - `help-all` — print help for every command/flag in one output.

## Troubleshooting
- Stale index: re-run `docdexd index --repo <path>`.
- Port conflicts: change `--host/--port`.

## Security considerations
- Default bind is `127.0.0.1`; keep it unless you are behind a trusted reverse proxy/firewall. Avoid `--host 0.0.0.0` on untrusted networks.
- By default, non-loopback binds require TLS; opt out only with `--require-tls=false` or `--insecure` when traffic is already terminating at a trusted proxy.
- If exposing externally, place a reverse proxy in front, terminate TLS, and require auth (basic/OAuth/mTLS) plus IP/VPN allowlisting. Example (nginx):
  ```
  server {
    listen 443 ssl;
    server_name docdex.example.com;
    ssl_certificate /path/fullchain.pem;
    ssl_certificate_key /path/privkey.pem;
    auth_basic "Protected";
    auth_basic_user_file /etc/nginx/.htpasswd; # or hook OAuth/mTLS instead
    allow 10.0.0.0/8;
    allow 192.168.0.0/16;
    deny all;
    location / {
      proxy_pass http://127.0.0.1:46137;
      proxy_set_header Host $host;
    }
  }
  ```
- Trim the corpus: prefer a curated staging directory, or use `--exclude-dir` / `--exclude-prefix` to keep secrets/private paths out before indexing; the watcher will ingest any in-scope file change under `repo`.
- Mind logs: avoid verbose logging in production if snippets/paths are sensitive; reverse-proxy access logs can also capture query terms and paths.
- Least privilege: run docdex under a low-privilege user/container and keep the state dir on a path with restricted permissions.
- Validate before publish: run `docdexd query` for sensitive keywords to confirm no hits; store indexes on encrypted disks if required.
- Optional hardening: require an auth token on the HTTP API (or proxy); enforce TLS when not on localhost (default) or explicitly opt out with `--require-tls=false`/`--insecure` only behind a trusted proxy; enable rate limiting (`--rate-limit-per-min`) and clamp `limit`/request sizes (`--max-limit`, `--max-query-bytes`, `--max-request-bytes`); escape/sanitize snippet HTML if embedding or disable snippets entirely with `--disable-snippet-text`; state dir is created `0700` by default—keep it under an unprivileged user, optionally `--run-as-uid/--run-as-gid`, `--chroot`, or containerize; keep access logging minimal/redacted (`--access-log`), and run `self-check` for sensitive terms before exposing the service; for at-rest confidentiality, place the state dir on encrypted storage or use host-level disk encryption.

## Integrating with LLM tools
Docdex is tool-agnostic. Drop-in recipe for agents/codegen tools:
- Start once per repo: `docdexd index --repo <repo>` then `docdexd serve --repo <repo> --host 127.0.0.1 --port 46137 --log warn` (or use the CLI directly without serving).
- Configure via env: `DOCDEX_STATE_DIR` (index location), `DOCDEX_EXCLUDE_PREFIXES`, `DOCDEX_EXCLUDE_DIRS`, `RUST_LOG=docdexd=debug` (optional verbose logs).
- Query over HTTP: `GET /search?q=<text>&limit=<n>` returns `{"hits":[{"doc_id","rel_path","score","summary","snippet","token_estimate"}...]}`; `GET /snippet/:doc_id` fetches a focused snippet plus doc metadata.
- Or query via CLI: `docdexd query --repo <repo> --query "<text>" --limit 8` (JSON to stdout).
- Health check: `GET /healthz` should return `ok` before issuing search requests.
- Inject snippets into prompts:
```
"You are building features for this repo. Use the following documentation snippets for context. If a snippet cites a path, keep that path in your response. Snippets:\n<insert docdex snippets here>\nQuestion: <your question>"
```

### MCP (optional stdio server for MCP-aware clients)
Docdex can run as an MCP tool provider over stdio; it does not replace the HTTP daemon—pick whichever fits your agent/editor. If your MCP client supports resource templates, Docdex advertises a `docdex.file` template (`docdex://{path}`) which delegates to `docdex.open`.
- Run: `docdexd mcp --repo /path/to/repo --log warn --max-results 8` (alias: `--mcp-max-results 8`).
- Env override: `DOCDEX_MCP_MAX_RESULTS` clamps `docdex.search` results (min 1).
- Packaging: MCP server is built into the main `docdexd` binary (invoked via `docdexd mcp` or `docdex mcp` from the npm bin); no separate `docdex-mcp` download required.
- Registering with MCP clients: add a server named `docdex` that runs `docdexd mcp --repo <repo> --log warn`. Example Codex config snippet:
  ```json
  {
    "mcpServers": {
      "docdex": {
        "command": "docdexd",
        "args": ["mcp", "--repo", ".", "--log", "warn", "--max-results", "8"],
        "env": {}
      }
    }
  }
  ```
- Tools exposed:
  - `docdex.search` — args: `{ "query": "<text>", "limit": <int optional>, "project_root": "<path optional>" }`. Returns `{ "results": [...], "repo_root": "...", "state_dir": "...", "limit": <int>, "project_root": "...", "meta": {...} }`.
  - `docdex.index` — args: `{ "paths": ["relative/or/absolute"], "project_root": "<path optional>" }`. Empty `paths` reindexes everything; otherwise ingests the listed files.
  - `docdex.files` — args: `{ "limit": <int optional, default 200, max 1000>, "offset": <int optional, default 0>, "project_root": "<path optional>" }`. Returns `{ "results": [{ "doc_id", "rel_path", "summary", "token_estimate" }], "total", "limit", "offset", "repo_root", "project_root" }`.
  - `docdex.open` — args: `{ "path": "<relative file>", "start_line": <int optional>, "end_line": <int optional>, "project_root": "<path optional>" }`. Returns `{ "path", "start_line", "end_line", "total_lines", "content", "repo_root", "project_root" }` (rejects paths outside repo and large files).
  - `docdex.stats` — args: `{ "project_root": "<path optional>" }`. Returns `{ "num_docs", "state_dir", "index_size_bytes", "segments", "avg_bytes_per_doc", "generated_at_epoch_ms", "last_updated_epoch_ms", "repo_root", "project_root" }`.
- Example calls:
  - Initialize: `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
  - Initialize with workspace root: `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"workspace_root":"/path/to/repo"}}` (must match the server repo; sets default project_root for later calls)
  - List tools: `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`
  - Reindex: `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"docdex.index","arguments":{"paths":[]}}}`
  - Search: `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"docdex.search","arguments":{"query":"payment auth flow","limit":3,"project_root":"/repo"}}}`
  - List files: `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"docdex.files","arguments":{"limit":10,"offset":0}}}`
  - Open file: `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"docdex.open","arguments":{"path":"docs/readme.md","start_line":1,"end_line":20}}}`
  - Stats: `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"docdex.stats","arguments":{}}}`
- Errors: invalid JSON → code -32700; unsupported/missing `jsonrpc` → -32600; unknown tool/method → -32601; invalid params (empty query, bad args, project_root mismatch) → -32602; internal errors include a `reason` string in `error.data`.
- Agent guidance: call `docdex.search` with concise queries before coding; fetch only a few hits; if results look stale, call `docdex.index`; keep using HTTP/CLI if your stack isn’t MCP-aware.
- Help: `docdexd mcp --help` shows MCP flags and defaults; `docdexd help-all` includes an MCP section listing tools and usage.

## HTTPS and Certbot
- TLS accepts PKCS8, PKCS1/RSA, and SEC1/EC private keys (compatible with Certbot output).
- Manual cert/key: `docdexd serve --repo <repo> --tls-cert /path/fullchain.pem --tls-key /path/privkey.pem`.
- Certbot helper: `docdexd serve --repo <repo> --host 0.0.0.0 --port 46137 --certbot-domain docs.example.com` (uses `/etc/letsencrypt/live/docs.example.com/{fullchain.pem,privkey.pem}`), or pass `--certbot-live-dir /custom/live/dir`.
- When using Certbot, set a deploy hook to restart/reload docdex after renewals (e.g., `certbot renew --deploy-hook "systemctl restart docdexd.service"` or kill -HUP your process supervisor).
- If binding to 443 directly, you need privileges; otherwise, keep docdex on 127.0.0.1 and let a reverse proxy terminate TLS.
