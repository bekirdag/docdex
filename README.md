# Docdex

[![smithery badge](https://smithery.ai/badge/@bekirdag/docdex)](https://smithery.ai/server/@bekirdag/docdex)

Docdex is a lightweight, local documentation indexer/search daemon. It runs per-project, keeps an on-disk index of your markdown/text docs, and serves top-k snippets over HTTP or CLI for any coding assistant or tool—no external services or uploads required.

## Install via npm
- Requires Node.js >= 18.
- Install: `npm i -g docdex` (or run `npx docdex --version` to verify).
- Commands: `docdex` (alias `docdexd`) downloads the right binary for your platform from the matching GitHub release.
- Installer integrity verification (mandatory): resolves exactly one `docdexd` release asset plus an expected SHA-256 (via release manifest or `SHA256SUMS` fallback), verifies the download before extraction, and fails closed with a non-zero exit code without leaving a runnable `docdexd` in place on verification failure; see `docs/ops/installer_error_codes.md`.
- Supported published binaries: macOS (arm64, x64), Linux glibc (arm64, x64), Linux musl (x64), Windows (x64); installer fetches the matching platform release asset.
- Supported platforms + manual source build + troubleshooting: `docs/ops/installer_supported_platforms.md`.
- Upgrade/downgrade/repair semantics (idempotent `no-op` / integrity-first): `docs/ops/installer_upgrade_downgrade.md`.
- Release manifest schema (assets + checksums + fallback rules): `docs/contracts/release_manifest_schema_v1.md`.
<<<<<<< HEAD
- Installer integrity policy: `DOCDEX_INTEGRITY_POLICY=required|allow-missing|off` (default `required`). Overrides are insecure and never silent.
=======
- Integrity policy: installs verify SHA-256 and fail closed if checksums are missing or mismatched; remediation: `docs/ops/installer_error_codes.md`.
>>>>>>> mcoda/task/ops-01-us-06-t08
- If you publish from a fork, set `DOCDEX_DOWNLOAD_REPO=<owner/repo>` before installing so the downloader fetches your release assets.
<<<<<<< HEAD
- Distribution: binaries stay in GitHub Releases (small npm package); postinstall fetches `docdexd-<platformKey>.tar.gz` matching the npm version.
=======
- Integrity configuration (defaults are safe and deterministic):
  - `DOCDEX_INTEGRITY_METADATA_SOURCES=manifest,checksums,sidecar` (order matters; default shown)
  - `DOCDEX_INTEGRITY_MISSING_POLICY=fallback|abort` (default: `fallback`)
- Distribution: binaries stay in GitHub Releases (small npm package); postinstall fetches `docdexd-<platform>.tar.gz` matching the npm version.
<<<<<<< HEAD
>>>>>>> mcoda/task/ops-01-us-04-t21
=======
- Installer is idempotent: if the expected version is already installed and verified, it prints `[docdex] Install outcome: no-op` and does not re-download the asset.
>>>>>>> mcoda/task/ops-01-us-06-t08
- Platform diagnostics (no download): `docdex doctor` (or `docdex diagnostics`) prints detected OS/arch(/libc), whether supported, and the expected Rust target triple + release asset naming pattern.
- Publishing uses npm Trusted Publishing (OIDC) — no NPM token needed; see `.github/workflows/release.yml`.

## Features at a glance
- Per-repo, local indexing of Markdown/text files (tantivy-backed; no network calls).
- HTTP API (`/search`, `/snippet`, `/healthz`) and CLI (`query`, `ingest`, `self-check`) share the same index.
- Live file watching while serving for incremental updates.
- Security knobs: TLS (manual certs or Certbot), auth token required by default (disable with `--secure-mode=false`), loopback-only allowlist by default, default rate limiting, request-size limits, strict state-dir perms, audit log, chroot/privilege drop/unshare net (Unix).
- Output ready for coding assistants: summaries, snippets, and doc metadata.
- AI-friendly: `GET /ai-help` returns a JSON playbook (endpoints, CLI commands, limits, best practices) for agents.

## What it does
- Indexes Markdown/text docs inside a repo and stores them locally (tantivy-based index under `~/.docdex/state/repos/<fingerprint>/index` by default).
- Serves the same index over HTTP (`/search`, `/snippet`, `/healthz`) and via CLI (`query`, `ingest`, `self-check`), so automation and interactive use share one dataset.
- Watches files while serving to incrementally ingest changes.
- Hardened defaults: loopback binding, TLS enforcement on non-loopback, auth token required by default (disable with `--secure-mode=false`), loopback-only allowlist and default rate limit (60 req/min) in secure mode, audit log enabled, and strict state-dir perms.

## How it works
1) `docdexd index` builds the on-disk index for your repo under `~/.docdex/state/repos/<fingerprint>/index`.  
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
<<<<<<< HEAD
- If you opt into in-repo state dirs (e.g., `--state-dir .docdex/index`), add `.docdex/` to `.gitignore` so indexes aren't committed.
=======
- State lives under `~/.docdex/state` by default; if you override `--state-dir` into the repo, add that directory to `.gitignore`.
>>>>>>> mcoda/task/ops-01-us-03-t02
- When MCP-aware, register a server named `docdex` that runs `docdexd mcp --repo . --log warn --max-results 8`, then call `docdex_search` before coding and `docdex_index` when stale.
- Prefer summary-first (snippets=false), fetch specific snippets only when needed, keep queries short, and respect token estimates.

## Usage cheat sheet
- Build index: `docdexd index --repo <path>` (add `--exclude-*` to skip paths).
- Serve with watcher: `docdexd serve --repo <path> --host 127.0.0.1 --port 46137 --log warn --auth-token <token>` (secure mode also allowlists loopback and rate-limits by default; add `--allow-ip`/`--secure-mode=false`/`--rate-limit-per-min` as needed for remote use).
- Secure serving: add `--auth-token <token>` (required by default); use TLS with `--tls-cert/--tls-key` or `--certbot-domain <domain>`.
- Single-file ingest: `docdexd ingest --repo <path> --file docs/new.md` (honors excludes).
- Query via CLI: `docdexd query --repo <path> --query "term" --limit 4` (add `--repo-only` to ignore libs index hits).
<<<<<<< HEAD
- Git hygiene: if you use an in-repo `--state-dir`, add `.docdex/` (and especially `.docdex/index/`) to your repo's `.gitignore` so index artifacts never get committed.
=======
- Git hygiene: default state is global (`~/.docdex/state`), so nothing in-repo is created unless you override `--state-dir`; add any repo-local override dir to `.gitignore`.
>>>>>>> mcoda/task/ops-01-us-03-t02
- Health check: `curl http://127.0.0.1:46137/healthz`.
- Summary-only search responses: `curl "http://127.0.0.1:46137/search?q=foo&snippets=false"`; fetch snippets only for top hits.
- Repo-only HTTP search (ignore libs index hits): `curl "http://127.0.0.1:46137/search?q=foo&include_libs=false"`.
- Token budgets: `curl "http://127.0.0.1:46137/search?q=foo&max_tokens=800"` to drop hits that would exceed your prompt budget; pair with `snippets=false` then fetch 1–2 snippets you keep.
- Text-only snippets: append `text_only=true` to `/snippet/:doc_id` or start `serve` with `--strip-snippet-html` (or `--disable-snippet-text` to return metadata only).
- Keep requests compact: defaults enforce `max_query_bytes=4096` and `max_request_bytes=16384`; keep queries short and leave `--max-limit` low (default 8) to avoid oversized responses.
- Prompt hygiene: in agent prompts, normalize whitespace and include only `rel_path`, `summary`, and trimmed `snippet` (omit `score`/`token_estimate`/`doc_id`).
- Trim noise early: use `--exclude-dir` and `--exclude-prefix` to keep vendor/build/cache/secrets out of the index so snippets stay relevant and short.
- Quiet logging for agents: run `docdexd serve --log warn --access-log=false` if you marshal responses elsewhere to cut log overhead.
- Cache hits client-side: store `doc_id` ↔ `rel_path` ↔ `summary` to avoid repeat snippet calls; fetch snippets only for new doc_ids.
- Agent help: `curl http://127.0.0.1:46137/ai-help` (requires auth if configured; include `Authorization: Bearer <token>` when you've set `--auth-token`). The response includes a short MCP registration recipe.

## Versioning
- Semantic versioning with tagged releases (`vX.Y.Z`). The Rust crate and npm package share the same version.
- Conventional Commits drive release notes via Release Please; it opens release PRs that bump `Cargo.toml` and `npm/package.json`, update changelogs, and creates the tag/release on merge.
- Pin to a released version when integrating (e.g., in scripts or Dockerfiles) so upgrades are explicit and reversible.
- If you build from source, the version comes from `Cargo.toml` in this repo; the npm wrapper uses the matching version to fetch binaries.

## Paths and defaults
<<<<<<< HEAD
- State/index directory: `~/.docdex/state/repos/<fingerprint>/index` (override base with `--state-dir`; relative or in-repo paths keep the legacy in-repo layout). The directory is created with `0700` permissions by default.
- HTTP API: defaults to `127.0.0.1:46137` when serving.
- Docdex data and logs stay local under `~/.docdex/state` (or a custom state dir); no external services.

## Configuration knobs
- `--repo <path>`: workspace root to index (defaults to `.`).
- `--state-dir <path>` / `DOCDEX_STATE_DIR`: override the state base directory (default `~/.docdex/state`). Relative paths or absolute paths inside the repo keep legacy in-repo layout; absolute paths outside the repo are treated as shared bases and scoped under `repos/<fingerprint>/index`. When using a shared base, repo moves/renames require an explicit `docdexd repo reassociate` step before Docdex will reuse the existing state.
=======
- State root: `~/.docdex/state` (created with `0700` permissions by default).
- Per-repo state root (`<repo-state-root>`): `~/.docdex/state/repos/<fingerprint>/` (index at `.../index`).
- HTTP API: defaults to `127.0.0.1:46137` when serving.
- Docdex data and logs stay on the local machine under the state root; no external services.

## Configuration knobs
- `--repo <path>`: workspace root to index (defaults to `.`).
- `--state-dir <path>` / `DOCDEX_STATE_DIR`: override the state root (default: `~/.docdex/state`). Relative paths are resolved under `repo`. Per-repo state lives under `<state-root>/repos/<fingerprint>/`; moves/renames with a shared state root (default) may require `docdexd repo reassociate` to reuse existing state.
>>>>>>> mcoda/task/ops-01-us-03-t02
- `--exclude-prefix a,b,c` / `DOCDEX_EXCLUDE_PREFIXES`: extra relative prefixes to skip.
- `--exclude-dir a,b,c` / `DOCDEX_EXCLUDE_DIRS`: extra directory names to skip anywhere in the tree.
- `DOCDEX_ENABLE_SYMBOL_EXTRACTION`: enable optional per-file symbol extraction during indexing; see `docs/symbols_store.md`.
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
<<<<<<< HEAD
- `--audit-log-path <path>` / `DOCDEX_AUDIT_LOG_PATH`: write audit log JSONL to this path (default: `<repo_state_dir>/audit.log`).
=======
- `--audit-log-path <path>` / `DOCDEX_AUDIT_LOG_PATH`: write audit log JSONL to this path (default: `<repo-state-root>/audit.log`).
>>>>>>> mcoda/task/ops-01-us-03-t02
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
- `GET /search?q=<text>&limit=<n>&snippets=<bool>&max_tokens=<u64>&include_libs=<bool>` — returns `{ hits: [...] }` with doc id, rel path, summary, snippet, score, token estimate. Set `snippets=false` for summary-only responses; set `max_tokens` to drop hits above your budget. `include_libs` defaults to `true` when a libs index exists; set `include_libs=false` to search repo-only.
- `GET /snippet/:doc_id?window=<lines>&q=<query>&text_only=<bool>&max_tokens=<u64>` — returns `{ doc, snippet }` with optional highlighted snippet; falls back to preview when query highlighting is empty (default window: 40 lines). Set `text_only=true` to drop HTML and shrink payloads; set `max_tokens` to omit the snippet if the doc exceeds your budget.
- `GET /v1/dag/export?session_id=<id>&format=json|text|dot&max_nodes=<n>` — export a session DAG in JSON/text/DOT.
- `GET /ai-help` — returns a JSON quickstart for agents (endpoints, CLI commands, limits, best practices).
- `GET /metrics` — returns Prometheus-style counters/gauges for rate-limit/auth/error and browser guard metrics (see `docs/ops/browser_guard.md`).
- If `--auth-token` is set, include `Authorization: Bearer <token>` on HTTP calls (including `/ai-help`).
- Rate limits: `429` responses include a JSON error body (`{error:{code:"rate_limited",message,...,retry_after_ms,...}}`) and a `Retry-After` header (seconds).

## CLI commands
- `serve --repo <path> [--host 127.0.0.1] [--port 46137] [--log info]` — start HTTP API with file watching for incremental updates.
- `index --repo <path>` — rebuild the entire index.
- `ingest --repo <path> --file <file>` — reindex a single file.
- `query --repo <path> --query "<text>" [--limit 8] [--repo-only]` — run a search and print JSON hits.
<<<<<<< HEAD
- `dag view --repo <path> <session_id> [--format text|dot] [--output <path>]` — export a session DAG to stdout or a file.
=======
- `dag view --repo <path> <session_id> [--format json|text|dot] [--max-nodes <n>]` — export a session DAG.
>>>>>>> mcoda/task/bck-05-us-07-t27
- `repo inspect --repo <path> [--state-dir <state_dir>]` — show normalized path, computed fingerprint, and any shared-state mapping (canonical + aliases + lastSeen) for move/rename recovery.
- `repo reassociate --repo <new_path> --state-dir <shared_state_dir> (--old-path <old_path> | --fingerprint <sha256>)` — explicitly re-associate a moved/renamed repo path to existing state under a shared base state directory.
- `self-check --repo <path> --terms "foo,bar" [--limit 5]` — scan the index for sensitive terms before enabling access (fails with non-zero exit if any are found; reports sample hits and if more exist). Includes built-in token/password patterns by default; disable with `--include-default-patterns=false` if you only want your provided terms.

## Perf checks
- Repo-only search latency (p95 < 50ms; see `docs/sds/sds.md`): `cargo test --release repo_only_search_p95_under_50ms_with_libs_index_present -- --ignored --nocapture`.

## Help and command discovery
- List all commands/flags: `docdexd --help`.
- Dump help for every subcommand: `docdexd help-all`.
- See `serve` options (TLS, auth, rate limits, watcher): `docdexd serve --help`.
- Indexing options: `docdexd index --help` (exclude paths, custom state dir).
- Ad-hoc queries: `docdexd query --help`.
- Self-check scanner options: `docdexd self-check --help`.
- Agent help endpoint: `curl http://127.0.0.1:46137/ai-help` (include `Authorization: Bearer <token>` if `--auth-token` is set) for a JSON listing of endpoints, limits, and best practices.
- MCP help/registration: `docdexd mcp --help` lists MCP flags; register with your client using `docdexd mcp --repo <repo> --log warn`. Example Codex config snippet:
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
- Optional: set `DOCDEX_ENABLE_SYMBOL_EXTRACTION=1` in the MCP server env to persist/query per-file symbols via `docdex_symbols`.
- MCP quick add commands (popular agents):
  - Docdex helper: `docdex mcp-add --repo /path/to/repo --log warn --max-results 8` auto-detects supported agents; add `--all` to attempt every known client and print manual steps for UI-only ones, or `--remove` to uninstall.
  - Codex CLI: `codex mcp add docdex -- docdexd mcp --repo /path/to/repo --log warn --max-results 8`.
  - Generic JSON config (Cursor, Continue, Windsurf, Cline, Claude Desktop devtools): add the `mcpServers.docdex` block above to your MCP config file (paths vary by client; most accept the `command`/`args` schema shown).
  - Manual/stdio-only clients: start `docdexd mcp --repo /path/to/repo --log warn --max-results 8` yourself and point the client at that command/binary.
- Tools exposed (CallToolResult content: result.content[0].text contains JSON):
<<<<<<< HEAD
- `docdex_search` — args: `{ "query": "<text>", "limit": <int optional>, "project_root": "<path optional>" }`. `limit` is clamped to the MCP server `--max-results` (default 8). Returns `{ "hits": [...], "results": [...], "top_score": <float|null>, "topScore": <float|null>, "repo_root": "...", "state_dir": "...", "limit": <int>, "project_root": "...", "meta": {...} }`.
  - `docdex_index` — args: `{ "paths": ["relative/or/absolute"], "project_root": "<path optional>" }`. Empty `paths` reindexes everything; otherwise ingests the listed files.
  - `docdex_files` — args: `{ "limit": <int optional, default 200, max 1000>, "offset": <int optional, default 0>, "project_root": "<path optional>" }`. Returns `{ "results": [{ "doc_id", "rel_path", "summary", "token_estimate" }], "total", "limit", "offset", "repo_root", "project_root" }`.
- `docdex_open` — args: `{ "path": "<relative file>", "start_line": <int optional>, "end_line": <int optional>, "project_root": "<path optional>" }`. Returns `{ "path", "start_line", "end_line", "total_lines", "content", "repo_root", "project_root" }` (rejects paths outside repo and files over 512 KiB).
  - `docdex_stats` — args: `{ "project_root": "<path optional>" }`. Returns `{ "num_docs", "state_dir", "index_size_bytes", "segments", "avg_bytes_per_doc", "generated_at_epoch_ms", "last_updated_epoch_ms", "repo_root", "project_root" }`.
<<<<<<< HEAD
  - `docdex_repo_inspect` — args: `{ "project_root": "<path optional>" }`. Returns a repo identity report (normalized path, fingerprint, state mapping, status).
  - `docdex_symbols` — args: `{ "path": "<relative file>", "project_root": "<path optional>" }`. Returns a `docdex.symbols` payload for that file including `outcome.status` (`ok`/`skipped`/`failed`).
  - `docdex_memory_store` (requires `DOCDEX_ENABLE_MEMORY=1`) — args: `{ "text": "<string>", "metadata": <object optional>, "project_root": "<path optional>" }`. Returns `{ "id", "created_at" }`.
  - `docdex_memory_recall` (requires `DOCDEX_ENABLE_MEMORY=1`) — args: `{ "query": "<text>", "top_k": <int optional, max 50>, "project_root": "<path optional>" }`. Returns `{ "top_k", "results": [{ "content", "score", "metadata" }] }`.
- Tool limits (server-scoped; schema-stable): max items and snippet/content caps are documented in `docs/mcp/errors.md` and do not vary by repo.
=======
  - `docdex_search` — args: `{ "query": "<text>", "limit": <int optional>, "project_root": "<path optional>" }`. Returns `{ "hits": [...], "results": [...], "top_score": <float|null>, "topScore": <float|null>, "repo_root": "...", "state_dir": "...", "limit": <int>, "project_root": "...", "meta": {...} }`.
  - `docdex_index` — args: `{ "paths": ["relative/or/absolute"], "project_root": "<path optional>" }`. Empty `paths` reindexes everything; otherwise ingests the listed files (max 1000 paths).
  - `docdex_files` — args: `{ "limit": <int optional, default 200, max 1000>, "offset": <int optional, default 0>, "project_root": "<path optional>" }`. Returns `{ "results": [{ "doc_id", "rel_path", "summary", "token_estimate" }], "total", "limit", "offset", "repo_root", "project_root" }`.
  - `docdex_open` — args: `{ "path": "<relative file>", "start_line": <int optional>, "end_line": <int optional>, "project_root": "<path optional>" }`. Returns `{ "path", "start_line", "end_line", "total_lines", "content", "repo_root", "project_root" }` (rejects paths outside repo and files > 512 KiB).
  - `docdex_stats` — args: `{ "project_root": "<path optional>" }`. Returns `{ "num_docs", "state_dir", "index_size_bytes", "segments", "avg_bytes_per_doc", "generated_at_epoch_ms", "last_updated_epoch_ms", "repo_root", "project_root" }`.
  - `docdex_symbols` — args: `{ "path": "<relative file>", "project_root": "<path optional>" }`. Returns a `docdex.symbols` payload for that file including `outcome.status` (`ok`/`skipped`/`failed`), capped at 5000 symbols / 512 KiB.
>>>>>>> mcoda/task/bck-05-us-10-t14
=======
  - `docdex_symbols` — args: `{ "path": "<relative file>", "project_root": "<path optional>", "limit": 2000 }` (limit optional, max 2000). Returns a `docdex.symbols` payload for that file including `outcome.status` (`ok`/`skipped`/`failed`).
>>>>>>> mcoda/task/bck-05-us-10-t03
- Example calls:
  - Initialize: `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
  - Initialize with workspace root: `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"workspace_root":"/path/to/repo"}}` (must match the server repo; sets default project_root for later calls)
  - List tools: `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`
  - Reindex: `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"docdex_index","arguments":{"paths":[]}}}`
  - Search: `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"docdex_search","arguments":{"query":"payment auth flow","limit":3,"project_root":"/repo"}}}`
  - List files: `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"docdex_files","arguments":{"limit":10,"offset":0}}}`
  - Open file: `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"docdex_open","arguments":{"path":"docs/readme.md","start_line":1,"end_line":20}}}`
  - Stats: `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"docdex_stats","arguments":{}}}`
- Errors: invalid JSON → code -32700; unsupported/missing `jsonrpc` → -32600; unknown tool/method → -32601; invalid params (empty query, bad args, project_root mismatch) → -32602; internal errors include a `reason` string in `error.data`.
<<<<<<< HEAD
<<<<<<< HEAD
- Rate limits (MCP tool calls): when `DOCDEX_MCP_RATE_LIMIT_PER_MIN` is enabled and exceeded, tool calls return JSON-RPC code `-32029` with the canonical MCP error envelope; retry hints live under `error.data.details` and are mirrored at the top level for compatibility: `{ retry_after_ms: <int>, retry_at?: <RFC3339>, limit_key: <string>, scope: <string> }`.
=======
- Rate limits (MCP tool calls): when `DOCDEX_MCP_RATE_LIMIT_PER_MIN` is enabled and exceeded, tool calls return JSON-RPC code `-32029`. `error.data` follows the canonical envelope (`code`, `message`, `error`) and includes stable retry hints: `{ code: \"rate_limited\", message: <string>, retry_after_ms: <int>, retry_at?: <RFC3339>, limit_key: <string>, scope: <string> }`. Payloads are capped (message <= 256 bytes; rate-limit/backoff data <= 2 KiB).
>>>>>>> mcoda/task/bck-05-us-09-t37
=======
- Rate limits (MCP tool calls): when `DOCDEX_MCP_RATE_LIMIT_PER_MIN` is enabled and exceeded, tool calls return JSON-RPC code `-32029` with `error.data` containing stable retry hints: `{ code: \"rate_limited\", retry_after_ms: <int>, retry_at?: <RFC3339>, limit_key: <string>, scope: <string>, resource_key: <string>, limit_per_min: <int>, limit_burst: <int>, denied_total: <int> }`.
>>>>>>> mcoda/task/bck-05-us-09-t05
- Agent guidance: call `docdex_search` with concise queries before coding; fetch only a few hits; if results look stale, call `docdex_index`; keep using HTTP/CLI if your stack isn't MCP-aware.
- Help: `docdexd mcp --help` shows MCP flags and defaults; `docdexd help-all` includes an MCP section listing tools and usage.

## Troubleshooting
- Stale index: re-run `docdexd index --repo <path>`.
- Port conflicts: change `--host/--port`.
- Installer failures (`npm i -g docdex`): use the printed `DOCDEX_*` error code; see `docs/ops/installer_error_codes.md` and `docs/ops/installer_rollback_guarantees.md`.

### Repo moved/renamed

Docdex is safety-first: it will not silently “cross-associate” an existing on-disk state directory with a different repo path when doing so could mix data between repos.

<<<<<<< HEAD
The default state dir is shared under `~/.docdex/state/repos/<fingerprint>/index`, so moves/renames typically keep working when the repo fingerprint stays stable. If you opt into an in-repo `--state-dir`, moves/renames require moving that directory with the repo. The stricter “explicit re-association” flow below applies when you use an absolute shared `--state-dir` outside the repo root.
=======
If you override `--state-dir` to a repo-local path, moves/renames typically require only moving that directory with the repo. The stricter “explicit re-association” flow below applies when you use the default shared state root (`~/.docdex/state`) or any absolute shared `--state-dir` outside the repo root.
>>>>>>> mcoda/task/ops-01-us-03-t02

Deterministic failures and what they mean:

- `missing_repo_path` (`"repo path not found"`): the `--repo` path (or MCP `project_root`) does not exist on disk (common after a move/rename, or when a client is still pointing at the old location).
  - Recovery: re-run with the repo’s current path; for HTTP, restart `docdexd serve --repo <repo>` with the correct path; for MCP, either omit `project_root` to use the MCP server’s default or restart `docdexd mcp --repo <repo>` with the correct path.
  - If the repo moved but you did not move its state with it, reindex: `docdexd index --repo <repo>`.
- `unknown_repo` (`"unknown repo"`): MCP-only — `project_root` does not match the MCP server’s configured `--repo`. This is a fast-fail guardrail to prevent accidental cross-repo access.
  - Recovery: restart the MCP server with `docdexd mcp --repo <repo>` matching the repo you want, or omit `project_root` in tool arguments to use the MCP server default.
- `repo_state_mismatch` (`"repo state mismatch; refusing to associate this repo with the existing state directory"`): Docdex detected that an existing *shared* `--state-dir` cannot be safely associated with the current `--repo` without an explicit user action (common when a repo moved/renamed while using an absolute shared `--state-dir` outside the repo root).
  - Why it fast-fails: reusing shared state across repos is a data-mixing risk; Docdex fails closed by default.
  - Recovery: either explicitly re-associate the moved repo to the existing shared state, or choose a different (empty) `--state-dir` and reindex.

Step-by-step recovery (shared `--state-dir` scenario):

1. Re-run the failing command and capture the JSON error `details` fields (notably `knownCanonicalPath` and `attemptedFingerprint`).
2. Explicitly re-associate the moved repo path to the existing shared state:
   - `docdexd repo reassociate --repo <new_path> --state-dir <shared_state_dir> --old-path <knownCanonicalPath>`
   - Or: `docdexd repo reassociate --repo <new_path> --state-dir <shared_state_dir> --fingerprint <attemptedFingerprint>`
3. Retry the original operation with the same `--repo <new_path>` and `--state-dir <shared_state_dir>`; reindex if needed: `docdexd index --repo <new_path> --state-dir <shared_state_dir>`.

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
<<<<<<< HEAD
- Configure via env: `DOCDEX_STATE_DIR` (state base), `DOCDEX_EXCLUDE_PREFIXES`, `DOCDEX_EXCLUDE_DIRS`, `RUST_LOG=docdexd=debug` (optional verbose logs).
- Query over HTTP: `GET /search?q=<text>&limit=<n>` returns `{"hits":[{"path","rel_path","doc_id","score","summary","snippet","token_estimate"}...],"top_score":<float|null>,"topScore":<float|null>,"meta":{...}}`; `GET /snippet/:doc_id` fetches a focused snippet plus doc metadata.
=======
- Configure via env: `DOCDEX_STATE_DIR` (index location), `DOCDEX_EXCLUDE_PREFIXES`, `DOCDEX_EXCLUDE_DIRS`, `RUST_LOG=docdexd=debug` (optional verbose logs).
- Query over HTTP: `GET /search?q=<text>&limit=<n>` returns `{"hits":[{"path","rel_path","doc_id","score","summary","snippet","token_estimate"}...],"top_score":<float|null>,"topScore":<float|null>,"meta":{...}}`; `GET /snippet/:doc_id` fetches a focused snippet plus doc metadata; `GET /v1/stats?runs_limit=<n>` returns index stats + symbols enablement + recent run summaries (runs capped at 20; samples capped at 25; error summaries truncated to 240 chars).
>>>>>>> mcoda/task/bck-05-us-10-t06
- Or query via CLI: `docdexd query --repo <repo> --query "<text>" --limit 8` (JSON to stdout).
- Health check: `GET /healthz` should return `ok` before issuing search requests.
- Inject snippets into prompts:
```
"You are building features for this repo. Use the following documentation snippets for context. If a snippet cites a path, keep that path in your response. Snippets:\n<insert docdex snippets here>\nQuestion: <your question>"
```

### MCP (optional stdio server for MCP-aware clients)
Docdex can run as an MCP tool provider over stdio; it does not replace the HTTP daemon—pick whichever fits your agent/editor. If your MCP client supports resource templates, Docdex advertises a `docdex_file` template (`docdex://{path}`) which delegates to `docdex_open`.
- Run: `docdexd mcp --repo /path/to/repo --log warn --max-results 8` (alias: `--mcp-max-results 8`).
- Env override: `DOCDEX_MCP_MAX_RESULTS` clamps `docdex_search` results (min 1).
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
- MCP quick add commands (popular agents):
  - Docdex helper: `docdex mcp-add --repo /path/to/repo --log warn --max-results 8` auto-detects supported agents; add `--all` to attempt every known client and print manual steps for UI-only ones, or `--remove` to uninstall.
  - Codex CLI: `codex mcp add docdex -- docdexd mcp --repo /path/to/repo --log warn --max-results 8`.
  - Generic JSON config (Cursor, Continue, Windsurf, Cline, Claude Desktop devtools): add the `mcpServers.docdex` block above to your MCP config file (paths vary by client; most accept the `command`/`args` schema shown).
  - Manual/stdio-only clients: start `docdexd mcp --repo /path/to/repo --log warn --max-results 8` yourself and point the client at that command/binary.
- Tools exposed (CallToolResult content: result.content[0].text contains JSON):
  - `docdex_search` — args: `{ "query": "<text>", "limit": <int optional>, "project_root": "<path optional>" }`. Returns `{ "hits": [...], "results": [...], "top_score": <float|null>, "topScore": <float|null>, "repo_root": "...", "state_dir": "...", "limit": <int>, "project_root": "...", "meta": {...} }`.
  - `docdex_index` — args: `{ "paths": ["relative/or/absolute"], "project_root": "<path optional>" }`. Empty `paths` reindexes everything; otherwise ingests the listed files.
  - `docdex_files` — args: `{ "limit": <int optional, default 200, max 1000>, "offset": <int optional, default 0>, "project_root": "<path optional>" }`. Returns `{ "results": [{ "doc_id", "rel_path", "summary", "token_estimate" }], "total", "limit", "offset", "repo_root", "project_root" }`.
  - `docdex_open` — args: `{ "path": "<relative file>", "start_line": <int optional>, "end_line": <int optional>, "project_root": "<path optional>" }`. Returns `{ "path", "start_line", "end_line", "total_lines", "content", "repo_root", "project_root" }` (rejects paths outside repo and large files).
  - `docdex_stats` — args: `{ "project_root": "<path optional>" }`. Returns `{ "num_docs", "state_dir", "index_size_bytes", "segments", "avg_bytes_per_doc", "generated_at_epoch_ms", "last_updated_epoch_ms", "repo_root", "project_root" }`.
  - `docdex_repo_inspect` — args: `{ "project_root": "<path optional>" }`. Returns a repo identity report (normalized path, fingerprint, state mapping, status).
  - `docdex_symbols` — args: `{ "path": "<relative file>", "project_root": "<path optional>" }`. Returns a `docdex.symbols` payload for that file including `outcome.status` (`ok`/`skipped`/`failed`).
  - `docdex_memory_store` (requires `DOCDEX_ENABLE_MEMORY=1`) — args: `{ "text": "<string>", "metadata": <object optional>, "project_root": "<path optional>" }`. Returns `{ "id", "created_at" }`.
  - `docdex_memory_recall` (requires `DOCDEX_ENABLE_MEMORY=1`) — args: `{ "query": "<text>", "top_k": <int optional, max 50>, "project_root": "<path optional>" }`. Returns `{ "top_k", "results": [{ "content", "score", "metadata" }] }`.
- Tool limits (server-scoped; schema-stable): max items and snippet/content caps are documented in `docs/mcp/errors.md` and do not vary by repo.
- Example calls:
  - Initialize: `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
  - Initialize with workspace root: `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"workspace_root":"/path/to/repo"}}` (must match the server repo; sets default project_root for later calls)
  - List tools: `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`
  - Reindex: `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"docdex_index","arguments":{"paths":[]}}}`
  - Search: `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"docdex_search","arguments":{"query":"payment auth flow","limit":3,"project_root":"/repo"}}}`
  - List files: `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"docdex_files","arguments":{"limit":10,"offset":0}}}`
  - Open file: `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"docdex_open","arguments":{"path":"docs/readme.md","start_line":1,"end_line":20}}}`
  - Stats: `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"docdex_stats","arguments":{}}}`
- Errors: invalid JSON → code -32700; unsupported/missing `jsonrpc` → -32600; unknown tool/method → -32601; invalid params (empty query, bad args, project_root mismatch) → -32602; internal errors include a `reason` string in `error.data`.
- Agent guidance: call `docdex_search` with concise queries before coding; fetch only a few hits; if results look stale, call `docdex_index`; keep using HTTP/CLI if your stack isn't MCP-aware.
- Help: `docdexd mcp --help` shows MCP flags and defaults; `docdexd help-all` includes an MCP section listing tools and usage.

## HTTPS and Certbot
- TLS accepts PKCS8, PKCS1/RSA, and SEC1/EC private keys (compatible with Certbot output).
- Manual cert/key: `docdexd serve --repo <repo> --tls-cert /path/fullchain.pem --tls-key /path/privkey.pem`.
- Certbot helper: `docdexd serve --repo <repo> --host 0.0.0.0 --port 46137 --certbot-domain docs.example.com` (uses `/etc/letsencrypt/live/docs.example.com/{fullchain.pem,privkey.pem}`), or pass `--certbot-live-dir /custom/live/dir`.
- When using Certbot, set a deploy hook to restart/reload docdex after renewals (e.g., `certbot renew --deploy-hook "systemctl restart docdexd.service"` or kill -HUP your process supervisor).
- If binding to 443 directly, you need privileges; otherwise, keep docdex on 127.0.0.1 and let a reverse proxy terminate TLS.
- Installer integrity policy: `DOCDEX_INTEGRITY_POLICY=required|allow-missing|off` (default `required`). Overrides are insecure and never silent.
