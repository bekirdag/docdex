# Docdex

[![smithery badge](https://smithery.ai/badge/@bekirdag/docdex)](https://smithery.ai/server/@bekirdag/docdex)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/bekirdag/docdex/main.yml?branch=main)
![GitHub License](https://img.shields.io/github/license/bekirdag/docdex)
![GitHub Release](https://img.shields.io/github/v/release/bekirdag/docdex)
![Made with Rust](https://img.shields.io/badge/Made%20with-Rust-orange?logo=rust)

Docdex is a local-first indexer/search daemon for docs and source code. It runs per-project, keeps an on-disk index of markdown/text plus common code extensions, and serves top-k snippets over HTTP, CLI, or MCP for any coding assistant or tool—no external services or uploads required.

## Introduction
Docdex indexes docs + code for a repo and serves search, chat, and code intelligence locally over HTTP/CLI/MCP.
Install it with npm (preferred) or build from source, then run `docdexd index --repo .`, `docdexd serve --repo .` (or `docdexd daemon` for singleton mode), and `docdexd chat --repo . --query "..."` (omit `--query` for the REPL).

## Install
### npm
- Requires Node.js >= 18.
- Install: `npm i -g docdex` (or run `npx docdex --version` to verify).
- Commands: `docdex` (alias `docdexd`) downloads the right binary for your platform from the matching GitHub release.
- Supported published binaries: macOS (arm64, x64), Linux glibc (arm64, x64), Linux musl (x64), Windows (x64); installer fetches the matching platform release asset.
- Supported platforms + manual source build + troubleshooting: `docs/ops/installer_supported_platforms.md`.
- Release manifest schema (assets + checksums + fallback rules): `docs/contracts/release_manifest_schema_v1.md`.
- If you publish from a fork, set `DOCDEX_DOWNLOAD_REPO=<owner/repo>` before installing so the downloader fetches your release assets.
- If you mirror release assets locally, set `DOCDEX_DOWNLOAD_BASE=http://host/path` to point the installer at the mirror.
- Distribution: binaries stay in GitHub Releases (small npm package); postinstall fetches `docdexd-<platform>.tar.gz` matching the npm version.
- Platform diagnostics (no download): `docdex doctor` (or `docdex diagnostics`) prints detected OS/arch(/libc), whether supported, and the expected Rust target triple + release asset naming pattern.
- Publishing uses npm Trusted Publishing (OIDC) — no NPM token needed; see `.github/workflows/release.yml`.
- Postinstall prompts: if Ollama is missing, the installer asks to install Ollama and `nomic-embed-text`. If Ollama is available, it prompts to pick a default chat model and can install `phi3.5:3.8b` (~2.2 GB) while showing free disk space. Skip with `DOCDEX_OLLAMA_INSTALL=0` or `DOCDEX_OLLAMA_MODEL_PROMPT=0`; force with `DOCDEX_OLLAMA_INSTALL=1` or `DOCDEX_OLLAMA_MODEL=<model>`; preselect with `DOCDEX_OLLAMA_DEFAULT_MODEL`.

### Build from source
- Requires Rust (stable) and Cargo.
- Build: `cargo build --release`.
- Install: `cargo install --path .` (use `--locked` if you want to pin dependencies).
- MCP server: build/install `docdex-mcp-server` too (or set `DOCDEX_MCP_SERVER_BIN`), e.g. `cargo build -p docdex-mcp-server`.

## Features at a glance
- Per-repo daemon (`docdexd serve`) with HTTP API and optional MCP; defaults to `127.0.0.1:3210` and per-repo state under `~/.docdex/state/repos/<fingerprint>/`.
- Singleton daemon (`docdexd daemon`) with a lockfile at `~/.docdex/daemon.lock`; CLI commands auto-spawn it unless `DOCDEX_DISABLE_DAEMON_AUTO=1` or `DOCDEX_CLI_LOCAL=1` is set.
- Local-first waterfall retrieval: repo index + libs, optional web fallback, memory enabled by default (Ollama embeddings).
- Search + chat surfaces: `/search`, `/v1/chat/completions`, CLI `chat` (CLI proxies to HTTP by default; `DOCDEX_CLI_LOCAL=1` for in-process).
- Code intelligence: symbols, AST, impact graph and diagnostics (`/v1/symbols`, `/v1/ast`, `/v1/graph/impact`).
- Web discovery + scraping (Tier 2, disabled by default; enable with `DOCDEX_WEB_ENABLED=1`): DuckDuckGo HTML + headless browser (Chrome/Chromium/Edge/Brave/Vivaldi) with caching and rate limits; Linux can auto-install Chromium when missing.
- Memory + reasoning DAG (`/v1/memory/*`, `/v1/dag/export`) enabled by default (disable in config if needed).
- Hardware-aware LLM guidance (`llm-list`, `llm-setup`) and Ollama defaults (`phi3.5:3.8b`, `nomic-embed-text`).
- Security/ops: loopback bind by default, non-loopback binds require auth token, secure-mode rate limiting, TLS options, audit logs, `/healthz` + `/metrics`, `docdexd check` preflight.
- Utilities: `self-check` secret scan, `help-all`, `repo inspect/reassociate`, `browser list/setup/install`, `libs discover/fetch/ingest`, `run-tests` harness, `web-cache-flush`, `tui`, `mcp-add`.

## What it does
- Indexes repo docs and source code (.md/.mdx/.txt plus common code extensions) into Tantivy plus symbols/AST/impact data, stored under `~/.docdex/state/repos/<fingerprint>/` (override with `--state-dir`).
- Serves the same repo data over HTTP and CLI (CLI uses the daemon unless `DOCDEX_CLI_LOCAL=1`).
- Watches files while serving to incrementally ingest changes.
- Offers optional web fallback (disabled by default; enable with `DOCDEX_WEB_ENABLED=1`) and MCP tooling per repo with strict isolation; memory is enabled by default but configurable.
- Hardened defaults: loopback binding, `--expose` required for non-loopback binds, auth token required on non-loopback, secure-mode rate limiting, audit logging, strict state-dir perms.

## How it works
1) `docdexd index` builds the repo index (docs + code, plus symbols/impact data) under `~/.docdex/state/repos/<fingerprint>/` and can ingest libs sources.  
2) `docdexd serve` opens the repo index, starts a file watcher, optionally auto-starts MCP, and serves the HTTP API.  
   `docdexd daemon` starts the same service in singleton mode with a daemon lock.  
3) CLI commands use HTTP by default; override with `DOCDEX_HTTP_BASE_URL` or `DOCDEX_CLI_LOCAL=1` for in-process.  
4) Waterfall retrieval uses local index first; web fallback is gated (enable with `DOCDEX_WEB_ENABLED=1`); memory is enabled by default but configurable.

## Quick start
```bash
# install (npm)
npm i -g docdex
# or use once
npx docdex --version

# full index for a repo/workspace
docdexd index --repo /path/to/repo

# serve HTTP API with live file watching (per-repo)
docdexd serve --repo /path/to/repo --host 127.0.0.1 --port 3210 --log info --secure-mode=false
# for non-loopback binds, add --expose and --auth-token (or use TLS options)
# docdexd serve --repo /path/to/repo --host 0.0.0.0 --port 3210 --expose --auth-token <token> --require-tls=false
# set a default profile agent id for preference memory
# docdexd serve --repo /path/to/repo --agent-id <agent-id>

# singleton daemon (same flags, uses daemon lock)
docdexd daemon --repo /path/to/repo --host 127.0.0.1 --port 3210 --log info --secure-mode=false

# ad-hoc search via CLI (JSON)
docdexd chat --repo /path/to/repo --query "otp flow" --limit 5 --agent <slug>
# interactive REPL
docdexd chat --repo /path/to/repo
# (CLI targets server.http_bind_addr by default; override with DOCDEX_HTTP_BASE_URL)
```

## TL;DR for agents
- Use Docdex for repo docs: run `docdexd index --repo .` once, then start the singleton daemon with `docdexd daemon --repo . --host 127.0.0.1 --port 3210` (shared MCP over `/sse`), or run legacy stdio MCP with `docdexd mcp --repo . --log warn`.
- Add `.docdex/` to `.gitignore` so indexes aren't committed.
- Use `.docdexignore` (gitignore syntax) to exclude files/dirs from indexing; `.gitignore` is honored too.
- When MCP-aware, register a server named `docdex` that points to `http://localhost:<port>/sse` (shared MCP) or, for stdio-only clients, runs `docdexd mcp --repo . --log warn --max-results 8`.
- Prefer summary-first (snippets=false), fetch specific snippets only when needed, keep queries short, and respect token estimates.

## Smithery local usage
Smithery already launches Docdex as a local MCP tool. `smithery.yaml` sets `runtime: "local"` and runs `docdexd mcp --repo {{repo_path}} --log warn --max-results 8` over stdio, so the tool never requires a remote HTTP endpoint; just point the `repo_path` parameter at your workspace (the example config defaults to `.`). Run `docdexd index --repo` before invoking Smithery so the index exists, then let the MCP command share that local repo—no remote server or proxy is involved.

## What is Smithery?
Smithery is a meta-framework that launches trusted local tools for MPC-aware agents and coding assistants. Instead of wiring Docdex through a remote HTTP server, the Smithery runtime keeps everything local: it runs the `docdexd mcp` command inside your workspace, streams stdout/stderr over stdio, and uses MCP JSON-RPC to deliver Docdex's search and indexing tools to the client. That means no `server.js`/`server.json` stub is needed—just the local `docdexd` binary and the repo path.

### Smithery-aware clients
- Codex CLI / Codex Studio
- Cursor
- Continue AI
- Windsurf
- Cline
- Claude Desktop devtools
- docdex's built-in helper harness (`docdex mcp-add`)

These clients already speak Smithery's discovery format (`smithery.yaml`, JSON-RPC tooling definitions, MCP handshake). Register `docdexd mcp --repo . --log warn --max-results 8` as the `docdex` MCP server and the client will treat it as a local tool; no network proxy is required.

## Hardware-aware LLM guidance
Use `docdexd llm-list` or `docdexd llm-setup` to print your host’s RAM + GPU summary (powered by `hardware::detect_hardware`) together with catalog entries from `docs/llm_list.json`. The commands highlight the recommended entry that satisfies `minRamGb`/`requiresGpu`, so you can always pick the model that fits your machine instead of guessing. Those tool outputs also double-check Ollama availability before you launch memory-heavy prompts.

## Repo-scoped caches & guardrails
State is fingerprinted and isolated under `~/.docdex/state/repos/<fingerprint>/` (index, `libs_index`, `memory.db`, `symbols.db`, `dag.db`, `impact_graph.json`). Global caches under `~/.docdex/state/cache/{web,libs}` are reused but only ingested into the active repo, preventing cross-repo bleed. `StateLayout`/`repo_manager` enforce secure directories and warn on unexpected state keys.
Impact graph snapshots carry schema metadata and are migrated on read; reindex to persist upgrades. Dynamic import resolution can be guided by `docdex.import_map.json` and runtime traces in `docdex.import_traces.jsonl` (imported into `impact_graph.json`).

## Usage cheat sheet
- Build index: `docdexd index --repo <path>` (add `--exclude-*` to skip paths).
- Serve with watcher: `docdexd serve --repo <path> --host 127.0.0.1 --port 3210 --log warn --secure-mode=false` (use `--expose --auth-token <token>` for non-loopback binds; secure mode adds default rate limits and loopback allowlist).
- Singleton daemon: `docdexd daemon --repo <path>` (uses the same flags as `serve`, plus a daemon lock to ensure one instance).
- MCP auto-start: `docdexd serve --repo <path>` spawns MCP when enabled (default); set `--disable-mcp` or `DOCDEX_ENABLE_MCP=0` to skip, or `--enable-mcp` to force on.
- MCP auth: `docdexd mcp --auth-token <token>` (or `DOCDEX_AUTH_TOKEN`) requires clients to pass `auth_token` in `initialize`.
- Secure serving: use `--auth-token <token>` for non-loopback binds; use TLS with `--tls-cert/--tls-key` or `--certbot-domain <domain>`.
- Single-file ingest: `docdexd ingest --repo <path> --file docs/new.md` (honors excludes).
- Query via CLI: `docdexd chat --repo <path> --query "term" --limit 4` (add `--repo-only` to ignore libs index hits; set `DOCDEX_HTTP_BASE_URL` if the daemon runs elsewhere; set `DOCDEX_CLI_LOCAL=1` for offline mode).
- Chat REPL: `docdexd chat --repo <path>` (omit `--query` to start interactive mode; `exit`/EOF quits).
- Git hygiene: if you store state under the repo (for example via `--state-dir .docdex`), add `.docdex/` to `.gitignore` so index artifacts never get committed.
- Health check: `curl http://127.0.0.1:3210/healthz`.
- Readiness check: `docdexd check` validates config/state, Ollama, Chrome, bind availability, and MCP binary availability (set `DOCDEX_CHECK_MCP_SPAWN=1` to spawn-check MCP; `DOCDEX_CHECK_MCP_SPAWN_TIMEOUT_MS` to tune timeout).
- Sensitive-term scan: `docdexd self-check --repo <path>` writes `self_check_report.json` to the repo state dir (fails non-zero if matches are found).
- Web fallback gate: set `DOCDEX_WEB_ENABLED=1` to allow Tier 2 web discovery, or `DOCDEX_OFFLINE=1` to force offline.
- Web cache flush: `docdexd web-cache-flush` (clears `~/.docdex/state/cache/web`).
- Profile memory: `docdexd profile list`, `docdexd profile add --agent-id <id> --category style --content \"Prefer X\"`, `docdexd profile export --out profile_sync.json`, `docdexd profile import profile_sync.json`.
- Hook checks: `docdexd hook pre-commit --repo <path>` (fails open if the daemon is unavailable; can use a Unix socket when `server.hook_socket_path` is set).
- Libs workflow: `docdexd libs discover --repo <path>` then `docdexd libs fetch --repo <path>` (or `docdexd libs ingest --repo <path> --sources <file>`; aliases: `libs-discover`, `libs-ingest`).
- Repo mapping: `docdexd repo inspect --repo <path>` and `docdexd repo reassociate --repo <new_path> --state-dir <shared_state_dir> --old-path <old_path>`.
- Test harness: `docdexd run-tests --repo <path> [--target <path>]` (see Run-tests config below).
- Agent eval: `docdexd agent eval --repo <path> [--max-queries N]` writes eval JSON to `./tmp`.
- Help-all: `docdexd help-all` prints every subcommand and flag.
- Summary-only search responses: `curl "http://127.0.0.1:3210/search?q=foo&snippets=false"`; fetch snippets only for top hits.
- Repo-only HTTP search (ignore libs index hits): `curl "http://127.0.0.1:3210/search?q=foo&include_libs=false"`.
- Token budgets: `curl "http://127.0.0.1:3210/search?q=foo&max_tokens=800"` to drop hits that would exceed your prompt budget; pair with `snippets=false` then fetch 1–2 snippets you keep.
- Text-only snippets: append `text_only=true` to `/snippet/:doc_id` or start `serve` with `--strip-snippet-html` (or `--disable-snippet-text` to return metadata only).
- Keep requests compact: defaults enforce `max_query_bytes=4096` and `max_request_bytes=16384`; keep queries short and leave `--max-limit` low (default 8) to avoid oversized responses.
- Prompt hygiene: in agent prompts, normalize whitespace and include only `rel_path`, `summary`, and trimmed `snippet` (omit `score`/`token_estimate`/`doc_id`).
- Trim noise early: use `--exclude-dir` and `--exclude-prefix` to keep vendor/build/cache/secrets out of the index so snippets stay relevant and short.
- Quiet logging for agents: run `docdexd serve --log warn --access-log=false` if you marshal responses elsewhere to cut log overhead.
- TUI: `docdexd tui` shells out to the `docdex-tui` binary; set `DOCDEX_TUI_BIN` if it is not on `PATH`.
- Cache hits client-side: store `doc_id` ↔ `rel_path` ↔ `summary` to avoid repeat snippet calls; fetch snippets only for new doc_ids.
- Agent help: `curl http://127.0.0.1:3210/ai-help` (requires auth if configured; include `Authorization: Bearer <token>` when you've set `--auth-token`). The response includes a short MCP registration recipe.

## Run-tests configuration
- Configure per-repo via `.docdex/run-tests.json` with `{ "command": "<bin>", "args": ["..."], "env": { "KEY": "VALUE" } }`.
- Or set `DOCDEX_RUN_TESTS_CMD` and optional `DOCDEX_RUN_TESTS_ARGS` (accepts JSON array or whitespace-split string).
- Docdex injects `DOCDEX_REPO_ROOT` and (when `--target` is set) `DOCDEX_TEST_TARGET` into the test process.

## Quality gates and audits
- Quality targets: `docs/quality_gates.md` (latency, error rate, soak, security).
- Metrics dashboard + alerts: `docs/metrics_dashboard.md` (PromQL, gate thresholds).
- Run-all tests: `scripts/test_run_all.sh` (unit, integration, API scripts).
- Load/soak: `scripts/load_test_http.sh`, `scripts/load_test_mcp.sh` (requires running daemon).
- Indexing bench: `scripts/bench_indexing.sh` (criterion benchmark).
- Security audit + SBOMs: `scripts/security_audit.sh` (cargo audit/sbom, npm audit).

### Sample performance results
- HTTP load test (30 minutes): 92,952 requests; 92,947 ok; 5 fail; 0.01% error rate; 51.64 qps.

### Repro perf results
- Start: `DOCDEX_WEB_ENABLED=0 DOCDEX_ENABLE_MCP=0 docdexd serve --repo /path/to/repo --secure-mode=false --access-log=false`.
- Load: `DOCDEX_LOAD_DURATION_SECS=1800 DOCDEX_LOAD_CONCURRENCY=4 scripts/load_test_http.sh`.
- Capture: record `docdex_http_request_latency_p95_ms` from `/metrics` and save the terminal output to `target/test_logs/`.

### Perf FAQ
- Browser path errors: run `docdexd browser setup` (Linux auto-installs Chromium when allowed), or set `DOCDEX_WEB_BROWSER`/`DOCDEX_CHROME_PATH`/`web.scraper.chrome_binary_path`.
- Ollama timeouts: ensure `ollama` is running and tune `DOCDEX_EMBEDDING_TIMEOUT_MS` (or set `DOCDEX_EMBEDDING_BASE_URL`).
- Rate limits (429): run with `--secure-mode=false` for load tests or increase `--rate-limit-per-min`.

## Versioning
- Semantic versioning with tagged releases (`vX.Y.Z`). The Rust crate and npm package share the same version.
- Conventional Commits drive release notes via Release Please; it opens release PRs that bump `Cargo.toml` and `npm/package.json`, update changelogs, and creates the tag/release on merge.
- Pin to a released version when integrating (e.g., in scripts or Dockerfiles) so upgrades are explicit and reversible.
- If you build from source, the version comes from `Cargo.toml` in this repo; the npm wrapper uses the matching version to fetch binaries.

## Paths and defaults
- State/index directory: `~/.docdex/state/repos/<fingerprint>/index` by default (override with `--state-dir` / `DOCDEX_STATE_DIR`). The directory is created with `0700` permissions by default.
- HTTP API: defaults to `127.0.0.1:3210` when serving.
- Docdex data stays local under `~/.docdex/state` unless overridden; no external services.
- Logs: set `DOCDEX_LOG_TO_STATE=1` to also write `~/.docdex/state/logs/docdexd-<pid>.log`.

## Configuration knobs
- `--repo <path>`: workspace root to index (defaults to `.`).
- `--state-dir <path>` / `DOCDEX_STATE_DIR`: override index storage path (relative paths are resolved under `repo`). When `--state-dir` is an absolute shared base used across repos, repo moves/renames require an explicit `docdexd repo reassociate` step before Docdex will reuse the existing state.
- `--exclude-prefix a,b,c` / `DOCDEX_EXCLUDE_PREFIXES`: extra relative prefixes to skip.
- `--exclude-dir a,b,c` / `DOCDEX_EXCLUDE_DIRS`: extra directory names to skip anywhere in the tree.
- `DOCDEX_HTTP_BASE_URL`: override the daemon base URL for CLI commands (defaults to `server.http_bind_addr`).
- `DOCDEX_HTTP_TIMEOUT_MS`: override the CLI HTTP client timeout (default 30000).
- `DOCDEX_CLI_LOCAL`: set to `1` to force CLI commands to run in-process instead of calling the daemon.
- `DOCDEX_ENABLE_SYMBOL_EXTRACTION`: deprecated (no-op). Symbols/AST/impact extraction are always enabled; see `docs/symbols_store.md` for drift/reindex behavior.
- `DOCDEX_DYNAMIC_IMPORT_SCAN_LIMIT` / `DOCDEX_ENABLE_IMPORT_TRACES`: impact graph controls for dynamic import scanning and runtime import traces (`docdex.import_traces.jsonl`).
- `DOCDEX_LLM_AGENT` / `DOCDEX_AGENT`: default LLM agent slug/id for daemon chat (also allows non-ollama providers when set).
- `DOCDEX_WEB_ENABLED` / `DOCDEX_OFFLINE`: enable Tier 2 web discovery or force offline mode (default: disabled unless explicitly enabled).
- `DOCDEX_WEB_TRIGGER_THRESHOLD` / `DOCDEX_WEB_MIN_MATCH_RATIO` / `DOCDEX_LOCAL_RELEVANCE_THRESHOLD`: web gate thresholds (defaults 0.7 / 0.2 / 0.7).
- `DOCDEX_WEB_MAX_HITS` / `DOCDEX_WEB_MAX_RESULTS`: clamp web hits (max hits defaults from config, max results default 20).
- `DOCDEX_WEB_USER_AGENT` / `DOCDEX_DDG_BASE_URL` / `DOCDEX_WEB_BLOCKLIST`: override discovery user agent, DDG base URL, or blocklist.
- `DOCDEX_WEB_MIN_SPACING_MS` / `DOCDEX_WEB_REQUEST_DELAY_MS` / `DOCDEX_WEB_REQUEST_TIMEOUT_MS`: discovery spacing, fetch delay, and request timeout.
- `DOCDEX_WEB_JITTER_MS` / `DOCDEX_WEB_MAX_ATTEMPTS` / `DOCDEX_WEB_BACKOFF_BASE_MS` / `DOCDEX_WEB_BACKOFF_MULTIPLIER` / `DOCDEX_WEB_BACKOFF_MAX_MS` / `DOCDEX_WEB_MAX_CONSEC_FAIL` / `DOCDEX_WEB_COOLDOWN_MS`: web backoff/cooldown tuning.
- `DOCDEX_WEB_CACHE_TTL_SECS`: override cache TTL (default 2,592,000 seconds).
- `DOCDEX_WEB_BROWSER` / `DOCDEX_CHROME_PATH` / `CHROME_PATH`: override the browser binary for scraping (or set `web.scraper.chrome_binary_path` in config).
- `DOCDEX_BROWSER_AUTO_INSTALL`: set to `0` to disable Linux auto-install of headless Chromium (config: `web.scraper.auto_install`).
- `DOCDEX_BROWSER_DOWNLOAD_BASE` / `DOCDEX_BROWSER_VERSION` / `DOCDEX_BROWSER_SHA256`: override the pinned Linux Chromium download URL + checksum (air-gapped mirrors).
- `--expose` / `DOCDEX_EXPOSE`: allow binding to non-loopback interfaces (requires `--auth-token`).
- `--auth-token <token>` / `DOCDEX_AUTH_TOKEN`: required for non-loopback binds; clients pass it as `Authorization: Bearer <token>`.
- `--secure-mode <true|false>` / `DOCDEX_SECURE_MODE`: default `true`; when enabled, applies loopback allowlist by default and default rate limiting (60 req/min).
- `--allow-ip a,b,c` / `DOCDEX_ALLOW_IPS`: optional comma-separated IPs/CIDRs allowed to reach the HTTP API (default: loopback-only unless `--expose`; when exposed and list is empty, allow all).
- `--tls-cert` / `DOCDEX_TLS_CERT` and `--tls-key` / `DOCDEX_TLS_KEY`: serve HTTPS with the provided cert/key. With TLS enforcement on, non-loopback binds must use HTTPS unless you explicitly opt out.
- `--certbot-domain <domain>` / `DOCDEX_CERTBOT_DOMAIN`: point TLS at `/etc/letsencrypt/live/<domain>/{fullchain.pem,privkey.pem}` (Certbot). Conflicts with manual `--tls-*`.
- `--certbot-live-dir <path>` / `DOCDEX_CERTBOT_LIVE_DIR`: use a specific Certbot live dir containing `fullchain.pem` and `privkey.pem`.
- `--require-tls <true|false>` / `DOCDEX_REQUIRE_TLS`: default `true`. Enforce TLS for non-loopback binds; set to `false` when TLS is already terminated by a trusted proxy.
- `--insecure` / `DOCDEX_INSECURE_HTTP=true`: allow plain HTTP on non-loopback binds even when TLS is enforced (only use behind a trusted proxy).
- `--preflight-check <true|false>` / `DOCDEX_PREFLIGHT_CHECK`: run `docdexd check` before serving; fail fast on missing dependencies (default false).
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
- `--enable-memory <true|false>` / `DOCDEX_ENABLE_MEMORY`: control memory endpoints for the daemon (default: enabled via `[memory].enabled=true` in config; set `[memory].enabled=false` to disable).
- `--embedding-base-url` / `DOCDEX_EMBEDDING_BASE_URL`: Ollama base URL for embedding calls (preferred over `--ollama-base-url`).
- `--ollama-base-url` / `DOCDEX_OLLAMA_BASE_URL`: legacy embedding base URL fallback.
- `--embedding-model` / `DOCDEX_EMBEDDING_MODEL`: embedding model identifier (default `nomic-embed-text`).
- `--embedding-timeout-ms` / `DOCDEX_EMBEDDING_TIMEOUT_MS`: embedding request timeout in milliseconds (`0` disables; default `0`).
- `--enable-mcp` / `--disable-mcp` / `DOCDEX_ENABLE_MCP`: control MCP auto-start when serving (default: enabled).
- `DOCDEX_MCP_SERVER_BIN`: override the MCP server binary path.
- `DOCDEX_MCP_MAX_RESULTS`: clamp MCP tool results (default 8).
- `DOCDEX_MCP_RATE_LIMIT_PER_MIN` / `DOCDEX_MCP_RATE_LIMIT_BURST`: MCP tool-call rate limiting.
- `--run-as-uid` / `DOCDEX_RUN_AS_UID`, `--run-as-gid` / `DOCDEX_RUN_AS_GID`: (Unix) drop privileges to the provided UID/GID after startup prep.
- Root safety: docdexd refuses to run as root unless you provide `--run-as-uid` and/or `--run-as-gid` (Unix).
- `--chroot <path>` / `DOCDEX_CHROOT`: (Unix) chroot into `path` before serving; repo/state paths must exist inside that jail.
- `--unshare-net` / `DOCDEX_UNSHARE_NET=true`: (Linux only) unshare the network namespace before serving (requires CAP_SYS_ADMIN/root); no-op on other platforms.
- `DOCDEX_REPO_CACHE_SIZE`: LRU size for repo resolution (default 16, max 256).
- `DOCDEX_DIFF_MAX_EDGES` / `DOCDEX_DIFF_MAX_DEPTH`: clamp diff-aware context edge/depth extraction.
- `DOCDEX_CHECK_MCP_SPAWN` / `DOCDEX_CHECK_MCP_SPAWN_TIMEOUT_MS`: enable MCP spawn probe during `docdexd check` and set timeout (default 2000ms).
- `DOCDEX_WEB_DEBUG` / `DOCDEX_LLM_DEBUG` / `DOCDEX_LLM_DEBUG_MAX_CHARS`: enable debug logging and limit debug output size.
- `DOCDEX_LOG_TO_STATE`: also write logs to `~/.docdex/state/logs/docdexd-<pid>.log`.
- Logging: `--log <level>` on `serve` (defaults to `info`), or `RUST_LOG=docdexd=debug` style filters.
- Secure mode defaults: when `--secure-mode=true` (default), docdex allowlists loopback by default and applies a 60 req/min rate limit. Set `--secure-mode=false` to opt out for local dev and adjust `--allow-ip`/rate limits as needed.

## Indexing rules (see `index/mod.rs`)
- File types: `.md`, `.markdown`, `.mdx`, `.txt`, `.rs`, `.py`, `.js`, `.jsx`, `.ts`, `.tsx`, `.go` (extend `DEFAULT_EXTENSIONS` to add more).

## Parser drift and reindexing

Docdex stores Tree-sitter parser versions in `symbols.db`. If the stored parser versions differ from the running build, symbols/AST data are invalidated and requests return `stale_index` until you reindex.

- Check drift status: `docdexd symbols-status --repo <path>` (or `GET /v1/symbols/status`).
- Rebuild symbols/AST: `docdexd index --repo <path>` (this refreshes `symbols.db` and `impact_graph.json`).
- Skipped directories: broad VCS/build/cache/vendor folders across ecosystems (e.g., `.git`, `.hg`, `.svn`, `node_modules`, `.pnpm-store`, `.yarn*`, `.nx`, `.rollup-cache`, `.webpack-cache`, `.tsbuildinfo`, `.next`, `.nuxt`, `.svelte-kit`, `.mypy_cache`, `.ruff_cache`, `.venv`, `target`, `go-build`, `.gradle`, `.mvn`, `pods`, `.dart_tool`, `.android`, `.serverless`, `.vercel`, `.netlify`, `_build`, `_opam`, `.stack-work`, `elm-stuff`, `library`, `intermediate`, `.godot`, etc.; see `DEFAULT_EXCLUDED_DIR_NAMES` for the full list).
- Skipped relative prefixes: `logs/`, `.docdex/`, `.docdex/logs/`, `.docdex/tmp/`, `.gpt-creator/logs/`, `.gpt-creator/tmp/`, `.mastercoda/logs/`, `.mastercoda/tmp/`, `docker/.data/`, `docker-data/`, `.docker/`.
- Snippet sizing: summaries ~360 chars (up to 4 segments); snippets ~420 chars.

## Ranking toggles

AST/symbol ranking boosts are enabled by default for search and chat, and can be toggled via config or env:

- Config (`~/.docdex/config.toml`): `[search].symbol_ranking_enabled`, `[search].ast_ranking_enabled`, `[search].chat_symbol_ranking_enabled`, `[search].chat_ast_ranking_enabled`.
- Env overrides: `DOCDEX_ENABLE_SYMBOL_RANKING`, `DOCDEX_ENABLE_AST_RANKING`, `DOCDEX_ENABLE_CHAT_SYMBOL_RANKING`, `DOCDEX_ENABLE_CHAT_AST_RANKING` (truthy/falsey values).

## Profile memory config
- Config (`~/.docdex/config.toml`): `[memory.profile].embedding_model` (default `nomic-embed-text`), `[memory.profile].embedding_dim` (default `768`).
- Optional defaults: `[server].default_agent_id` sets the fallback agent for profile recall; `[server].hook_socket_path` enables Unix socket hook transport.

Example:
```toml
[memory.profile]
embedding_model = "nomic-embed-text"
embedding_dim = 768
```

## HTTP API
- `GET /healthz` — returns `ok`; this endpoint is unauthenticated and not rate-limited (IP allowlist still applies).
- `GET /search?q=<text>&limit=<n>&snippets=<bool>&max_tokens=<u64>&include_libs=<bool>` — returns `{ hits: [...] }` with doc id, `rel_path`/`path`, `kind` (`doc`|`code`), summary, snippet, score, token estimate. Optional: `force_web`, `skip_local_search`, `no_cache`, `max_web_results`, `llm_filter_local_results`, `diff_mode`, `diff_base`, `diff_head`, `diff_path`, `repo_id`. Set `snippets=false` for summary-only responses; set `max_tokens` to drop hits above your budget. `include_libs` defaults to `true` when a libs index exists; set `include_libs=false` to search repo-only.
- `GET /snippet/:doc_id?window=<lines>&q=<query>&text_only=<bool>&max_tokens=<u64>` — returns `{ doc, snippet }` with optional highlighted snippet; falls back to preview when query highlighting is empty (default window: 40 lines). Set `text_only=true` to drop HTML and shrink payloads; set `max_tokens` to omit the snippet if the doc exceeds your budget.
- `POST /v1/index/rebuild` — rebuild the repo index (body `{ libs_sources?: "<path>" }` pointing at a libs sources JSON file).
- `POST /v1/index/ingest` — ingest a single file (body `{ file: "<path>" }`).
- `POST /v1/chat/completions` — OpenAI-compatible chat completion with docdex context; optional `docdex` object (`limit`, `force_web`, `skip_local_search`, `no_cache`, `include_libs`, `max_web_results`, `llm_filter_local_results`, `compress_results`, `diff`) and `repo_id` in query/body.
- `GET /v1/graph/impact?file=<path>&repo_id=<id>` — returns inbound/outbound dependency edges; `file` is required, `repo_id` is optional (must match the daemon repo if provided). Optional controls: `maxEdges=<int>`, `maxDepth=<int>`, `edgeTypes=<comma-separated>`.
- `GET /v1/graph/impact/diagnostics` — returns unresolved import diagnostics; optional `file`, `limit`, `offset`.
- `GET /v1/symbols?path=<repo-relative>&repo_id=<id>` — returns symbols for a file (`docdex.symbols`).
- `GET /v1/symbols/status?repo_id=<id>` — Tree-sitter parser drift status.
- `GET /v1/ast?path=<repo-relative>&maxNodes=<n>&repo_id=<id>` — returns AST nodes for a file (`docdex.ast`).
- `GET /v1/ast/search?kinds=<csv>&mode=<any|all>&limit=<n>&repo_id=<id>` — returns files containing AST kinds.
- `POST /v1/ast/query` — returns files with matching AST nodes (kinds + optional `name`, `field`, `pathPrefix`, `mode`, `limit`, `sampleLimit`, `repo_id`).
- `POST /v1/memory/store` / `POST /v1/memory/recall` — store/recall repo-scoped memory items (memory enabled by default).
- `GET /v1/dag/export?session_id=<id>&format=<json|text|dot>&max_nodes=<n>` — export reasoning DAG for a session.
- `POST /v1/web/search` / `POST /v1/web/fetch` / `POST /v1/web/cache/flush` — web discovery/fetch and cache control.
- `POST /v1/libs/discover` / `POST /v1/libs/ingest` / `POST /v1/libs/fetch` — library docs discovery and ingestion (body `{ sources_path?: "<path>" }`).
- `GET /ai-help` — returns a JSON quickstart for agents (endpoints, CLI commands, limits, best practices).
- `GET /metrics` — returns Prometheus-style counters/gauges for rate-limit/auth/error and browser guard metrics (see `docs/ops/browser_guard.md`).
- If `--auth-token` is set, include `Authorization: Bearer <token>` on HTTP calls (including `/ai-help`).
- Repo scoping: include `repo_id` in query/body or the `x-docdex-repo-id` header; mismatches are rejected.

## CLI commands
- `check` — validate config/state, bind availability, and local dependencies (Ollama/Chrome/MCP); set `DOCDEX_CHECK_MCP_SPAWN=1` to spawn-check MCP.
- `browser list|setup|install` — inspect browser candidates, run discovery/auto-install, or install headless Chromium on Linux.
- `serve --repo <path> [--host 127.0.0.1] [--port 3210] [--log info]` — start HTTP API with file watching for incremental updates.
- `index --repo <path>` — rebuild the entire index.
- `ingest --repo <path> --file <file>` — reindex a single file.
- `chat --repo <path> --query "<text>" [--limit 8] [--repo-only|--web-only] [--max-web-results N] [--no-cache] [--llm-filter-local-results] [--diff-mode working-tree|staged|range --diff-base <rev> --diff-head <rev> --diff-path <path>]` — run a search and print JSON hits (omit `--query` to enter REPL mode).
- `help-all` — print full help for every subcommand and flag.
- `self-check --repo <path> [--terms "foo,bar"]` — scan the index for sensitive terms; writes `self_check_report.json` and exits non-zero on matches (default patterns on; disable with `--include-default-patterns=false`).
- `web-search --query "<text>" [--limit 8]`, `web-fetch --url <url>`, `web-rag --query "<text>" [--limit 8]` — web discovery/fetch and web-assisted queries.
- `web-cache-flush` — clear cached web discovery/fetch entries.
- `libs discover --repo <path> [--sources <file>]`, `libs fetch --repo <path> [--sources <file>]`, `libs ingest --repo <path> --sources <file>` (aliases: `libs-discover`, `libs-ingest`) — library docs discovery and ingestion.
- `memory-store --text "<text>"` / `memory-recall --query "<text>" --top-k 5` — memory store/recall (requires embeddings; memory enabled by default).
- `symbols-status --repo <path>` — Tree-sitter parser drift status.
- `impact-diagnostics --repo <path>` — unresolved import diagnostics.
- `dag view --repo <path> <session_id> [--format text|dot|json]` — render a session DAG trace.
- `llm-list`, `llm-setup` — hardware-aware model guidance and setup.
- `run-tests --repo <path> [--target <path>]` — run repo-specific test commands from `.docdex/run-tests.json` or env overrides.
- `tui [--repo <path>]` — launch the `docdex-tui` binary (set `DOCDEX_TUI_BIN` if needed).
- `agent eval --repo <path>` — run mcoda agent evals with a fixed query set (writes to `./tmp`).
- `repo inspect --repo <path> [--state-dir <state_dir>]` — show normalized path, computed fingerprint, and any shared-state mapping (canonical + aliases + lastSeen) for move/rename recovery.
- `repo reassociate --repo <new_path> --state-dir <shared_state_dir> (--old-path <old_path> | --fingerprint <sha256>)` — explicitly re-associate a moved/renamed repo path to existing state under a shared base state directory.
- `mcp --repo <path>` / `mcp-add` — run or register the MCP server.

## Perf checks
- Repo-only search latency (p95 < 50ms; see `docs/sds/sds.md`): `cargo test --release repo_only_search_p95_under_50ms_with_libs_index_present -- --ignored --nocapture`.

## Help and command discovery
- List all commands/flags: `docdexd --help`.
- Dump help for every subcommand: `docdexd help-all`.
- See `serve` options (TLS, auth, rate limits, watcher): `docdexd serve --help`.
- Indexing options: `docdexd index --help` (exclude paths, custom state dir).
- Ad-hoc queries: `docdexd chat --help`.
- Self-check scanner options: `docdexd self-check --help`.
- Hardware guidance: `docdexd llm-list` outputs model recommendations based on detected RAM/VRAM; `docdexd llm-setup` repeats that guidance and reports Ollama availability.
- Agent help endpoint: `curl http://127.0.0.1:3210/ai-help` (include `Authorization: Bearer <token>` if `--auth-token` is set) for a JSON listing of endpoints, limits, and best practices.
- MCP help/registration: `docdexd mcp --help` lists MCP flags; see the MCP section below for tool lists and registration examples.
- MCP helper: `docdexd mcp-add --help` lists agent-specific registration helpers.

## Troubleshooting
- Stale index: re-run `docdexd index --repo <path>`.
- Optional libs ingestion during index: `docdexd index --repo <path> --libs-sources /path/to/libs_sources.json` (expects `{ "sources": [...] }`).
- Port conflicts: change `--host/--port`.
- Installer failures (`npm i -g docdex`): use the printed `DOCDEX_*` error code; see `docs/ops/installer_error_codes.md`.

### Repo moved/renamed

Docdex is safety-first: it will not silently “cross-associate” an existing on-disk state directory with a different repo path when doing so could mix data between repos.

If you use the default shared state dir (`~/.docdex/state`), moving a repo changes its fingerprint and typically requires a reindex. If you keep state inside the repo (for example, `--state-dir .docdex`), moves/renames carry the state with the repo and usually only require updating `--repo`. The stricter “explicit re-association” flow below applies when you use an absolute shared `--state-dir` outside the repo root.

Deterministic failures and what they mean:

- `missing_repo_path` (`"repo path not found"`): the `--repo` path (or MCP `project_root`/`repo_path`) does not exist on disk (common after a move/rename, or when a client is still pointing at the old location).
  - Recovery: re-run with the repo’s current path; for HTTP, restart `docdexd serve --repo <repo>` with the correct path; for MCP, restart `docdexd mcp --repo <repo>` with the correct path and pass `project_root`/`repo_path`.
  - If the repo moved but you did not move its state with it, reindex: `docdexd index --repo <repo>`.
- `unknown_repo` (`"unknown repo"`): MCP-only — `project_root`/`repo_path` does not match the MCP server’s configured `--repo`. This is a fast-fail guardrail to prevent accidental cross-repo access.
  - Recovery: restart the MCP server with `docdexd mcp --repo <repo>` matching the repo you want, and pass `project_root`/`repo_path` in tool arguments.
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
      proxy_pass http://127.0.0.1:3210;
      proxy_set_header Host $host;
    }
  }
  ```
- Trim the corpus: prefer a curated staging directory, or use `--exclude-dir` / `--exclude-prefix` to keep secrets/private paths out before indexing; the watcher will ingest any in-scope file change under `repo`.
- Mind logs: avoid verbose logging in production if snippets/paths are sensitive; reverse-proxy access logs can also capture query terms and paths.
- Least privilege: run docdex under a low-privilege user/container and keep the state dir on a path with restricted permissions.
- Validate before publish: run `docdexd chat` for sensitive keywords to confirm no hits; store indexes on encrypted disks if required.
- Optional hardening: require an auth token on the HTTP API (or proxy); enforce TLS when not on localhost (default) or explicitly opt out with `--require-tls=false`/`--insecure` only behind a trusted proxy; enable rate limiting (`--rate-limit-per-min`) and clamp `limit`/request sizes (`--max-limit`, `--max-query-bytes`, `--max-request-bytes`); escape/sanitize snippet HTML if embedding or disable snippets entirely with `--disable-snippet-text`; state dir is created `0700` by default—keep it under an unprivileged user, optionally `--run-as-uid/--run-as-gid`, `--chroot`, or containerize; keep access logging minimal/redacted (`--access-log`), and run `self-check` for sensitive terms before exposing the service; for at-rest confidentiality, place the state dir on encrypted storage or use host-level disk encryption.

## Integrating with LLM tools
Docdex is tool-agnostic. Drop-in recipe for agents/codegen tools:
- Start once per repo: `docdexd index --repo <repo>` then `docdexd serve --repo <repo> --host 127.0.0.1 --port 3210 --log warn` (or set `DOCDEX_CLI_LOCAL=1` to run CLI commands without serving).
- Configure via env: `DOCDEX_STATE_DIR` (index location), `DOCDEX_EXCLUDE_PREFIXES`, `DOCDEX_EXCLUDE_DIRS`, `DOCDEX_HTTP_BASE_URL` (CLI target), `DOCDEX_CLI_LOCAL` (force local CLI), `RUST_LOG=docdexd=debug` (optional verbose logs).
- Query over HTTP: `GET /search?q=<text>&limit=<n>` returns `{"hits":[{"path","rel_path","doc_id","score","summary","snippet","token_estimate"}...],"top_score":<float|null>,"topScore":<float|null>,"meta":{...}}`; `GET /snippet/:doc_id` fetches a focused snippet plus doc metadata.
- Or query via CLI: `docdexd chat --repo <repo> --query "<text>" --limit 8` (JSON to stdout).
- Health check: `GET /healthz` should return `ok` before issuing search requests.
- Inject snippets into prompts:
```
"You are building features for this repo. Use the following documentation snippets for context. If a snippet cites a path, keep that path in your response. Snippets:\n<insert docdex snippets here>\nQuestion: <your question>"
```

### MCP (shared HTTP/SSE + legacy stdio)
Docdex exposes MCP over the singleton daemon (`/sse`, `/v1/mcp`, `/v1/mcp/message`) so multiple clients can share one service. Legacy stdio MCP (`docdexd mcp`) remains available for local-only tooling. If your MCP client supports resource templates, Docdex advertises a `docdex_file` template (`docdex://{path}`) which delegates to `docdex_open`.
- Shared MCP: `docdexd daemon --repo /path/to/repo --host 127.0.0.1 --port 3210` then point clients at `http://localhost:3210/sse`.
- npm install: the npm installer auto-selects a port (prefers 3000, fallback 3210), updates `~/.docdex/config.toml`, and injects the MCP URL into supported client configs.
- Legacy stdio: `docdexd mcp --repo /path/to/repo --log warn --max-results 8` (alias: `--mcp-max-results 8`).
- Auto-start: `docdexd daemon` starts the shared MCP proxy when enabled (config/default); `docdexd serve` still spawns stdio MCP when enabled.
- Env override: `DOCDEX_MCP_MAX_RESULTS` clamps `docdex_search` results (min 1).
- Auth: `docdexd mcp --auth-token <token>` (or `DOCDEX_AUTH_TOKEN`) requires clients to pass `auth_token` during `initialize`.
- Rate limits: `--rate-limit-per-min` / `--rate-limit-burst` or `DOCDEX_MCP_RATE_LIMIT_PER_MIN` / `DOCDEX_MCP_RATE_LIMIT_BURST`.
- Default repo: call `initialize` with `workspace_root` to set a default `project_root`; after that, tools may omit `project_root`/`repo_path`.
- Default profile agent: include `agent_id` in `initialize` to set the default agent for profile tools; profile tool calls may omit `agent_id` after that.
- Packaging: `docdexd mcp` launches the companion `docdex-mcp-server` binary; build/install it with `cargo build -p docdex-mcp-server` or set `DOCDEX_MCP_SERVER_BIN` to the binary path.
- Registering with MCP clients (shared HTTP/SSE): add a server named `docdex` that points to `http://localhost:<port>/sse`. Example JSON config snippet:
  ```json
  {
    "mcpServers": {
      "docdex": {
        "url": "http://localhost:3210/sse"
      }
    }
  }
  ```
- MCP quick add commands (popular agents):
  - Docdex helper (stdio): `docdex mcp-add --repo /path/to/repo --log warn --max-results 8` auto-detects supported agents; add `--all` to attempt every known client and print manual steps for UI-only ones, or `--remove` to uninstall.
  - Codex CLI (stdio): `codex mcp add docdex -- docdexd mcp --repo /path/to/repo --log warn --max-results 8`.
  - Generic JSON config (Cursor, Continue, Windsurf, Cline, Claude Desktop devtools): add the `mcpServers.docdex` block above to your MCP config file (paths vary by client; most accept the `url` schema shown).
  - Manual/stdio-only clients: start `docdexd mcp --repo /path/to/repo --log warn --max-results 8` yourself and point the client at that command/binary.
- Tools exposed (CallToolResult content: result.content[0].text contains JSON):
  - `docdex_search` — args: `{ "query": "<text>", "limit": <int optional>, "force_web": <bool>, "diff": { "mode": "...", "base": "...", "head": "...", "paths": [...] }, "project_root": "<path required unless initialize set default>", "repo_path": "<path optional alias>" }`. Returns local hits + metadata.
  - `docdex_web_research` — args: `{ "query": "<text>", "limit": <int>, "web_limit": <int>, "force_web": <bool>, "skip_local_search": <bool>, "no_cache": <bool>, "llm_filter_local_results": <bool>, "repo_only": <bool>, "llm_model": "<id>", "llm_agent": "<slug>", "project_root": "<path>", "repo_path": "<path alias>" }`. Returns combined local + web response.
  - `docdex_index` — args: `{ "paths": ["relative/or/absolute"], "project_root": "<path required unless initialize set default>", "repo_path": "<path optional alias>" }`. Empty `paths` reindexes everything; otherwise ingests the listed files.
  - `docdex_files` — args: `{ "limit": <int optional, default 200, max 1000>, "offset": <int optional, default 0>, "project_root": "<path required unless initialize set default>", "repo_path": "<path optional alias>" }`. Returns `{ "results": [{ "doc_id", "rel_path", "summary", "token_estimate" }], "total", "limit", "offset", "repo_root", "project_root" }`.
  - `docdex_open` — args: `{ "path": "<relative file>", "start_line": <int optional>, "end_line": <int optional>, "project_root": "<path required unless initialize set default>", "repo_path": "<path optional alias>" }`. Returns `{ "path", "start_line", "end_line", "total_lines", "content", "repo_root", "project_root" }` (rejects paths outside repo and large files).
  - `docdex_stats` — args: `{ "project_root": "<path required unless initialize set default>", "repo_path": "<path optional alias>" }`. Returns `{ "num_docs", "state_dir", "index_size_bytes", "segments", "avg_bytes_per_doc", "generated_at_epoch_ms", "last_updated_epoch_ms", "repo_root", "project_root" }`.
  - `docdex_repo_inspect` — args: `{ "project_root": "<path required unless initialize set default>", "repo_path": "<path optional alias>" }`. Returns repo identity and state-key mapping details.
  - `docdex_symbols` — args: `{ "path": "<relative file>", "project_root": "<path>", "repo_path": "<path alias>" }`. Returns per-file symbols with status.
  - `docdex_ast` — args: `{ "path": "<relative file>", "max_nodes": <int optional>, "project_root": "<path>", "repo_path": "<path alias>" }`. Returns AST nodes with status.
  - `docdex_impact_diagnostics` — args: `{ "file": "<relative file optional>", "limit": <int>, "offset": <int>, "project_root": "<path>", "repo_path": "<path alias>" }`. Returns unresolved import diagnostics.
  - `docdex_memory_store` / `docdex_memory_save` — args: `{ "text": "<string>", "metadata": { ... }, "project_root": "<path>", "repo_path": "<path alias>" }`. Returns `{ "id", "created_at" }`.
  - `docdex_memory_recall` — args: `{ "query": "<string>", "top_k": <int>, "project_root": "<path>", "repo_path": "<path alias>" }`. Returns memory hits.
  - `docdex_save_preference` — args: `{ "agent_id": "<string optional>", "content": "<string>", "category": "<style|tooling|constraint|workflow>", "role": "<string optional>" }`. Saves a preference and triggers evolution.
  - `docdex_get_profile` — args: `{ "agent_id": "<string optional>" }`. Returns agents and preferences for the requested/default agent.
- Example calls:
  - Initialize: `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
  - Initialize with workspace root: `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"workspace_root":"/path/to/repo"}}` (must match the server repo; sets default project_root for later calls)
  - List tools: `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`
  - Reindex: `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"docdex_index","arguments":{"paths":[],"project_root":"/repo"}}}`
  - Search: `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"docdex_search","arguments":{"query":"payment auth flow","limit":3,"project_root":"/repo"}}}`
  - Web research: `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"docdex_web_research","arguments":{"query":"payment auth flow","limit":3,"project_root":"/repo"}}}`
  - Open file: `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"docdex_open","arguments":{"path":"docs/readme.md","start_line":1,"end_line":20,"project_root":"/repo"}}}`
  - Stats: `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"docdex_stats","arguments":{"project_root":"/repo"}}}`
- Errors: invalid JSON → code -32700; unsupported/missing `jsonrpc` → -32600; unknown tool/method → -32601; invalid params (empty query, bad args, project_root mismatch) → -32602; internal errors include a `reason` string in `error.data`.
- Rate limits (MCP tool calls): when `DOCDEX_MCP_RATE_LIMIT_PER_MIN` is enabled and exceeded, tool calls return JSON-RPC code `-32029` with `error.data` containing stable retry hints: `{ code: "rate_limited", retry_after_ms: <int>, retry_at?: <RFC3339>, limit_key: <string>, scope: <string> }`.
- Agent guidance: call `docdex_search` with concise queries before coding; use `docdex_web_research` when local hits are weak and web is allowed; if results look stale, call `docdex_index`; keep using HTTP/CLI if your stack isn't MCP-aware.
- Help: `docdexd mcp --help` shows MCP flags and defaults; `docdexd help-all` includes an MCP section listing tools and usage.

## HTTPS and Certbot
- TLS accepts PKCS8, PKCS1/RSA, and SEC1/EC private keys (compatible with Certbot output).
- Manual cert/key: `docdexd serve --repo <repo> --tls-cert /path/fullchain.pem --tls-key /path/privkey.pem`.
- Certbot helper: `docdexd serve --repo <repo> --host 0.0.0.0 --port 3210 --certbot-domain docs.example.com` (uses `/etc/letsencrypt/live/docs.example.com/{fullchain.pem,privkey.pem}`), or pass `--certbot-live-dir /custom/live/dir`.
- When using Certbot, set a deploy hook to restart/reload docdex after renewals (e.g., `certbot renew --deploy-hook "systemctl restart docdexd.service"` or kill -HUP your process supervisor).
- If binding to 443 directly, you need privileges; otherwise, keep docdex on 127.0.0.1 and let a reverse proxy terminate TLS.
