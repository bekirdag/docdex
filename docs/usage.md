# Docdex Usage Guide

This is the detailed, technical guide for Docdex. Use it for installation, setup, MCP wiring, HTTP usage, and configuration.

## Contents
- Install
- First run
- Operating modes
- MCP integration
- HTTP API
- State, paths, and defaults
- Configuration reference
- Ops and safety
- Troubleshooting
- References

## Install

### npm (recommended)
- Requires Node.js >= 18.
- Install: `npm i -g docdex`
- Verify: `docdex --version`
- `docdex` (alias `docdexd`) downloads the matching platform binary from the GitHub release that matches the npm version.

Supported published binaries:
- macOS: arm64, x64
- Linux glibc: arm64, x64
- Linux musl: x64
- Windows: x64

Installer notes:
- Supported platforms and troubleshooting: `docs/ops/installer_supported_platforms.md`.
- Release manifest schema: `docs/contracts/release_manifest_schema_v1.md`.
- Forks: set `DOCDEX_DOWNLOAD_REPO=<owner/repo>` before install.
- Mirrors: set `DOCDEX_DOWNLOAD_BASE=http://host/path` to redirect downloads.
- Local dev fallback: if release assets are missing and a local `target/release/docdexd` (or `target/debug/docdexd`) exists, the installer can use it. Disable with `DOCDEX_LOCAL_FALLBACK=0` or override with `DOCDEX_LOCAL_BINARY=/path/to/docdexd`.
- Platform diagnostics (no download): `docdex doctor` (alias `docdex diagnostics`).

Postinstall behavior:
- Docdex registers a local daemon and writes MCP client config pointing to `http://localhost:28491/v1/mcp/sse` (Codex uses `http://localhost:28491/v1/mcp`). Install fails if port `28491` is already in use.
- Auto-configured clients (when config files are present): Claude Desktop, Cursor, Windsurf, Cline, Roo Code, Continue, VS Code, PearAI, Void, Zed, Codex. Restart clients after install.
- If Ollama is missing, the installer can prompt to install it and the default embedding model.
- Skip prompts with `DOCDEX_OLLAMA_INSTALL=0` or `DOCDEX_OLLAMA_MODEL_PROMPT=0`.
- Force with `DOCDEX_OLLAMA_INSTALL=1` or `DOCDEX_OLLAMA_MODEL=<model>`.

### Build from source
- Requires Rust (stable) and Cargo.
- Build: `cargo build --release`
- Install: `cargo install --path .`
- MCP is served by the daemon over HTTP/SSE; no separate MCP server binary is required.

### Uninstall
- `npm uninstall -g docdex` stops the daemon, removes its startup registration, and deletes Docdex MCP entries from supported client config files.

## First run

```bash
# index a repo

docdexd index --repo /path/to/repo

# serve HTTP API with watcher (legacy; singleton lock enforced)

docdexd serve --repo /path/to/repo --host 127.0.0.1 --port 28491 --log warn --secure-mode=false

# singleton daemon (shared MCP over /v1/mcp/sse; preferred)

docdexd daemon --host 127.0.0.1 --port 28491 --log warn --secure-mode=false

# ad-hoc query via CLI

docdexd chat --repo /path/to/repo --query "otp flow" --limit 5

# interactive REPL

docdexd chat --repo /path/to/repo
```

Notes:
- CLI commands default to the daemon HTTP base URL (from config). Use `DOCDEX_HTTP_BASE_URL` to override or `DOCDEX_CLI_LOCAL=1` to run in-process.
- Add `.docdex/` to `.gitignore` if you store state under the repo.

## Operating modes
- `index`: builds the repo index and code intelligence artifacts.
- `serve`: legacy per-repo HTTP API with watcher; a global singleton lock prevents multiple servers from starting.
- `daemon`: singleton service that hosts shared MCP over HTTP/SSE (`/v1/mcp/sse`).

## Repo scoping (multi-repo daemon)
When a singleton daemon starts without a default repo or has more than one repo mounted, the daemon requires an explicit repo scope.

- Mount a repo and get its `repo_id`:
  - `POST /v1/initialize` with `{ "rootUri": "file:///path/to/repo" }`
- For HTTP calls, send `x-docdex-repo-id: <sha256>` or `repo_id` in query/body.
- MCP SSE sessions bind to the repo in `initialize.rootUri` and reuse it automatically.
- Per-request `project_root`/`repo_path` overrides the bound repo for MCP calls.

## MCP integration

Supported auto-detected MCP clients (installation adds config when the file exists):
- Claude Desktop
- Cursor
- Windsurf
- Cline
- Roo Code
- Continue
- VS Code
- PearAI
- Void
- Zed
- Codex

### Shared MCP (daemon, HTTP/SSE)
Start the daemon and point clients at `http://localhost:28491/v1/mcp/sse`.

JSON config example (Cursor, Continue, Cline, Claude Desktop devtools):
```json
{
  "mcpServers": {
    "docdex": {
      "url": "http://localhost:28491/v1/mcp/sse"
    }
  }
}
```

Codex config example (TOML):
```toml
[mcp_servers]
docdex = { url = "http://localhost:28491/v1/mcp" }
```

## HTTP API

Core endpoints:
- `GET /healthz`
- `GET /search?q=...&limit=...`
- `GET /snippet/:doc_id`
- `POST /v1/chat/completions`
- `GET /v1/symbols`, `GET /v1/ast`, `GET /v1/graph/impact`

Reference: `docs/http_api.md`.

## Code intelligence
Docdex builds symbol, AST, and impact graph data during indexing so tools can reason about structure, not just text.
Supported AST/symbols languages: Rust, Python, JavaScript, TypeScript, Go, Java, C#, C/C++, PHP, Kotlin, Swift, Ruby, Lua, Dart.

Examples:
```bash
curl "http://127.0.0.1:28491/v1/symbols?file=src/app.ts"
curl "http://127.0.0.1:28491/v1/ast?name=handleRequest&pathPrefix=src"
curl "http://127.0.0.1:28491/v1/graph/impact?file=src/app.ts&maxDepth=3"
```

## Local LLM usage (Ollama)
Docdex uses Ollama for embeddings and optional local chat. Use `docdexd llm-list` to see recommended models for your hardware.

First-time setup (recommended):
```bash
docdex setup
```
The wizard is interactive; run it from a terminal.
If Ollama is installed but not running, the wizard will attempt to start it to pull models.
When supported, the wizard also enables the Ollama service to run on restart.
Skip auto-setup on install:
```bash
DOCDEX_SETUP_SKIP=1 npm i -g docdex
```
Setup markers are stored under `~/.docdex/state`: `setup_status.json`, `setup_pending.json`, and `setup_failed.json`.
Setup overrides:
- `DOCDEX_SETUP_FORCE=1`: re-run the wizard even if deferred/complete.
- `DOCDEX_OLLAMA_INSTALL=1|0`: auto-accept or skip the Ollama install prompt.
- `DOCDEX_OLLAMA_MODEL_PROMPT=1|0`: force model prompts on/off.
- `DOCDEX_OLLAMA_MODEL_ASSUME_Y=1`: auto-accept recommended model installs.
- `DOCDEX_BROWSER_INSTALL=chromium|skip`: auto-accept or skip the Chromium download prompt.

The setup wizard can download Chromium into `~/.docdex/state/bin/chromium/`.

Manual setup:
```bash
ollama serve
ollama pull nomic-embed-text
```

Change the default chat model later:
- Run the wizard again: `docdexd setup` (alias: `docdexd llm-setup`).
- Or edit `~/.docdex/config.toml`:
  - `[llm].default_model` (chat model)
  - `[llm].embedding_model`
  - `[llm].base_url` (Ollama base URL)
  - `[llm].provider` (must be `ollama` for built-in features)
Restart the daemon after changing config so it reloads the new defaults.

Enable Ollama later (if skipped during install):
- Install Ollama for your OS.
- Run `docdexd setup` to validate the daemon and pull configured models.

Run Docdex with Ollama:
```bash
DOCDEX_OLLAMA_BASE_URL=http://127.0.0.1:11434 docdexd daemon --host 127.0.0.1 --port 28491
```

## Local delegation (cheap agents)
Docdex can offload small code tasks to a local model (Ollama or a mcoda agent) to reduce paid-token usage. This powers `/v1/delegate` and the MCP tool `docdex_local_completion`.

Config (`~/.docdex/config.toml`):
```toml
[llm.delegation]
enabled = true
auto_enable = true
local_agent_id = "ollama-local" # mcoda agent id/slug (optional)
primary_agent_id = "claude-code" # optional, used for refinement/fallback
mode = "draft_only" # or "draft_then_refine"
timeout_ms = 30000
max_tokens = 512
max_context_chars = 12000
task_allowlist = ["generate_tests", "write_docstring", "scaffold_boilerplate", "refactor_simple", "format_code"]
```

Notes:
- `auto_enable` defaults to true; delegation auto-enables when local models or mcoda agents are present (opt out with `auto_enable = false`).
- If `local_agent_id` is empty, Docdex selects a local model/agent from the library by task type; fallback is the configured Ollama model.
- `task_allowlist` is optional; an empty list allows all task types.
- `draft_then_refine` returns a primary-agent refinement when available; otherwise returns the local draft with a warning.
- Local model library: `~/.docdex/state/llm/local_model_library.json` (or under `DOCDEX_STATE_DIR`).
- Env overrides: `DOCDEX_DELEGATION_ENABLED`, `DOCDEX_DELEGATION_AUTO_ENABLE`, `DOCDEX_DELEGATION_LOCAL_AGENT`, `DOCDEX_DELEGATION_PRIMARY_AGENT`, `DOCDEX_DELEGATION_MODE`, `DOCDEX_DELEGATION_TIMEOUT_MS`, `DOCDEX_DELEGATION_MAX_TOKENS`.
- Expensive model library: `docs/expensive_models.json`. Agents should match `agent_id`, `agent_slug`, `model`, or adapter type (case-insensitive) to decide whether to delegate.

## Repo memory
Repo memory stores project facts (notes, decisions, edge cases) and is used during chat/context assembly. Memory is enabled by default; disable with `DOCDEX_ENABLE_MEMORY=0` or `[memory].enabled = false`.

CLI:
```bash
docdexd memory-store --repo /path/to/repo --text "Payments retry up to 3 times with backoff."
docdexd memory-recall --repo /path/to/repo --query "payments retry policy" --top-k 5
```

HTTP:
```bash
curl -X POST "http://127.0.0.1:28491/v1/memory/store" \\
  -H "Content-Type: application/json" \\
  -d '{\"text\":\"Payments retry up to 3 times with backoff.\"}'

curl -X POST "http://127.0.0.1:28491/v1/memory/recall" \\
  -H "Content-Type: application/json" \\
  -d '{\"query\":\"payments retry policy\",\"top_k\":5}'
```

Notes:
- Memory uses embeddings (Ollama). If Ollama is unavailable, these calls fail with a structured error.
- When the daemon has no default repo or more than one repo is mounted, `repo_id` is required (query/body or `x-docdex-repo-id`).

## Agent memory (profile preferences)
Agent memory stores long-lived preferences across repos (style, tooling, constraints, workflow). It lives in the global state dir and does not require a repo path.

CLI:
```bash
docdexd profile add --agent-id "default" --category style --content "Use concise bullet points."
docdexd profile search --agent-id "default" --query "style" --top-k 5
```

HTTP:
```bash
curl -X POST "http://127.0.0.1:28491/v1/profile/add" \\
  -H "Content-Type: application/json" \\
  -d '{\"agent_id\":\"default\",\"content\":\"Use concise bullet points.\",\"category\":\"style\"}'
```

Notes:
- Categories: `style`, `tooling`, `constraint`, `workflow`.
- Set a default agent with `[server].default_agent_id` or `docdexd serve --agent-id` (`DOCDEX_AGENT_ID`).

## Hardware-aware LLM guidance
Use `docdexd llm-list` or `docdex setup` to print your host RAM + GPU summary together with entries from `docs/llm_list.json`. The commands highlight a recommended entry that satisfies `minRamGb` and `requiresGpu`.

## State, paths, and defaults
- State/index directory: `~/.docdex/state/repos/<fingerprint>/index` by default (override with `--state-dir` / `DOCDEX_STATE_DIR`).
- HTTP API: defaults to `127.0.0.1:28491` when serving.
- Docdex data stays local under `~/.docdex/state` unless overridden.
- Daemon lock: `~/.docdex/locks/daemon.lock` by default (override with `DOCDEX_DAEMON_LOCK_PATH`; falls back to OS temp dir when home is unavailable).
- Logs: set `DOCDEX_LOG_TO_STATE=1` to also write `~/.docdex/state/logs/docdexd-<pid>.log`.

## Configuration reference

### Common flags and env vars
- `--repo <path>`: repo root (defaults to `.`).
- `--state-dir <path>` / `DOCDEX_STATE_DIR`: override state dir (relative paths resolve under `repo`).
- `--exclude-prefix a,b,c` / `DOCDEX_EXCLUDE_PREFIXES`.
- `--exclude-dir a,b,c` / `DOCDEX_EXCLUDE_DIRS`.
- `DOCDEX_HTTP_BASE_URL`: override daemon base URL for CLI.
- `DOCDEX_HTTP_TIMEOUT_MS`: override CLI HTTP timeout (default 30000).
- `DOCDEX_CLI_LOCAL=1`: run CLI in-process.
- `DOCDEX_ENABLE_SYMBOL_EXTRACTION`: deprecated (no-op).

### Security and serving
- `--expose` / `DOCDEX_EXPOSE`: allow non-loopback binds (requires auth).
- `--auth-token <token>` / `DOCDEX_AUTH_TOKEN`: required for non-loopback binds.
- `--secure-mode <true|false>` / `DOCDEX_SECURE_MODE`: default true.
- `--allow-ip a,b,c` / `DOCDEX_ALLOW_IPS`: allowlist for HTTP API.
- `--tls-cert`, `--tls-key`, `--certbot-domain`, `--certbot-live-dir`.
- `--require-tls <true|false>` / `DOCDEX_REQUIRE_TLS`.
- `--insecure` / `DOCDEX_INSECURE_HTTP=true`.
- `--preflight-check` / `DOCDEX_PREFLIGHT_CHECK`.

### Limits and logging
- `--max-limit <n>` / `DOCDEX_MAX_LIMIT`.
- `--max-query-bytes <n>` / `DOCDEX_MAX_QUERY_BYTES`.
- `--max-request-bytes <n>` / `DOCDEX_MAX_REQUEST_BYTES`.
- `--rate-limit-per-min <n>` / `DOCDEX_RATE_LIMIT_PER_MIN`.
- `--rate-limit-burst <n>` / `DOCDEX_RATE_LIMIT_BURST`.
- `--audit-log-path`, `--audit-max-bytes`, `--audit-max-files`, `--audit-disable`.
- `--strip-snippet-html` / `DOCDEX_STRIP_SNIPPET_HTML`.
- `--disable-snippet-text` / `DOCDEX_DISABLE_SNIPPET_TEXT`.
- `--access-log <true|false>` / `DOCDEX_ACCESS_LOG`.

### Memory and LLM
- `--enable-memory <true|false>` / `DOCDEX_ENABLE_MEMORY`.
- `--embedding-base-url` / `DOCDEX_EMBEDDING_BASE_URL`.
- `--ollama-base-url` / `DOCDEX_OLLAMA_BASE_URL`.
- `--embedding-model` / `DOCDEX_EMBEDDING_MODEL` (default `nomic-embed-text`).
- `DOCDEX_LLM_AGENT` / `DOCDEX_AGENT` for default chat agent.

### Web discovery (Tier 2)
- `DOCDEX_WEB_ENABLED=1` to enable (daemon sets this by default unless overridden).
- `DOCDEX_OFFLINE=1` to force offline.
- `DOCDEX_WEB_*` knobs for thresholds, timeouts, cache TTL, and backoff.
- `DOCDEX_WEB_BROWSER` / `DOCDEX_CHROME_PATH` to set a Chromium binary.
- `web.scraper.engine` in `config.toml` is `chromium` (only supported engine).
- `DOCDEX_BROWSER_AUTO_INSTALL=0` to disable Chromium auto-install.
- Optional API providers (set in `config.toml` under `[web.providers]` or via env):
  - Brave: `DOCDEX_BRAVE_API_KEY`
  - Google CSE: `DOCDEX_GOOGLE_CSE_API_KEY` + `DOCDEX_GOOGLE_CSE_CX`
  - Bing: `DOCDEX_BING_API_KEY`
  - URL overrides: `DOCDEX_BRAVE_API_URL`, `DOCDEX_GOOGLE_CSE_API_URL`, `DOCDEX_BING_API_URL`

## Ops and safety
- Health check: `GET /healthz`.
- Metrics: `GET /metrics`.
- `docdexd check`: preflight validation for config, state, Ollama, browser, ports.
- `docdexd self-check --repo <path>`: sensitive-term scan.

## Troubleshooting
- Browser path issues: `docdexd browser setup` or set `DOCDEX_WEB_BROWSER`/`DOCDEX_CHROME_PATH`.
- Ollama timeouts: ensure `ollama` is running and tune `DOCDEX_EMBEDDING_TIMEOUT_MS`.
- 429s in load tests: run with `--secure-mode=false` or raise rate limits.

## References
- HTTP API: `docs/http_api.md`
- MCP errors: `docs/mcp/errors.md`
- Quality gates: `docs/quality_gates.md`
- Metrics dashboard: `docs/metrics_dashboard.md`
