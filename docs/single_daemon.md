# Docdex Single Daemon Roadmap

This document captures the plan to make Docdex a singleton, install-and-forget service
with multi-repo mounting, shared MCP transport, and automated config injection.

## Goals

- Prevent MCP/daemon bloat by running a single shared service.
- Auto-mount repos on client initialize without manual indexing.
- Keep indexes up to date via background watchers.
- Patch client configs automatically (Claude/Cursor/Codex).
- Support shared MCP over HTTP/SSE and Unix sockets, plus a stdio proxy for legacy clients.
- No external process managers (pm2, launchd wrappers, etc.).

## Phase 1: Singleton Daemon + Lock

- Add `docdexd daemon` as a multi-repo service.
- Create a lockfile at `~/.docdex/daemon.lock` using OS file locks (not just PID).
- CLI adds `ensure_daemon()`:
  - Ping `GET /healthz`.
  - If not reachable, spawn detached daemon (Windows: hidden window).
- Record daemon metadata (pid, port, started_at) in lockfile or companion file.

## Phase 2: Context-Aware Multi-Repo Mounting

- Use MCP `initialize` handshake `rootUri` as the primary signal.
- Add `POST /v1/initialize` with `{ rootUri }` for HTTP/SSE clients.
- Resolve repo fingerprint and state directory.
- New repo:
  - Kick off async index crawl.
  - Return `{ repo_id, status: "indexing" }`.
- Existing repo:
  - Load index + repo state into memory.
  - Return `{ repo_id, status: "ready" }`.
- Stale repo:
  - Trigger async re-index (or return `status: "stale"` and reindex).
- Internal manager map:
  - `repo_id -> RepoHandle { indexer, watcher, last_accessed, state_dir }`.

## Phase 3: Dynamic Lifecycle + Re-indexing

- Use Rust `notify` watchers for active repos.
- `.docdexignore` support, optional `.gitignore` parse.
- LRU lifecycle:
  - Active: repo accessed recently, watcher live.
  - Idle (<=2h): watcher stays, reduced activity.
  - Hibernate (>=24h): watcher stopped, in-memory index released; on next init, reload from disk.

## Phase 4: Shared MCP Transport

- Add shared MCP transport:
  - HTTP/SSE endpoint, e.g. `http://127.0.0.1:3210/sse` (port configurable).
  - Unix socket listener, e.g. `docdex-mcp-server --listen-unix ~/.docdex/mcp.sock`.
- Multi-client JSON-RPC; each request includes `rootUri` or `repo_id`.
- Add stdio proxy:
  - Codex instances use stdio proxy which multiplexes to the Unix socket.
  - Avoids per-client MCP server processes.

## Phase 5: Auto-Config + Startup

- Extend npm installer to patch config files (idempotent):
  - Claude Desktop: `~/Library/Application Support/Claude/claude_desktop_config.json`.
  - Cursor: `settings.json` or `mcp.json`.
  - Codex: `~/.codex/config.toml`.
- Startup integration:
  - macOS: LaunchAgent.
  - Linux: systemd --user.
  - Windows: Task Scheduler entry.
- CLI commands should auto-start daemon when invoked.
- Automatic port selection:
  - If the preferred port is busy, pick the next available port.
  - Inject the chosen port into client configs.
- First-run message:
  - Emit only when OS startup registration fails (permission or policy).
  - Provide manual setup instructions for that OS.

## State Persistence

- Keep repo state at `~/.docdex/state/repos/<fingerprint>/`.
- Re-mounts reuse on-disk indexes to avoid full re-crawls.

## Client Config Paths (Auto-Injection Targets)

To achieve install-and-forget behavior, the installer should look for these files and
append the docdex HTTP entry (`http://localhost:3000/sse`) where `mcpServers` is supported.

### Windows

- Claude Desktop: `%APPDATA%\Claude\claude_desktop_config.json`
- Cursor: `%USERPROFILE%\.cursor\mcp.json`
- Windsurf: `%USERPROFILE%\.codeium\windsurf\mcp_config.json`
- Cline: `%APPDATA%\Code\User\globalStorage\saoudrizwan.claude-dev\settings\cline_mcp_settings.json`
- Roo Code: `%APPDATA%\Code\User\globalStorage\rooveterinaryinc.roo-cline\settings\mcp_settings.json`
- Codex: `%USERPROFILE%\.codex\config.toml`
- Continue.dev: `%USERPROFILE%\.continue\config.json`
- PearAI: `%USERPROFILE%\.kiro\settings\mcp.json`
- Zed Editor: `%APPDATA%\Zed\settings.json`
- Aider: `%APPDATA%\Aider\config.yml`

### macOS

- Claude Desktop: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Cursor: `~/.cursor/mcp.json`
- Windsurf: `~/.codeium/windsurf/mcp_config.json`
- Cline: `~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json`
- Roo Code: `~/Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json`
- Codex: `~/.codex/config.toml`
- Continue.dev: `~/.continue/config.json`
- PearAI: `~/.kiro/settings/mcp.json`
- Zed Editor: `~/.config/zed/settings.json`
- Aider: `~/.config/aider/config.yml` (or `~/.aider.conf.yml`)

### Linux / Unix

- Claude Desktop (Preview): `~/.config/Claude/claude_desktop_config.json`
- Cursor: `~/.cursor/mcp.json`
- Windsurf: `~/.codeium/windsurf/mcp_config.json`
- Cline: `~/.config/Code/User/globalStorage/saoudrizwan.claude-dev/settings/cline_mcp_settings.json`
- Roo Code: `~/.config/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings/mcp_settings.json`
- Codex: `~/.codex/config.toml`
- Continue.dev: `~/.continue/config.json`
- PearAI: `~/.kiro/settings/mcp.json`
- Zed Editor: `~/.config/zed/settings.json`
- Aider: `~/.config/aider/config.yml`

### Idempotent Injector (Post-Install Logic)

- Check OS via `process.platform`.
- Locate candidate config files from the lists above.
- Read and parse JSON/TOML/YAML.
- Inject `mcpServers.docdex = { url: "http://localhost:3000/sse" }` if missing.
- Write back to disk without duplicating entries.

Note: the daemon default port remains 3210; if you use `http://localhost:3000/sse`,
ensure the daemon is configured to bind to port 3000.

## Defaults / Decisions

- Default HTTP port stays `3210`.
- Shared MCP endpoint supports HTTP/SSE + Unix socket (Unix socket first for local clients).
- Provide a stdio proxy for legacy clients.
