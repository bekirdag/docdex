# Docdex Single Daemon Task List

This task list translates `docs/single_daemon.md` into implementable work items.

## Phase 1: Singleton Daemon + Lock

- Add `docdexd daemon` command (multi-repo service).
  - Files: `src/cli/mod.rs`, `src/cli/commands/serve.rs`, new `src/daemon/multi_repo.rs`.
  - Acceptance: `docdexd daemon` starts and stays resident.
- Implement lockfile with OS locking at `~/.docdex/daemon.lock`.
  - Files: `src/daemon/lock.rs`, `src/daemon.rs`.
  - Acceptance: second daemon exits with clear error; stale lock is detected and replaced.
- Add `ensure_daemon()` to CLI entrypoints.
  - Files: `src/cli/mod.rs`, `src/cli/commands/*`.
  - Acceptance: CLI auto-spawns daemon if `/healthz` unreachable.
- Detached spawn per OS (no window flash on Windows).
  - Files: `src/cli/daemon_spawn.rs`.
  - Acceptance: background spawn works on macOS/Linux/Windows.

## Phase 2: Context-Aware Multi-Repo Mounting

- Add `POST /v1/initialize` endpoint for HTTP/SSE clients.
  - Files: `src/api/v1/initialize.rs`, `src/search/mod.rs`, `docs/http_api.md`, `openapi/mcoda.yaml`.
  - Acceptance: returns `{repo_id, status}` for known/unknown repos.
- Add MCP initialize handling for `rootUri`.
  - Files: `src/mcp_server.rs`, `src/api/mcp_http.rs`.
  - Acceptance: MCP initialize mounts repo and returns repo metadata.
- Implement RepoManager map: `repo_id -> RepoHandle`.
  - Files: `src/daemon/multi_repo.rs`, `src/index/mod.rs`.
  - Acceptance: multiple repos can be mounted concurrently.
- Async background index crawl on new repo or stale index.
  - Files: `src/index/mod.rs`, `src/daemon/multi_repo.rs`.
  - Acceptance: new repo returns `status: indexing` and finishes in background.

## Phase 3: Dynamic Lifecycle + Re-indexing

- Add `.docdexignore` parser and optional `.gitignore` honoring.
  - Files: `src/index/ignore.rs`, `src/index/mod.rs`, docs update.
  - Acceptance: ignored paths are excluded from index and watcher updates.
- LRU watcher lifecycle with idle/hibernate timers.
  - Files: `src/daemon/multi_repo.rs`, `src/watcher.rs`.
  - Acceptance: repo watcher stops after 24h idle and reloads on demand.
- Persist last_accessed + lifecycle state.
  - Files: `src/state_layout.rs`, `src/daemon/multi_repo.rs`.
  - Acceptance: daemon restart preserves idle/active state.

## Phase 4: Shared MCP Transport

- Add HTTP/SSE MCP endpoint (optional transport).
  - Files: `src/api/mcp_http.rs`, `src/search/mod.rs`, docs.
  - Acceptance: MCP requests over HTTP/SSE accepted.

## Phase 5: Auto-Config + Startup

- Implement idempotent config injector for all listed clients.
  - Files: `npm/lib/install.js`, new `npm/lib/install_configs.js`.
  - Acceptance: running npm install twice does not duplicate entries.
- Fixed port enforcement and config injection.
  - Files: `npm/lib/install_configs.js`, `npm/lib/install.js`, daemon config.
  - Acceptance: installer rejects port conflicts, uses port `28491`, injects correct URL.
- Add startup integration:
  - macOS LaunchAgent, Linux systemd user, Windows Task Scheduler.
  - Files: `npm/lib/startup/*.js`, docs.
  - Acceptance: daemon auto-starts after reboot on each OS.
- First-run message on startup registration failure.
  - Files: `npm/lib/startup/*.js`, `npm/lib/install.js`.
  - Acceptance: message emitted only when OS startup integration fails.
- Document all changes in README + release notes.
  - Files: `README.md`, `docs/CHANGELOG.md`, `docs/http_api.md`.
  - Acceptance: docs reference new daemon/initialize/SSE/MCP setup.

## Tests

- Add unit tests for lockfile behavior.
- Add integration tests for `/v1/initialize`.
- Add MCP HTTP/SSE tests.
- Add installer config injection tests.
- Add tests for fixed port conflict detection + config injection.
- Add tests for startup failure message gating.
- Update `docs/test_artifacts.md` with new tests.
