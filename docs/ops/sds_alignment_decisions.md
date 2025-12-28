# SDS alignment decisions

This document records decisions and acceptance criteria for aligning SDS expectations with the current implementation.

## Decisions

1) Daemon scope
- Decision: keep **per-repo daemon** behavior. `docdexd serve`/`docdexd mcp`/`docdexd index` remain repo-scoped and require `--repo`.

2) MCP scope
- Decision: keep **repo-scoped MCP**. `project_root`/`repo_path` must match the repo used to start the MCP server. `initialize` may set a default repo for subsequent calls, but it does not enable cross-repo access.

3) `docdexd chat` REPL
- Decision: add **interactive REPL** when `--query` is omitted.
- UX: prompt `docdex> `; `exit`/`quit`/EOF ends session; each line is a separate query; no persistent history file.
- Streaming: if `--stream` is set, stream response for each query; otherwise print JSON for each query.

4) `run-tests` / `tui`
- Decision: keep **local CLI exceptions** (not routed through daemon). Update SDS to document that `run-tests` and `tui` run locally and do not require daemon endpoints.

5) MCP spawn checks
- Decision: keep `docdexd check` **opt-in** for MCP spawn probes via `DOCDEX_CHECK_MCP_SPAWN=1`, with a configurable timeout. Preflight (`docdexd serve --preflight-check`) forces MCP spawn probes when MCP is enabled.

## Acceptance criteria

- Daemon scope:
  - `docdexd serve --repo <path>` starts a daemon scoped to that repo; all HTTP/MCP requests are rejected if they target a different repo.
  - CLI/HTTP/MCP errors for unknown or mismatched repo remain explicit (`unknown_repo`/`repo_state_mismatch` as applicable).

- MCP scope:
  - Tools accept `project_root`/`repo_path` only if it matches the MCP server repo.
  - `initialize` with `project_root` sets a default for subsequent tool calls without repo args.
  - Cross-repo tool calls return a consistent error code/message.

- REPL UX:
  - Running `docdexd chat --repo <path>` without `--query` starts a prompt loop.
  - `exit`, `quit`, or EOF cleanly terminates without error.
  - Each input line results in a normal chat request using existing HTTP/local path; `--stream` streams output per query.

- `run-tests` / `tui`:
  - CLI continues to run these locally by default (no HTTP endpoints required).
  - SDS explicitly documents these as local-only exceptions.

- MCP spawn checks:
  - `docdexd check` reports missing MCP binary without spawning; spawn probes are only attempted when `DOCDEX_CHECK_MCP_SPAWN=1`.
  - Preflight mode forces MCP spawn probes when MCP is enabled and fails fast on spawn timeouts/non-zero exit.
