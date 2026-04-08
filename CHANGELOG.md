# Changelog

## 0.2.59
- Backfill wake-up knowledge episodes from matched facts and graph edges so `/v1/wakeup`, CLI, and MCP return episode context even when retrieval matches graph artifacts instead of episode summary text.
- Reserve chat prompt budget for the project map so OpenAI-compatible chat responses include cached map context under the default answer-token configuration.

## 0.2.58
- Export Docdex delegation savings in hourly mswarm telemetry packages and expose matching runtime/admin mswarm summaries for frontend visibility.

## 0.2.57
- Bump release metadata to 0.2.57.

## 0.2.56
- Clarify agent-facing local delegation docs for code-oriented tasks versus `general_question`.

## 0.2.55
- Raise Docdex-managed Codex MCP `tool_timeout_sec` and `startup_timeout_sec` defaults to 300 seconds in both `docdexd mcp add` and the npm installer.
- Raise the Codex/OpenAI CLI local delegation timeout floor to 300 seconds and update the Codex MCP examples accordingly.

## 0.2.54
- Add a per-project actual cost savings table to `docdexd delegation savings --all`.
- Include optional per-project `projects` telemetry entries for `/v1/telemetry/delegation?all=true`, resolving persisted repo telemetry to canonical project paths with live mounted-repo fallback.

## 0.2.52
- Persist delegation savings telemetry across daemon restarts and reinstalls, including daemon-global `--all` totals and repo-scoped counters.
- Store daemon-global delegation savings under `~/.docdex/state/telemetry/delegation.json` and repo totals under `~/.docdex/state/repos/<state_key>/delegation_telemetry.json`.

## 0.2.51
- Persist local delegation failures to `~/.docdex/state/logs/errors/delegation_local_failures.jsonl` with repo/source metadata and recovery details.
- Document the dedicated delegation failure history path in the usage guide.

## 0.2.50
- Attribute delegation savings to the actual expensive caller via `caller_agent_id`, `caller_model`, or `primary_cost_per_million`, and expose avoided primary cost plus effective per-1M telemetry rates.
- Canonicalize delegation pricing config to `primary_usd_per_million_tokens` and `local_usd_per_million_tokens` while preserving legacy `*_usd_per_1k_tokens` config, env, and telemetry compatibility.

## 0.2.49
- Generate MCP client config with `127.0.0.1` instead of `localhost` so installer-written endpoints match the default daemon bind address.
- Update MCP documentation/examples to use the canonical loopback URL and add regression coverage for the installer helpers.

## 0.2.48
- Exclude paid or expensive mcoda agents from automatic local delegation target selection.
- Document the zero-cost local delegation rule in the agent guidance and usage guide.

## 0.2.47
- Bump release metadata to 0.2.47.

## 0.2.46
- Bump release metadata to 0.2.46.

## 0.2.45
- Add FD-hardening guidance to agent docs (startup nofile warning threshold, profile lock retry knobs, and ops playbook reference).
- Bump release metadata to 0.2.45.

## 0.2.44
- Fix MCP tool schema compatibility with Claude Code by removing top-level anyOf from `docdex_dag_export`.
- Bump release metadata to 0.2.44.

## 0.2.42
- Bump release metadata to 0.2.42.

## 0.2.41
- Propagate DAG session IDs: `/search` responses include `meta.dag_session_id`, MCP `docdex_dag_export` accepts `dag_session_id`, and agent docs call out passing it to export traces.
- Improve Windows npm postinstall UX with a plain setup hint, npm lifecycle non-interactive detection, and no empty cmd window from immediate daemon start.
- Fix setup TUI menu selection highlighting on Windows terminals.

## 0.2.40
- Ensure startup registration runs even when a daemon is already running so auto-start after reboot works on macOS/Linux/Windows (best-effort systemd linger on Linux).
- Allow nightly release manifests to be generated from partial asset sets and align nightly artifact naming with release assets.
- Add `docdex start` as an alias for `docdexd daemon` and document it in README/usage/agents guides.
- Bump release metadata to 0.2.40.

## 0.2.39
- Bump release metadata to 0.2.39.

## 0.2.38
- Bump release metadata to 0.2.38.

## 0.2.37
- Bump release metadata to 0.2.37.

## 0.2.36
- Bump release metadata to 0.2.36.

## 0.2.35
- Route legacy MCP JSON-RPC method names (docdex_* / docdex.*) through tools/call so older clients keep working.
- Harden the HTTP soak script with a /search preflight and safer index status parsing.
- Bump release metadata to 0.2.35.

## 0.2.34
- Normalize local delegation output by stripping top-level markdown fences (with warnings) so fenced wrappers don't fail delegation.
- Allow delegation outputs to include fenced code markers inside content while still rejecting wrapped fenced output.
- Bump release metadata to 0.2.34.

## 0.2.33
- Warn Windows users to install the VC++ 2015-2022 runtime in the README and npm README.
- Fix Windows setup to detect the default Ollama install path and use it for the current process.
- Document the Windows default Chromium auto-install location.
- Bump release metadata to 0.2.33.

## 0.2.32
- Fix Windows npm installs by pointing CLI bin entries at stable `lib/` entrypoints (no missing `bin/docdex.js`).
- Bump release metadata to 0.2.32.

## 0.2.31
- Fix nightly HTTP soak by waiting for `/v1/index/status` readiness (with optional rebuild) before load testing.
- Bump release metadata to 0.2.31.

## 0.2.30
- Harden Windows npm installs: fallback to writable dist dirs when LOCALAPPDATA is locked, unblock downloaded binaries, retry file operations on EPERM/EACCES, and add AV/PowerShell guidance.
- Postinstall now restores missing CLI wrapper scripts and the npm tarball guardrails assert the required bin entrypoints are present.
- Postinstall and CLI now search multiple dist roots to find the installed daemon reliably outside npm-managed paths.
- Bump release metadata to 0.2.30.

## 0.2.29
- Fix nightly load tests in multi-repo mode by resolving `repo_id` from `/v1/initialize` in `load_test_http.sh` and wiring `DOCDEX_LOAD_REPO_ROOT` in CI.
- Improve npm installer behavior: postinstall stops or reuses the existing daemon on 127.0.0.1:28491 and restarts when versions differ so the updated binary is running.
- Bump release metadata to 0.2.29.

## 0.2.28
- Add delegation enforcement controls (`enforce_local`, `allow_fallback_to_primary`) with new enforcement metric.
- Add delegation savings telemetry endpoint + CLI output.
- Improve setup wizard API key prompts with masked, input-like fields.
- Bump release metadata to 0.2.28.

## 0.2.27
- Fix nightly HTTP soak to hit local search by default and pre-index before load tests.
- Clean up Windows IPC build warnings in `mcp_ipc`.
- Bump release metadata to 0.2.27.

## 0.2.26
- Add `/v1/index/status` and `indexing_in_progress` responses for search while indexing.
- Add async web deferral for `/search` and `docdex_search` (return local hits immediately).
- Accept `repo_id` via query params for `POST /v1/ast/query` and expand AST guidance docs.
- Add `docdex_tree` (MCP) and `docdexd tree` (CLI) for filtered repo folder structure rendering.

## 0.2.25
- Enforce `repo_id` when multiple repos are mounted, returning detailed errors for missing repo context.
- Add multi-repo daemon plan/tasks docs and expand repo scoping tests.

## 0.2.24
- Remove legacy stdio MCP (`docdexd mcp` / `docdex-mcp-server`); MCP is served only over HTTP/SSE.
- Add global profile memory (HTTP profile endpoints, CLI profile commands, MCP profile tools).
- Add default profile agent selection via `server.default_agent_id`, `docdexd serve --agent-id`, and MCP initialize `agent_id`.
- Add semantic gatekeeper hooks (`/v1/hooks/validate`, `docdexd hook pre-commit`) with optional Unix socket transport.
- Add `reasoning_trace` metadata to chat completions and project map context injection.
- Add profile import/export schema checks and sync compatibility validation.
- Add singleton daemon mode (`docdexd daemon`) with daemon lock and CLI auto-spawn guardrails.
- Add `POST /v1/initialize` repo validation endpoint and OpenAPI docs.
- Accept boolish env values for `DOCDEX_ENABLE_MCP`/`DOCDEX_DISABLE_MCP`.
- Add quality gates doc plus load/bench/audit scripts for release validation.
- Add network fault, concurrency, property, and metrics baseline tests.
- Add fuzz targets for libs, hooks, profile sync, and MCP payload parsing.
- Installer supports http download mirrors via `DOCDEX_DOWNLOAD_BASE` and skips docker matrix when the daemon is unavailable.

## 0.2.12
- Add AST/symbols support for Java, C#, C/C++, PHP, Kotlin, Swift, Ruby, Lua, and Dart.
- Bump Tree-sitter dependencies and parser version metadata for the expanded language set.
- Extend `docdexd mcp-add` to support Windsurf, Roo Code, PearAI, Void, and Zed configs.
- Expand indexed code extensions and default exclude folders for the new language ecosystems.
- Document expanded AST language support and auto-detected MCP clients.

## 0.1.11
- Added glama support

## 0.1.10
- smithery deployment work to get a bettwe score. enriched server.js, added mcp.json and an icon address.

## 0.1.9
- smithery deployment work

## 0.1.8
- smithery.yaml and Docker file fixes and added a entrypoint.sh to read environment variables and passes them as flags to docdexd

## 0.1.7
- Added smithery.yaml and Docker files for smithery.ai directory listing

## 0.1.6
- Fix MCP compliance: accept notifications, advertise underscore tool names, and return CallToolResult `content` payloads so Codex/other MCP clients stay connected.
- Keep docs/tests in sync with MCP spec responses ahead of npm publish.

## 0.1.5
- Ship MCP mode (docdex.search/index/files/open/stats) with resource templates and docs for MCP-aware clients.
- Expand CLI/help and tests around MCP usage to make agent/editor integration reliable.
- Bump versions for the MCP release and upcoming npm publish.

## 0.1.4
- Bump version for republish after 0.1.3 was already on npm.
- Keep trusted publishing fixes and expanded platform targets.

## 0.1.3
- Fix npm trusted publishing setup (environment + registry configuration) and bump version for release.
- Add musl/Windows targets to the release workflow and doc updates for broader platform support.

## 0.1.2
- Add musl/Windows targets to the release workflow and align npm publish trigger on tags.
- Doc updates for broader platform support.

## 0.1.1
- Bump version for npm doc updates and release alignment.

## 0.1.0
- Initial release of docdexd.
