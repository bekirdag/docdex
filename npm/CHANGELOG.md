# Changelog

## 0.2.65
- Consolidate packaged repo-relative path handling, secure state-dir/repo-state helpers, and shared HTTP repo-resolution/index-readiness flows so the daemon stops carrying duplicate infrastructure across API, CLI, index, memory, DAG, and MCP code paths; this also fixes AST search using the wrong repo indexer in multi-repo contexts.
- Refactor the packaged impact subsystem by splitting parser, store, and traversal responsibilities and by adding a fingerprint-invalidated parsed impact-graph cache so repeated impact queries stop reparsing `impact_graph.json` on every request.
- Continue the packaged runtime hardening pass by moving mswarm and mswarm telemetry HTTP paths to async `reqwest::Client`, decomposing MCP handler groups into focused modules, extracting bulky config/test support modules, and replacing remaining production `unwrap()`/`expect()` panic points with validated fallbacks.

## 0.2.64
- Add packaged automatic six-layer memory routing across HTTP, CLI, MCP, and `/v1/chat/completions`, including a compact `Automatic memory route` context and a unified `Core memory` block so agents are not relying only on prompt guidance to pick a memory lane.
- Move packaged memory routing earlier in the waterfall, reuse the same route for retrieval and prompt assembly, and gate repo/profile/wake-up recall plus chat-side archive and personal-preferences capture on meaningful read and write lane signals.
- Improve packaged durable-memory extraction for natural-language repo facts, decisions, and tooling/style preferences, and add regression coverage for route helpers, memory-route surfaces, and chat-side capture behavior.

## 0.2.63
- Add the packaged six-layer memory map over HTTP, CLI, and MCP so agents can inspect repo, profile, conversation, diary, temporal-KG, and personal-preferences lanes before selecting a memory surface.
- Extend packaged wake-up context assembly with optional recent-diary startup episodes, expose diary trace counters, and cover the new memory-layers and wake-up flows with HTTP, CLI, chat, and MCP regression tests.
- Update the packaged agent guidance to call `docdex_memory_layers` first when memory scope is unclear and to document the six-lane memory model in the shipped prompt assets.

## 0.2.62
- Expand the packaged personal-preferences surface with claim, snapshot, feedback, and mind-clone flows across HTTP, CLI, and MCP, including review/override/forget controls and clone regression coverage.
- Harden the packaged installer's local-binary path selection by validating `docdexd --version` output before using explicit or fallback local binaries and by avoiding stale repo-local binaries during registry installs.

## 0.2.61
- Add the optional personal-preferences memory subsystem with local capture, background digestion, and packaged HTTP/CLI/MCP controls for status, search, processing, export, redaction, deletion, and purge flows.
- Align the packaged personal-preferences surface with the top-level `[personal_preferences]` config, richer lineage/materialization, review and retention controls, bounded chat-context injection, and supported-client transcript scanning.
- Harden installer-managed client config rewrites so whitespace-padded Docdex keys and section names are normalized instead of duplicated on reinstall.

## 0.2.60
- Deduplicate installer-managed Docdex client config on reinstall: JSON client configs now collapse stale `docdex` entries, Codex TOML converges to one canonical Docdex entry, and packaged Docdex instruction blocks replace older Codex/Gemini/Claude prompt blocks instead of duplicating them.
- Update the packaged daemon dependency set to remove the vulnerable `rustls-webpki` chain that caused the nightly security audit failure.

## 0.2.58
- Export Docdex delegation savings in hourly mswarm telemetry packages and expose matching runtime/admin mswarm summaries for frontend visibility.

## 0.2.57
- Bump release metadata to 0.2.57.

## 0.2.56
- Clarify packaged agent-facing local delegation docs for code-oriented tasks versus `general_question`.

## 0.2.55
- Raise installer-managed Codex MCP `tool_timeout_sec` and `startup_timeout_sec` defaults to 300 seconds.
- Update packaged Codex MCP examples to show the 300-second timeout settings.

## 0.2.54
- Add a per-project actual cost savings table to `docdexd delegation savings --all`.
- Include optional per-project `projects` telemetry entries for `/v1/telemetry/delegation?all=true`, resolving persisted repo telemetry to canonical project paths with live mounted-repo fallback.

## 0.2.52
- Persist delegation savings telemetry across daemon restarts and reinstalls, including packaged daemon-global `--all` totals and repo-scoped counters.
- Store daemon-global delegation savings under `~/.docdex/state/telemetry/delegation.json` and repo totals under `~/.docdex/state/repos/<state_key>/delegation_telemetry.json`.

## 0.2.51
- Persist local delegation failures to `~/.docdex/state/logs/errors/delegation_local_failures.jsonl` with repo/source metadata and recovery details.
- Document the packaged delegation failure history path in the usage guide.

## 0.2.50
- Attribute delegation savings to the actual expensive caller via `caller_agent_id`, `caller_model`, or `primary_cost_per_million`, and expose avoided primary cost plus effective per-1M telemetry rates.
- Canonicalize delegation pricing config to `primary_usd_per_million_tokens` and `local_usd_per_million_tokens` while preserving legacy `*_usd_per_1k_tokens` compatibility in packaged docs and telemetry.

## 0.2.49
- Generate installer-managed MCP URLs with `127.0.0.1` so client configs match the daemon bind default.
- Update packaged MCP examples and add regression coverage for the postinstall URL helpers.

## 0.2.48
- Exclude paid or expensive mcoda agents from automatic local delegation target selection.
- Document the zero-cost local delegation rule in the packaged agent guidance.

## 0.2.47
- Bump release metadata to 0.2.47.

## 0.2.46
- Bump release metadata to 0.2.46.

## 0.2.45
- Update packaged agent docs with FD-hardening guidance and bump release metadata to 0.2.45.

## 0.2.44
- Fix MCP tool schema compatibility with Claude Code by removing top-level anyOf from `docdex_dag_export`.
- Bump release metadata to 0.2.44.

## 0.2.42
- Bump release metadata to 0.2.42.

## 0.2.41
- Improve Windows npm postinstall UX with a plain setup hint, npm lifecycle non-interactive detection, and no empty cmd window from immediate daemon start.
- Fix setup TUI menu selection highlighting on Windows terminals.
- Propagate DAG session IDs in docs so `docdex_dag_export` is called with the `dag_session_id` from search results.

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

## 0.2.34
- Normalize delegation output by stripping top-level markdown fences so local delegation doesn't fail on wrapped output.

## 0.2.33
- Warn Windows users to install the VC++ 2015-2022 runtime in the npm README.
- Ensure `docdex setup` detects the default Ollama install path on Windows.
- Document the Windows default Chromium auto-install location.

## 0.2.23
- Add Smithery session config schema metadata (titles/descriptions, defaults, example config) for local MCP sessions.
- Enrich MCP tools with titles, descriptions, parameter descriptions, and annotations to improve Smithery scoring.
- Expose MCP prompts and resources (with titles/mime types/annotations) for onboarding, incident triage, and refactor planning.
- Switch web scraping to Chromium-only installs under `~/.docdex/state/bin/chromium/` and remove legacy browser tooling.

## 0.2.21
- Prompt for npm updates at CLI start (TTY-only, opt-out via `DOCDEX_UPDATE_CHECK=0`).

## 0.2.19
- Agents md adding command manually
- Agents md append repeat fix

## 0.2.16
- Repo memory now tags items with `repoId` and filters recalls to prevent cross-repo leakage in multi-repo daemons.
- MCP HTTP requires explicit repo selection when multiple repos are active.
- Postinstall banner now guides users to run `docdex setup`.
- Docs refreshed with memory, agent memory, code intelligence, web search, and Ollama guidance.

## 0.1.10
- smithery deployment work to get a bettwe score. enriched server.js, added mcp.json and an icon address.

## 0.1.9
- smithery deployment work

## 0.1.8
- smithery.yaml and Docker file fixes and added a entrypoint.sh to read environment variables and passes them as flags to docdexd

## 0.1.7
- Added smithery.yaml and Docker files for smithery.ai directory listing

## 0.1.6
- Align with MCP spec fixes (notification handling, CallToolResult content payloads, underscore tool names) so Codex and other clients stay stable.
- Publish npm wrapper with the latest MCP-compliant binary.

## 0.1.5
- Publish the MCP-enabled CLI wrapper and align docs with MCP mode.
- Keep npm version in sync with the MCP release for binary downloads.

## 0.1.4
- Version bump for republish (0.1.3 already exists on npm).

## 0.1.3
- Fixed npm trusted publishing configuration (environment + registry) and aligned version bump.

## 0.1.2
- Broadened platform coverage in the workflow (musl, Windows) and kept npm version aligned with release tags.

## 0.1.1
- Updated npm README with clearer install and usage details.

## 0.1.0
- Initial npm scaffold for the Docdex CLI (`docdex`/`docdexd` bin).
- Postinstall downloader to fetch platform-specific `docdexd` binaries.
- Supports macOS (arm64/x64) and Linux (arm64/x64, gnu/musl auto-detect).
