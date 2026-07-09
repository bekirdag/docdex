# Changelog

## Unreleased

## 0.2.83
- Distinguish daemon startup-in-progress locks from healthy already-running daemons so `docdexd daemon` tells clients to wait for `/healthz` and `/v1/mcp` readiness instead of advertising an unavailable MCP endpoint.
- Harden npm postinstall daemon readiness checks by requiring both `/healthz` and the streamable MCP `/v1/mcp` route before treating a started or reused daemon as ready.
- Make daemon singleton and mcoda registry tests deterministic by using a bounded full health response read, disabling cloud refresh for registry-only assertions, and allowing slower daemon binds in local/CI environments with `DOCDEX_DAEMON_AUTO_START_TIMEOUT_SECS`.
- Bump release metadata to 0.2.83.

## 0.2.81
- Harden repo memory storage by enabling SQLite WAL mode and a 5-second busy timeout so concurrent Docdex agents can tolerate transient `database is locked` contention during memory saves.
- Add regression coverage for repo memory connection settings.
- Bump release metadata to 0.2.81.

## 0.2.79
- Enable hosted/server memory lanes, personal preferences, and mind-clone context by default so encrypted-search tenants can use company-wide memory out of the box.
- Preserve explicit personal-preferences enablement when repo/vector memory is disabled, allowing hosted chat clients to keep global user memory while local repo memory stays off.
- Update server memory documentation and startup validation coverage for default-on personal-preferences status.
- Bump release metadata to 0.2.79.

## 0.2.78
- Add encrypted source file storage and large archive uploads so source documents can be stored encrypted, expanded server-side, and searched without base64 or JSON buffering.
- Add encrypted-deployment parity for open/web access plus an HTTP LLM diagnostics surface with updated API and usage documentation.
- Auto-install Chromium for runtime web scraping, stabilize mcoda registry discovery tests, and move the Docdex deploy workflow to the private self-hosted runner.
- Bump release metadata to 0.2.78.

## 0.2.77
- Fix setup CLI help so `docdexd setup --help` describes provider-neutral local LLM service detection and optional fallbacks instead of an Ollama-first wizard.
- Sync `.well-known/mcp/server-card.json` release metadata with the package version and add regression coverage for MCP/package metadata drift.
- Bump release metadata to 0.2.77.

## 0.2.76
- Add provider-neutral local LLM setup, diagnostics, and migration coverage so Docdex can reuse existing Ollama, vLLM, llama.cpp-compatible, OpenAI-compatible local services, and mcoda agents before offering the Ollama fallback.
- Add fixture coverage for the observed local LLM environment and guard setup migration so explicit user model/provider/agent settings are not overwritten.
- Bump release metadata to 0.2.76.

## 0.2.75
- Add automatic AI-terminal capture, generated-skill registry, validation, sync, install, rollback, and context-hint surfaces for personal-preferences and mind-clone workflows.
- Add generated-skill quality reports with replay, drift, stale-source, activation feedback, and promote/keep/review/demote/quarantine recommendations.
- Split personal-preferences storage, digestion, routines, clone, governance, operator-event, and generated-skill logic into focused modules with HTTP, CLI, MCP, and test coverage.
- Bump release metadata to 0.2.75.

## 0.2.74
- Add compatibility HTTP aliases for repo memory, profile memory, personal-preferences, conversation, diary, KG, index, tree, files, stats, repo-inspect, impact diagnostics, and retrieval-only RAG surfaces.
- Add delete endpoints for repo memory, profile preferences, and diary entries, including storage cleanup and HTTP regression coverage.
- Bump release metadata to 0.2.74.

## 0.2.73
- Add a service-admin document ingest endpoint for encrypted repositories and remove plaintext source artifacts after encrypted ingestion.
- Allow bound service-token search for encrypted repositories when repository access bindings authorize the request.
- Skip structural ranking for encrypted search and disable encrypted-repository file watching to avoid plaintext-side watcher behavior.
- Bump release metadata to 0.2.73.

## 0.2.72
- Update the MCP Registry publisher used by the release workflow so GitHub OIDC login requests the registry URL audience expected by the current registry service.
- Bump release metadata to 0.2.72.

## 0.2.71
- Add generic encrypted-repository external API-key authorization with `AuthContext`, external introspection, service-token admin auth, and SQLite repository access bindings.
- Gate encrypted repository search, batch search, snippet, chat-context, and MCP data paths behind repository access policy while preserving default local/static-token compatibility for non-encrypted deployments.
- Add service-only encrypted repository provisioning, binding update, and auth-cache invalidation endpoints, plus auth/encryption capability reporting.
- Harden stale-index cleanup retries during automatic reindexing.
- Bump release metadata to 0.2.71.

## 0.2.70
- Serialize GitHub Release asset upload after matrix artifacts are collected so parallel release builds cannot race to create the same tag release.
- Bump release metadata to 0.2.70.

## 0.2.69
- Add explicit personal-preferences digest retry controls across HTTP, CLI, and MCP so failed captures and stale processing captures can be requeued without direct database edits.
- Raise the personal-preferences local digest timeout cap to 10 minutes, matching larger remote-Ollama mcoda agents such as qwen3.5:35b.
- Harden personal-preferences digest parsing by preferring the final balanced JSON payload, preserving strict `records` validation, and adding a one-shot local JSON repair pass for malformed local-model output.
- Bump release metadata to 0.2.69.

## 0.2.68
- Harden local delegation by failing fast when mcoda CLI-backed adapters point at missing binaries, routing Codex CLI prompts through stdin reliably, and retrying OpenAI-compatible `429` responses when `retry_after_ms` fits inside the request timeout.
- Reduce repeat delegation failures by sharing Ollama cooldowns across sibling aliases of the same backend model, preserving mcoda health details from registry refresh/load paths, and extending the mcoda CLI refresh timeout to 30 seconds.
- Improve mswarm setup recovery by surfacing typed paid-consent auth failures, clearing stale upload signing secrets or API keys when consent/config changes invalidate them, and making the setup wizard retry/abort flow clearer.
- Fix CI-only delegation tests by seeding executable CLI paths for CLI adapters and encrypted auth for explicit managed-cloud fixtures so `cargo test --locked --all` passes in GitHub Actions.
- Bump release metadata to 0.2.68.

## 0.2.66
- Update `Cargo.lock` to `rustls-webpki 0.103.12` so the nightly `cargo audit` gate clears RustSec `RUSTSEC-2026-0098` and `RUSTSEC-2026-0099`.
- Bump release metadata to 0.2.66.

## 0.2.65
- Consolidate repo-relative path handling, secure state-dir/repo-state helpers, and shared HTTP repo-resolution/index-readiness flows so API, CLI, index, memory, DAG, and MCP code paths stop carrying duplicate infrastructure logic; this also fixes AST search using the wrong repo indexer in multi-repo contexts.
- Refactor the impact subsystem by splitting parser, store, and traversal responsibilities and by adding a fingerprint-invalidated parsed impact-graph cache so repeated impact queries stop reparsing `impact_graph.json` on every request.
- Continue the runtime hardening pass by moving mswarm and mswarm telemetry HTTP paths to async `reqwest::Client`, decomposing MCP handler groups into focused modules, extracting bulky config/test support modules, and replacing remaining production `unwrap()`/`expect()` panic points with validated fallbacks.

## 0.2.64
- Add automatic six-layer memory routing across HTTP, CLI, MCP, and `/v1/chat/completions`, including a compact `Automatic memory route` context and a unified `Core memory` block so agents do not have to choose memory lanes purely from prompt guidance.
- Move memory routing earlier in the waterfall, reuse the same route for retrieval and prompt assembly, and gate repo/profile/wake-up recall plus chat-side archive and personal-preferences capture on meaningful read and write lane signals.
- Improve durable-memory extraction for natural-language repo facts, decisions, tooling/style preferences, and add regression coverage for the new route helpers, HTTP/MCP/CLI memory-route surfaces, and chat-side capture behavior.

## 0.2.63
- Add a six-layer memory map across HTTP, CLI, and MCP so agents can inspect repo memory, profile memory, conversation archives, diary notes, the temporal knowledge graph, and personal-preferences storage before choosing a recall lane.
- Extend wake-up context assembly with optional recent-diary startup episodes plus trace counters for diary candidates and selections, and cover the new memory-layers and wake-up flows with HTTP, CLI, chat, and MCP regression tests.
- Update the shipped agent guidance to call `docdex_memory_layers` first when memory scope is unclear and to document the six-lane memory model in the canonical agent prompt assets.

## 0.2.62
- Expand personal-preferences operations with claim, snapshot, feedback, and mind-clone surfaces across HTTP, CLI, and MCP, including review/override/forget flows and clone regression coverage.
- Harden the npm installer's local-binary path selection by validating `docdexd --version` output before using explicit or fallback local binaries and by avoiding stale repo-local binaries during registry installs.

## 0.2.61
- Add the optional personal-preferences memory subsystem: capture Docdex and supported local client conversations into a dedicated local store, digest them in the background, and expose status/search/process/export/redact/delete/purge controls over HTTP, CLI, and MCP.
- Align the personal-preferences release surface with the new top-level `[personal_preferences]` config, richer record lineage/materialization, review and retention controls, bounded chat-context injection, and supported-client transcript scanning.
- Harden the npm installer against whitespace-padded Docdex config keys and section names so reinstalling does not leave malformed duplicate Docdex entries in Codex, Gemini, Claude, and related client configs.

## 0.2.60
- Deduplicate installer-managed Docdex client config on reinstall: collapse stale `docdex` entries in JSON client configs, normalize Codex TOML to one canonical Docdex entry, and replace older versioned Docdex agent-instruction blocks without duplicating Codex/Gemini/Claude prompt files.
- Fix the nightly security audit failure by moving the direct `tokio-rustls` dependency to 0.26 with explicit `ring`/`tls12` features so the vulnerable `rustls-webpki` dependency chain is removed from the release build.

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
