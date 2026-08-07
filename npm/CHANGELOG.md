# Changelog

## Unreleased
- Throttle LaunchAgent restarts on macOS to match the hardened Linux unit.
- Harden the installed Linux systemd unit against OOM crashloops with a longer restart delay, a start-limit, memory bounds, and control-group kill so browser children are reaped.

## 0.2.96
- Query the owned SearXNG instance for the `general,it` categories so its code, documentation, and package-registry engines are used.
- Keep provider titles and snippets on discovery results and drop low-relevance hits before fetching them.
- Bump packaged release metadata to 0.2.96.

## 0.2.95
- Fix `docdex setup` closing right after the consent screen was accepted, caused by a nested Tokio runtime panic during local-service detection.
- Accept `Y`, `y`, and `Enter` as consent; only `n`, `N`, and `Esc` decline.
- Save consent locally as soon as it is accepted and skip the screen on later runs, so a failed mswarm registration no longer re-asks or ends setup.
- Make packaged interrupted-install backup recovery deterministic when two backups share an mtime.
- Bump packaged release metadata to 0.2.95.

## 0.2.94
- Resolve packaged SearXNG endpoints through system DNS so private deployment hostnames work without weakening DuckDuckGo's public-DNS protections.
- Add private-hostname regression coverage and bump packaged release metadata to 0.2.94.

## 0.2.93
- Add packaged SearXNG fallback configuration and setup support with the owned `se.overrid.com` endpoint as the default.
- Keep DuckDuckGo first, SearXNG second, and paid Brave last unless Brave is explicitly selected.
- Add fallback-order, setup, configuration-precedence, and no-paid-call regression coverage.
- Ship the native core with the patched Ammonia HTML sanitizer floor for RUSTSEC-2026-0213.
- Bump packaged release metadata to 0.2.93.

## 0.2.92
- Return HTTP 404 for unknown, expired, or already deleted packaged Streamable HTTP MCP sessions so clients automatically initialize replacements.
- Preserve HTTP 400 for missing required MCP session headers and add focused recovery regression coverage.
- Bump packaged release metadata to 0.2.92.

## 0.2.91
- Prevent packaged CLI auto-start probes from killing a live daemon when a short health check times out, preserving active MCP sessions under load.
- Allow global profile reads and preference writes in unbound multi-repo Streamable HTTP MCP sessions while repo-scoped tools remain fail-closed.
- Add regression coverage and bump packaged release metadata to 0.2.91.

## 0.2.90
- Fix packaged Streamable HTTP MCP startup for multi-repo daemons without a default repo by allowing unbound initialize/tool discovery and binding a repo only when repo-scoped tools run.
- Preserve packaged fail-closed behavior for repo tool calls that still omit `project_root` or `repo_path`, returning `missing_repo` instead of leaking an arbitrary mounted repo.
- Bump packaged release metadata to 0.2.90.

## 0.2.89
- Let the packaged tag-triggered release asset job publish with the workflow `GITHUB_TOKEN` by removing an admin-only immutable-release repository API precheck while retaining remote-tag and asset verification.
- Bump packaged release metadata to 0.2.89.

## 0.2.88
- Keep packaged tag-triggered release publication from failing when optional external feature-matrix adapters are not configured, while still recording blocked external lanes in the uploaded evidence ledger.
- Retain the stricter external `--release-gate` for explicitly configured validation runs.
- Bump packaged release metadata to 0.2.88.

## 0.2.87
- Harden packaged profile, DAG, conversation, knowledge, repo-memory, and personal-preferences SQLite connection setup behind a shared 5-second busy-timeout policy so concurrent agents tolerate transient local database writer contention.
- Move packaged DAG logging to WAL mode and add regression coverage for memory-adjacent stores that previously opened SQLite with no busy timeout.
- Bump packaged release metadata to 0.2.87.

## 0.2.86
- Enforce a packaged fail-closed outbound web policy across HTTP, CLI, discovery, and Chromium paths, keep browser sandboxing enabled by default, cap responses, restore bounded transient discovery retries, and shut down owned browser processes deterministically.
- Pin packaged Chromium TCP egress through a bounded host/IP allowlisting proxy, secure DevTools with an owned ephemeral endpoint and recursive target interception, deny service-worker/cache/download bypasses, and make managed-browser refresh, rollback, locking, and Windows process identity fail safe.
- Make packaged stale/read-only index handling non-destructive, report accurate paginated document totals, move public indexing work off async executors, and serialize rebuilds with a panic-safe gate.
- Isolate packaged MCP runtime options and per-session authentication/agent state, remove cross-session head-of-line blocking, bound in-flight work, and fail closed for ambiguous multi-repo initialization.
- Single-flight packaged concurrent repository mounts, preserve read-only watcher invariants, and bound/coalesce watcher queues with full reconciliation after overflow or directory-level events.
- Merge packaged repository and library search results deterministically and refill pages after stale-file filtering with a bounded second lookup.
- Update packaged vulnerable compatible dependencies and document the temporary `ring` advisory exception pending a coordinated Tree-sitter grammar migration.
- Harden packaged release publication around one tested npm tarball, synchronized version checks, integrity/SBOM evidence, resumable registry verification, and manual-only production deployment with pinned SSH host trust.
- Replace packaged false-positive-prone aggregate smoke coverage with isolated, locked, evidence-producing feature gates and explicit external-provider blockers.
- Make packaged release reruns immutable and resumable with SHA-256 asset comparison, fully pinned Actions, split least-privilege npm/MCP/GitHub publication jobs, strict feature-ledger/version/audit validation, and ephemeral pinned-host SSH credentials.
- Bump packaged release metadata to 0.2.86.

## 0.2.85
- Add a packaged disabled-by-default encrypted user-memory sync preview with config/status/dry-run support, bundle generation, and server-store register, push, feed, apply, and ack endpoints.
- Scope packaged hosted user-memory sync requests through external API-key introspection, including user-memory sync scope checks and a canonical hashed principal so multiple API keys for one user merge into one feed.
- Add packaged AES-256-GCM payload envelopes, local decrypt/AAD/hash verification, profile-memory down-sync apply with embedding rebuild and last-write-wins import, and applied/skipped ledger tracking.
- Document packaged production plan, progress, and threat model boundaries; non-profile lanes currently sync as encrypted inventory/policy events until safe importers are implemented.
- Harden packaged release validation by widening daemon health waits under full-suite load and serializing MCP local-completion daemon tests that contend for local SQLite state.
- Upgrade the packaged tar extraction dependency to `tar` 7.5.19 so production npm audit is clean before publish.
- Bump packaged release metadata to 0.2.85.

## 0.2.84
- Distinguish packaged daemon startup-in-progress locks from healthy already-running daemons so `docdexd daemon` tells clients to wait for `/healthz` and `/v1/mcp` readiness instead of advertising an unavailable MCP endpoint.
- Harden packaged npm postinstall daemon readiness checks by requiring both `/healthz` and the streamable MCP `/v1/mcp` route before treating a started or reused daemon as ready.
- Make packaged daemon singleton and mcoda registry tests deterministic by using a bounded full health response read, disabling cloud refresh for registry-only assertions, and allowing slower daemon binds in local/CI environments with `DOCDEX_DAEMON_AUTO_START_TIMEOUT_SECS`.
- Pin packaged GitHub Actions npm upgrades to npm 11.18.0 so trusted publishing remains compatible with the workflow's Node 24 runtime.
- Box packaged MCP service dispatch futures at the proxy boundary so Rust 1.97 debug builds remain well below Linux's default test-thread stack while preserving per-session fairness, cancellation, and timeouts.
- Pin the Rust 1.97.0 toolchain and Node 24 GitHub Actions by immutable commit across CI, nightly, release, and deployment workflows.
- Bump packaged release metadata to 0.2.84.

## 0.2.81
- Harden packaged repo memory storage by enabling SQLite WAL mode and a 5-second busy timeout so concurrent Docdex agents can tolerate transient `database is locked` contention during memory saves.
- Add packaged regression coverage for repo memory connection settings.
- Bump packaged release metadata to 0.2.81.

## 0.2.79
- Enable packaged hosted/server memory lanes, personal preferences, and mind-clone context by default so encrypted-search tenants can use company-wide memory out of the box.
- Preserve packaged explicit personal-preferences enablement when repo/vector memory is disabled, allowing hosted chat clients to keep global user memory while local repo memory stays off.
- Update packaged server memory documentation and startup validation coverage for default-on personal-preferences status.
- Bump packaged release metadata to 0.2.79.

## 0.2.78
- Add packaged encrypted source file storage and large archive uploads so source documents can be stored encrypted, expanded server-side, and searched without base64 or JSON buffering.
- Add packaged encrypted-deployment parity for open/web access plus an HTTP LLM diagnostics surface with updated API and usage documentation.
- Auto-install packaged Chromium support for runtime web scraping, stabilize packaged mcoda registry discovery tests, and move the packaged release deploy workflow to the private self-hosted runner.
- Bump packaged release metadata to 0.2.78.

## 0.2.77
- Fix packaged setup CLI help so `docdexd setup --help` describes provider-neutral local LLM service detection and optional fallbacks instead of an Ollama-first wizard.
- Sync packaged MCP server-card release metadata with the package version and add regression coverage for MCP/package metadata drift.
- Bump packaged release metadata to 0.2.77.

## 0.2.76
- Add packaged provider-neutral local LLM setup and diagnostics guidance so npm installs do not imply Ollama is mandatory when another supported local service or mcoda agent already exists.
- Add packaged migration/test coverage notes for preserving explicit user model/provider/agent settings while replacing generated legacy Ollama defaults.
- Bump packaged release metadata to 0.2.76.

## 0.2.75
- Add packaged automatic AI-terminal capture, generated-skill registry, validation, sync, install, rollback, and context-hint surfaces for personal-preferences and mind-clone workflows.
- Add packaged generated-skill quality reports with replay, drift, stale-source, activation feedback, and promote/keep/review/demote/quarantine recommendations.
- Split packaged personal-preferences storage, digestion, routines, clone, governance, operator-event, and generated-skill logic into focused modules with HTTP, CLI, MCP, and test coverage.
- Bump packaged release metadata to 0.2.75.

## 0.2.74
- Add packaged compatibility HTTP aliases for repo memory, profile memory, personal-preferences, conversation, diary, KG, index, tree, files, stats, repo-inspect, impact diagnostics, and retrieval-only RAG surfaces.
- Add packaged delete endpoints for repo memory, profile preferences, and diary entries, including storage cleanup and HTTP regression coverage.
- Bump packaged release metadata to 0.2.74.

## 0.2.73
- Add a packaged service-admin document ingest endpoint for encrypted repositories and remove plaintext source artifacts after encrypted ingestion.
- Allow packaged bound service-token search for encrypted repositories when repository access bindings authorize the request.
- Skip packaged structural ranking for encrypted search and disable encrypted-repository file watching to avoid plaintext-side watcher behavior.
- Bump packaged release metadata to 0.2.73.

## 0.2.72
- Update the packaged release workflow MCP Registry publisher so GitHub OIDC login requests the registry URL audience expected by the current registry service.
- Bump packaged release metadata to 0.2.72.

## 0.2.71
- Add packaged generic encrypted-repository external API-key authorization with `AuthContext`, external introspection, service-token admin auth, and SQLite repository access bindings.
- Gate packaged encrypted repository search, batch search, snippet, chat-context, and MCP data paths behind repository access policy while preserving default local/static-token compatibility for non-encrypted deployments.
- Add packaged service-only encrypted repository provisioning, binding update, and auth-cache invalidation endpoints, plus auth/encryption capability reporting.
- Harden packaged stale-index cleanup retries during automatic reindexing.
- Bump packaged release metadata to 0.2.71.

## 0.2.70
- Serialize packaged GitHub Release asset upload after matrix artifacts are collected so parallel release builds cannot race to create the same tag release.
- Bump packaged release metadata to 0.2.70.

## 0.2.69
- Add packaged personal-preferences digest retry controls across HTTP, CLI, and MCP so failed captures and stale processing captures can be requeued without direct database edits.
- Raise the packaged personal-preferences local digest timeout cap to 10 minutes for larger remote-Ollama mcoda agents such as qwen3.5:35b.
- Harden packaged personal-preferences digest parsing by preferring the final balanced JSON payload, preserving strict `records` validation, and adding a one-shot local JSON repair pass for malformed local-model output.
- Bump packaged release metadata to 0.2.69.

## 0.2.68
- Harden packaged local delegation by failing fast when mcoda CLI-backed adapters point at missing binaries, routing Codex CLI prompts through stdin reliably, and retrying OpenAI-compatible `429` responses when `retry_after_ms` fits inside the request timeout.
- Reduce repeat packaged delegation failures by sharing Ollama cooldowns across sibling aliases of the same backend model, preserving mcoda health details from registry refresh/load paths, and extending the mcoda CLI refresh timeout to 30 seconds.
- Improve packaged mswarm setup recovery by surfacing typed paid-consent auth failures, clearing stale upload signing secrets or API keys when consent/config changes invalidate them, and making the setup wizard retry/abort flow clearer.
- Fix packaged CI-only delegation tests by seeding executable CLI paths for CLI adapters and encrypted auth for explicit managed-cloud fixtures so `cargo test --locked --all` passes in GitHub Actions.
- Bump packaged release metadata to 0.2.68.

## 0.2.66
- Update the packaged daemon lockfile to `rustls-webpki 0.103.12` so the nightly `cargo audit` gate clears RustSec `RUSTSEC-2026-0098` and `RUSTSEC-2026-0099`.
- Bump packaged release metadata to 0.2.66.

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
