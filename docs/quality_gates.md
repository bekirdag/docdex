# Docdex Quality Gates

This document defines measurable quality gates for Docdex releases. It extends the v2.0
phase-gated validation described in `docs/sds/sds.md` and includes v2.1-specific
requirements from `docs/sds/sdsv2.1.md`.

## Release Targets (Global)

These targets must be met before a release is considered stable.

- Stability:
  - p95 local search latency < 50ms on typical repos (target < 20ms).
  - p95 repo map generation < 200ms for medium repos (<= 50k files).
  - p95 memory recall < 150ms for 10k entries.
  - Error rate < 0.5% across HTTP + MCP requests during 30-minute soak.
  - No daemon crashes during 2-hour soak on large repos.
- Performance:
  - Index build: <= 3 min for 100k LOC on a 4-core laptop.
  - Peak RSS under 2.5 GB during indexing for 100k LOC.
  - Token budget enforcement never exceeds cap (profile, map, repo).
- Security:
  - No critical/high CVEs in direct dependencies. Mediums require explicit mitigation.
  - Localhost-only bind by default; token required when `--expose` is enabled.
  - No paid/external API calls without explicit gate (web waterfall only).
- Documentation:
  - All new flags, headers, and APIs documented in `docs/http_api.md` and CLI help.
  - Release notes include migration notes and breaking changes.
- Test Coverage:
  - Unit + integration tests for all new contracts and error shapes.
  - Property tests for profile/memory invariants.
  - Fuzz targets for parsers (manifest, hooks, profile import/export, MCP payloads).

## Phase Gate Criteria

Gate criteria mirror the SDS "Phase Gates" and add v2.1 checks.

- Phase 0 (Foundation):
  - `docdexd check` passes config RW, repo registry, localhost bind, MCP binary discovery.
  - Ollama and headless browser presence validated (Linux may auto-install Chromium).
- Phase 1 (Local RAG/Chat):
  - `index --repo` builds per-repo index.
  - `chat --repo` answers from local snippets.
  - `llm-list` / `llm-setup` functional with hardware-aware guidance.
- Phase 2 (Web Intelligence):
  - Web waterfall only triggers when confidence < `web_trigger_threshold`.
  - `web-search` / `web-fetch` / `web-rag` enforce DDG spacing and browser guard.
- Phase 2.1 (Library Context):
  - `libs fetch --repo` detects Rust/Node/Python dependencies.
  - Cached library docs are ingested into repo `libs_index`.
- Phase 3/3.5 (Unified API + Memory):
  - `/v1/chat/completions` defaults to daemon repo, token budgets enforced.
  - `memory_store` / `memory_recall` isolated per repo.
- Phase 4 (Reasoning DAG):
  - `dag view --repo` renders text/DOT with deterministic ordering.
- Phase 5 (MCP):
  - MCP tools are repo-aware; unknown repos fail with explicit error.
- Phase 6 (Code Intelligence):
  - Symbols populated; impact API returns directed edges with schema tags.
  - `run-tests --repo` emits structured JSON results.
- Phase 7 (UI Surfaces):
  - UI surfaces always pass `repo_path` and preserve repo scoping.

## v2.1-Specific Gates

- Dual-Lobe Memory:
  - Profile memory and repo memory are isolated in storage and retrieval.
  - Conflicts resolve in favor of Technical Truth over Behavioral Truth.
- Partitioned Token Budget:
  - Profile memory capped at 1k tokens.
  - Project map capped at 500 tokens.
  - Unused repo budget can be reallocated to chat history without exceeding caps.
- Profile Evolution:
  - Evolution triggers are deterministic and logged.
  - `profile import/export` is safe for network shares (no direct SQLite over NFS/SMB).
- Hooks:
  - HTTP and Unix socket hooks both supported.
  - Hook rate limits and errors are stable and machine-readable.

## Evidence Artifacts

- Test logs: `target/test_logs/*.log`
- Benchmarks: `target/criterion/*` and `target/bench_logs/*`
- Security reports: `target/audit/*.json`
- Release artifact checks: `target/release_checks/*`
- Gate snapshot: `GET /v1/gates/status`
