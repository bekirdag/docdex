Baseline

  - Repo-scoped memory is already in place via src/memory/db.rs, with sqlite-vec tables, file locks, and token-pruned context assembly in src/orchestrator/waterfall.rs and src/api/v1/chat.rs.
  - Global state layout only creates repos/, cache/, locks/, and logs/ in src/state_layout.rs; there is no profiles/ directory yet.
  - Config supports [memory] with enabled/backend and uses [llm].embedding_model in src/config.rs; no profile-specific embedding settings exist.
  - There is no src/profiles/ module or global profile DB path; AppState only carries repo memory in src/search/mod.rs.

  Plan (Phase 1: Storage Infrastructure)

  - Add src/profiles/mod.rs with domain types (Agent, Preference, PreferenceCategory, ProfileMeta) and reexports to mirror the memory module structure.
  - Implement src/profiles/db.rs using rusqlite + sqlite-vec: create agents, preferences, profile_meta, and preferences_vec (vec0) tables; enable WAL; persist embedding_dim and schema_version; reuse f32 encode/decode patterns from src/memory/db.rs for embeddings.
  - Add path helpers for the global DB (profiles/main.db) and lock file (profiles/profiles.lock) in src/profiles/mod.rs or src/profiles/paths.rs, anchored to core.global_state_dir from src/config.rs.
  - Extend src/state_layout.rs with profiles_dir() and profiles_sync_dir() and ensure they’re created in ensure_global_dirs; optionally surface them in StatePathsDebug for diagnostics.
  - Implement seed initialization in profile_db::init() using an embedded JSON (src/profiles/defaults.json via include_str!): if agents is empty, insert agents + preferences in a single transaction with last_updated set.
  - Build src/profiles/manager.rs as the SWMR façade: Arc<parking_lot::RwLock<Connection>> for read/write separation plus fs4 file locks for cross-process safety; expose create_agent, get_agent, list_agents, add_preference, and search_preferences (vector query on preferences_vec).
  - Wire the manager into runtime without surface changes: create a ProfileManager in src/daemon.rs on startup (based on core.global_state_dir + new profile embedding config) and store it in AppState in src/search/mod.rs for future phases.
  - Extend config with a new [memory.profile] block in src/config.rs (embedding_model, embedding_dim), defaulted via apply_defaults(); include validation (dim > 0, non-empty model).
  - Add a new profile_db check in src/cli/commands/check.rs to ensure profiles/main.db is writable and the vector schema is initialized (similar to the existing memory_db checks).
  - Add focused tests: unit tests in src/profiles/db.rs for schema creation, embedding_dim mismatch, seed idempotency, and vector search ordering; integration test under tests/ to initialize a temp state dir and verify profiles/main.db + profiles/sync creation.


• Here are separated, implementation‑ready tasks for Phase 1 (Storage Infrastructure). Each task is scoped, includes key files, and has acceptance criteria.

  1. Add profile module scaffolding + domain types

  - Files: src/profiles/mod.rs, src/lib.rs
  - Work: create module; define Agent, Preference, PreferenceCategory, ProfileMeta structs/enums; expose via pub use; register module in src/lib.rs.
  - Acceptance: crate compiles; types are usable by other modules.

  2. Add global profile paths to state layout

  - Files: src/state_layout.rs
  - Work: add profiles_dir() and profiles_sync_dir(); update ensure_global_dirs() to create them; add to StatePathsDebug to aid diagnostics.
  - Acceptance: calling ensure_global_dirs() creates profiles/ and profiles/sync/ under state root.

  3. Implement profile DB schema + sqlite-vec setup

  - Files: src/profiles/db.rs (new)
  - Work: create schema for agents, preferences, preferences_vec, profile_meta; enable WAL; store/read schema_version + embedding_dim; add vec0 table creation + backfill; add encode/decode embedding helpers modeled after src/memory/db.rs.
  - Acceptance: init_profile_db() creates tables and vec index; opening DB with mismatched embedding_dim returns a clear error.

  4. Implement seeding of default profiles/preferences

  - Files: src/profiles/defaults.json (new), src/profiles/db.rs
  - Work: create defaults JSON (agents + preferences); in init_profile_db(), if agents is empty, insert defaults in a single transaction; ensure idempotent on re‑init.
  - Acceptance: empty DB is seeded once; subsequent inits do not duplicate rows.

  5. Build ProfileManager with SWMR gating

  - Files: src/profiles/manager.rs (new), src/profiles/mod.rs
  - Work: add manager with RW locks for read/write gating + fs4 lock file for cross‑process safety; provide create_agent, get_agent, list_agents, add_preference, search_preferences.
  - Acceptance: operations compile and are thread‑safe; write operations acquire exclusive lock; reads can proceed concurrently.

  6. Add [memory.profile] config block

  - Files: src/config.rs
  - Work: add MemoryProfileConfig { embedding_model, embedding_dim }; nest under MemoryConfig or AppConfig per serde; update defaults and apply_defaults(); update config serialization.
  - Acceptance: ~/.docdex/config.toml includes memory.profile defaults; config loads without breaking existing fields.

  7. Wire profile manager into daemon app state

  - Files: src/daemon.rs, src/search/mod.rs
  - Work: initialize ProfileManager at daemon startup using core.global_state_dir + profile embedding config; store in AppState as profile_manager: Option<ProfileManager>.
  - Acceptance: daemon starts without requiring profile usage; AppState carries profile manager for future phases.

  8. Add profile DB checks to docdexd check

  - Files: src/cli/commands/check.rs
  - Work: add profile_db check: verify profiles dir, ensure db can be created/written, log status.
  - Acceptance: docdexd check reports profile_db status alongside memory_db.

  9. Add unit tests for profile DB + seed logic

  - Files: src/profiles/db.rs (tests module) or tests/profile_db.rs
  - Work: test schema creation, embedding_dim mismatch, seed idempotency, vec search ordering (minimal vector).
  - Acceptance: tests pass locally; failure modes are deterministic and human‑readable.

 ──────────────────────────────────────────────────────────────────────────────────────────────────────────── 

Phase 2 Plan — Evolution Logic

  - Step 1: Profile embedding integration
      - Create src/profiles/embedder.rs with ProfileEmbedder wrapping OllamaEmbedder.
      - Inputs: base_url, model, timeout_ms, expected_dim; output: Vec<f32> with strict dimension check.
      - Error behavior: return ERR_EMBEDDING_FAILED (or a new profile-specific error) if the returned vector size != expected_dim; log provider/model for traceability.
  - Step 2: Evolution engine core types
      - Add src/profiles/evolution.rs with:
          - EvolutionAction enum (Add, Update, Ignore)
          - EvolutionDecision struct (action, target_preference_id, new_content, reasoning)
          - EvolutionOutcome struct (applied_action, affected_preference_id, reasoning)
      - Keep EvolutionEngine constructor dependency-injected: ProfileManager, ProfileEmbedder, and Arc<dyn LlmClient> (from src/llm/adapter.rs).
  - Step 3: Recall → Reason → Decide flow
      - Implement EvolutionEngine::evolve(agent_id, category, new_fact) -> Result<EvolutionOutcome>.
      - Recall: call ProfileManager::search_preferences(agent_id, query_embedding, recall_k); order by distance asc + last_updated desc.
      - Prompt build:
          - Include current memory list with {id, content, recency}; compute recency from last_updated (simple days/hours).
          - Inject a strict JSON output requirement and the action definitions from the SDS.
      - Decide: call LlmClient::generate() with bounded tokens/timeouts (configurable constants); parse and validate JSON.
  - Step 4: JSON parsing + validation guardrails
      - Implement a parser that:
          - Strips code fences and leading/trailing text.
          - Validates action enum; enforces target_preference_id for UPDATE.
          - Requires new_content for ADD/UPDATE (non-empty).
          - Verifies target_preference_id exists in the recalled set.
      - Retry policy: if parse/validation fails, retry up to N=2 times; if still invalid, default to IGNORE.
  - Step 5: Apply decision to DB
      - For ADD: re-embed new_content (not the original input) and insert a new preference row + vector row; last_updated = now.
      - For UPDATE: re-embed new_content, update content, vector, last_updated.
      - For IGNORE: no DB change; log the decision with reasoning.
  - Step 6: Logging + metrics hooks
      - Add structured logs on decision outcomes (action, agent_id, preference_id, latency).
      - Prepare counters (optional stub in src/metrics.rs) for decisions, retries, and invalid JSON (to be wired later).
  - Step 7: Tests (unit-focused)
      - src/profiles/evolution.rs tests with a stub LlmClient:
          - Valid JSON → correct action + DB change.
          - Invalid JSON → retries → IGNORE.
          - UPDATE without target → invalid → IGNORE.
      - src/profiles/embedder.rs tests:
          - Dimension mismatch returns error.
      - src/profiles/db.rs tests:
          - Update path overwrites content + vector.
          - ADD path inserts new row with correct category and timestamp.


• Below is a detailed, separated task list for Phase 2 (Evolution Logic). Each task is intentionally narrow and implementable.

  1. Add profile embedding wrapper with dimension enforcement

  - Files: src/profiles/embedder.rs, src/profiles/mod.rs
  - Work: implement ProfileEmbedder that wraps OllamaEmbedder; enforce expected_dim; return explicit error on mismatch; expose provider()/model() for metadata.
  - Acceptance: embedding call fails fast on dimension mismatch; module exports compile.

  2. Define evolution core types

  - Files: src/profiles/evolution.rs
  - Work: create EvolutionAction enum, EvolutionDecision and EvolutionOutcome structs; add serde for JSON parsing; add helpers for validation.
  - Acceptance: unit tests can construct/parse decisions; type names are stable.

  3. Build EvolutionEngine skeleton

  - Files: src/profiles/evolution.rs
  - Work: implement EvolutionEngine::new(profile_manager, embedder, llm_client); store config (timeouts, retries, recall_k).
  - Acceptance: engine compiles and can be instantiated in tests.

  4. Implement recall step for evolution

  - Files: src/profiles/evolution.rs, src/profiles/manager.rs
  - Work: add ProfileManager::search_preferences_for_evolution(agent_id, query_embedding, top_k) returning {id, content, last_updated}; ensure ordering by vector distance + recency.
  - Acceptance: search returns deterministic ordering and includes required fields.

  5. Implement evolution prompt builder

  - Files: src/profiles/evolution.rs
  - Work: build the “Memory Manager” prompt exactly as in SDS with strict JSON output instructions; include recalled memory items with recency strings.
  - Acceptance: prompt builder outputs stable format; unit test snapshot validates required sections.

  6. Implement LLM decision call + strict JSON parsing

  - Files: src/profiles/evolution.rs
  - Work: call LlmClient::generate() with bounded tokens/timeouts; parse JSON; strip code fences; validate required fields.
  - Acceptance: valid JSON yields EvolutionDecision; invalid JSON is rejected.

  7. Add retry + default IGNORE behavior

  - Files: src/profiles/evolution.rs
  - Work: retry LLM decision parsing up to N=2; if still invalid, return EvolutionOutcome { action: Ignore }.
  - Acceptance: unit test shows invalid output → retries → IGNORE.

  8. Implement APPLY for ADD

  - Files: src/profiles/evolution.rs, src/profiles/manager.rs
  - Work: on ADD, embed new_content, insert into preferences + preferences_vec, update last_updated.
  - Acceptance: DB row + vec row created; content is from new_content not raw input.

  9. Implement APPLY for UPDATE

  - Files: src/profiles/evolution.rs, src/profiles/manager.rs
  - Work: on UPDATE, validate target id exists; re-embed new_content; update row and vector; bump last_updated.
  - Acceptance: updated content replaces old; vector row updated; invalid target id rejects the update.

  10. Implement IGNORE path + reasoning capture

  - Files: src/profiles/evolution.rs
  - Work: for IGNORE, return outcome with reasoning; no DB writes.
  - Acceptance: no DB mutation; reasoning returned for logging.

  11. Add logging hooks for evolution outcomes

  - Files: src/profiles/evolution.rs
  - Work: structured logs with agent_id, action, preference_id, latency; include parse error counts.
  - Acceptance: logs emitted in all action paths.

  12. Unit tests for evolution decision flow

  - Files: src/profiles/evolution.rs (tests module)
  - Work: stub LlmClient; test ADD, UPDATE, IGNORE; test invalid JSON → retry → IGNORE.
  - Acceptance: tests pass without external dependencies.

  13. Unit tests for embedder dimension check

  - Files: src/profiles/embedder.rs (tests module)
  - Work: mock embedder response with wrong length; assert error.
  - Acceptance: tests fail on mismatch and pass on correct length.

  14. Unit tests for DB update behaviors

  - Files: src/profiles/manager.rs or src/profiles/db.rs
  - Work: verify ADD inserts; UPDATE replaces content and vector; last_updated monotonic.
  - Acceptance: tests pass in temp state dir.

────────────────────────────────────────────────────────────────────────────────────────────────────────────
  
• Phase 3 Plan (Integration & Tooling)

  - Profile Budget + Context Assembly: add profile budget caps (1000 tokens hard cap) and prune helpers alongside memory pruning; update src/orchestrator/budget.rs and add ProfileContextAssembly/trace types so Tier 0 retrieval can surface token counts and drops.
  - Tier 0 Retrieval in Waterfall: extend WaterfallRequest/WaterfallResult to carry profile_agent_id and profile_state; in src/orchestrator/waterfall.rs embed the query with the profile embedder, search profile.db, prune to budget, and attach profile_context before Tier 1; emit DAG
    logs for recall/latency.
  - Prompt/Context Injection Order: update chat_context_budgets and build_context_summary in src/api/v1/chat.rs to include “Profile context” before repo memory and matches (Hierarchy of Truth); update format_compressed_results and log_budget_drops to include profile drops and
    snippets.
  - Agent ID plumbing (HTTP + CLI): accept x-docdex-agent-id header and docdex.agent_id body in src/api/v1/chat.rs, pass into WaterfallRequest; add CLI flag --agent-id (or --profile-agent) in src/cli/mod.rs and src/cli/commands/query.rs, defaulting to LLM agent if not provided.
  - Search Response Surface: add profile_context to SearchResponse in src/search/mod.rs and propagate through CLI JSON output in src/cli/commands/query.rs so the profile layer is inspectable.
  - CLI Profile Commands: implement docdex profile list|add|search|export|import in a new src/cli/commands/profile.rs; add bypasses evolution; search uses embeddings; export/import use JSON manifest with LWW; decide local‑only vs HTTP fallback and document behavior.
  - MCP Tools: register docdex_save_preference and docdex_get_profile in crates/mcp-server/src/lib.rs with schema + handlers; decide how repo scoping is handled for global profile tools (skip or allow default repo) and update tool discovery list.
  - Async Evolution Hook: wire docdex_save_preference and CLI “add via evolution” (if exposed) to spawn the evolution pipeline asynchronously and return immediately with status + request_id.
  - Tests + Contracts: add tests for header/body agent_id parsing, prompt order (profile before repo), profile budget truncation, CLI profile commands, and MCP tool registration/argument validation.

    - Work: define ProfileBudget (max_items, token_budget, recall_candidates); add ProfileContextAssembly + prune trace; wire into SearchResponse as profile_context.
  - Acceptance: types compile; SearchResponse serializes profile_context when present.

  2. Add profile context pruning helper

  - Files: src/profiles/ops.rs (new) or src/memory/ops.rs reuse
  - Work: implement prune_and_truncate_profile_context (same logic as memory pruning but separate types); include token estimates.
  - Acceptance: deterministic ordering + pruning with tests.

  3. Extend Waterfall request/result for Tier 0

  - Files: src/orchestrator/waterfall.rs
  - Work: add profile_state: Option<ProfileState> and profile_agent_id: Option<&str> to WaterfallRequest; add profile_context to WaterfallResult.
  - Acceptance: compiler passes; no callers broken.

  4. Implement Tier 0 retrieval in waterfall

  - Files: src/orchestrator/waterfall.rs
  - Work: before local search, if profile_state + profile_agent_id exist, embed query, search profile DB, prune by profile budget, add to profile_context; add DAG logs for recall.
  - Acceptance: Tier 0 logs appear; profile_context attached to result.

  5. Add profile budgets to chat context split

  - Files: src/api/v1/chat.rs
  - Work: update ChatContextBudgets to include profile_tokens; adjust chat_context_budgets to allocate 1000 tokens to profile (hard cap); ensure total budget remains consistent.
  - Acceptance: budgets reflect 1k profile tokens and existing totals still balance.

  6. Inject profile context into prompt (Hierarchy of Truth)

  - Files: src/api/v1/chat.rs
  - Work: update build_context_summary to add “Profile context” block before Memory/Repo blocks; update log_budget_drops to include profile drops; update format_compressed_results to include top profile snippets.
  - Acceptance: prompt order is System → Profile → Repo Memory → Repo Context; compressed output includes profile section.


  7. Parse agent_id from HTTP header + body

  - Files: src/api/v1/chat.rs
  - Work: read x-docdex-agent-id header and docdex.agent_id body; precedence: header > body; propagate into WaterfallRequest.profile_agent_id.
  - Acceptance: requests with header/body route to profile memory; default behavior unchanged.

  8. Add profile state to daemon AppState

  - Files: src/search/mod.rs, src/daemon.rs
  - Work: extend AppState with profile_state: Option<ProfileState> holding ProfileManager + embedder; initialize in daemon when profiles enabled.
  - Acceptance: daemon starts with profile enabled; no impact when disabled.

  9. Add CLI agent-id plumbing

  - Files: src/cli/mod.rs, src/cli/commands/query.rs
  - Work: add --agent-id (or --profile-agent-id) to query commands; pass into WaterfallRequest.profile_agent_id.
  - Acceptance: CLI supports --agent-id and results include profile_context.

  10. Add CLI profile command group

  - Files: src/cli/mod.rs, src/cli/commands/profile.rs (new)
  - Work: implement docdex profile list|add|search|export|import; add JSON outputs; decide local vs HTTP mode parity.
  - Acceptance: CLI subcommands available and produce JSON.

  11. Add HTTP endpoints for profile operations

  - Files: src/search/mod.rs or src/api/v1/profile.rs (new)
  - Work: add /v1/profile/list, /v1/profile/add, /v1/profile/search, /v1/profile/export, /v1/profile/import; wire to ProfileManager; enforce auth/rate limits like existing endpoints.
  - Acceptance: endpoints return expected JSON; errors follow existing error envelope patterns.

  12. Add MCP tools for profile memory

  - Files: crates/mcp-server/src/lib.rs
  - Work: register docdex_save_preference + docdex_get_profile definitions; add handlers using daemon HTTP or direct manager; add to tool list and validation.
  - Acceptance: MCP tool list includes new tools; handlers return structured results.

  13. Implement async evolution trigger (fire-and-forget)

  - Files: src/profiles/evolution.rs, src/search/mod.rs, src/cli/commands/profile.rs
  - Work: add a spawn path for evolution pipeline when saving preference; return request_id immediately.
  - Acceptance: save returns quickly; evolution runs in background with logs.

  14. Update compressed result envelope

  - Files: src/api/v1/chat.rs
  - Work: include profile in CompressedResults with max N items; add truncation rules.
  - Acceptance: compressed JSON includes profile section when available.

  15. Update tests for integration

  - Files: tests/ (new test files as needed)
  - Work: test agent_id header/body precedence; profile budget pruning; prompt order; CLI profile commands; MCP tool schema validation.
  - Acceptance: tests pass and cover the new integration surfaces.

────────────────────────────────────────────────────────────────────────────────────────────────────────────

• Phase 4 Plan (Advanced Features / “Perfect Tool” Suite)

  - Semantic Gatekeeper (Hook + Daemon Endpoint)
      - Add a pre-commit client (docdex hook pre-commit) that gathers staged paths and POSTs to /v1/hooks/validate.
      - Implement /v1/hooks/validate in daemon: load constraint preferences, run AST‑based checks (reuse symbols/AST stores), return pass|fail with specific messages; fail‑open if daemon unreachable.
      - Add policy mapping from preference category=constraint to checks (e.g., “no any types” → TS AST scan; “no circular deps” → impact graph cycle detection).
      - Cache AST/symbols and use repo state to keep latency <100ms.
  - Context-Aware Project Mapping (Heuristic Skeleton Tree)
      - Add ProjectMapBuilder that extracts keywords from agent role + preferences (tooling/style), queries repo index for top N paths, reconstructs a minimal tree, collapses the rest into “N hidden files.”
      - Cache maps in ~/.docdex/state/repos/<hash>/maps/<agent_id>.json; invalidate on directory create/delete events from watcher.
      - Inject map into prompt (after profile context, before repo matches) with a hard token cap (500 tokens).
  - Visual Impact Explorer (TUI overlay)
      - Extend the TUI view to render dependency graph nodes with profile constraints overlaid (e.g., “avoid circular deps” highlights cycles; “avoid moment.js” flags imports).
      - Use existing impact graph data, add a lightweight renderer with Unicode box‑drawing; add legend and filtering by constraint.
      - Add key bindings to toggle overlay and select constraints.
  - Swarm Sync (Export / Import / LWW)
      - Implement docdex profile export to generate profile_sync.json with preferences + timestamps.
      - Implement docdex profile import to merge by preference ID using last‑write‑wins; lock profile DB exclusively during import.
      - Add validation for schema version and embedding dimensions; report conflicts and counts.
  - Performance & Safety Gates
      - Enforce token caps for profile + project map; add logging for dropped items.
      - Ensure async evolution stays off the response path; gate new features behind config flags for gradual rollout.

  

    1. Add hook CLI command (client)

  - Files: src/cli/mod.rs, src/cli/commands/hook.rs (new)
  - Work: implement docdex hook pre-commit; collect staged files (git diff --cached --name-only), build payload, send to /v1/hooks/validate via local daemon; fail‑open if daemon unreachable.
  - Acceptance: hook prints warning on daemon missing and exits 0; on daemon response, exits 0/1 based on status.

  2. Add HTTP endpoint /v1/hooks/validate

  - Files: src/api/v1/hooks.rs (new), src/search/mod.rs
  - Work: define request/response schema; handler loads constraint preferences, runs validation checks, returns {status: "pass"|"fail", errors:[...]}.
  - Acceptance: endpoint is registered; returns JSON with stable shape.

  3. Implement constraint rule registry

  - Files: src/profiles/constraints.rs (new)
  - Work: map preference text/category to rule types (e.g., TS “no any”); include regex/keyword match to activate rules.
  - Acceptance: given preference text, registry returns correct rule(s).

  4. Implement AST-based constraint checks

  - Files: src/profiles/constraints.rs, src/symbols.rs/src/api/v1/ast.rs (reuse)
  - Work: add check to scan AST for forbidden patterns (e.g., any in TS); return per-file violations.
  - Acceptance: constraint violations are detected and reported with file + line.

  5. Implement impact-graph constraint checks

  - Files: src/impact.rs, src/profiles/constraints.rs
  - Work: use impact graph to detect cycles for “no circular deps”; return list of files involved.
  - Acceptance: cycle detection is triggered when constraint is present.

  6. Hook fail-open behavior

  - Files: src/cli/commands/hook.rs
  - Work: if HTTP request fails/timeout, print warning and exit 0.
  - Acceptance: hook never blocks commit when daemon is down.

  7. Project map builder (heuristic skeleton tree)

  - Files: src/project_map/mod.rs (new)
  - Work: extract keywords from agent role + tooling prefs; query index for top N paths; build collapsed tree; output JSON format.
  - Acceptance: map includes only top N paths + parent dirs; other dirs collapsed.

  
  8. Cache project maps + invalidation

  - Files: src/project_map/mod.rs, src/watcher.rs
  - Work: cache map at ~/.docdex/state/repos/<hash>/maps/<agent_id>.json; invalidate on directory create/delete events.
  - Acceptance: map reused across requests until invalidated.

  9. Inject project map into prompt

  - Files: src/api/v1/chat.rs
  - Work: add map context injection after profile context; enforce 500 token cap; include truncation log.
  - Acceptance: prompt includes “Project map” block when available.

  10. TUI graph overlay for constraints

  - Files: src/cli/commands/tui.rs or TUI crate files
  - Work: render dependency graph with constraint overlays; add legend and toggle keybinding.
  - Acceptance: TUI shows overlay when toggled; performance remains acceptable.

  11. Profile export implementation

  - Files: src/cli/commands/profile.rs, src/profiles/manager.rs
  - Work: export JSON manifest with agents + preferences + last_updated; ensure stable schema.
  - Acceptance: export writes valid JSON with counts.

  12. Profile import with LWW merge

  - Files: src/cli/commands/profile.rs, src/profiles/manager.rs
  - Work: import manifest, compare by preference ID; overwrite if incoming last_updated newer; lock DB exclusively during import.
  - Acceptance: import merges correctly; conflicting prefs resolved by timestamp.

  13. Validate sync manifest schema

  - Files: src/profiles/manager.rs
  - Work: check schema version + embedding_dim before import; reject mismatch with clear error.
  - Acceptance: invalid manifest fails fast with reason.

  14. Add config flags for advanced features

  - Files: src/config.rs
  - Work: add flags to enable/disable hook checks, project map, and TUI overlay; default to off.
  - Acceptance: features can be toggled via config/env.

  15. Integration tests for hook endpoint

  - Files: tests/ (new)
  - Work: test /v1/hooks/validate with a dummy constraint and a staged file fixture; ensure pass/fail.
  - Acceptance: hook endpoint returns deterministic results.

  16. Tests for export/import LWW

  - Files: tests/profile_sync.rs (new)
  - Work: import two manifests with different timestamps; assert newest wins.
  - Acceptance: LWW logic verified.

  ────────────────────────────────────────────────────────────────────────────────────────────────────────────


• Phase 5 Plan (Stabilization + Trust + Release Readiness)

  - Default Agent Selection (Daemon/Config/MCP)
      - Add --agent-id to docdexd serve and server.default_agent_id in config.
      - Use default agent when no header/body agent_id is supplied.
      - Align MCP initialize to accept and persist a default agent_id for tools.
  - Category-Specific Behavior Wiring
      - style: soft injection into prompt (advice tone, non-blocking).
      - constraint: strict enforcement via hook/gatekeeper (already planned, now fully wired).
      - tooling: seed project-map keyword heuristics (already partial, now formalized).
      - workflow: emit into “reasoning trace” and optional planning guidance.
  - Reasoning Trace Surface
      - Expose “Behavioral Truth” vs “Technical Truth” in response metadata and/or compressed output.
      - Add trace block to DAG logs and optional API field for inspection/debugging.
  - Unix Socket Support for Hook
      - Add optional Unix socket endpoint for /v1/hooks/validate.
      - Update hook client to prefer Unix socket if configured, fallback to HTTP.
  - Dynamic Token Budget Adjustment
      - Implement budget reallocation: if repo context < budget, reassign leftover to chat history (but profile cap fixed).
      - Ensure prompt assembly remains stable and auditable.
  - Docs + Contract Updates
      - Update docs/http_api.md for new headers/fields/endpoints.
      - Update CLI help + README for new flags/commands.
      - Update MCP tool descriptions for profile tools + hook behavior.
      - Document [memory.profile] config block and defaults.
  - Metrics/Observability
      - Add counters/timers for: profile recall latency, evolution decisions, hook checks, project map cache hits, profile budget drops.
      - Include log fields and optional Prometheus labels.


  1.   Add profile module scaffolding + domain types

  - Files: src/profiles/mod.rs, src/lib.rs
  - Work: create module; define Agent, Preference, PreferenceCategory, ProfileMeta structs/enums; expose via pub use; register module in src/lib.rs.
  - Acceptance: crate compiles; types are usable by other modules.

  2. Add config default for agent id

  - Files: src/config.rs
  - Work: add server.default_agent_id field with default empty; load/apply defaults.
  - Acceptance: config serializes/deserializes and shows field in config.toml.

  3. Wire default agent into AppState

  - Files: src/daemon.rs, src/search/mod.rs
  - Work: store default_agent_id in AppState and use it when no header/body agent is provided.
  - Acceptance: requests without agent_id use default.

  4. MCP initialize default agent alignment

  - Files: crates/mcp-server/src/lib.rs
  - Work: add optional agent_id in initialize params; store default_agent_id and use it when profile tools are called without explicit agent_id.
  - Acceptance: MCP tools use default agent after initialize.

  5. Style category wiring (soft prompt injection)

  - Files: src/api/v1/chat.rs, src/profiles/ops.rs
  - Work: when building prompt, add “Style preferences” block (advice tone) from profile_context with category=style.
  - Acceptance: style preferences appear as non-blocking guidance.

  6. Workflow category wiring (reasoning/planning guidance)

  - Files: src/api/v1/chat.rs
  - Work: add “Workflow preferences” block into reasoning trace metadata (not in main prompt unless enabled); include in compressed output when compress_results.
  - Acceptance: workflow preferences surfaced in trace/metadata.

  7. Reasoning Trace surface (API + DAG)

  - Files: src/api/v1/chat.rs, src/dag/logging.rs
  - Work: add reasoning_trace in response meta with behavioral_truth and technical_truth sections; log to DAG.
  - Acceptance: response includes trace fields; DAG logs show separation.

  8. Unix socket support for hook endpoint

  - Files: src/daemon.rs, src/api/v1/hooks.rs, src/cli/commands/hook.rs
  - Work: add optional Unix socket bind for /v1/hooks/validate; hook client prefers socket if configured.
  - Acceptance: hook works via Unix socket; fallback to HTTP if missing.

  
  9. Dynamic token budget reallocation

  - Files: src/api/v1/chat.rs
  - Work: adjust budgeting logic to reallocate unused repo tokens to chat history while keeping profile cap fixed.
  - Acceptance: prompt assembly uses extra history when repo context is small.

  10. Update HTTP API docs

  - Files: docs/http_api.md
  - Work: document x-docdex-agent-id, docdex.agent_id, profile endpoints, hook endpoint, and reasoning_trace fields.
  - Acceptance: docs reflect new interfaces.

  11. Update CLI help + README

  - Files: README.md, src/cli/mod.rs (help strings)
  - Work: document docdex profile, docdex hook pre-commit, and --agent-id.
  - Acceptance: README and --help reflect new commands.

  12. Update MCP tool documentation

  - Files: MCP README/docs if present
  - Work: add docdex_save_preference, docdex_get_profile, and default agent behavior.
  - Acceptance: docs updated with schemas + usage.

  13. Add config docs for [memory.profile]

  - Files: docs/http_api.md or config doc section
  - Work: document memory.profile.embedding_model + embedding_dim and defaults.
  - Acceptance: config docs include new block.

  14. Metrics: profile recall + evolution decisions

  - Files: src/metrics.rs, src/profiles/evolution.rs, src/orchestrator/waterfall.rs
  - Work: add counters/timers and increment for profile recall and evolution actions.
  - Acceptance: metrics exposed via /metrics.

  15. Metrics: hook checks + map cache hits + budget drops

  - Files: src/metrics.rs, src/api/v1/hooks.rs, src/project_map/mod.rs, src/api/v1/chat.rs
  - Work: add counters for hook runs, failures, cache hits, and dropped profile items.
  - Acceptance: metrics increment in relevant paths.

  16. Integration tests for defaults + trace

  - Files: tests/ (new)
  - Work: test default agent selection; test reasoning_trace presence; test Unix socket hook if feasible.
  - Acceptance: tests pass and validate new behavior.