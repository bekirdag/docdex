# Docdev v2.1 Detailed Tasks

## Phase 1 - Storage Infrastructure

### P1-T1: Add profile module scaffolding + domain types
- Subtask P1-T1.1: Create `src/profiles/mod.rs` module skeleton and public reexports.
  - Files: `src/profiles/mod.rs`
  - System: profile module entry point mirroring `src/memory/mod.rs`.
  - Acceptance: module compiles and can be imported as `crate::profiles`.
- Subtask P1-T1.2: Define `Agent`, `Preference`, `PreferenceCategory`, and `ProfileMeta` types with fields aligned to SDS schema.
  - Files: `src/profiles/mod.rs`
  - System: domain model types for profile DB rows and metadata.
  - Acceptance: structs/enums match SDS field names and compile with derives needed for DB/serde usage.
- Subtask P1-T1.3: Register the profiles module in `src/lib.rs`.
  - Files: `src/lib.rs`
  - System: crate module registry includes `pub mod profiles`.
  - Acceptance: `cargo check` succeeds with module visible.

### P1-T2: Add global profile paths to state layout
- Subtask P1-T2.1: Add `profiles_dir()` and `profiles_sync_dir()` helpers to `StateLayout`.
  - Files: `src/state_layout.rs`
  - System: state layout exposes `profiles/` and `profiles/sync/` paths under state base.
  - Acceptance: helper methods return expected paths under `~/.docdex/state`.
- Subtask P1-T2.2: Ensure global state initialization creates `profiles/` and `profiles/sync/`.
  - Files: `src/state_layout.rs`
  - System: state directory initialization includes profile directories.
  - Acceptance: `ensure_global_dirs()` creates both directories without errors.
- Subtask P1-T2.3: Surface profile paths in `StatePathsDebug` for diagnostics.
  - Files: `src/state_layout.rs`
  - System: debug report includes profile directory paths for check tooling.
  - Acceptance: `StatePathsDebug` contains `profiles_dir` and `profiles_sync_dir` fields.

### P1-T3: Implement profile DB schema + sqlite-vec setup
- Subtask P1-T3.1: Implement profile DB open and WAL mode initialization.
  - Files: `src/profiles/db.rs`
  - System: SQLite connection setup with WAL for profile DB.
  - Acceptance: `profile_db::init()` enables WAL and opens DB without errors.
- Subtask P1-T3.2: Create schema for `agents`, `preferences`, and `profile_meta` tables.
  - Files: `src/profiles/db.rs`
  - System: relational tables for agents and preferences with timestamps and category.
  - Acceptance: schema exists and can be queried via sqlite.
- Subtask P1-T3.3: Create `preferences_vec` vec0 table and backfill from `preferences`.
  - Files: `src/profiles/db.rs`
  - System: vector index for semantic search using sqlite-vec.
  - Acceptance: vec table created and populated for existing rows.
- Subtask P1-T3.4: Persist and validate `embedding_dim` and `schema_version`.
  - Files: `src/profiles/db.rs`
  - System: profile DB metadata for dimension and schema upgrades.
  - Acceptance: dimension mismatch returns a clear error; schema version is stored.

### P1-T4: Implement seeding of default profiles/preferences
- Subtask P1-T4.1: Create `src/profiles/defaults.json` with baseline agents and preferences.
  - Files: `src/profiles/defaults.json`
  - System: seed manifest embedded into the binary.
  - Acceptance: JSON validates and covers required agent + preference fields.
- Subtask P1-T4.2: Add seed loader that parses embedded JSON into DB rows.
  - Files: `src/profiles/db.rs`
  - System: seed import routine invoked by `profile_db::init()`.
  - Acceptance: seeds inserted in a single transaction with timestamps set.
- Subtask P1-T4.3: Enforce seed idempotency when `agents` table is non-empty.
  - Files: `src/profiles/db.rs`
  - System: seed only runs on empty DB.
  - Acceptance: repeated init does not create duplicate rows.

### P1-T5: Build ProfileManager with SWMR gating
- Subtask P1-T5.1: Implement ProfileManager struct with RW lock and file lock path.
  - Files: `src/profiles/manager.rs`
  - System: SWMR gate for concurrent profile access.
  - Acceptance: read and write locks compile and are used internally.
- Subtask P1-T5.2: Add CRUD methods for agents and preferences (create_agent, get_agent, list_agents, add_preference).
  - Files: `src/profiles/manager.rs`
  - System: high-level DB accessors for profile operations.
  - Acceptance: methods compile and perform expected SQL mutations.
- Subtask P1-T5.3: Add vector search method `search_preferences` on preferences_vec.
  - Files: `src/profiles/manager.rs`
  - System: semantic search query for profile constraints.
  - Acceptance: query returns ordered results with score/distance.

### P1-T6: Add [memory.profile] config block
- Subtask P1-T6.1: Introduce `MemoryProfileConfig` struct with `embedding_model` and `embedding_dim`.
  - Files: `src/config.rs`
  - System: configuration surface for profile embeddings.
  - Acceptance: config loads and serializes with new fields.
- Subtask P1-T6.2: Extend `AppConfig` defaults and apply_defaults for profile settings.
  - Files: `src/config.rs`
  - System: default profile embedding config derived at startup.
  - Acceptance: config auto-fills defaults when missing.
- Subtask P1-T6.3: Add validation for profile embedding settings (non-empty model, dim > 0).
  - Files: `src/config.rs`
  - System: config validation errors for invalid profile embedding config.
  - Acceptance: invalid settings produce clear errors or warnings.

### P1-T7: Wire profile manager into daemon app state
- Subtask P1-T7.1: Add `ProfileState` and include in `AppState`.
  - Files: `src/search/mod.rs`
  - System: runtime state container for profile manager and embedder.
  - Acceptance: `AppState` compiles with optional profile state.
- Subtask P1-T7.2: Initialize ProfileManager on daemon startup using global state dir.
  - Files: `src/daemon.rs`
  - System: profile manager lifecycle bound to daemon lifecycle.
  - Acceptance: daemon starts with profile manager available when enabled.
- Subtask P1-T7.3: Plumb profile embedder config into daemon initialization.
  - Files: `src/daemon.rs`, `src/config.rs`
  - System: profile embedder uses `[memory.profile]` config values.
  - Acceptance: profile embedder configuration is consistent with config defaults.

### P1-T8: Add profile DB checks to docdexd check
- Subtask P1-T8.1: Add `profile_db` check entry and status output.
  - Files: `src/cli/commands/check.rs`
  - System: health check for global profile DB.
  - Acceptance: `docdexd check` reports `profile_db` status.
- Subtask P1-T8.2: Implement writable check using scratch dir and `ProfileManager` init.
  - Files: `src/cli/commands/check.rs`
  - System: profile DB RW validation with sqlite-vec schema creation.
  - Acceptance: writable checks succeed on valid state dirs.

### P1-T9: Add tests for profile DB + seed logic
- Subtask P1-T9.1: Unit test schema creation and schema_version persistence.
  - Files: `src/profiles/db.rs` (tests)
  - System: DB schema correctness validation.
  - Acceptance: test verifies tables and metadata keys exist.
- Subtask P1-T9.2: Unit test embedding_dim mismatch errors.
  - Files: `src/profiles/db.rs` (tests)
  - System: dimension mismatch guardrail.
  - Acceptance: test fails on mismatched dimension as expected.
- Subtask P1-T9.3: Unit test seed idempotency with repeated init.
  - Files: `src/profiles/db.rs` (tests)
  - System: seed data inserted once.
  - Acceptance: repeated init does not change row counts.
- Subtask P1-T9.4: Integration test for profiles dir creation under state root.
  - Files: `tests/profile_state_layout.rs` (new)
  - System: state layout creates `profiles/` and `profiles/sync/`.
  - Acceptance: test verifies directories are created in temp state root.

## Phase 2 - Evolution Logic

### P2-T1: Add profile embedding wrapper with dimension enforcement
- Subtask P2-T1.1: Create `ProfileEmbedder` wrapper that delegates to `OllamaEmbedder`.
  - Files: `src/profiles/embedder.rs`, `src/profiles/mod.rs`
  - System: profile embedding client with consistent interface.
  - Acceptance: wrapper compiles and can embed text via Ollama.
- Subtask P2-T1.2: Enforce expected embedding dimension and return explicit error on mismatch.
  - Files: `src/profiles/embedder.rs`
  - System: dimension guard for profile embeddings.
  - Acceptance: mismatch returns error and does not write to DB.
- Subtask P2-T1.3: Expose provider/model metadata for logging and memory metadata.
  - Files: `src/profiles/embedder.rs`
  - System: embedder metadata for traceability.
  - Acceptance: provider/model strings are accessible for logs.

### P2-T2: Define evolution core types
- Subtask P2-T2.1: Add `EvolutionAction` enum and `EvolutionDecision` struct.
  - Files: `src/profiles/evolution.rs`
  - System: core decision model aligned with SDS schema.
  - Acceptance: JSON parsing into `EvolutionDecision` works.
- Subtask P2-T2.2: Add `EvolutionOutcome` struct for applied results.
  - Files: `src/profiles/evolution.rs`
  - System: output contract for evolution pipeline results.
  - Acceptance: outcome captures action, preference id, and reasoning.
- Subtask P2-T2.3: Add validation helper for decision fields.
  - Files: `src/profiles/evolution.rs`
  - System: decision validation utility for required fields.
  - Acceptance: invalid decisions return structured errors.

### P2-T3: Build EvolutionEngine skeleton
- Subtask P2-T3.1: Implement `EvolutionEngine` struct with injected dependencies.
  - Files: `src/profiles/evolution.rs`
  - System: evolution pipeline container.
  - Acceptance: engine can be constructed with manager, embedder, LLM client.
- Subtask P2-T3.2: Add configuration fields (timeouts, retries, recall_k).
  - Files: `src/profiles/evolution.rs`
  - System: configurable evolution behavior.
  - Acceptance: defaults are set and configurable in tests.

### P2-T4: Implement recall step for evolution
- Subtask P2-T4.1: Add `search_preferences_for_evolution` method returning id/content/last_updated.
  - Files: `src/profiles/manager.rs`
  - System: evolution recall query API.
  - Acceptance: method returns required fields and supports top_k.
- Subtask P2-T4.2: Order recall results by distance asc, then last_updated desc.
  - Files: `src/profiles/manager.rs`
  - System: deterministic recall ordering.
  - Acceptance: ordering stable across runs.
- Subtask P2-T4.3: Add unit test for recall ordering with mocked rows.
  - Files: `src/profiles/manager.rs` (tests)
  - System: recall ordering verification.
  - Acceptance: test enforces distance then recency ordering.

### P2-T5: Implement evolution prompt builder
- Subtask P2-T5.1: Implement prompt template with strict JSON response contract.
  - Files: `src/profiles/evolution.rs`
  - System: prompt assembly for LLM decision.
  - Acceptance: prompt includes rules and JSON-only instruction.
- Subtask P2-T5.2: Add recency calculation from `last_updated` timestamps.
  - Files: `src/profiles/evolution.rs`
  - System: human-readable recency strings in prompt.
  - Acceptance: recency strings use days/hours as specified.
- Subtask P2-T5.3: Add snapshot test for prompt output.
  - Files: `src/profiles/evolution.rs` (tests)
  - System: prompt stability guard.
  - Acceptance: snapshot includes memory list and JSON schema instructions.

### P2-T6: Implement LLM decision call + strict JSON parsing
- Subtask P2-T6.1: Call `LlmClient::generate()` with bounded timeout and token cap.
  - Files: `src/profiles/evolution.rs`
  - System: LLM decision execution.
  - Acceptance: call returns raw text within configured timeout.
- Subtask P2-T6.2: Strip code fences and extract JSON from LLM output.
  - Files: `src/profiles/evolution.rs`
  - System: robust JSON extraction.
  - Acceptance: parser handles fenced and unfenced JSON.
- Subtask P2-T6.3: Parse JSON into `EvolutionDecision` and validate fields.
  - Files: `src/profiles/evolution.rs`
  - System: strict decision parsing.
  - Acceptance: invalid JSON returns validation errors.

### P2-T7: Add retry + default IGNORE behavior
- Subtask P2-T7.1: Implement retry loop for invalid JSON/validation failures.
  - Files: `src/profiles/evolution.rs`
  - System: decision retry control flow.
  - Acceptance: retries up to configured limit.
- Subtask P2-T7.2: Default to IGNORE after retries exhausted.
  - Files: `src/profiles/evolution.rs`
  - System: safe fallback behavior.
  - Acceptance: evolution returns IGNORE without DB writes.

### P2-T8: Implement APPLY for ADD
- Subtask P2-T8.1: Re-embed `new_content` and insert into preferences table.
  - Files: `src/profiles/evolution.rs`, `src/profiles/manager.rs`
  - System: add preference mutation.
  - Acceptance: new row created with updated timestamp.
- Subtask P2-T8.2: Insert into `preferences_vec` with the new embedding.
  - Files: `src/profiles/manager.rs`
  - System: vector index insert for new preference.
  - Acceptance: vec table includes new row with correct rowid.

### P2-T9: Implement APPLY for UPDATE
- Subtask P2-T9.1: Validate target preference id exists in recall set.
  - Files: `src/profiles/evolution.rs`
  - System: guard against invalid updates.
  - Acceptance: invalid id returns error or IGNORE.
- Subtask P2-T9.2: Update `preferences` content and `last_updated`.
  - Files: `src/profiles/manager.rs`
  - System: update mutation for preference rows.
  - Acceptance: content changes and timestamp updates.
- Subtask P2-T9.3: Update `preferences_vec` for the target row.
  - Files: `src/profiles/manager.rs`
  - System: vector index update.
  - Acceptance: vector embedding updated for target id.

### P2-T10: Implement IGNORE path + reasoning capture
- Subtask P2-T10.1: Return `EvolutionOutcome` with IGNORE and reasoning.
  - Files: `src/profiles/evolution.rs`
  - System: no-op decision handling.
  - Acceptance: no DB writes; outcome includes reasoning string.

### P2-T11: Add logging hooks for evolution outcomes
- Subtask P2-T11.1: Add structured logs with action, agent_id, preference_id, latency.
  - Files: `src/profiles/evolution.rs`
  - System: evolution telemetry logs.
  - Acceptance: logs emitted on ADD/UPDATE/IGNORE.
- Subtask P2-T11.2: Add counters for invalid JSON and retries (stub if needed).
  - Files: `src/metrics.rs`, `src/profiles/evolution.rs`
  - System: evolution metrics placeholders.
  - Acceptance: counters increment on retry/parse failure.

### P2-T12: Unit tests for evolution decision flow
- Subtask P2-T12.1: Add stub LLM client returning ADD decision JSON.
  - Files: `src/profiles/evolution.rs` (tests)
  - System: test harness for evolution engine.
  - Acceptance: test verifies ADD inserts preference.
- Subtask P2-T12.2: Add tests for UPDATE and IGNORE paths.
  - Files: `src/profiles/evolution.rs` (tests)
  - System: decision outcomes verification.
  - Acceptance: update modifies rows; ignore leaves DB unchanged.
- Subtask P2-T12.3: Add test for invalid JSON leading to IGNORE after retries.
  - Files: `src/profiles/evolution.rs` (tests)
  - System: retry fallback validation.
  - Acceptance: outcome is IGNORE and no DB writes.

### P2-T13: Unit tests for embedder dimension check
- Subtask P2-T13.1: Add test for mismatch dimension error.
  - Files: `src/profiles/embedder.rs` (tests)
  - System: embedder guardrail validation.
  - Acceptance: mismatch returns explicit error.
- Subtask P2-T13.2: Add test for correct dimension pass-through.
  - Files: `src/profiles/embedder.rs` (tests)
  - System: successful embedding scenario.
  - Acceptance: correct dimension returns vector without error.

### P2-T14: Unit tests for DB update behaviors
- Subtask P2-T14.1: Verify ADD inserts preference and vector rows.
  - Files: `src/profiles/manager.rs` (tests)
  - System: add mutation correctness.
  - Acceptance: row counts increase by one.
- Subtask P2-T14.2: Verify UPDATE overwrites content and vector data.
  - Files: `src/profiles/manager.rs` (tests)
  - System: update mutation correctness.
  - Acceptance: content changes and vector row updates.
- Subtask P2-T14.3: Verify last_updated is monotonic on updates.
  - Files: `src/profiles/manager.rs` (tests)
  - System: timestamp update validation.
  - Acceptance: last_updated increases after update.

## Phase 3 - Integration and Tooling

### P3-T1: Add profile budget + context assembly types
- Subtask P3-T1.1: Introduce `ProfileBudget` struct in orchestrator budget module.
  - Files: `src/orchestrator/budget.rs`
  - System: profile token budget settings for Tier 0 retrieval.
  - Acceptance: `ProfileBudget` can be constructed and has defaults.
- Subtask P3-T1.2: Add `ProfileContextAssembly` and prune trace types.
  - Files: `src/orchestrator/waterfall.rs`
  - System: profile context structure for downstream assembly.
  - Acceptance: types compile and are serializable.
- Subtask P3-T1.3: Add `profile_context` to `SearchResponse`.
  - Files: `src/search/mod.rs`
  - System: API surface includes profile context in responses.
  - Acceptance: JSON includes `profileContext` when present.

### P3-T2: Add profile context pruning helper
- Subtask P3-T2.1: Implement `prune_and_truncate_profile_context` with score ordering.
  - Files: `src/profiles/ops.rs` (new)
  - System: token-budgeted pruning for profile preferences.
  - Acceptance: pruning is deterministic and token-based.
- Subtask P3-T2.2: Add token estimate and truncation logic for profile items.
  - Files: `src/profiles/ops.rs`
  - System: token limit enforcement for preferences.
  - Acceptance: truncated items record `truncated=true` and token usage.
- Subtask P3-T2.3: Add unit tests for pruning and truncation.
  - Files: `src/profiles/ops.rs` (tests)
  - System: pruning correctness validation.
  - Acceptance: tests cover ordering and budget exhaustion.

### P3-T3: Extend Waterfall request/result for Tier 0
- Subtask P3-T3.1: Add `profile_state` and `profile_agent_id` to `WaterfallRequest`.
  - Files: `src/orchestrator/waterfall.rs`
  - System: waterfall input supports profile retrieval.
  - Acceptance: new fields compile and are optional.
- Subtask P3-T3.2: Add `profile_context` to `WaterfallResult`.
  - Files: `src/orchestrator/waterfall.rs`
  - System: waterfall output includes profile context.
  - Acceptance: result struct includes optional profile context.
- Subtask P3-T3.3: Update callers to populate profile fields when available.
  - Files: `src/api/v1/chat.rs`, `src/cli/commands/query.rs`
  - System: profile fields passed into waterfall execution.
  - Acceptance: compile errors resolved and profile fields used.

### P3-T4: Implement Tier 0 retrieval in waterfall
- Subtask P3-T4.1: Embed query with profile embedder when profile_state exists.
  - Files: `src/orchestrator/waterfall.rs`
  - System: Tier 0 embedding for profile search.
  - Acceptance: embedding called before local search when enabled.
- Subtask P3-T4.2: Search profile DB and prune results to profile budget.
  - Files: `src/orchestrator/waterfall.rs`, `src/profiles/ops.rs`
  - System: Tier 0 retrieval and pruning pipeline.
  - Acceptance: profile_context attached with prune trace.
- Subtask P3-T4.3: Add DAG logs for Tier 0 recall and pruning stats.
  - Files: `src/orchestrator/waterfall.rs`, `src/dag/logging.rs`
  - System: observability for Tier 0 retrieval.
  - Acceptance: logs include candidates, kept, dropped, and latency.

### P3-T5: Add profile budgets to chat context split
- Subtask P3-T5.1: Extend `ChatContextBudgets` to include `profile_tokens`.
  - Files: `src/api/v1/chat.rs`
  - System: explicit profile allocation in prompt budgeting.
  - Acceptance: struct includes profile budget field.
- Subtask P3-T5.2: Allocate a fixed 1000-token cap for profile context.
  - Files: `src/api/v1/chat.rs`
  - System: profile budget enforced regardless of total size.
  - Acceptance: budget calc reflects 1000 token cap.
- Subtask P3-T5.3: Adjust budget balancing to keep total consistent.
  - Files: `src/api/v1/chat.rs`
  - System: budget distribution stays within total limit.
  - Acceptance: no negative budgets or overflow.

### P3-T6: Inject profile context into prompt (Hierarchy of Truth)
- Subtask P3-T6.1: Add profile block to `build_context_summary` ahead of repo memory.
  - Files: `src/api/v1/chat.rs`
  - System: prompt ordering follows profile then repo context.
  - Acceptance: prompt order is System -> Profile -> Memory -> Repo.
- Subtask P3-T6.2: Update `log_budget_drops` to include profile drops.
  - Files: `src/api/v1/chat.rs`
  - System: profile pruning logged alongside other budgets.
  - Acceptance: log includes profile_dropped and profile_budget_tokens.
- Subtask P3-T6.3: Update compressed results to include profile snippets.
  - Files: `src/api/v1/chat.rs`
  - System: compressed response includes profile summary.
  - Acceptance: compressed JSON includes profile section when present.

### P3-T7: Parse agent_id from HTTP header + body
- Subtask P3-T7.1: Add header extraction for `x-docdex-agent-id`.
  - Files: `src/api/v1/chat.rs`
  - System: agent id resolved from HTTP header.
  - Acceptance: header value is parsed and trimmed.
- Subtask P3-T7.2: Add body extraction for `docdex.agent_id`.
  - Files: `src/api/v1/chat.rs`
  - System: agent id resolved from request payload.
  - Acceptance: body value parsed when present.
- Subtask P3-T7.3: Enforce precedence: header overrides body.
  - Files: `src/api/v1/chat.rs`
  - System: deterministic agent id resolution.
  - Acceptance: header takes priority when both provided.

### P3-T8: Add profile state to daemon AppState
- Subtask P3-T8.1: Define `ProfileState` with manager and embedder.
  - Files: `src/search/mod.rs`
  - System: runtime container for profile operations.
  - Acceptance: profile state is optional and clonable.
- Subtask P3-T8.2: Initialize profile state in daemon when enabled.
  - Files: `src/daemon.rs`
  - System: profile state bootstrapped on startup.
  - Acceptance: daemon starts with profile state in AppState.

### P3-T9: Add CLI agent-id plumbing
- Subtask P3-T9.1: Add `--agent-id` flag to query CLI.
  - Files: `src/cli/mod.rs`
  - System: CLI accepts profile agent id for queries.
  - Acceptance: `docdex query --agent-id` is recognized.
- Subtask P3-T9.2: Pass CLI agent id into WaterfallRequest.
  - Files: `src/cli/commands/query.rs`
  - System: profile agent id reaches waterfall execution.
  - Acceptance: profile_context populated when agent id is set.

### P3-T10: Add CLI profile command group
- Subtask P3-T10.1: Add `profile` subcommand with list/add/search/export/import.
  - Files: `src/cli/mod.rs`
  - System: CLI command surface for profile management.
  - Acceptance: `docdex profile --help` lists subcommands.
- Subtask P3-T10.2: Implement list/add/search commands in `profile.rs`.
  - Files: `src/cli/commands/profile.rs`
  - System: local CLI operations for profile CRUD.
  - Acceptance: commands return JSON output.
- Subtask P3-T10.3: Implement export/import commands with file IO.
  - Files: `src/cli/commands/profile.rs`
  - System: swarm sync CLI operations.
  - Acceptance: export writes JSON; import reads and merges.

### P3-T11: Add HTTP endpoints for profile operations
- Subtask P3-T11.1: Add routes for `/v1/profile/list`, `/v1/profile/add`, `/v1/profile/search`.
  - Files: `src/search/mod.rs`
  - System: API endpoints for profile management.
  - Acceptance: endpoints return JSON with proper status codes.
- Subtask P3-T11.2: Add routes for `/v1/profile/export` and `/v1/profile/import`.
  - Files: `src/search/mod.rs`, `src/api/v1/profile.rs` (new)
  - System: HTTP surface for swarm sync.
  - Acceptance: export/import endpoints work with JSON manifests.
- Subtask P3-T11.3: Apply auth/rate limits consistent with existing APIs.
  - Files: `src/search/mod.rs`, `src/api/v1/profile.rs`
  - System: security policy enforcement for profile endpoints.
  - Acceptance: unauthorized requests are rejected consistently.

### P3-T12: Add MCP tools for profile memory
- Subtask P3-T12.1: Define tool schemas for `docdex_save_preference` and `docdex_get_profile`.
  - Files: `crates/mcp-server/src/lib.rs`
  - System: MCP tool schema definitions.
  - Acceptance: tools appear in MCP capabilities list.
- Subtask P3-T12.2: Implement handlers that call profile HTTP endpoints.
  - Files: `crates/mcp-server/src/lib.rs`
  - System: MCP tool handlers wired to daemon.
  - Acceptance: handlers return structured JSON results.
- Subtask P3-T12.3: Decide and enforce repo scoping behavior for profile tools.
  - Files: `crates/mcp-server/src/lib.rs`
  - System: consistent policy for global profile tools.
  - Acceptance: tools run with default repo or bypass repo gate per spec.

### P3-T13: Implement async evolution trigger (fire-and-forget)
- Subtask P3-T13.1: Add async spawn path for evolution pipeline on save.
  - Files: `src/profiles/evolution.rs`, `src/search/mod.rs`
  - System: non-blocking evolution writes.
  - Acceptance: API returns immediately with request id.
- Subtask P3-T13.2: Log background evolution execution status.
  - Files: `src/profiles/evolution.rs`
  - System: evolution background logs for visibility.
  - Acceptance: logs include request id and action outcome.

### P3-T14: Update compressed result envelope
- Subtask P3-T14.1: Add `profile` section to compressed response structs.
  - Files: `src/api/v1/chat.rs`
  - System: compressed API includes profile summaries.
  - Acceptance: compressed JSON includes profile section when available.
- Subtask P3-T14.2: Enforce max items and truncation rules for profile snippets.
  - Files: `src/api/v1/chat.rs`
  - System: compressed profile output respects size caps.
  - Acceptance: output limited to configured max items.

### P3-T15: Update tests for integration
- Subtask P3-T15.1: Test agent_id header/body precedence.
  - Files: `tests/profile_agent_header.rs` (new)
  - System: HTTP agent id selection behavior.
  - Acceptance: header overrides body in tests.
- Subtask P3-T15.2: Test profile budget pruning and prompt order.
  - Files: `tests/profile_prompt_order.rs` (new)
  - System: profile context ordering enforcement.
  - Acceptance: tests assert profile block precedes repo context.
- Subtask P3-T15.3: Test MCP tool registration and argument validation.
  - Files: `tests/mcp_profile_tools.rs` (new)
  - System: MCP tool schema correctness.
  - Acceptance: tool schemas validate and handlers respond.

## Phase 4 - Advanced Features

### P4-T1: Add hook CLI command (client)
- Subtask P4-T1.1: Add `hook` subcommand with `pre-commit` action.
  - Files: `src/cli/mod.rs`
  - System: CLI entry for semantic gatekeeper hook.
  - Acceptance: `docdex hook pre-commit --help` is available.
- Subtask P4-T1.2: Collect staged file paths using `git diff --cached --name-only`.
  - Files: `src/cli/commands/hook.rs`
  - System: staged file collector for hook payload.
  - Acceptance: non-empty payload when staged files exist.
- Subtask P4-T1.3: Send JSON payload to `/v1/hooks/validate` with timeout.
  - Files: `src/cli/commands/hook.rs`
  - System: hook client HTTP request to daemon.
  - Acceptance: hook returns pass/fail based on response status.

### P4-T2: Add HTTP endpoint `/v1/hooks/validate`
- Subtask P4-T2.1: Define request/response structs for hook validation.
  - Files: `src/api/v1/hooks.rs` (new)
  - System: HTTP contract for hook validation.
  - Acceptance: request/response JSON matches spec.
- Subtask P4-T2.2: Register hook endpoint in router.
  - Files: `src/search/mod.rs`
  - System: hook endpoint accessible via daemon.
  - Acceptance: route is active under `/v1/hooks/validate`.
- Subtask P4-T2.3: Implement handler to load constraint prefs and run checks.
  - Files: `src/api/v1/hooks.rs`
  - System: gatekeeper validation logic.
  - Acceptance: handler returns pass or fail with errors.

### P4-T3: Implement constraint rule registry
- Subtask P4-T3.1: Define constraint rule enum and registry mapping.
  - Files: `src/profiles/constraints.rs`
  - System: constraint rules catalog.
  - Acceptance: registry maps preference text to rules.
- Subtask P4-T3.2: Add keyword/regex matchers for rule activation.
  - Files: `src/profiles/constraints.rs`
  - System: constraint matching logic.
  - Acceptance: matching returns expected rule for sample text.
- Subtask P4-T3.3: Add unit tests for rule matching.
  - Files: `src/profiles/constraints.rs` (tests)
  - System: rule activation validation.
  - Acceptance: tests cover style/tooling vs constraint matches.

### P4-T4: Implement AST-based constraint checks
- Subtask P4-T4.1: Implement TS any-type detection using AST nodes.
  - Files: `src/profiles/constraints.rs`, `src/api/v1/ast.rs`
  - System: AST constraint checker for forbidden constructs.
  - Acceptance: detects `any` usage in TS files.
- Subtask P4-T4.2: Map AST violations to hook error format.
  - Files: `src/api/v1/hooks.rs`
  - System: violation formatting with file and line details.
  - Acceptance: response includes file + line for violations.

### P4-T5: Implement impact-graph constraint checks
- Subtask P4-T5.1: Add cycle detection using impact graph data.
  - Files: `src/impact.rs`, `src/profiles/constraints.rs`
  - System: cycle detection for dependency constraints.
  - Acceptance: cycles detected in synthetic graph fixtures.
- Subtask P4-T5.2: Convert cycle results to hook violation errors.
  - Files: `src/api/v1/hooks.rs`
  - System: hook error formatting for cycles.
  - Acceptance: hook response lists files in cycle.

### P4-T6: Hook fail-open behavior
- Subtask P4-T6.1: Treat connection errors as warnings and exit 0.
  - Files: `src/cli/commands/hook.rs`
  - System: fail-open semantics for hook client.
  - Acceptance: hook does not block commit on daemon failure.
- Subtask P4-T6.2: Add explicit warning message on fail-open path.
  - Files: `src/cli/commands/hook.rs`
  - System: user-facing hook warning.
  - Acceptance: warning printed on timeout/connection failure.

### P4-T7: Project map builder (heuristic skeleton tree)
- Subtask P4-T7.1: Extract keywords from agent role and tooling prefs.
  - Files: `src/project_map/mod.rs`
  - System: keyword source for project map queries.
  - Acceptance: keyword list is non-empty for seeded profiles.
- Subtask P4-T7.2: Query index for top N paths and build minimal tree.
  - Files: `src/project_map/mod.rs`
  - System: heuristic directory tree builder.
  - Acceptance: tree includes only top N paths and parents.
- Subtask P4-T7.3: Collapse non-selected directories into hidden node count.
  - Files: `src/project_map/mod.rs`
  - System: compact map output format.
  - Acceptance: output includes hidden count placeholders.

### P4-T8: Cache project maps + invalidation
- Subtask P4-T8.1: Implement cache read/write to `maps/<agent_id>.json`.
  - Files: `src/project_map/mod.rs`
  - System: cached project map storage.
  - Acceptance: cache hit returns map without rebuild.
- Subtask P4-T8.2: Add cache invalidation on directory create/delete events.
  - Files: `src/watcher.rs`
  - System: map cache invalidation trigger.
  - Acceptance: cache cleared on directory changes.

### P4-T9: Inject project map into prompt
- Subtask P4-T9.1: Load cached map and inject into prompt after profile context.
  - Files: `src/api/v1/chat.rs`
  - System: project map prompt integration.
  - Acceptance: prompt includes map section when available.
- Subtask P4-T9.2: Enforce 500-token cap for map context.
  - Files: `src/api/v1/chat.rs`
  - System: map token budget enforcement.
  - Acceptance: map is truncated to cap with logs.

### P4-T10: TUI graph overlay for constraints
- Subtask P4-T10.1: Add overlay data model for constraint highlights.
  - Files: TUI crate files (as used by `docdexd tui`)
  - System: representation of constraint overlay state.
  - Acceptance: overlay model compiles with TUI.
- Subtask P4-T10.2: Render dependency graph with overlay markers.
  - Files: TUI crate files
  - System: visual constraint overlay in TUI.
  - Acceptance: overlay shows flagged nodes with legend.
- Subtask P4-T10.3: Add keybinding to toggle overlay and cycle constraints.
  - Files: TUI crate files
  - System: interactive overlay control.
  - Acceptance: keybinding toggles overlay on/off.

### P4-T11: Profile export implementation
- Subtask P4-T11.1: Add manager method to export agents and preferences.
  - Files: `src/profiles/manager.rs`
  - System: JSON export generator for profile sync.
  - Acceptance: export returns stable JSON structure.
- Subtask P4-T11.2: Implement CLI export writing to file path.
  - Files: `src/cli/commands/profile.rs`
  - System: CLI export command output.
  - Acceptance: file created with valid JSON payload.

### P4-T12: Profile import with LWW merge
- Subtask P4-T12.1: Parse import manifest and validate schema.
  - Files: `src/profiles/manager.rs`
  - System: import manifest parsing logic.
  - Acceptance: invalid JSON returns clear error.
- Subtask P4-T12.2: Apply LWW merge by preference id and timestamp.
  - Files: `src/profiles/manager.rs`
  - System: last-write-wins merge behavior.
  - Acceptance: newer entries overwrite older ones.
- Subtask P4-T12.3: Acquire exclusive DB lock during import.
  - Files: `src/profiles/manager.rs`
  - System: import lock to avoid concurrent writes.
  - Acceptance: import is serialized via exclusive lock.

### P4-T13: Validate sync manifest schema
- Subtask P4-T13.1: Check manifest `schema_version` compatibility.
  - Files: `src/profiles/manager.rs`
  - System: schema validation for import.
  - Acceptance: mismatched schema returns error.
- Subtask P4-T13.2: Check manifest embedding_dim matches local profile DB.
  - Files: `src/profiles/manager.rs`
  - System: embedding dimension validation.
  - Acceptance: mismatch returns error before import.

### P4-T14: Add config flags for advanced features
- Subtask P4-T14.1: Add config flags for hook checks, project map, TUI overlay.
  - Files: `src/config.rs`
  - System: feature gating configuration.
  - Acceptance: config includes boolean flags with defaults.
- Subtask P4-T14.2: Wire feature flags into hook, map, and TUI paths.
  - Files: `src/api/v1/hooks.rs`, `src/project_map/mod.rs`, TUI files
  - System: features can be disabled via config.
  - Acceptance: disabled features are skipped without error.

### P4-T15: Integration tests for hook endpoint
- Subtask P4-T15.1: Test hook pass case with no violations.
  - Files: `tests/hook_validate_pass.rs` (new)
  - System: hook endpoint behavior for valid input.
  - Acceptance: returns `status=pass`.
- Subtask P4-T15.2: Test hook fail case with constraint violation.
  - Files: `tests/hook_validate_fail.rs` (new)
  - System: hook endpoint behavior for violations.
  - Acceptance: returns `status=fail` and error list.

### P4-T16: Tests for export/import LWW
- Subtask P4-T16.1: Create two manifests with same id and different timestamps.
  - Files: `tests/profile_sync.rs`
  - System: test fixtures for LWW merge.
  - Acceptance: newer manifest overwrites older entry.
- Subtask P4-T16.2: Validate import rejects mismatched embedding_dim.
  - Files: `tests/profile_sync.rs`
  - System: import guardrail validation.
  - Acceptance: import fails with clear error.

## Phase 5 - Stabilization, Trust, and Release Readiness

### P5-T1: Add profile module scaffolding + domain types (verification)
- Subtask P5-T1.1: Audit profile domain types for category coverage (style, tooling, constraint, workflow).
  - Files: `src/profiles/mod.rs`
  - System: category enum completeness for phase 5 behaviors.
  - Acceptance: enum includes all SDS categories and compiles.
- Subtask P5-T1.2: Add any missing fields required for reasoning trace metadata.
  - Files: `src/profiles/mod.rs`
  - System: profile types support reasoning trace surfaces.
  - Acceptance: types include fields needed for trace (id, content, category, timestamps).

### P5-T2: Add config default for agent id
- Subtask P5-T2.1: Add `server.default_agent_id` to config struct and defaults.
  - Files: `src/config.rs`
  - System: default agent config surface.
  - Acceptance: config loads with default_agent_id field.
- Subtask P5-T2.2: Add config serialization to `config.toml` output.
  - Files: `src/config.rs`
  - System: config output includes default agent id.
  - Acceptance: generated config includes `server.default_agent_id`.

### P5-T3: Wire default agent into AppState
- Subtask P5-T3.1: Add `default_agent_id` to `AppState`.
  - Files: `src/search/mod.rs`
  - System: runtime state carries default agent id.
  - Acceptance: `AppState` compiles with new field.
- Subtask P5-T3.2: Use default agent when header/body agent id is missing.
  - Files: `src/api/v1/chat.rs`
  - System: default agent fallback for profile context.
  - Acceptance: requests without agent id use config default.

### P5-T4: MCP initialize default agent alignment
- Subtask P5-T4.1: Extend MCP initialize params to accept `agent_id`.
  - Files: `crates/mcp-server/src/lib.rs`
  - System: MCP default agent configuration.
  - Acceptance: initialize request stores agent_id in server state.
- Subtask P5-T4.2: Use MCP default agent for profile tools without explicit agent_id.
  - Files: `crates/mcp-server/src/lib.rs`
  - System: default agent fallback in MCP profile tools.
  - Acceptance: tool calls resolve agent id without error.

### P5-T5: Style category wiring (soft prompt injection)
- Subtask P5-T5.1: Filter profile context items by category=style.
  - Files: `src/api/v1/chat.rs`
  - System: style preference selection logic.
  - Acceptance: only style items appear in style block.
- Subtask P5-T5.2: Inject style block as non-blocking advice.
  - Files: `src/api/v1/chat.rs`
  - System: prompt guidance with advisory wording.
  - Acceptance: prompt includes "Style preferences" section.

### P5-T6: Workflow category wiring (reasoning/planning guidance)
- Subtask P5-T6.1: Extract workflow preferences into reasoning trace metadata.
  - Files: `src/api/v1/chat.rs`
  - System: workflow guidance in trace metadata.
  - Acceptance: reasoning_trace includes workflow entries.
- Subtask P5-T6.2: Add optional flag to include workflow guidance in prompt.
  - Files: `src/config.rs`, `src/api/v1/chat.rs`
  - System: configurable workflow injection.
  - Acceptance: flag toggles workflow block in prompt.

### P5-T7: Reasoning Trace surface (API + DAG)
- Subtask P5-T7.1: Define reasoning trace structure with behavioral and technical sections.
  - Files: `src/api/v1/chat.rs`
  - System: response metadata for trust and transparency.
  - Acceptance: response JSON includes `reasoning_trace` when enabled.
- Subtask P5-T7.2: Populate behavioral truth from profile context and workflow guidance.
  - Files: `src/api/v1/chat.rs`
  - System: behavioral truth content in trace.
  - Acceptance: trace lists profile constraints and preferences.
- Subtask P5-T7.3: Populate technical truth from repo memory and matches.
  - Files: `src/api/v1/chat.rs`
  - System: technical truth content in trace.
  - Acceptance: trace lists repo context sources.
- Subtask P5-T7.4: Add DAG log node for reasoning trace metadata.
  - Files: `src/dag/logging.rs`, `src/api/v1/chat.rs`
  - System: trace observability in DAG logs.
  - Acceptance: DAG logs include trace payload summary.

### P5-T8: Unix socket support for hook endpoint
- Subtask P5-T8.1: Add config for hook Unix socket path.
  - Files: `src/config.rs`
  - System: socket path configuration for hook server.
  - Acceptance: config includes optional socket path.
- Subtask P5-T8.2: Add Unix socket listener for hook validation requests.
  - Files: `src/daemon.rs`, `src/api/v1/hooks.rs`
  - System: Unix socket server for hook endpoint.
  - Acceptance: hook endpoint reachable via socket when enabled.
- Subtask P5-T8.3: Update hook client to prefer socket and fallback to HTTP.
  - Files: `src/cli/commands/hook.rs`
  - System: client transport selection logic.
  - Acceptance: socket used when configured; HTTP fallback works.

### P5-T9: Dynamic token budget reallocation
- Subtask P5-T9.1: Compute unused repo budget after context selection.
  - Files: `src/api/v1/chat.rs`
  - System: budget reconciliation for prompt assembly.
  - Acceptance: remaining tokens calculated without underflow.
- Subtask P5-T9.2: Reassign unused budget to chat history while keeping profile cap.
  - Files: `src/api/v1/chat.rs`
  - System: dynamic budget reallocation.
  - Acceptance: history grows when repo context is small.

### P5-T10: Update HTTP API docs
- Subtask P5-T10.1: Document agent_id header/body and profile endpoints.
  - Files: `docs/http_api.md`
  - System: API documentation for profile features.
  - Acceptance: doc lists headers and payload fields.
- Subtask P5-T10.2: Document hook endpoint and reasoning trace fields.
  - Files: `docs/http_api.md`
  - System: API docs for hook and trace.
  - Acceptance: docs include request/response examples.

### P5-T11: Update CLI help + README
- Subtask P5-T11.1: Update CLI help strings for profile and hook commands.
  - Files: `src/cli/mod.rs`
  - System: CLI documentation surfaces.
  - Acceptance: `--help` shows new flags and commands.
- Subtask P5-T11.2: Update README with profile, hook, and agent-id usage examples.
  - Files: `README.md`
  - System: user-facing docs for new features.
  - Acceptance: README includes new usage sections.

### P5-T12: Update MCP tool documentation
- Subtask P5-T12.1: Add MCP tool docs for profile tools and defaults.
  - Files: MCP documentation files (to be identified)
  - System: MCP usage guidance for profile tools.
  - Acceptance: docs include schemas and examples.
- Subtask P5-T12.2: Document default agent selection in MCP initialize.
  - Files: MCP documentation files
  - System: default agent behavior described.
  - Acceptance: docs describe agent_id fallback.

### P5-T13: Add config docs for [memory.profile]
- Subtask P5-T13.1: Document `memory.profile.embedding_model` and `embedding_dim` defaults.
  - Files: `docs/http_api.md` or config doc section
  - System: config documentation for profile embeddings.
  - Acceptance: docs include defaults and valid values.
- Subtask P5-T13.2: Add example config snippet for profile memory.
  - Files: `docs/http_api.md` or config doc section
  - System: example config section for profile setup.
  - Acceptance: example uses valid keys and values.

### P5-T14: Metrics for profile recall + evolution decisions
- Subtask P5-T14.1: Add metric definitions for profile recall latency and counts.
  - Files: `src/metrics.rs`
  - System: metrics for Tier 0 retrieval.
  - Acceptance: metrics appear in `/metrics` output.
- Subtask P5-T14.2: Increment metrics in profile recall and evolution flows.
  - Files: `src/orchestrator/waterfall.rs`, `src/profiles/evolution.rs`
  - System: runtime metrics updates.
  - Acceptance: counters/timers increment on use.

### P5-T15: Metrics for hook checks + map cache hits + budget drops
- Subtask P5-T15.1: Add counters for hook runs, failures, and latency.
  - Files: `src/metrics.rs`, `src/api/v1/hooks.rs`
  - System: hook metrics.
  - Acceptance: metrics increment on hook requests.
- Subtask P5-T15.2: Add cache hit/miss counters for project maps.
  - Files: `src/metrics.rs`, `src/project_map/mod.rs`
  - System: project map cache metrics.
  - Acceptance: counters update on cache hit/miss.
- Subtask P5-T15.3: Add counter for profile budget drops.
  - Files: `src/metrics.rs`, `src/api/v1/chat.rs`
  - System: profile pruning metrics.
  - Acceptance: counter increments when profile items are dropped.

### P5-T16: Integration tests for defaults + trace
- Subtask P5-T16.1: Test default agent selection when no agent_id provided.
  - Files: `tests/default_agent_selection.rs` (new)
  - System: default agent fallback behavior.
  - Acceptance: profile_context uses configured default agent.
- Subtask P5-T16.2: Test reasoning_trace presence and separation of truth blocks.
  - Files: `tests/reasoning_trace.rs` (new)
  - System: reasoning trace validation.
  - Acceptance: trace includes behavioral and technical sections.
- Subtask P5-T16.3: Test Unix socket hook path if enabled.
  - Files: `tests/hook_unix_socket.rs` (new)
  - System: hook Unix socket transport.
  - Acceptance: hook request succeeds via socket.
