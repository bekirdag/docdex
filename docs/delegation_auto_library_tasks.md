# Delegation Auto-Enable + Local Model Library Tasks

This task list implements `docs/delegation_auto_library_plan.md`. Each task is scoped, decoupled, and includes test coverage and acceptance criteria.

---

## Task: local-lib-schema-01
**Title:** Add local model library schema + persistence

**Description:**
- Create a new module to represent the local model library (Ollama models + Mcoda agents).
- Add load/save helpers with atomic writes and safe handling for missing/corrupt files.
- Resolve the library path under the state root (respect `DOCDEX_STATE_DIR` when set).
- Keep the file JSON-only and ASCII safe.

**Files to touch:**
- `src/llm/local_library.rs` (new module with schema + load/save helpers)
- `src/llm.rs` (export the module)

**Tests (unit/component/integration/api):**
- Unit: add tests in `src/llm/local_library.rs`:
  - `local_library_roundtrip`
  - `local_library_corrupt_falls_back`
  - Run: `cargo test local_library_ --lib`
- Component: none.
- Integration: none.
- API: none.

**Dependencies:**
- None.

**Acceptance Criteria:**
- Library file is written under `<state-root>/llm/local_model_library.json`.
- Corrupt JSON is backed up and a fresh empty library is returned.
- Round-trip serialization preserves fields and defaults.

---

## Task: local-lib-discovery-ollama-01
**Title:** Discover local Ollama models safely

**Description:**
- Add Ollama discovery helpers that:
  - Resolve a local Ollama base URL (from `llm.provider=ollama` or `DOCDEX_OLLAMA_BASE_URL`).
  - Treat non-loopback base URLs as non-local and skip delegation candidates.
  - Attempt model discovery via `/api/tags`, with a CLI fallback when available.
- Normalize model names (trim, lowercase for classification) without losing the raw name.
- Ensure failures do not block delegation (log + continue).

**Files to touch:**
- `src/llm/local_library.rs`

**Tests:**
- Unit: add tests in `src/llm/local_library.rs`:
  - `ollama_base_url_local_detection`
  - `ollama_model_name_normalization`
  - Run: `cargo test ollama_ --lib`
- Component: none.
- Integration: none.
- API: none.

**Dependencies:**
- local-lib-schema-01

**Acceptance Criteria:**
- Remote base URLs do not count as local Ollama for delegation.
- Discovery failures do not error the caller (library refresh continues).
- Normalization leaves the stored display name intact.

---

## Task: local-lib-discovery-mcoda-01
**Title:** Discover Mcoda agents and map to library entries

**Description:**
- Add Mcoda registry discovery to the local library refresh.
- Map agent id/slug/adapter/default_model + capability tags into library entries.
- Ensure empty registry or missing DB is handled gracefully.

**Files to touch:**
- `src/llm/local_library.rs`

**Tests:**
- Unit: add tests in `src/llm/local_library.rs`:
  - `mcoda_agent_mapping`
  - Run: `cargo test mcoda_agent_ --lib`
- Component: none.
- Integration: none.
- API: none.

**Dependencies:**
- local-lib-schema-01

**Acceptance Criteria:**
- At least one mcoda agent results in at least one library entry.
- Missing registry or load errors do not crash the refresh.

---

## Task: local-lib-classify-01
**Title:** Add known + heuristic classification for models

**Description:**
- Create a classification pipeline with:
  - Known mappings for common model families (phi, llama, qwen, deepseek-coder, codellama).
  - Heuristics based on name tokens (code/coder/instruct/embed/vision).
- Produce standardized capability tags (`code_writer`, `code_reviewer`, `general_chat`, `embedding`, `vision`).

**Files to touch:**
- `src/llm/local_library.rs`

**Tests:**
- Unit: add tests in `src/llm/local_library.rs`:
  - `classify_known_model_families`
  - `classify_model_heuristics`
  - Run: `cargo test classify_model_ --lib`
- Component: none.
- Integration: none.
- API: none.

**Dependencies:**
- local-lib-schema-01

**Acceptance Criteria:**
- Code-tagged models receive code-related capabilities.
- Embedding/vision models are tagged to exclude them from delegation.

---

## Task: local-lib-web-01
**Title:** Add web classification for unknown models

**Description:**
- When a model cannot be classified by known/heuristic rules, call web research:
  - Use `run_web_research` with `force_web=true` and `skip_local_search=true`.
  - Extract capability keywords from web results.
  - Cache results in the library to avoid repeated calls.
- Support dependency injection for unit tests (stub web responses).

**Files to touch:**
- `src/llm/local_library.rs`

**Tests:**
- Unit: add tests in `src/llm/local_library.rs`:
  - `classify_model_web_stub`
  - Run: `cargo test classify_model_web_ --lib`
- Component: none.
- Integration: none.
- API: none.

**Dependencies:**
- local-lib-classify-01

**Acceptance Criteria:**
- Unknown models trigger web classification when web is enabled.
- Classification results are cached in the library with `classification_method=web`.

---

## Task: local-lib-refresh-01
**Title:** Implement library refresh + TTL gating

**Description:**
- Implement `refresh_local_library_if_stale`:
  - Load existing library, check `updated_at` against a TTL (env override allowed).
  - Discover Ollama + Mcoda sources, classify, and write back.
  - Record `last_seen_at` per entry and prune stale entries.
- Add helper to detect whether the library has delegation-eligible candidates.

**Files to touch:**
- `src/llm/local_library.rs`

**Tests:**
- Unit: add tests in `src/llm/local_library.rs`:
  - `local_library_refresh_ttl`
  - `local_library_has_candidates`
  - Run: `cargo test local_library_refresh_ --lib`
- Component: none.
- Integration: none.
- API: none.

**Dependencies:**
- local-lib-discovery-ollama-01
- local-lib-discovery-mcoda-01
- local-lib-web-01

**Acceptance Criteria:**
- Refresh skips work when TTL has not elapsed.
- Eligible candidates are detected correctly for auto-enable.

---

## Task: local-lib-logging-01
**Title:** Add discovery/classification/auto-enable logging

**Description:**
- Emit clear logs for library discovery (models/agents counts) and classification methods (known/heuristic/web).
- Log auto-enable decisions when delegation is enabled via library candidates rather than explicit config.
- Keep logs concise and avoid per-model spam.

**Files to touch:**
- `src/llm/local_library.rs`
- `src/api/v1/delegate.rs` (or `src/mcp_server.rs` if logging belongs there)

**Tests:**
- Unit: none.
- Component: none.
- Integration: none.
- API: none.

**Dependencies:**
- local-lib-refresh-01
- delegation-auto-enable-01

**Acceptance Criteria:**
- Logs clearly indicate when local discovery ran and what classification methods were used.
- Auto-enable decision is observable in logs when applicable.

---

## Task: delegation-auto-enable-01
**Title:** Add auto-enable flag for delegation

**Description:**
- Add `llm.delegation.auto_enable` (default true).
- Add env override `DOCDEX_DELEGATION_AUTO_ENABLE`.
- Add helper to compute `delegation_enabled` from config + library.
- Update config tests to cover defaults and overrides.

**Files to touch:**
- `src/config.rs`
- `src/config/tests.rs`
- `src/llm/local_library.rs`

**Tests:**
- Unit: add tests in `src/config/tests.rs`:
  - `delegation_auto_enable_defaults`
  - `delegation_auto_enable_env_override`
  - Run: `cargo test delegation_auto_enable_ --lib`
- Component: none.
- Integration: none.
- API: none.

**Dependencies:**
- local-lib-schema-01
- local-lib-refresh-01

**Acceptance Criteria:**
- Auto-enable defaults to true without breaking existing configs.
- Explicit disable via `auto_enable=false` blocks auto-enable.

---

## Task: delegation-selection-01
**Title:** Select local models/agents by task type

**Description:**
- Add selection logic to choose a local target (Ollama model or Mcoda agent) based on task type + capabilities.
- Update delegation flow to accept a selected local target when no explicit agent override is provided.
- Keep existing explicit `agent` override semantics unchanged.

**Files to touch:**
- `src/llm/delegation.rs`
- `src/llm/local_library.rs`
- `src/llm/tests.rs`

**Tests:**
- Unit: add tests in `src/llm/tests.rs`:
  - `delegation_selects_code_writer`
  - `delegation_falls_back_without_candidates`
  - Run: `cargo test delegation_selects_ --lib`
- Component: none.
- Integration: none.
- API: none.

**Dependencies:**
- local-lib-refresh-01
- delegation-auto-enable-01

**Acceptance Criteria:**
- Selection prefers matching capabilities by task type.
- Explicit `agent` override always wins.

---

## Task: delegation-refresh-hooks-01
**Title:** Refresh library before delegation (API + MCP)

**Description:**
- Before delegating, refresh the library (TTL guarded) and compute auto-enable status.
- If delegation is disabled after evaluation, return the existing "delegation disabled" error.
- Ensure API and MCP both pass the refreshed library into selection.

**Files to touch:**
- `src/api/v1/delegate.rs`
- `src/mcp_server.rs`
- `src/search/mod.rs`
- `src/daemon.rs`
- `src/api/mcp_http.rs`

**Tests:**
- Integration/API: update `tests/delegate_http.rs` to keep passing with auto-enable logic.
  - Run: `cargo test delegate_endpoint_returns_output --test delegate_http`
- Unit: none.
- Component: none.

**Dependencies:**
- delegation-selection-01

**Acceptance Criteria:**
- Delegation works when enabled or auto-enabled.
- Delegation returns disabled error when explicitly disabled.

---

## Task: daemon-startup-refresh-01
**Title:** Refresh local library at daemon startup

**Description:**
- Kick off a TTL-guarded local library refresh when the daemon starts.
- Keep startup non-blocking (spawn a background task) and log failures.
- Use the global state dir + current LLM config to drive the refresh.

**Files to touch:**
- `src/daemon.rs`

**Tests:**
- Unit: none.
- Component: none.
- Integration: none.
- API: none.

**Dependencies:**
- local-lib-refresh-01

**Acceptance Criteria:**
- Daemon startup triggers a background refresh once per run.
- Startup does not fail if refresh errors.

---

## Task: setup-refresh-hook-01
**Title:** Refresh library after setup model installs

**Description:**
- After setup completes and models are installed, refresh the local model library once.
- Ensure failures are logged but do not fail setup.
- Record installed model names into the library even when web classification is unavailable.

**Files to touch:**
- `src/setup/mod.rs`
- `src/setup/ui.rs`

**Tests:**
- Unit: none.
- Component: none.
- Integration: none.
- API: none.

**Dependencies:**
- local-lib-refresh-01

**Acceptance Criteria:**
- Setup completes even if library refresh fails.
- Installed models are visible in the library file after setup.

---

## Task: delegation-prompt-clarity-01
**Title:** Make delegation prompts more explicit about task capsules

**Description:**
- Update delegation prompt templates to include explicit task capsule expectations:
  - Objective, constraints, files/paths, output format.
- Keep strict output formatting rules (no markdown).

**Files to touch:**
- `prompts/delegation/generate_tests.txt`
- `prompts/delegation/write_docstring.txt`
- `prompts/delegation/scaffold_boilerplate.txt`
- `prompts/delegation/refactor_simple.txt`
- `prompts/delegation/format_code.txt`
- `prompts/delegation/refine_draft.txt`

**Tests:**
- Unit: none.
- Component: none.
- Integration: none.
- API: none.

**Dependencies:**
- None.

**Acceptance Criteria:**
- Templates clearly request a task capsule and constraints in context.
- Output rules remain unchanged.

---

## Task: docs-auto-library-01
**Title:** Document the local model library + auto-enable behavior

**Description:**
- Update docs to describe:
  - Library path and contents.
  - Auto-enable behavior and opt-out.
  - How delegation chooses local models.
- Keep docs aligned with config defaults.

**Files to touch:**
- `docs/usage.md`
- `docs/http_api.md`
- `docs/metrics_dashboard.md` (if needed for new counters)

**Tests:**
- None.

**Dependencies:**
- delegation-auto-enable-01
- delegation-selection-01

**Acceptance Criteria:**
- Docs clearly explain how auto-enable works and where the library is stored.
- Delegation API docs mention selection + auto-enable semantics.
