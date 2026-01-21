# Delegation Auto-Enable + Local Model Library Plan

## Goal
Automatically discover local Ollama models and available Mcoda agents, catalog them under `~/.docdex`, classify them by usefulness (e.g., code writer/reviewer), and auto-enable delegation when eligible local resources exist. Keep the catalog fresh and use web research to classify unknown models.

## Requirements Mapping
1) Detect local Ollama, list installed models, catalog + classify them, and auto-enable delegation.
2) After Ollama install/model pull during setup (e.g., `phi3.5:3.8b`), refresh the catalog and enable delegation.
3) If Mcoda agents exist, add them to the catalog and enable delegation.
4) Before delegation, refresh both Ollama and Mcoda sources so the catalog is current.
5) If a model is unknown, run web research to infer its best-use categories and store the results.

## Current State
- Delegation exists but requires manual `[llm.delegation].enabled = true`.
- Ollama model discovery exists in setup CLI via `ollama list`.
- Mcoda registry loading exists (`src/mcoda/registry.rs`).
- Web research pipeline exists (`orchestrator::web::run_web_research`).
- No unified local model/agent catalog under `~/.docdex`.

## Proposed Architecture
### A. Local Model Library (Global State)
Store a JSON catalog under the global state dir (e.g., `~/.docdex/state/llm/local_model_library.json`).

Schema (high level):
- `version`
- `updated_at`
- `models[]`
  - `name` (e.g., `phi3.5:3.8b`)
  - `source` (`ollama`)
  - `capabilities[]` (e.g., `code_writer`, `code_reviewer`, `general_chat`)
  - `notes` (short summary)
  - `classification_method` (`known_map`, `heuristic`, `web`)
  - `last_seen_at`
- `agents[]`
  - `agent_id`, `agent_slug`, `adapter`, `default_model`
  - `capabilities[]` (mapped from mcoda tags)
  - `notes`, `classification_method`, `last_seen_at`

### B. Discovery Sources
1) Ollama:
   - Use HTTP `/api/tags` when base URL is local and reachable.
   - Use CLI `ollama list` if a local binary exists and the daemon is running.
2) Mcoda:
   - Load registry via `McodaRegistry::load_default()`.

### C. Classification Pipeline
1) Known map: explicit mappings for well-known models (phi3.5, llama, code-*).
2) Heuristics: model name rules (`*code*`, `*embed*`, `*vision*`, `*instruct*`).
3) Web research (if unknown):
   - Query web with `force_web=true`, `skip_local_search=true`.
   - Extract keywords from results and map to capability categories.
   - Cache results in the library to avoid repeated calls.

### D. Auto-Enable Delegation
Delegation is considered enabled if:
- `llm.delegation.enabled = true`, OR
- `llm.delegation.auto_enable = true` (new default) and the catalog contains at least one eligible local model/agent.

### E. Refresh Strategy
- Startup: refresh library when the daemon starts.
- Setup: refresh after successful Ollama installation/model pull.
- Delegation: refresh before each delegation request (bounded by TTL to avoid repeated IO).

### F. Selection Strategy
If `local_agent_id` is empty, select a local model/agent from the catalog by task type:
- `GENERATE_TESTS` / `REFACTOR_SIMPLE`: prefer `code_reviewer` or `refactor`.
- `WRITE_DOCSTRING` / `SCAFFOLD_BOILERPLATE`: prefer `code_writer`.
- `FORMAT_CODE`: prefer `code_reviewer` or `formatting`.
Fallback: default Ollama model if no match.

## Edge Cases
- Ollama installed but daemon not running; `ollama list` fails or /api/tags times out.
- Base URL is remote or non-loopback; do not assume "local" models.
- Installed models list includes embeddings or vision-only models; exclude from delegation.
- Web research disabled or rate-limited; classification must fall back to heuristics.
- Model name collisions and duplicates across sources.
- Mcoda registry exists but no agents; do not enable delegation.
- User explicitly disables delegation; require explicit opt-out override.
- Catalog file missing/corrupted; recreate safely with backups.
- Large model list; avoid blocking startup (use TTL + background refresh).
 - Ollama CLI present but no models installed; keep catalog empty and do not enable.
 - Ollama list/HTTP tags returns transient errors; avoid hard-failing delegation requests.
 - Local base URL set but points to a remote host; never treat as local.
 - Concurrent refreshes; guard with atomic writes and last-updated checks.
 - Home/state dir is not writable; log and continue without auto-enable.
 - Unknown model names (namespaced tags, unicode); normalize + store raw values.
 - Mcoda registry exists but is locked/corrupt; skip and keep existing catalog.
 - Web research yields conflicting signals; retain last-known classification unless unknown.
 - Classification TTL: avoid repeating web calls every request for the same model.

## Acceptance Criteria (High Level)
- Local catalog is created under `~/.docdex` and updated automatically.
- Delegation auto-enables when eligible local models/agents exist.
- Delegation refreshes catalog before use.
- Unknown models trigger web research classification when possible.
- Clear logging for discovery, classification, and auto-enable decisions.
