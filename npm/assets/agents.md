---- START OF DOCDEX INFO V0.2.64 ----
Docdex URL: http://127.0.0.1:28491
Use this base URL for Docdex HTTP endpoints.
Health check endpoint: `GET /healthz` (not `/v1/health`).

## Priority Directives (Mandatory)

- Always use both memory lobes early: docdex_get_profile + docdex_memory_recall; save new facts via docdex_memory_save and new preferences via docdex_save_preference.
- Profile memory is always-on and global; never gate on DOCDEX_ENABLE_MEMORY or repo state. docdex_save_preference must persist (fallback if embeddings/LLM unavailable). If profile calls fail, treat it as a bug.
- Maintain agent-specific profile memory: use your agent_id with docdex_get_profile/docdex_save_preference; store generic self-knowledge (role, tooling, preferences).
- Use impact analysis for every code change: prefer MCP tools `docdex_impact_graph` / `docdex_dag_export` (IPC/HTTP). If shell networking is blocked, do not use curl; use MCP/IPC instead. If unavailable, state it and proceed cautiously.
- Apply DAG reasoning for planning: prefer dependency graph facts (impact results and /v1/dag/export) to choose the right change order and scope.
- Use Docdex tools intentionally: docdex_search/symbols/ast for repo truth; docdex_stats/files/repo_inspect/index for index health.
- When session history matters, use conversation-memory tools intentionally: archive/search/read with `docdex_conversation_*`, build compact context with `docdex_wakeup`, record durable notes with `docdex_diary_*`, and inspect temporal graph state with `docdex_kg_*` instead of replaying full transcripts.
- For folder structure, use docdex_tree instead of raw `rg --files`/`find` to avoid noisy folders.
- When you do not know something, run docdex_web_research (force_web=true). Web research is encouraged by default for non-repo facts and external APIs.
- When a Docdex feature makes a task easier/safer, you MUST use it instead of ad-hoc inspection. Examples: `docdex_search` for context, `docdex_open`/`/v1/snippet` for file slices, `docdex_symbols`/`docdex_ast` for structure, `docdex_impact_graph`/`docdex_impact_diagnostics` for dependency safety, and `docdex_dag_export` to review session traces.
- For dependency/library docs, run `docdexd libs discover`/`docdexd libs fetch` and search with `include_libs` rather than web searching.
- For test execution, use `docdexd run-tests` (or `docdexd test run-node`) instead of ad-hoc commands when feasible.
- For daemon stability triage, prioritize FD hardening checks: startup nofile warning threshold (`DOCDEX_MIN_NOFILE_SOFT`), profile lock retry knobs (`DOCDEX_PROFILE_LOCK_MAX_ATTEMPTS`, `DOCDEX_PROFILE_LOCK_RETRY_BASE_MS`), installer pressure defaults (`DOCDEX_REPO_IDLE_SECONDS`, `DOCDEX_REPO_HIBERNATE_SECONDS`, `DOCDEX_REPO_CLEANUP_INTERVAL_SECONDS`), and `docs/ops/fd_exhaustion_playbook.md`.
- For staged-change validation, use `docdexd hook pre-commit`.
- For MCP client registration, use `docdexd mcp add` (or `--all`) instead of editing configs by hand.

# Docdex Agent Usage Instructions

> Context for AI Agents: Docdex is your local-first Dual-Lobe Memory and Code Intelligence daemon. Unlike simple vector stores, it provides structural understanding of code (AST/Graph), persistent behavioral profiles (Agent Memory), and gated web enrichment, all strictly scoped to the local machine.

## Identity & Architecture

Docdex (Documentation Indexer) serves as your persistent "brain" on the user's machine. It operates on a Waterfall Retrieval model:

1. Local First (Tier 1): Instant search of repo code, symbols, and ingested library documentation.
2. Web Enrichment (Tier 2): Gated fallback to the configured web provider (DuckDuckGo by default, `mswarm` when selected) plus Headless Chrome when local confidence is low or explicitly requested.
3. Cognition (Tier 3): Local LLM inference (Ollama) with context assembly.

Key Constraints:

- Repo Isolation: Data never bleeds between repositories. You must identify the active repo for every operation.
- Hierarchy of Truth: Technical Truth (Code/Repo Memory) > Behavioral Truth (Profile Memory).
- Privacy: Code is never uploaded to a cloud vector store.

## The Dual-Lobe Memory System

Docdex v2.1 introduces a strict separation between "facts" and "preferences." Use the correct lobe for the task.

### 1. Repo Memory (The Hippocampus)

- Scope: Project-bound. Specific to the current repository.
- Content: Technical facts, architectural decisions, logic locations.
- Example: "The calculateTax function is located in utils/money.ts."
- Tools: docdex_memory_save, docdex_memory_recall

### 2. Profile Memory (The Neocortex)

- Scope: Global / agent-bound. Persists across all projects.
- Content: Your persona, user preferences, coding style, tooling constraints.
- Example: "Always use Zod for validation," or "User prefers strict TypeScript types."
- Tools: docdex_save_preference, docdex_get_profile
- Agent-specific: Each agent should use its own agent_id and store generic self-knowledge (role, tooling, preferences).
- Usage: Use this to "learn" from corrections. If a user corrects your style, save it here so you do not repeat the mistake in a different repo.

## Tool Capabilities (MCP & HTTP)

### A. Semantic Search & Web (Waterfall)

Standard retrieval. The daemon automatically handles the waterfall (Local -> Web).

| MCP Tool | Purpose |
| --- | --- |
| docdex_search | Search code, docs, and ingested libraries. Returns ranked snippets. |
| docdex_web_research | Explicitly trigger Tier 2 web discovery (configured provider + Headless Chrome). Use when you need external docs not present locally. |

When `DOCDEX_WEB_DISCOVERY_PROVIDER=mswarm` or `[web].discovery_provider = "mswarm"`, Docdex's runtime web-discovery adapter sends `POST {base_url}/v1/swarm/web/search` using `[integrations.mswarm].base_url`, adds the `x-api-key` header from `[integrations.mswarm].api_key`, and sends JSON shaped like `{ "query": "<search query>", "tool_id": "docdex" }`. Treat this as a runtime integration detail: agents should normally configure and invoke Docdex search/web tools rather than calling the raw mswarm endpoint directly unless they are debugging the integration itself.

### B. Code Intelligence (AST & Graph)

Precision tools for structural analysis. Do not rely on text search for definitions or dependencies.

| MCP Tool | Purpose |
| --- | --- |
| docdex_symbols | Get exact definitions/signatures for a file. |
| docdex_ast | Specific AST nodes (e.g., "Find all class definitions"). |
| docdex_impact_diagnostics | Check for broken/dynamic imports. |
| docdex_impact_graph | Impact Analysis: "What breaks if I change this?" Returns inbound/outbound dependencies. |
| docdex_dag_export | Export the dependency DAG for change ordering and scope. |

### C. Memory Operations

| MCP Tool | Purpose |
| --- | --- |
| docdex_memory_save | Store a technical fact about the current repo. |
| docdex_memory_recall | Retrieve technical facts about the current repo. |
| docdex_save_preference | Store a global user preference (Style, Tooling, Constraint). |
| docdex_get_profile | Retrieve global preferences. |
| docdex_memory_route | Recommend which Docdex memory lanes to read from or write to for a specific task. |
| docdex_memory_layers | Inspect the six memory layers, their scope/storage, and when each one should be used. |

When unsure which memory lane fits the task, call `docdex_memory_route` first.
- Use `docdex_memory_layers` when you need the full six-layer map and storage/scope details.
- Repo memory and profile memory are the core/default lanes.
- Conversation memory, diary memory, temporal knowledge graph, and personal-preferences memory are selective lanes for continuity, handoff notes, structured recall, and richer user-specific context.

### D. Conversation Memory + Temporal Knowledge Graph

Use these when prior sessions, durable notes, wake-up context, or graph-derived facts matter.

| MCP Tool / HTTP | Purpose |
| --- | --- |
| docdex_conversation_import / search / list / read / export / redact / delete | Manage archived conversations inside the current repo scope or an explicit conversation namespace. |
| docdex_conversation_prune | Preview or apply retention and compaction for sessions, diary entries, hook events, working memory, and episodic rollups. |
| docdex_diary_write / docdex_diary_read | Persist concise durable notes for an agent and read them back later. |
| docdex_conversation_hook | Trigger periodic or session-close summarization from transcript or summary payloads. |
| docdex_wakeup | Build a compact wake-up bundle from working memory, episodic summaries, KG facts, and transcript snippets. |
| docdex_kg_query / search_nodes / search_edges / search_episodes / timeline / neighborhood / entity_links / episode / delete_edge / delete_episode / rebuild / clear | Query and maintain the temporal knowledge graph derived from conversations. |

### E. Local Delegation (Cheap Models)

Use local delegation for low-complexity code-writing tasks and lightweight general questions to reduce paid-model usage.

| MCP Tool / HTTP | Purpose |
| --- | --- |
| docdex_local_completion | Delegate small tasks to a local model with strict output formats. |
| HTTP /v1/delegate | HTTP endpoint for delegated completions with structured responses. |

Required fields: `task_type`, `instruction`, `context`. Optional: `max_tokens`, `timeout_ms`, `mode` (`draft_only` or `draft_then_refine`), `agent` (local agent id/slug or `model:<name>` to force an Ollama model; raw model names from `docdexd delegation agents` are also accepted). Use `general_question` for lightweight Q&A and the existing code-oriented task types for code writing/editing. Lane-specific defaults come from `[llm.delegation.code]` for code-oriented task types and `[llm.delegation.general]` for `general_question`; flat `local_agent_id` / `cloud_agent_id` / `primary_agent_id` remain compatibility fallbacks when lane-specific values are unset. This allows a coder-focused local agent for code work, a more general local agent for Q&A, and optional cloud fallbacks for each lane.
Expensive model library: `docs/expensive_models.json` (match by `agent_id`, `agent_slug`, `model`, or adapter type; case-insensitive).
If `[llm.delegation.cloud].enabled = true` and `[integrations.mswarm].api_key` is set, Docdex discovers managed cloud fallbacks with `mcoda cloud agent list --json` and materializes them as `mswarm-cloud-<remote-slug>` mcoda agents. Use `[llm.delegation.code].cloud_agent_id` / `[llm.delegation.general].cloud_agent_id` to pin the preferred cloud fallback for each lane.
To choose a local target, run `docdexd delegation agents` (or `--json`) and prefer:
- `code_writer` for scaffolding/boilerplate/docstrings.
- `code_reviewer` for tests/format/refactors.
- `general_chat` for lightweight Q&A or fallback.
For mcoda agents, also consider:
- `max_complexity`: do not assign tasks above this ceiling.
- `rating`: prefer higher-rated agents for reliability.
- `cost_per_million`: USD per 1M tokens; prefer lower cost when ratings/complexity match.
- Automatic target selection prefers healthy local Ollama models and local mcoda agents first. Managed `mswarm-cloud-*` agents are only considered after local candidates, or when the user/config explicitly prefers a cloud fallback.
- Automatic target selection excludes paid mcoda candidates unless they are cheaper than the effective caller/primary model. Explicit per-request `agent` overrides remain hard overrides.
- `usage`: best-fit role (for example `code_writer` or `code_reviewer`); use this for quick matching.
- `reasoning_rating`: reasoning score out of 10; prefer higher for complex reasoning tasks.
- `health_status`: only use agents marked `healthy` (treat `-` as unknown).
- For setup/ops, inspect cloud candidates with `mcoda cloud agent list --json --provider openrouter --limit ... --max-cost-per-1m-token ... --sorted-by-catalog-rating --min-context ... --min-reasoning ...`.
- Docdex refreshes mcoda inventory via `mcoda agent list --json --refresh-health`; it retries with legacy `mcoda agent list --json` if the refresh flag is unavailable. That refresh also updates `agent_usage_limits`, so managed cloud agents with exhausted quota appear as `limited` and are skipped until reset.
- Supported mcoda local CLI adapters include `claude-cli` in addition to `codex-cli`/`gemini-cli`/`openai-cli`/`ollama-cli`.
Table output shows `USAGE`, `COMPLEXITY`, `RATING`, `REASON`, `COST/$1M`, and `HEALTH` for mcoda agents (`-` means unknown).
- When `llm.delegation.re_evaluate = true` (default), Docdex reviews successful mcoda delegation runs, including managed cloud agents, using the primary agent when available and writes updated ratings to `~/.mcoda/mcoda.db` (disable with `DOCDEX_DELEGATION_REEVALUATE=0`).
Use `agent: model:<ollama-model>` to force a specific local model (for example, `model:phi3.5:3.8b`).
Avoid entries that only advertise `embedding` or `vision`.

### F. Index Health + File Access

Use these to verify index coverage, repo binding, and to read precise file slices.

| MCP Tool | Purpose |
| --- | --- |
| docdex_repo_inspect | Confirm normalized repo root/identity (resolve missing_repo). |
| docdex_stats | Index size/last update; detect stale indexes. |
| docdex_files | Indexed file coverage; confirm a file is in the index. |
| docdex_index | Reindex full repo or ingest specific files when stale/missing. |
| docdex_open | Read exact file slices after you identify targets. |
| docdex_tree | Render a repo folder tree with standard excludes (avoid noisy folders). |

## Quick Tool Map (Often Missed)

- docdex_files: List indexed docs with rel_path/doc_id/token_estimate; use to verify indexing coverage.
- docdex_stats: Show index size, state dir, and last update time.
- docdex_repo_inspect: Confirm normalized repo root and repo identity mapping.
- docdex_index: Reindex the full repo or ingest specific files when stale.
- docdex_search diff: Limit search to working tree, staged, or ref ranges; filter by paths.
- docdex_web_research knobs: force_web, skip_local_search, repo_only, no_cache, web_limit, llm_filter_local_results, llm_model.
- docdex_conversation_import/search/list/read/export/redact/delete: Archive and inspect scoped conversation sessions instead of depending on transient chat history. After redaction, read/export keep message slots but replace stored content with `[redacted]` placeholders.
- docdex_conversation_prune: Dry-run or apply retention across sessions, diary entries, hook events, working memory, and episodic rollups.
- docdex_diary_write/read: Persist concise durable notes tied to an agent and repo or conversation namespace.
- docdex_conversation_hook: Enqueue or synchronously process periodic/session-close summarization from transcript or summary input.
- docdex_wakeup: Build a bounded wake-up bundle before answering instead of replaying whole transcripts.
- docdex_kg_*: Inspect derived entities, edges, episodes, timelines, neighborhoods, entity links, and graph maintenance actions.
- docdex_open: Read narrow file slices after targets are identified.
- docdex_tree: Render a filtered folder tree (prefer this over `rg --files` / `find`).
- docdex_impact_diagnostics: Scan dynamic imports when imports are unclear or failing.
- docdex_local_completion: Delegate low-complexity local tasks such as codegen work or lightweight general questions.
- docdex_ast: Use AST queries for precise structure (class/function definitions, call sites, imports).
- docdex_symbols: Use symbols to confirm exact signatures/locations before edits.
- docdex_impact_graph: Mandatory before code changes to review inbound/outbound deps (use MCP/IPC if shell networking is blocked).
- docdex_dag_export: Export dependency graph to plan change order.
- HTTP /v1/initialize: Mount/bind a repo for HTTP daemon mode. Request JSON uses rootUri/root_uri (NOT repo_root).
- HTTP /v1/capabilities: Read optional retrieval feature flags and bounded limits before using optional flows.
- HTTP /v1/search/rerank: Rerank a candidate hit set; use when capability negotiation says rerank is available.
- HTTP /v1/search/batch: Execute bounded multi-query retrieval in one request.
- MCP tools `docdex_capabilities`, `docdex_rerank`, `docdex_batch_search`: optional capability/flow surfaces for Codali integration.
- HTTP /v1/snippet: Fetch exact line-safe snippets for a doc_id returned by search.
- HTTP /v1/chat/completions: OpenAI-compatible chat can inject wake-up, profile, and cached project-map context; non-streaming responses may include `reasoning_trace`.
- HTTP /v1/impact/diagnostics: Inspect unresolved/dynamic imports when impact graphs look incomplete.

## CLI Fallbacks (when MCP/IPC is unavailable)
Use these only when MCP tools cannot be called (e.g., blocked sandbox networking). Prefer MCP/IPC otherwise.

- `docdexd repo init --repo <path>`: initialize repo in daemon and return repo_id JSON.
- `docdexd repo id --repo <path>`: compute repo fingerprint locally.
- `docdexd repo status --repo <path>` / `docdexd repo dirty --exit-code`: git working tree status.
- `docdexd impact-graph --repo <path> --file <rel>`: impact graph (HTTP/local).
- `docdexd dag view --repo <path> <session_id>` / `docdexd dag export --repo <path> <session_id>`: DAG export/render.
- `docdexd search --repo <path> --query "<q>"`: /search equivalent (HTTP/local).
- `docdexd conversations import|list|search|read|export|redact|delete --repo <path>`: conversation archive management via the daemon HTTP API.
- `docdexd conversations prune --repo <path> [--apply] [--manual-retention-days ... --auto-capture-retention-days ... --diary-retention-days ... --hook-event-retention-days ... --working-memory-retention-days ... --episodic-rollup-retention-days ...]`: retention preview/apply.
- `docdexd diary write|read --repo <path>`: store and read agent diary entries in the current scope.
- `docdexd hook conversation --repo <path> --action <periodic_memory_save|pre_compaction_summarization|session_close_summarization>`: trigger conversation-memory hooks.
- `docdexd conversations kg-query|kg-search-nodes|kg-search-edges|kg-search-episodes|kg-neighborhood|kg-entity-links|kg-episode|kg-timeline|kg-delete-edge|kg-delete-episode|kg-rebuild|kg-clear --repo <path>`: temporal KG exploration and maintenance.
- `docdexd delegation savings`: delegation telemetry (JSON: offloaded count, local/primary tokens & costs, savings).
- `docdexd delegation agents --json`: list local delegation targets and capabilities (mcoda agents include `max_complexity`, `rating`, `cost_per_million`, `usage`, `reasoning_rating`, `health_status`).
- `mcoda agent list --json --refresh-health`: preferred machine-consumer inventory command for fresh health; fallback to plain `--json` for older mcoda versions.
- `docdexd open --repo <path> --file <rel>`: safe file slice read (head/start/end/clamp).
- `docdexd file ensure-newline|write --repo <path> --file <rel>`: minimal file edits.
- `docdexd test run-node --repo <path> --file <rel> --args "..."`: run Node scripts.
- `docdexd run-tests --repo <path> [--target <file|dir>]`: run repo tests (preferred for test execution).
- `docdexd hook pre-commit --repo <path>`: run semantic gatekeeper hooks against staged changes.
- `docdexd impact-diagnostics --repo <path> [--file <rel>]`: list unresolved import diagnostics.
- `docdexd libs discover|fetch --repo <path> [--sources <file>]`: dependency docs discovery/ingestion.
- `docdexd mcp add --agent <name> [--transport http|ipc] [--all]`: register Docdex MCP in supported clients.

## Docdex Usage Cookbook (Mandatory, Exact Schemas)

This section is the authoritative source for how to call Docdex. Do not guess field names or payloads.

### 0) Base URL + daemon modes

- Default HTTP base URL: http://127.0.0.1:28491 (override with DOCDEX_HTTP_BASE_URL).
- Single-repo HTTP daemon: `docdexd serve --repo /abs/path`. /v1/initialize is NOT used. repo_id is optional, but must match the serving repo if provided.
- Multi-repo HTTP daemon: `docdexd daemon` (alias: `docdex start`). You MUST call /v1/initialize before repo-scoped HTTP endpoints. When multiple repos are mounted, repo_id is required on every repo-scoped request.

### 1) Initialize (HTTP) - exact request payload

POST /v1/initialize

Request JSON (exact field names):

```json
{ "rootUri": "file:///abs/path/to/repo" }
```

Alias accepted:

```json
{ "root_uri": "/abs/path/to/repo" }
```

Rules:
- Do NOT send `repo_root` in the request. `repo_root` is a response field.
- Use file:// URIs when possible; plain absolute paths are also accepted.
- Response returns `repo_id`, `status`, and `repo_root`. Use that repo_id for subsequent HTTP calls.

### 2) Repo scoping (HTTP)

- Send repo_id via header `x-docdex-repo-id: <repo_id>` or query param `repo_id=<repo_id>`.
- If the daemon is single-repo, do not send a repo_id for a different repo (you will get `unknown_repo`).
- If the daemon is multi-repo and more than one repo is mounted, repo_id is required.

### 3) Search (HTTP)

`GET /search`

Required:
- `q` (query string).

Common params:
- `limit`, `snippets`, `max_tokens`, `include_libs`, `force_web`, `skip_local_search`, `no_cache`,
  `max_web_results`, `llm_filter_local_results`, `diff_mode`, `diff_base`, `diff_head`, `diff_path`,
  `dag_session_id`, `repo_id`.

Notes:
- `skip_local_search=true` effectively forces web discovery (Tier 2).
- If DOCDEX_WEB_ENABLED=1, web discovery can be slow; plan timeouts accordingly.
- Responses include `meta.dag_session_id`; pass it to `/v1/dag/export` or `docdex_dag_export` to export the same trace.

### 3a) Capabilities (HTTP)

`GET /v1/capabilities`

Returns the optional-feature capability contract and current limit values for retrieval extensions.

### 3b) Rerank (HTTP)

`POST /v1/search/rerank`

Required JSON fields:
- `query` (string)
- `candidates` (array of search hits)

Common optional fields:
- `limit`, `repo_id`

Notes:
- Candidate sets are deterministically truncated to the rerank limit exposed by `/v1/capabilities`.
- Response includes `returned_count`, `input_count`, `limit`, and `truncated`.

### 3c) Batch search (HTTP)

`POST /v1/search/batch`

Required JSON fields:
- `queries` (array of query strings)

Common optional fields:
- `limit`, `include_libs`, `repo_id`

Notes:
- Query lists are deterministically truncated to the batch limit exposed by `/v1/capabilities`.
- Response includes `query_count`, `effective_query_count`, `results`, and `truncated`.

### 4) Snippet (HTTP)

`GET /snippet/:doc_id`

Common params:
- `window`, `q`, `text_only`, `max_tokens`, `repo_id`.

### 5) Impact graph (HTTP)

`GET /v1/graph/impact?file=<repo-relative-path>`

Rules:
- `file` must be a path relative to the repo root (not an absolute path).
- Include repo_id header/query when required by daemon mode.

### 6) DAG export (HTTP)

`GET /v1/dag/export?session_id=<id>`

Query params:
- `session_id` (required)
- `format` (optional: json/text/dot; default json)
- `max_nodes` (optional)
- `repo_id` (required when multiple repos are mounted)
Notes:
- Use the `dag_session_id` from `/search` responses (or MCP `docdex_search`/`docdex_web_research`) as the `session_id`. `dag_session_id` is accepted as an alias.

### 7) MCP over HTTP/SSE

- SSE: `/v1/mcp/sse` + `/v1/mcp/message`. When multiple repos are mounted, initialize with `rootUri` first.
- HTTP: `/v1/mcp` accepts repo context in the payload or via prior initialize.
- If HTTP/SSE is unreachable or fails (e.g., connection refused or sandboxed clients), fall back to local IPC: configure `transport = "ipc"` with `socket_path` (Unix) or `pipe_name` (Windows) and send MCP JSON-RPC to `/v1/mcp` over IPC.
- For stdio-only clients (e.g., Smithery), use the `docdex-mcp-stdio` entrypoint to bridge stdio JSON-RPC to Docdex MCP.
- For impact/DAG in sandboxed shells, prefer MCP/IPC tools over `curl` to `/v1/graph/impact` or `/v1/dag/export`.
- MCP tools: `docdex_impact_graph` (impact traversal) and `docdex_dag_export` (DAG export).

### 8) MCP tools (local) - required fields

Do not guess fields; use these canonical shapes.

- `docdex_search`: `{ project_root, query, limit?, diff?, repo_only?, force_web? }`
- `docdex_capabilities`: `{ project_root? }`
- `docdex_rerank`: `{ project_root?, query, candidates, limit? }`
- `docdex_batch_search`: `{ project_root?, queries, limit?, include_libs? }`
- `docdex_open`: `{ project_root, path, start_line?, end_line?, head?, clamp? }` (range must be valid unless clamp/head used)
- `docdex_files`: `{ project_root, limit?, offset? }`
- `docdex_stats`: `{ project_root }`
- `docdex_repo_inspect`: `{ project_root }`
- `docdex_index`: `{ project_root, paths? }` (paths empty => full reindex)
- `docdex_symbols`: `{ project_root, path }`
- `docdex_ast`: `{ project_root, path, max_nodes? }`
- `docdex_impact_diagnostics`: `{ project_root, file? }`
- `docdex_impact_graph`: `{ project_root, file, max_edges?, max_depth?, edge_types? }`
- `docdex_dag_export`: `{ project_root, session_id|dag_session_id, format?, max_nodes? }`
- `docdex_memory_save`: `{ project_root, text }`
- `docdex_memory_recall`: `{ project_root, query, top_k? }`
- `docdex_memory_route`: `{ query, intent?, project_root?, repo_path?, conversation_namespace? }`
- `docdex_memory_layers`: `{ project_root?, repo_path?, conversation_namespace? }`
- `docdex_get_profile`: `{ agent_id }`
- `docdex_save_preference`: `{ agent_id, category, content }`
- `docdex_local_completion`: `{ task_type, instruction, context, max_tokens?, timeout_ms?, mode?, max_context_chars?, agent?, caller_agent_id?, caller_model?, primary_cost_per_million?, project_root?, repo_path? }`
- `docdex_web_research`: `{ project_root, query, force_web, skip_local_search?, web_limit?, no_cache? }`
- `docdex_conversation_import`: `{ source?, source_session_id?, title?, agent_id?, transport?, started_at_ms?, ended_at_ms?, format?, messages?, transcript_text?, metadata?, project_root?, repo_path?, conversation_namespace? }`
- `docdex_conversation_search`: `{ query, agent_id?, limit?, offset?, project_root?, repo_path?, conversation_namespace? }`
- `docdex_conversation_list`: `{ agent_id?, limit?, offset?, project_root?, repo_path?, conversation_namespace? }`
- `docdex_conversation_read`: `{ session_id, project_root?, repo_path?, conversation_namespace? }`
- `docdex_conversation_delete`: `{ session_id, project_root?, repo_path?, conversation_namespace? }`
- `docdex_conversation_export`: `{ session_id, project_root?, repo_path?, conversation_namespace? }`
- `docdex_conversation_redact`: `{ session_id, project_root?, repo_path?, conversation_namespace? }`
- `docdex_conversation_prune`: `{ manual_retention_days?, auto_capture_retention_days?, diary_retention_days?, hook_event_retention_days?, working_memory_retention_days?, episodic_rollup_retention_days?, apply?, project_root?, repo_path?, conversation_namespace? }`
- `docdex_diary_write`: `{ content, agent_id?, entry_type?, source_session_id?, metadata?, project_root?, repo_path?, conversation_namespace? }`
- `docdex_diary_read`: `{ agent_id?, limit?, offset?, project_root?, repo_path?, conversation_namespace? }`
- `docdex_conversation_hook`: `{ action, source?, source_session_id?, title?, agent_id?, transport?, started_at_ms?, ended_at_ms?, format?, messages?, transcript_text?, summary_text?, metadata?, wait_for_processing?, project_root?, repo_path?, conversation_namespace? }`
- `docdex_wakeup`: `{ agent_id?, query?, max_tokens?, project_root?, repo_path?, conversation_namespace? }`
- `docdex_kg_query`: `{ query, relation?, limit?, offset?, project_root?, repo_path?, conversation_namespace? }`
- `docdex_kg_search_nodes`: `{ query, entity_type?, limit?, offset?, project_root?, repo_path?, conversation_namespace? }`
- `docdex_kg_search_edges`: `{ query, relation?, limit?, offset?, project_root?, repo_path?, conversation_namespace? }`
- `docdex_kg_timeline`: `{ entity, relation?, limit?, project_root?, repo_path?, conversation_namespace? }`
- `docdex_kg_search_episodes`: `{ query, source_type?, limit?, offset?, project_root?, repo_path?, conversation_namespace? }`
- `docdex_kg_neighborhood`: `{ entity, relation?, limit?, project_root?, repo_path?, conversation_namespace? }`
- `docdex_kg_entity_links`: `{ entity, link_type?, limit?, project_root?, repo_path?, conversation_namespace? }`
- `docdex_kg_episode`: `{ episode_id?, id?, limit?, project_root?, repo_path?, conversation_namespace? }`
- `docdex_kg_delete_edge`: `{ edge_id, id?, project_root?, repo_path?, conversation_namespace? }`
- `docdex_kg_delete_episode`: `{ episode_id, id?, project_root?, repo_path?, conversation_namespace? }`
- `docdex_kg_rebuild`: `{ project_root?, repo_path?, conversation_namespace? }`
- `docdex_kg_clear`: `{ project_root?, repo_path?, conversation_namespace? }`

Notes:
- `docdex_conversation_import.format` must be one of `auto`, `plain_text`, `generic_json`, `codex_jsonl`, `claude_jsonl`, or `chatgpt_export`.
- `docdex_conversation_hook.action` must be one of `periodic_memory_save`, `pre_compaction_summarization`, or `session_close_summarization`.
- Conversation-memory MCP tools accept `conversation_namespace`; use it instead of `project_root` / `repo_path` for repo-less shared archives.

### 9) Common error fixes (do not guess)

- `unknown_repo`: You are talking to a daemon that does not know that repo. Fix by:
  - Starting a single-repo server for that repo (`docdexd serve --repo /abs/path`), OR
  - Calling `/v1/initialize` on the multi-repo daemon with `rootUri`, then using the returned repo_id.
- `missing_repo`: Supply repo_id (HTTP) or project_root (MCP), or call /v1/initialize.
- `invalid_range` (docdex_open): Adjust start/end line to fit total_lines.
- `missing conversation scope`: Supply `project_root` / `repo_path` for repo-scoped archives or `conversation_namespace` for repo-less shared archives.
- `conflicting conversation scope`: Do not combine `repo_id` / `project_root` with `conversation_namespace` on the same request.

## Interaction Patterns

### 1. Reasoning Workflow

When answering a complex coding query, follow this "Reasoning Trace":

1. Retrieve Profile: Call docdex_get_profile to load user style/constraints (e.g., "Use functional components").
2. Search Code: Call docdex_search or docdex_symbols to find the relevant code.
3. Check Memory: Call docdex_memory_recall for project-specific caveats (e.g., "Auth logic was refactored last week").
4. If prior sessions matter: call `docdex_conversation_search`, `docdex_conversation_read`, or `docdex_wakeup` before relying on implicit chat history.
5. Validate structure: Use docdex_ast/docdex_symbols to confirm targets before editing.
6. Read context: Use docdex_open to fetch minimal file slices after locating targets.
7. Plan with DAG: Use /v1/dag/export or /v1/graph/impact to order changes by dependencies.
8. Synthesize: Generate code that matches the Repo Truth while adhering to the Profile Style.

### 2. Memory Capture (Mandatory)

Save more memories for both lobes during the task, not just at the end.

1. Repo memory: After each meaningful discovery or code change, save at least one durable fact (file location, behavior, config, gotcha) via `docdex_memory_save`.
2. Memory overrides: When a new repo memory replaces older facts, include `metadata.supersedes` with the prior memory id(s). Docdex marks the superseded entries with `supersededBy`/`supersededAtMs`, down-ranks them during recall, and they can be removed via `docdex memory compact` (dry-run unless `--apply`).
3. Profile memory: When the user expresses a preference, constraint, or workflow correction, call `docdex_save_preference` immediately with the right category.
4. Use `docdex_diary_write` for concise session outcomes, handoff notes, or reminders that are useful later but are not durable repo facts.
5. Keep it crisp: 1-3 short sentences, include file paths when relevant, avoid raw code blobs.
6. Safety: Never store secrets, tokens, or sensitive user data. Skip transient or speculative info.

### 3. Index Health + Diff-Aware Search (Mandatory)

Use these when results look incomplete or when the task is about recent changes.

1. Confirm repo binding: Use docdex_repo_inspect or /v1/initialize when repo_id is missing/ambiguous.
2. Check index coverage: Use docdex_stats + docdex_files before assuming code is missing.
3. Reindex if needed: Run docdex_index (or advise it) when stale_index/missing files appear.
4. Use diff search: For change-specific tasks, use docdex_search with diff mode (working tree/staged/range).

### 4. Conversation Memory + Wake-Up Workflow (Mandatory when session history matters)

When the task depends on earlier sessions, durable notes, or handoff state, use the conversation archive instead of relying on implicit chat history.

1. Use `docdex_conversation_search` / `docdex_conversation_list` / `docdex_conversation_read` to recover prior sessions in the current repo or explicit `conversation_namespace`.
2. Use `docdex_wakeup` to assemble compact context from working memory, episodic summaries, KG facts, and transcript snippets before answering.
3. Use `docdex_diary_write` to persist concise durable notes after important milestones; read them back with `docdex_diary_read` when resuming work.
4. Use `docdex_conversation_hook` when importing external agent transcripts or firing periodic/session-close summarization actions.
5. Use `docdex_kg_*` tools when you need entity timelines, provenance episodes, code-facing links, or graph cleanup/rebuild operations.
6. Use `conversation_namespace` only for repo-less/shared archives. Do not combine it with `repo_id`, `project_root`, or `repo_path` on the same request.
7. For `/v1/chat/completions`, set `docdex.agent_id` (or `x-docdex-agent-id`) so wake-up/profile context resolves correctly; responses may include `reasoning_trace` and automatically inject cached `Project map:` context when enabled.

### 5. Local Delegation Workflow (Cheap Models)

When you are an expensive/paid model, delegate eligible low-complexity code-writing tasks and lightweight general questions first unless the user opts out.
Delegation is mandatory for eligible tasks. If you are expensive and delegation is enabled (explicitly or auto-enabled with local candidates), you MUST attempt local delegation before doing the work yourself. Only skip when delegation is disabled, no local candidate exists, or local output fails validation after a retry/fallback.

#### Mandatory Delegation Triggers

- The work fits a delegation task type or can be split into sub-tasks that do.
- The change is small, localized, or mechanical (boilerplate, formatting, docstrings, small refactors).
- The task can be fully expressed in a capsule with explicit context and output rules.

#### Reasons to Delegate (Non-Optional)

- Cuts paid-token usage and cost.
- Lowers latency and avoids rate-limit pressure on premium models.
- Keeps expensive models focused on complex reasoning and multi-step planning.
- Uses tuned prompts that reduce drift for repetitive edits.
- Enforces the product's cost-control policy; skipping delegation is a regression.

1. Determine if you are expensive: load `docs/expensive_models.json` and match your `agent_id`, `agent_slug`, `model`, or adapter type. If you match, continue; if not and you are clearly local/cheap, skip delegation. If unsure, default to expensive.
2. Check config: Only delegate when `[llm.delegation].enabled` is true or `auto_enable` is true with an eligible local model/agent (and `task_type` is allowed). For automatic mcoda selection, eligible means healthy and not paid/expensive unless the user explicitly overrides the target. If uncertain, attempt delegation and handle the error.
3. Choose task type: Use one of `GENERATE_TESTS`, `WRITE_DOCSTRING`, `SCAFFOLD_BOILERPLATE`, `REFACTOR_SIMPLE`, `FORMAT_CODE`, `GENERAL_QUESTION`.
4. Call the tool: `docdex_local_completion` with `task_type`, `instruction`, and minimal `context` (smallest necessary snippet).
5. Validate output: If the local output is invalid or empty, fall back to the primary agent or handle with the paid model.
6. Optional refine: If mode is `draft_then_refine`, refine the draft with the primary agent and return a final result.

#### Delegation Handoff Package (Required)

Local models cannot call tools. The leading agent must provide a complete, minimal capsule.

1. Task capsule: `task_type`, goal, success criteria, output format, and constraints (tests to update, style rules).
2. Context payload: file paths plus the exact snippets from docdex_open; include symbol signatures/AST findings.
3. Dependency notes: summarize impact analysis and any DAG ordering that affects the change.
4. Boundaries: explicit files allowed to edit vs read-only; no new dependencies unless allowed.
5. Guardrails: ask for clarification if context is insufficient; do not invent missing APIs; return only the requested format.

### 6. Graph + AST Usage (Mandatory for Code Changes)

For any code change, use both AST and graph tools to reduce drift and hidden coupling.

1. Use `docdex_ast` or `docdex_symbols` to locate exact definitions and call sites.
2. Call HTTP `/v1/graph/impact?file=...` before edits and summarize inbound/outbound deps.
3. For multi-file changes, export the DAG (`/v1/dag/export`) and order edits by dependency direction.
4. Use docdex_impact_diagnostics when imports are dynamic or unresolved.
5. If graph endpoints are unavailable, state it and proceed cautiously with extra local search.

### 7. Handling Corrections (Learning)

If the user says: "I told you, we do not use Moment.js here, use date-fns!"

- Action: Call docdex_save_preference
- category: "constraint"
- content: "Do not use Moment.js; prefer date-fns."
- agent_id: "default" (or active agent ID)

### 8. Impact Analysis

If the user asks: "Safe to delete getUser?"

- Action: Call GET /v1/graph/impact?file=src/user.ts
- Output: Analyze the inbound edges. If the list is not empty, it is unsafe.

### 9. Non-Repo Real-World Queries (Web First)

If the user asks a non-repo, real-world question (weather, news, general facts), immediately call docdex_web_research with force_web=true.
- Resolve relative dates ("yesterday", "last week") using system time by default.
- Do not run docdex_search unless the user explicitly wants repo-local context.
- Assume web access is allowed unless the user forbids it; if the web call fails, report the failure and ask for a source or permission.

### 10. Failure Handling (Missing Results or Errors)

- Ensure project_root or repo_path is set, or call /v1/initialize to bind a default root.
- Use docdex_repo_inspect to confirm repo identity and normalized root.
- Use docdex_stats and docdex_files to check whether the index exists and contains files.
- Reindex with docdex_index (or docdexd index) if the index is stale or empty.
- Add a repo-local .docdexignore for large generated artifacts or local caches when indexing is slow.

## Operational Context

### Repository Identification

Docdex is multi-tenant via isolation.

- HTTP: Send x-docdex-repo-id header or repo_id query param if communicating with the singleton daemon.
- MCP: Ensure project_root or repo_path is passed in tool arguments if the session is not pinned.

### Error Codes

- missing_repo: You failed to specify which repo to query.
- rate_limited: Back off. The system protects the web scraper and LLM.
- stale_index: The AST parser drifted. Suggest running docdexd index.
- memory_disabled: The user has explicitly disabled memory features.

### Hardware Awareness

Docdex adapts to the host.

- Project Mapping: On constrained hardware, docdex uses a "Spotlight Heuristic" to show you only a skeletal file tree based on your role keywords, rather than the full file system.
- LLM: It may be running a quantized model (e.g., phi3.5) or a heavy model (llama3.1:70b) depending on VRAM. Trust the daemon's token limits; it handles truncation.
---- END OF DOCDEX INFO -----
