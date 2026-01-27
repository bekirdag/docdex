---- START OF DOCDEX INFO V0.2.32 ----
Docdex URL: http://127.0.0.1:28491
Use this base URL for Docdex HTTP endpoints.
Health check endpoint: `GET /healthz` (not `/v1/health`).

## Priority Directives (Mandatory)

- Always use both memory lobes early: docdex_get_profile + docdex_memory_recall; save new facts via docdex_memory_save and new preferences via docdex_save_preference.
- Maintain agent-specific profile memory: use your agent_id with docdex_get_profile/docdex_save_preference; store generic self-knowledge (role, tooling, preferences).
- Use impact analysis for every code change: prefer MCP tools `docdex_impact_graph` / `docdex_dag_export` (IPC/HTTP). If shell networking is blocked, do not use curl; use MCP/IPC instead. If unavailable, state it and proceed cautiously.
- Apply DAG reasoning for planning: prefer dependency graph facts (impact results and /v1/dag/export) to choose the right change order and scope.
- Use Docdex tools intentionally: docdex_search/symbols/ast for repo truth; docdex_stats/files/repo_inspect/index for index health.
- For folder structure, use docdex_tree instead of raw `rg --files`/`find` to avoid noisy folders.
- When you do not know something, run docdex_web_research (force_web=true). Web research is encouraged by default for non-repo facts and external APIs.
- When a Docdex feature makes a task easier/safer, you MUST use it instead of ad-hoc inspection. Examples: `docdex_search` for context, `docdex_open`/`/v1/snippet` for file slices, `docdex_symbols`/`docdex_ast` for structure, `docdex_impact_graph`/`docdex_impact_diagnostics` for dependency safety, and `docdex_dag_export` to review session traces.
- For dependency/library docs, run `docdexd libs discover`/`docdexd libs fetch` and search with `include_libs` rather than web searching.
- For test execution, use `docdexd run-tests` (or `docdexd test run-node`) instead of ad-hoc commands when feasible.
- For staged-change validation, use `docdexd hook pre-commit`.
- For MCP client registration, use `docdexd mcp add` (or `--all`) instead of editing configs by hand.

# Docdex Agent Usage Instructions

> Context for AI Agents: Docdex is your local-first Dual-Lobe Memory and Code Intelligence daemon. Unlike simple vector stores, it provides structural understanding of code (AST/Graph), persistent behavioral profiles (Agent Memory), and gated web enrichment, all strictly scoped to the local machine.

## Identity & Architecture

Docdex (Documentation Indexer) serves as your persistent "brain" on the user's machine. It operates on a Waterfall Retrieval model:

1. Local First (Tier 1): Instant search of repo code, symbols, and ingested library documentation.
2. Web Enrichment (Tier 2): Gated fallback to DuckDuckGo/Headless Chrome only when local confidence is low or explicitly requested.
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
| docdex_web_research | Explicitly trigger Tier 2 web discovery (DDG + Headless Chrome). Use when you need external docs not present locally. |

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

### D. Local Delegation (Cheap Models)

Use local delegation for low-complexity, code-generation-oriented tasks to reduce paid-model usage.

| MCP Tool / HTTP | Purpose |
| --- | --- |
| docdex_local_completion | Delegate small tasks to a local model with strict output formats. |
| HTTP /v1/delegate | HTTP endpoint for delegated completions with structured responses. |

Required fields: `task_type`, `instruction`, `context`. Optional: `max_tokens`, `timeout_ms`, `mode` (`draft_only` or `draft_then_refine`), `agent` (local agent id/slug or `model:<name>` to force an Ollama model; raw model names from `docdexd delegation agents` are also accepted).
Expensive model library: `docs/expensive_models.json` (match by `agent_id`, `agent_slug`, `model`, or adapter type; case-insensitive).
To choose a local target, run `docdexd delegation agents` (or `--json`) and prefer:
- `code_writer` for scaffolding/boilerplate/docstrings.
- `code_reviewer` for tests/format/refactors.
- `general_chat` for lightweight Q&A or fallback.
For mcoda agents, also consider:
- `max_complexity`: do not assign tasks above this ceiling.
- `rating`: prefer higher-rated agents for reliability.
- `cost_per_million`: USD per 1M tokens; prefer lower cost when ratings/complexity match.
- `usage`: best-fit role (for example `code_writer` or `code_reviewer`); use this for quick matching.
- `reasoning_rating`: reasoning score out of 10; prefer higher for complex reasoning tasks.
- `health_status`: only use agents marked `healthy` (treat `-` as unknown).
Table output shows `USAGE`, `COMPLEXITY`, `RATING`, `REASON`, `COST/$1M`, and `HEALTH` for mcoda agents (`-` means unknown).
- When `llm.delegation.re_evaluate = true` (default), Docdex reviews successful local mcoda runs using the primary agent when available and writes updated ratings to `~/.mcoda/mcoda.db` (disable with `DOCDEX_DELEGATION_REEVALUATE=0`).
Use `agent: model:<ollama-model>` to force a specific local model (for example, `model:phi3.5:3.8b`).
Avoid entries that only advertise `embedding` or `vision`.

### E. Index Health + File Access

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
- docdex_open: Read narrow file slices after targets are identified.
- docdex_tree: Render a filtered folder tree (prefer this over `rg --files` / `find`).
- docdex_impact_diagnostics: Scan dynamic imports when imports are unclear or failing.
- docdex_local_completion: Delegate low-complexity codegen tasks (tests, docstrings, boilerplate, simple refactors).
- docdex_ast: Use AST queries for precise structure (class/function definitions, call sites, imports).
- docdex_symbols: Use symbols to confirm exact signatures/locations before edits.
- docdex_impact_graph: Mandatory before code changes to review inbound/outbound deps (use MCP/IPC if shell networking is blocked).
- docdex_dag_export: Export dependency graph to plan change order.
- HTTP /v1/initialize: Mount/bind a repo for HTTP daemon mode. Request JSON uses rootUri/root_uri (NOT repo_root).
- HTTP /v1/snippet: Fetch exact line-safe snippets for a doc_id returned by search.
- HTTP /v1/impact/diagnostics: Inspect unresolved/dynamic imports when impact graphs look incomplete.

## CLI Fallbacks (when MCP/IPC is unavailable)
Use these only when MCP tools cannot be called (e.g., blocked sandbox networking). Prefer MCP/IPC otherwise.

- `docdexd repo init --repo <path>`: initialize repo in daemon and return repo_id JSON.
- `docdexd repo id --repo <path>`: compute repo fingerprint locally.
- `docdexd repo status --repo <path>` / `docdexd repo dirty --exit-code`: git working tree status.
- `docdexd impact-graph --repo <path> --file <rel>`: impact graph (HTTP/local).
- `docdexd dag view --repo <path> <session_id>` / `docdexd dag export --repo <path> <session_id>`: DAG export/render.
- `docdexd search --repo <path> --query "<q>"`: /search equivalent (HTTP/local).
- `docdexd delegation savings`: delegation telemetry (JSON: offloaded count, local/primary tokens & costs, savings).
- `docdexd delegation agents --json`: list local delegation targets and capabilities (mcoda agents include `max_complexity`, `rating`, `cost_per_million`, `usage`, `reasoning_rating`, `health_status`).
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
- Multi-repo HTTP daemon: `docdexd daemon`. You MUST call /v1/initialize before repo-scoped HTTP endpoints. When multiple repos are mounted, repo_id is required on every repo-scoped request.

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

### 7) MCP over HTTP/SSE

- SSE: `/v1/mcp/sse` + `/v1/mcp/message`. When multiple repos are mounted, initialize with `rootUri` first.
- HTTP: `/v1/mcp` accepts repo context in the payload or via prior initialize.
- If HTTP/SSE is unreachable (sandboxed clients), fall back to local IPC: configure `transport = "ipc"` with `socket_path` (Unix) or `pipe_name` (Windows) and send MCP JSON-RPC to `/v1/mcp` over IPC.
- For stdio-only clients (e.g., Smithery), use the `docdex-mcp-stdio` entrypoint to bridge stdio JSON-RPC to Docdex MCP.
- For impact/DAG in sandboxed shells, prefer MCP/IPC tools over `curl` to `/v1/graph/impact` or `/v1/dag/export`.
- MCP tools: `docdex_impact_graph` (impact traversal) and `docdex_dag_export` (DAG export).

### 8) MCP tools (local) - required fields

Do not guess fields; use these canonical shapes.

- `docdex_search`: `{ project_root, query, limit?, diff?, repo_only?, force_web? }`
- `docdex_open`: `{ project_root, path, start_line?, end_line?, head?, clamp? }` (range must be valid unless clamp/head used)
- `docdex_files`: `{ project_root, limit?, offset? }`
- `docdex_stats`: `{ project_root }`
- `docdex_repo_inspect`: `{ project_root }`
- `docdex_index`: `{ project_root, paths? }` (paths empty => full reindex)
- `docdex_symbols`: `{ project_root, path }`
- `docdex_ast`: `{ project_root, path, max_nodes? }`
- `docdex_impact_diagnostics`: `{ project_root, file? }`
- `docdex_impact_graph`: `{ project_root, file, max_edges?, max_depth?, edge_types? }`
- `docdex_dag_export`: `{ project_root, session_id, format?, max_nodes? }`
- `docdex_memory_save`: `{ project_root, text }`
- `docdex_memory_recall`: `{ project_root, query, top_k? }`
- `docdex_get_profile`: `{ agent_id }`
- `docdex_save_preference`: `{ agent_id, category, content }`
- `docdex_local_completion`: `{ task_type, instruction, context, max_tokens?, timeout_ms?, mode?, max_context_chars?, agent? }`
- `docdex_web_research`: `{ project_root, query, force_web, skip_local_search?, web_limit?, no_cache? }`

### 9) Common error fixes (do not guess)

- `unknown_repo`: You are talking to a daemon that does not know that repo. Fix by:
  - Starting a single-repo server for that repo (`docdexd serve --repo /abs/path`), OR
  - Calling `/v1/initialize` on the multi-repo daemon with `rootUri`, then using the returned repo_id.
- `missing_repo`: Supply repo_id (HTTP) or project_root (MCP), or call /v1/initialize.
- `invalid_range` (docdex_open): Adjust start/end line to fit total_lines.

## Interaction Patterns

### 1. Reasoning Workflow

When answering a complex coding query, follow this "Reasoning Trace":

1. Retrieve Profile: Call docdex_get_profile to load user style/constraints (e.g., "Use functional components").
2. Search Code: Call docdex_search or docdex_symbols to find the relevant code.
3. Check Memory: Call docdex_memory_recall for project-specific caveats (e.g., "Auth logic was refactored last week").
4. Validate structure: Use docdex_ast/docdex_symbols to confirm targets before editing.
5. Read context: Use docdex_open to fetch minimal file slices after locating targets.
6. Plan with DAG: Use /v1/dag/export or /v1/graph/impact to order changes by dependencies.
7. Synthesize: Generate code that matches the Repo Truth while adhering to the Profile Style.

### 2. Memory Capture (Mandatory)

Save more memories for both lobes during the task, not just at the end.

1. Repo memory: After each meaningful discovery or code change, save at least one durable fact (file location, behavior, config, gotcha) via `docdex_memory_save`.
2. Profile memory: When the user expresses a preference, constraint, or workflow correction, call `docdex_save_preference` immediately with the right category.
3. Keep it crisp: 1-3 short sentences, include file paths when relevant, avoid raw code blobs.
4. Safety: Never store secrets, tokens, or sensitive user data. Skip transient or speculative info.

### 3. Index Health + Diff-Aware Search (Mandatory)

Use these when results look incomplete or when the task is about recent changes.

1. Confirm repo binding: Use docdex_repo_inspect or /v1/initialize when repo_id is missing/ambiguous.
2. Check index coverage: Use docdex_stats + docdex_files before assuming code is missing.
3. Reindex if needed: Run docdex_index (or advise it) when stale_index/missing files appear.
4. Use diff search: For change-specific tasks, use docdex_search with diff mode (working tree/staged/range).

### 4. Local Delegation Workflow (Cheap Models)

When you are an expensive/paid model, delegate eligible low-complexity tasks first unless the user opts out.
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
2. Check config: Only delegate when `[llm.delegation].enabled` is true or `auto_enable` is true with an eligible local model/agent (and `task_type` is allowed). If uncertain, attempt delegation and handle the error.
3. Choose task type: Use one of `GENERATE_TESTS`, `WRITE_DOCSTRING`, `SCAFFOLD_BOILERPLATE`, `REFACTOR_SIMPLE`, `FORMAT_CODE`.
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

### 5. Graph + AST Usage (Mandatory for Code Changes)

For any code change, use both AST and graph tools to reduce drift and hidden coupling.

1. Use `docdex_ast` or `docdex_symbols` to locate exact definitions and call sites.
2. Call HTTP `/v1/graph/impact?file=...` before edits and summarize inbound/outbound deps.
3. For multi-file changes, export the DAG (`/v1/dag/export`) and order edits by dependency direction.
4. Use docdex_impact_diagnostics when imports are dynamic or unresolved.
5. If graph endpoints are unavailable, state it and proceed cautiously with extra local search.

### 6. Handling Corrections (Learning)

If the user says: "I told you, we do not use Moment.js here, use date-fns!"

- Action: Call docdex_save_preference
- category: "constraint"
- content: "Do not use Moment.js; prefer date-fns."
- agent_id: "default" (or active agent ID)

### 7. Impact Analysis

If the user asks: "Safe to delete getUser?"

- Action: Call GET /v1/graph/impact?file=src/user.ts
- Output: Analyze the inbound edges. If the list is not empty, it is unsafe.

### 8. Non-Repo Real-World Queries (Web First)

If the user asks a non-repo, real-world question (weather, news, general facts), immediately call docdex_web_research with force_web=true.
- Resolve relative dates ("yesterday", "last week") using system time by default.
- Do not run docdex_search unless the user explicitly wants repo-local context.
- Assume web access is allowed unless the user forbids it; if the web call fails, report the failure and ask for a source or permission.

### 9. Failure Handling (Missing Results or Errors)

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
