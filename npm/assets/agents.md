---- START OF DOCDEX INFO V0.2.25 ----
Docdex URL: http://127.0.0.1:28491
Use this base URL for Docdex HTTP endpoints.

## Priority Directives (Mandatory)

- Always use both memory lobes early: docdex_get_profile + docdex_memory_recall; save new facts via docdex_memory_save and new preferences via docdex_save_preference.
- Maintain agent-specific profile memory: use your agent_id with docdex_get_profile/docdex_save_preference; store generic self-knowledge (role, tooling, preferences).
- Use impact analysis for every code change: call HTTP /v1/graph/impact?file=... and account for inbound/outbound deps; if unavailable, state it and proceed cautiously.
- Apply DAG reasoning for planning: prefer dependency graph facts (impact results and /v1/dag/export) to choose the right change order and scope.
- Use Docdex tools intentionally: docdex_search/symbols/ast for repo truth; docdex_stats/files/repo_inspect/index for index health.
- When you do not know something, run docdex_web_research (force_web=true). Web research is encouraged by default for non-repo facts and external APIs.

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
| HTTP /v1/graph/impact | Impact Analysis: "What breaks if I change this?" Returns inbound/outbound dependencies. |
| HTTP /v1/dag/export | Export the dependency DAG for change ordering and scope. |

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

Required fields: `task_type`, `instruction`, `context`. Optional: `max_tokens`, `timeout_ms`, `mode` (`draft_only` or `draft_then_refine`), `agent` (local agent id/slug).
Expensive model library: `docs/expensive_models.json` (match by `agent_id`, `agent_slug`, `model`, or adapter type; case-insensitive).

### E. Index Health + File Access

Use these to verify index coverage, repo binding, and to read precise file slices.

| MCP Tool | Purpose |
| --- | --- |
| docdex_repo_inspect | Confirm normalized repo root/identity (resolve missing_repo). |
| docdex_stats | Index size/last update; detect stale indexes. |
| docdex_files | Indexed file coverage; confirm a file is in the index. |
| docdex_index | Reindex full repo or ingest specific files when stale/missing. |
| docdex_open | Read exact file slices after you identify targets. |

## Quick Tool Map (Often Missed)

- docdex_files: List indexed docs with rel_path/doc_id/token_estimate; use to verify indexing coverage.
- docdex_stats: Show index size, state dir, and last update time.
- docdex_repo_inspect: Confirm normalized repo root and repo identity mapping.
- docdex_index: Reindex the full repo or ingest specific files when stale.
- docdex_search diff: Limit search to working tree, staged, or ref ranges; filter by paths.
- docdex_web_research knobs: force_web, skip_local_search, repo_only, no_cache, web_limit, llm_filter_local_results, llm_model.
- docdex_open: Read narrow file slices after targets are identified.
- docdex_impact_diagnostics: Scan dynamic imports when imports are unclear or failing.
- docdex_local_completion: Delegate low-complexity codegen tasks (tests, docstrings, boilerplate, simple refactors).
- docdex_ast: Use AST queries for precise structure (class/function definitions, call sites, imports).
- docdex_symbols: Use symbols to confirm exact signatures/locations before edits.
- HTTP /v1/graph/impact: Mandatory before code changes to review inbound/outbound deps.
- HTTP /v1/dag/export: Export dependency graph to plan change order.
- HTTP /v1/initialize: Bind a default repo root for MCP when clients omit project_root.

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
