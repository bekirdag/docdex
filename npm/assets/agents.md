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

### C. Memory Operations

| MCP Tool | Purpose |
| --- | --- |
| docdex_memory_save | Store a technical fact about the current repo. |
| docdex_memory_recall | Retrieve technical facts about the current repo. |
| docdex_save_preference | Store a global user preference (Style, Tooling, Constraint). |
| docdex_get_profile | Retrieve global preferences. |

## Quick Tool Map (Often Missed)

- docdex_files: List indexed docs with rel_path/doc_id/token_estimate; use to verify indexing coverage.
- docdex_stats: Show index size, state dir, and last update time.
- docdex_repo_inspect: Confirm normalized repo root and repo identity mapping.
- docdex_index: Reindex the full repo or ingest specific files when stale.
- docdex_search diff: Limit search to working tree, staged, or ref ranges; filter by paths.
- docdex_web_research knobs: force_web, skip_local_search, repo_only, no_cache, web_limit, llm_filter_local_results, llm_model.
- HTTP /v1/initialize: Bind a default repo root for MCP when clients omit project_root.
- HTTP /v1/dag/export: Export the dependency graph for external analysis.

## Interaction Patterns

### 1. Reasoning Workflow

When answering a complex coding query, follow this "Reasoning Trace":

1. Retrieve Profile: Call docdex_get_profile to load user style/constraints (e.g., "Use functional components").
2. Search Code: Call docdex_search or docdex_symbols to find the relevant code.
3. Check Memory: Call docdex_memory_recall for project-specific caveats (e.g., "Auth logic was refactored last week").
4. Synthesize: Generate code that matches the Repo Truth while adhering to the Profile Style.

### 2. Handling Corrections (Learning)

If the user says: "I told you, we do not use Moment.js here, use date-fns!"

- Action: Call docdex_save_preference
- category: "constraint"
- content: "Do not use Moment.js; prefer date-fns."
- agent_id: "default" (or active agent ID)

### 3. Impact Analysis

If the user asks: "Safe to delete getUser?"

- Action: Call GET /v1/graph/impact?file=src/user.ts
- Output: Analyze the inbound edges. If the list is not empty, it is unsafe.

### 4. Non-Repo Real-World Queries (Web First)

If the user asks a non-repo, real-world question (weather, news, general facts), immediately call docdex_web_research with force_web=true.
- Resolve relative dates ("yesterday", "last week") using system time by default.
- Do not run docdex_search unless the user explicitly wants repo-local context.
- Assume web access is allowed unless the user forbids it; if the web call fails, report the failure and ask for a source or permission.

### 5. Failure Handling (Missing Results or Errors)

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
