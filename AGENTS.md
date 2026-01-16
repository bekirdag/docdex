# Docdex Agent Usage Instructions

> Context for AI Agents: Docdex is your local-first Dual-Lobe Memory and Code Intelligence daemon. Unlike simple vector stores, it provides structural understanding of code (AST/Graph), persistent behavioral profiles (Agent Memory), and gated web enrichment, all strictly scoped to the local machine.

## Identity & Architecture

Docdex (Documentation Indexer) serves as your persistent "brain" on the user's machine. It operates on a Waterfall Retrieval model:

1. Local First (Tier 1): Instant search of repo code, symbols, and ingested library documentation.
2. Web Enrichment (Tier 2): Gated fallback to DuckDuckGo HTML + Headless Chrome only when local confidence is low or explicitly requested. Discovery fallbacks include DuckDuckGo Lite, SearXNG JSON, Google Mobile, and optional API-backed providers (Tavily, Exa) when configured.
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
- Usage: Use this to "learn" from corrections. If a user corrects your style, save it here so you do not repeat the mistake in a different repo.

## Tool Capabilities (MCP & HTTP)

### A. Semantic Search & Web (Waterfall)

Standard retrieval. The daemon automatically handles the waterfall (Local -> Web).

| MCP Tool | Purpose |
| --- | --- |
| docdex_search | Search code, docs, and ingested libraries. Returns ranked snippets. |
| docdex_web_research | Explicitly trigger Tier 2 web discovery (DDG + Headless Chrome). Use when you need external docs not present locally. |

Tier 2 discovery providers (in fallback order when DDG HTML fails or is blocked):
- DuckDuckGo Lite
- SearXNG JSON (public instance or self-hosted)
- Google Mobile
- Brave Search API (requires DOCDEX_BRAVE_API_KEY)
- Google Custom Search JSON API (requires DOCDEX_GOOGLE_CSE_API_KEY + DOCDEX_GOOGLE_CSE_CX)
- Bing Web Search API (requires DOCDEX_BING_API_KEY)
- Tavily API (requires DOCDEX_TAVILY_API_KEY)
- Exa API (requires DOCDEX_EXA_API_KEY)

Defaults and overrides:
- Default endpoints: `https://html.duckduckgo.com/html/`, `https://lite.duckduckgo.com/lite/`, `https://searx.be/search` (built-in fallback list), `https://www.google.com/m`, `https://api.search.brave.com/res/v1/web/search`, `https://www.googleapis.com/customsearch/v1`, `https://api.bing.microsoft.com/v7.0/search`, `https://api.tavily.com/search`, `https://api.exa.ai/search`
- Override envs: `DOCDEX_DDG_BASE_URL`, `DOCDEX_WEB_SEARXNG_URLS` (comma list, or `DOCDEX_SEARXNG_URLS`), `DOCDEX_WEB_GOOGLE_MOBILE_URL`, `DOCDEX_BRAVE_API_KEY` + `DOCDEX_BRAVE_API_URL`, `DOCDEX_GOOGLE_CSE_API_KEY` + `DOCDEX_GOOGLE_CSE_CX` + `DOCDEX_GOOGLE_CSE_API_URL`, `DOCDEX_BING_API_KEY` + `DOCDEX_BING_API_URL`, `DOCDEX_TAVILY_API_KEY` + `DOCDEX_TAVILY_API_URL`, `DOCDEX_EXA_API_KEY` + `DOCDEX_EXA_API_URL`

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
