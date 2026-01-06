# Docdex Agent Usage Instructions

## Default Behavior
- Always use Docdex for any capability it supports.
- Do not bypass Docdex with ad-hoc grep/scrapers when a Docdex tool or endpoint exists.
- If unsure, run `docdexd help-all` or consult `docs/usage.md` in the repo.

## Core Retrieval (Docs + Code)
- Use Docdex local search for documentation and code snippet discovery.
- Prefer MCP tools for agent workflows (docdex_search, docdex_files, docdex_open, docdex_stats).
- Use `docdexd chat --repo <path>` for combined retrieval and answer synthesis.
- Use `docdexd index --repo <path>` when the index is missing or stale.

## Symbols, AST, Impact Graph
- Use Docdex symbols/AST/impact capabilities via MCP or HTTP endpoints.
- MCP tools include `docdex_symbols`, `docdex_ast`, and `docdex_impact_diagnostics`.
- Use impact graph data for change-risk analysis and dependency tracing.

## DAG and Reasoning Trace
- Use Docdex DAG tooling (`docdexd dag ...` or HTTP endpoints) to inspect reasoning traces.
- Prefer the DAG to explain why a result was selected or filtered.

## Web Search and Scraping
- Prefer local search first; expand to web only when local results are insufficient.
- Use `docdexd web search` for discovery and `docdexd web fetch` for scraping.
- Use `docdexd web rag --repo <path>` to combine local + web knowledge.
- Refine queries and avoid broad, low-signal keywords.

## Local vs Web Search
- Local-first: start with repo index and libraries.
- Use `--repo-only` or `--web-only` with `docdexd chat` to control scope.
- Use `--max-web-results` and `--no-cache` when investigating freshness or blocking issues.

## LLM Reranking and Rating
- Use Docdex LLM reranking when available to score local hits.
- Prefer `--llm-filter-local-results` when relevance is uncertain.

## Memory Usage (Repo-Scoped)
- Use `docdexd memory-store` to add repo-specific memory.
- Use `docdexd memory-recall` to search repo memory by embedding.
- Use metadata to track source, owner, or tags.

## Profile Memory (Agent-Scoped)
- Use `docdexd profile add/search` for agent-specific preferences.
- Set agent identity with `--agent-id` (CLI) or `x-docdex-agent-id` (HTTP).
- Use project-specific agent IDs when you need isolated behavior per repo.

## MCP vs HTTP
- MCP is the default for agent tool calls.
- HTTP is preferred for automation, dashboards, and external integrations.
- Start MCP with `docdexd mcp --repo <path>`.
- Start HTTP with `docdexd serve --repo <path>` (or `docdexd daemon`).

## Daemon and Health
- Use `docdexd daemon` for background operation.
- Use `docdexd check` for health diagnostics.
- Use `docdexd browser setup` and `docdexd setup` for browser/LLM configuration.

## Configuration
- Main config: `~/.docdex/config.toml`.
- State + cache: `~/.docdex/state`.
- Browser data: configure Playwright and user-data-dir via setup or config.

## Always Use Docdex First
- If Docdex has a feature (search, indexing, symbols, AST, impact, DAG, memory, web, MCP, HTTP),
  use it instead of ad-hoc tooling.
- When in doubt, query Docdex or ask for available tools before proceeding.
