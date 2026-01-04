---
title: Memory Isolation Tasks (Multi-Repo)
status: complete
owner: docdex
---

# Memory Isolation Tasks (Multi-Repo)

## Task 1: repo-selection-audit
**Title:** Audit repo selection and default fallback behavior  
**Description:** Map all locations where repo_id is derived or defaulted, including MCP session handling, HTTP endpoints, and memory/chat pipelines. Document current behavior and risky fallbacks.  
**Files to touch:**  
- `docs/memory_isolation_plan.md` (notes)  
- `src/daemon/*`  
- `crates/mcp-server/src/lib.rs`  
- `src/api/v1/*`  
**Acceptance criteria:**  
- Written summary of current repo selection flow and all fallback points.  
**Dependencies:** None

## Task 2: mcp-session-repo-binding
**Title:** Bind repo_id to MCP session at initialize  
**Description:** Store rootUri→repo_id per MCP connection/session and use it as the default repo for all tool calls on that session. Remove/avoid global mutable defaults.  
**Files to touch:**  
- `crates/mcp-server/src/lib.rs`  
- `src/daemon/multi_repo.rs` (or session manager)  
**Acceptance criteria:**  
- Two concurrent MCP sessions keep distinct repo_id bindings.  
- Tool calls without explicit repo_id use the session binding.  
**Dependencies:** Task 1

## Task 3: multi-repo-scope-enforcement
**Title:** Enforce repo_id in multi-repo mode  
**Description:** When more than one repo is active, reject requests missing repo_id unless a session binding exists. Preserve single-repo behavior.  
**Files to touch:**  
- `src/api/v1/*` (chat/search/memory)  
- `crates/mcp-server/src/lib.rs`  
**Acceptance criteria:**  
- Multi-repo mode rejects missing repo_id with a stable error.  
- Single-repo mode continues to work without repo_id.  
**Dependencies:** Task 2

## Task 4: memory-guardrails
**Title:** Guardrails for memory and chat assembly  
**Description:** Validate repo_id/fingerprint on memory store/recall and chat context assembly. Drop mismatches and emit metrics/warnings.  
**Files to touch:**  
- `src/memory/*`  
- `src/api/v1/chat.rs`  
- `src/orchestrator/*`  
**Acceptance criteria:**  
- Mismatched memory never appears in chat context.  
- Metrics/logs emitted on mismatch.  
**Dependencies:** Task 3

## Task 5: isolation-tests
**Title:** Add multi-repo isolation tests  
**Description:** Add tests for MCP + HTTP multi-repo isolation: two sessions, two repos, missing repo_id in multi-repo should error, and no cross-repo memory.  
**Files to touch:**  
- `tests/mcp_multi_repo_concurrency.rs`  
- `tests/http_multi_repo.rs`  
- `tests/memory_*`  
- `tests/chat_*`  
**Acceptance criteria:**  
- Tests pass locally and in CI.  
- Demonstrates no leakage across repos.  
**Dependencies:** Task 2, Task 3, Task 4

## Task 6: docs-update
**Title:** Document repo scoping rules and isolation guidance  
**Description:** Update usage + API docs to explain repo scoping, session binding, and how to isolate agent memory with agent_id.  
**Files to touch:**  
- `README.md`  
- `docs/usage.md`  
- `docs/http_api.md`  
**Acceptance criteria:**  
- Docs explain when repo_id is required and how MCP session binding works.  
**Dependencies:** Task 3
