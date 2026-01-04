---
title: Memory Isolation Fix Plan (Multi-Repo)
status: complete
owner: docdex
---

# Memory Isolation Fix Plan (Multi-Repo)

## Goal
Eliminate cross-repo leakage of memory/context when multiple Codex/MCP clients are connected to the same daemon. Ensure each request is scoped to the correct repo, and reject or drop unsafe cross-repo context.

## Problem Summary
When multiple MCP sessions run concurrently, repo selection may fall back to a mutable global “default repo”. Requests missing `repo_id` can silently use the wrong repo, causing memory/context from one repo to leak into another.

## Audit Notes (Repo Selection & Fallbacks)
- **HTTP API**: `resolve_repo_context` selects repo via `x-docdex-repo-id` or `repo_id` (query/body). Previously defaulted to the daemon’s base repo when missing.
- **MCP HTTP proxy**: `mcp_request_handler` used a global default repo set by the latest initialize; tool calls without `project_root` used that default.
- **MCP SSE sessions**: session binding existed but did not enforce repo scoping when missing `rootUri`.
- **Repo manager**: multi-repo mode tracks repo mounts but did not require `repo_id` for API calls when >1 repo active.
- **Memory/chat**: memory store/recall used repo-scoped DBs, but wrong repo selection could still pull the wrong memory into chat context.

## Design Principles
- **Session-scoped repo binding:** Repo identity is stored per MCP connection, not globally.
- **Explicit scoping required:** When multiple repos are active, a request without `repo_id` must fail fast unless a session-bound repo exists.
- **Fail safe:** When repo mismatch is detected, drop memory/context and log metrics.
- **Backwards compatible:** Single-repo usage should remain seamless.

## Work Plan

### 1) Audit current repo selection flow
**Focus**
- Locate global/default repo tracking in daemon + MCP server.
- Identify where `repo_id` is optional and where it falls back to “last initialized”.

**Likely files**
- `src/daemon/*`
- `crates/mcp-server/src/lib.rs`
- `src/api/v1/*` (search/chat/memory)

**Acceptance**
- Clear map of repo selection paths and fallback behavior.

---

### 2) Bind repo to MCP session (initialize → session state)
**Changes**
- Store `rootUri` → `repo_id` on MCP connection state at `initialize`.
- Use session-bound repo_id for all subsequent tool calls in that session.
- Prevent overwriting the binding globally.

**Likely files**
- `crates/mcp-server/src/lib.rs`
- `src/daemon/multi_repo.rs` or session manager

**Acceptance**
- Two MCP sessions can run concurrently with distinct repos, no cross-use.

---

### 3) Enforce repo scoping for multi-repo
**Changes**
- If multiple repos are mounted and a request lacks `repo_id` and no session binding exists, return a clear error.
- Keep legacy behavior for single-repo mode.

**Likely files**
- `src/api/v1/*`
- `crates/mcp-server/src/lib.rs`

**Acceptance**
- Missing `repo_id` yields deterministic error only when multiple repos are active.

---

### 4) Guardrail memory + chat assembly
**Changes**
- Verify repo fingerprint matches request repo before memory recall/store.
- Drop mismatched entries, log metric + warning.
- Ensure agent memory (profiles) remains global by design, but highlight in docs.

**Likely files**
- `src/memory/*`
- `src/api/v1/chat.rs`
- `src/orchestrator/*`

**Acceptance**
- Any mismatched memory is ignored and recorded in metrics.

---

### 5) Tests
**New/updated tests**
- MCP multi-repo isolation for memory + chat + search.
- HTTP multi-repo isolation with and without repo_id.
- Ensure missing repo_id returns error only when >1 repo active.

**Likely files**
- `tests/mcp_multi_repo_concurrency.rs`
- `tests/http_multi_repo.rs`
- `tests/memory_*`
- `tests/chat_*`

**Acceptance**
- Deterministic green tests with concurrent sessions; no cross-repo context.

---

### 6) Documentation updates
**Changes**
- Clarify repo scoping rules (MCP + HTTP).
- Recommend unique `agent_id` per workspace if profile isolation desired.

**Likely files**
- `README.md`
- `docs/usage.md`
- `docs/http_api.md`

**Acceptance**
- Docs explicitly state when repo_id is required and how session binding works.

## Risks / Mitigations
- **Risk:** breaking legacy clients that omit repo_id.  
  **Mitigation:** only enforce when multiple repos are active.

- **Risk:** session binding not available for some transports.  
  **Mitigation:** allow explicit repo_id header/body as override.

## Exit Criteria
- No cross-repo leakage in concurrent sessions.
- Clear errors on missing repo_id in multi-repo mode.
- Updated docs and tests. 
