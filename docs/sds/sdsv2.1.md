# System Design Specification: Docdex v2.1

**Feature:** Agent Profile & Preference Memory (Global Context Layer)

*This document defines the specification for the v2.1 "Agent Profile" extension. This feature runs **parallel** to the v2.0 Repository Memory system, introducing a global, evolutionary memory store specifically designed for the **Mcoda** multi-agent environment.*

---

## 1. Architecture Overview

### 1.1 Design Philosophy: The "Dual-Lobe" Memory

To prevent contamination between *technical facts* (Repo Code) and *behavioral preferences* (Agent Rules), v2.1 introduces a strict separation of concerns:

1. **Repo Memory (v2.0 - Existing):**
* **Scope:** Repository-bound (`~/.docdex/state/repos/<hash>/memory.db`).
* **Role:** Technical RAG. Stores immutable code snippets and project-specific docs.
* **Lifecycle:** Append-only / LRU Eviction.
* **Status:** **UNCHANGED**.


2. **Profile Memory (v2.1 - New):**
* **Scope:** Global / Team-bound (`~/.docdex/state/profiles/main.db`).
* **Role:** Behavioral Adaptation. Stores agent preferences, coding style guides, and cross-project lessons.
* **Lifecycle:** Evolutionary (Read  Reason  Update/Delete).
* **Status:** **NEW COMPONENT**.



### 1.2 System Diagram

The `Waterfall Orchestrator` now queries two distinct memory systems before generating a response.

---

## 2. Core Components

### 2.1 Profile Manager (`src/profiles/`)

A new singleton service responsible for the lifecycle of the global `profile.db`. Unlike the `RepoManager` which manages many ephemeral DB handles, the `ProfileManager` holds a single persistent connection to the global profile database.

* **Responsibilities:**
* Initialize `~/.docdex/state/profiles/` on startup.
* Manage the SQLite-vec connection to `main.db`.
* Expose CRUD operations for Agent Entities and Preference Facts.



### 2.2 The Evolution Pipeline (`src/profiles/evolution.rs`)

This engine implements the "Mem0-like" logic to keep preferences clean and non-contradictory. It does not just append data; it actively curates it.

* **Logic Flow:**
1. **Input:** New Fact ("I prefer `vitest` over `jest`").
2. **Recall:** Semantic search `profile.db` for existing facts about "testing frameworks".
3. **Reasoning:** LLM compares [New Fact] vs [Existing Fact: "I use `jest`"].
4. **Decision:** LLM outputs `UPDATE` (Replace "jest" with "vitest").
5. **Write:** Execute SQL Update.



### 2.3 Context Injection

The `Waterfall Orchestrator` (v2.0) is modified to inject Profile Memory *upstream* of the RAG context.

* **Priority Order:**
1. **System Prompt:** Core identity.
2. **Profile Memory:** "Act like a Senior Frontend Dev who prefers Tailwind." (v2.1)
3. **Repo/Vector Memory:** "Here is the code for `Button.tsx`." (v2.0)



---

## 3. Data Management

### 3.1 Directory Layout

The Profile system lives completely outside the `repos/` directory to ensure global persistence.

```text
~/.docdex/state/
├── repos/                  # (v2.0) Repo-specific data
│   └── <fingerprint>/...
├── cache/                  # (v2.0) Web/Lib caches
└── profiles/               # (v2.1) NEW: Global Profile Data
    ├── main.db             # The SQLite database for Agents & Preferences
    └── main.db-shm         # (WAL files)

```

### 3.2 Database Schema (`profile.db`)

We use a relational schema enhanced with vectors for semantic retrieval.

**Table: `agents**`
*Defines the distinct personas within the Mcoda swarm.*

* `id` (TEXT PK): The unique agent identifier (e.g., `mcoda_frontend`, `mcoda_qa`).
* `role` (TEXT): A brief description of responsibilities (e.g., "UI Implementation").
* `created_at` (INT): Epoch timestamp.

**Table: `preferences**`
*Stores the learned rules and constraints.*

* `id` (UUID PK): Unique ID.
* `agent_id` (TEXT FK): Links to `agents.id`.
* `content` (TEXT): The preference (e.g., "Always use strict type checking").
* `embedding` (BLOB): 1024d vector (via `llama3.1:8b-embed`) for semantic search.
* `category` (TEXT): Enum [`style`, `tooling`, `constraint`, `workflow`].
* `last_updated` (INT): Timestamp for recency weighting.

---

## 4. Interfaces & Integration

### 4.1 CLI Extensions

New commands are added to the `docdex` binary to manage profiles manually.

* `docdex profile list`: Show all registered agents.
* `docdex profile add --agent <id> "<text>"`: Manually teach an agent a preference.
* *Example:* `docdex profile add --agent frontend "Use CSS Modules"`


* `docdex profile search --agent <id> "<query>"`: Debug tool to see what an agent "remembers" about a topic.

### 4.2 HTTP API Extensions

The Chat API is updated to accept an `agent_id` context.

* **Endpoint:** `POST /v1/chat/completions`
* **New Header/Body Param:** `x-docdex-agent-id` (Optional).
* **Behavior:**
* If provided, the system queries `profile.db` for relevant preferences matching the `agent_id` + user query.
* These preferences are prepended to the System Prompt.



### 4.3 MCP Tooling

New tools exposed to the Mcoda agents via the Model Context Protocol.

* `docdex_save_preference`:
* **Input:** `{ agent_id: string, preference: string, category: string }`
* **Action:** Triggers the Evolution Pipeline (Add/Update/Delete).


* `docdex_get_profile`:
* **Input:** `{ agent_id: string, query: string }`
* **Action:** Semantic search on `profile.db` to retrieve relevant constraints for the current task.



---

## 5. Implementation Roadmap (v2.1)

### Phase 1: Storage Infrastructure

1. Create `src/profiles/` module structure.
2. Implement `profile.db` schema initialization (SQLite + Vec).
3. Implement `ProfileManager` to handle global database connections.

### Phase 2: The "Evolution" Logic

1. Implement the `EvolutionEngine` struct.
2. Add the `CUSTOM_UPDATE_PROMPT` (the LLM logic that decides Add vs Update).
3. Wire up `Ollama` client to generate embeddings for preference text.

### Phase 3: Integration

1. Modify `WaterfallOrchestrator` to accept an optional `agent_id`.
2. Add a "Tier 0" retrieval step: Query Profile Memory -> Inject into Prompt.
3. Expose the CLI commands and MCP tools.

---

## 6. Risks & Mitigations

* **Risk:** **Prompt Injection / Hallucination.** An agent might save a preference that contradicts repo reality (e.g., "Use Python 2" in a Python 3 repo).
* **Mitigation:** **Hierarchy of Truth.** The System Prompt must explicitly state: *"Repo context (v2.0) overrides Agent Preferences (v2.1) if they conflict."*


* **Risk:** **Database Locking.** Since `profile.db` is global, multiple concurrent agents accessing it might cause SQLite locking errors (`SQLITE_BUSY`).
* **Mitigation:** Use SQLite WAL (Write-Ahead Logging) mode and a connection pool with a specialized writer queue in the `ProfileManager`.