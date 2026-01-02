# **System Design Specification: Docdex v2.1**

**Feature: Agent Profile & Preference Memory (Global Context Layer)**

## **Table of Contents**

1. **Introduction**  
   * 1.1 Purpose & Scope  
   * 1.2 The Problem: The "Amnesia" Gap  
   * 1.3 The Solution: Dual-Lobe Memory  
   * 1.4 Strategic Goals  
2. **Architecture Overview**  
   * 2.1 Design Philosophy: The "Dual-Lobe" Memory  
   * 2.2 System Diagram & Components  
   * 2.3 **Technical Constraint: Token Budgeting Strategy** (Allocation & Eviction)  
3. **Core Components**  
   * 3.1 Profile Manager (src/profiles/)  
   * 3.2 The Evolution Pipeline (src/profiles/evolution.rs)  
   * 3.3 **Specification: The Evolution Prompt Schema** (Structured JSON Output)  
   * 3.4 Context Injection & The "Hierarchy of Truth"  
4. **Data Management**  
   * 4.1 Directory Layout & Persistence  
   * 4.2 Database Schema (profile.db)  
   * 4.3 **Specification: Embedding Models & Dimension Alignment**  
   * 4.4 **Specification: Functional Logic of "Categories"**  
   * 4.5 **Swarm Synchronization: Conflict Resolution & Locking**  
5. **Advanced Capabilities (The "Perfect Tool" Suite)**  
   * 5.1 The "Semantic Gatekeeper" (**Daemon-Client Interface**)  
   * 5.2 Context-Aware Project Mapping (**Heuristics & Caching**)  
   * 5.3 Visual Impact Explorer (TUI/GUI)  
   * 5.4 Zero-Config Persona Bootstrap & **Seed Strategy**  
6. **Interfaces & Integration**  
   * 6.1 CLI Extensions  
   * 6.2 HTTP API Extensions  
   * 6.3 MCP Tooling  
7. **Implementation Roadmap**  
   * Phase 1: Storage Infrastructure  
   * Phase 2: The "Evolution" Logic  
   * Phase 3: Integration & Tooling  
   * Phase 4: Advanced Features  
8. **Risks & Mitigations**  
   * 8.1 Prompt Injection & Hallucination  
   * 8.2 Database Concurrency & Locking  
   * 8.3 "Bad Apple" Propagation

---

# **1\. Introduction**

### **1.1 Purpose & Scope**

This document specifies the architecture for **Docdex v2.1**, a transformative feature release focused on **Agent Profile & Preference Memory**.

While Docdex v2.0 successfully solved the problem of *technical retrieval* (finding relevant code and documentation), v2.1 addresses the problem of *behavioral continuity* (remembering how the user wants that code written). This update introduces a **Global Context Layer** that runs parallel to the existing repository-scoped memory. It enables Docdex agents to evolve over time, learning user preferences, stylistic constraints, and architectural lessons that persist across different projects and sessions.

### **1.2 The Problem: The "Amnesia" Gap**

Current local-first RAG tools (including Docdex v2.0) operate in strict isolation. This creates three critical friction points that limit their utility as true development partners:

1. **Repository Isolation (The "Groundhog Day" Effect):**  
   * *Scenario:* A developer spends two hours teaching an agent in Project A that "We prefer vitest over jest."  
   * *Failure:* When the developer opens Project B the next day, the agent has "forgotten" this lesson and suggests jest again. The user must re-teach the same preference for every new repository.  
2. **Context Pollution:**  
   * *Scenario:* To avoid the isolation issue, users currently paste massive "System Instruction" blocks into every prompt (e.g., "Always use strict types," "Don't use any," "Prefer functional components").  
   * *Failure:* This mixes mutable *behavioral preferences* with immutable *technical context*, wasting token budget and confusing the LLM's attention mechanism with noise that should be implicit.  
3. **The Cold Start Problem:**  
   * *Scenario:* A new team member installs Docdex.  
   * *Failure:* Their agent starts with a "blank slate" personality. It has zero knowledge of the team's established culture, requiring weeks of usage before it begins to feel personalized.

### **1.3 The Solution: Dual-Lobe Memory Architecture**

Docdex v2.1 solves these issues by implementing a biological metaphor for memory, separating "facts" from "skills":

1. **The Hippocampus (Repo Memory \- v2.0):**  
   * **Role:** Rapid storage of specific, episodic facts about the *current* codebase.  
   * **Nature:** Ephemeral, Project-Bound, Technical.  
   * **Example:** "The calculateTax function is in utils.ts."  
2. **The Neocortex (Profile Memory \- v2.1):**  
   * **Role:** Slow, consolidated storage of generalized rules, habits, and skills that apply everywhere.  
   * **Nature:** Persistent, Global, Behavioral.  
   * **Example:** "I should always use Zod for validation schemas."

By decoupling these two systems, Docdex transforms from a passive search engine into an **adaptive development partner** that arrives at a new project already knowing the team's culture, style, and tooling preferences.

### **1.4 Strategic Goals**

1. **True Personalization:** Enable "Zero-Config" persona bootstrapping where the agent mimics a specific developer or role (e.g., "Senior Frontend Dev") immediately upon installation.  
2. **Swarm Alignment:** Facilitate "Swarm Synchronization" where a preference update by one senior engineer propagates to the entire team, ensuring consistency in coding standards.  
3. **Transparent Reasoning:** Provide a clear "Reasoning Trace" that allows users to distinguish between "what the code says" (Technical Truth) and "what the agent prefers" (Behavioral Truth), building trust in the AI's suggestions.

---

## 

## **2\. Architecture Overview**

### **2.1 Design Philosophy: The "Dual-Lobe" Memory**

To prevent contamination between *technical facts* (Repo Code) and *behavioral preferences* (Agent Rules), v2.1 introduces a strict separation of concerns known as the **Dual-Lobe Memory Architecture**.

Current RAG systems often fail because they mix "what the code does" with "how the user wants code written," leading to retrieval noise. Docdex v2.1 solves this by maintaining two distinct, parallel memory systems:

1. **Repo Memory (The Technical Lobe \- v2.0)**  
   * **Scope:** Repository-bound (\~/.docdex/state/repos/\<hash\>/memory.db).  
   * **Role:** Technical RAG. Stores immutable code snippets, project-specific docs, and definitions.  
   * **Lifecycle:** Append-only / LRU Eviction.  
   * **Status:** **UNCHANGED**.  
2. **Profile Memory (The Behavioral Lobe \- v2.1)**  
   * **Scope:** Global / Team-bound (\~/.docdex/state/profiles/main.db).  
   * **Role:** Behavioral Adaptation. Stores agent preferences, coding style guides, and cross-project lessons (e.g., "Always prefer functional components").  
   * **Lifecycle:** Evolutionary (Read $\\to$ Reason $\\to$ Update/Delete).  
   * **Status:** **NEW COMPONENT**.

### **2.2 System Diagram & Components**

The core Waterfall Orchestrator is modified to query the Profile Memory *before* engaging the standard RAG pipeline. This ensures that the agent's "personality" frames the technical context, rather than being an afterthought.

The retrieval flow is now:

1. **User Query:** "Create a new button component."  
2. **Tier 0 (Profile Retrieval):** The **ProfileManager** queries main.db for the active Agent ID (e.g., mcoda\_frontend) to retrieve style constraints (e.g., "Use Tailwind", "Use TypeScript").  
3. **Tier 1 (Repo Retrieval):** The **RepoManager** searches the vector index for existing button implementations to maintain consistency.  
4. **Synthesis:** The LLM receives the technical snippets wrapped in the behavioral constraints.

### **2.3 Technical Constraint: Token Budgeting Strategy**

With the introduction of Profile Memory and Project Maps, the LLM's context window becomes a scarce resource. To prevent the system from overflowing the context with "nice-to-have" behavioral rules at the expense of critical code snippets, v2.1 enforces a strict **Partitioned Token Budget**.

**Total Context Allocation (Example 8k Window):**

| Component | Allocation | Priority | Eviction Strategy |
| :---- | :---- | :---- | :---- |
| **System Prompt** | Fixed (\~500 tokens) | **Critical** | None (Immutable Identity) |
| **Profile Memory** (v2.1) | Capped (1,000 tokens) | High | **Semantic Relevance Score.** If \> 1k tokens, drop preferences with the lowest similarity score to the current query. |
| **Project Map** (v2.1) | Capped (500 tokens) | Medium | **Depth Pruning.** Collapse deep directory trees into parent folders; keep only top-level architecture. |
| **Repo Memory** (v2.0) | Variable (\~4,000 tokens) | Critical | **Reranking.** Keep highest semantic match; truncate bottom results. |
| **User Query/History** | Variable (\~2,000 tokens) | High | FIFO (First-In-First-Out) truncation of chat history. |

**Allocation Rules:**

* **Hard Cap:** The Profile Memory retrieval step MUST return a token\_count. If token\_count \> 1000, the ProfileManager performs an internal filter to discard the least relevant constraints before passing the set to the Orchestrator.  
* **Dynamic Adjustment:** If the user query is short (e.g., "Hi"), the unused budget from Repo Memory can be temporarily reallocated to Chat History, but Profile Memory always respects its cap to prevent hallucination loops.

---

## 

## **3\. Core Components**

### **3.1 Profile Manager (src/profiles/)**

The ProfileManager is a new singleton service responsible for the lifecycle of the global profile.db. Unlike the RepoManager, which manages many ephemeral database handles per project, the ProfileManager holds a persistent, thread-safe connection to the global profile storage.

* **Responsibilities:**  
  * **Initialization:** Bootstraps the \~/.docdex/state/profiles/ directory and applies SQLite vector schemas on startup.  
  * **Concurrency Control:** To safely handle database access across multiple concurrent agent threads and prevent SQLITE\_BUSY errors, the manager implements a **Single-Writer / Multi-Reader (SWMR) Mutex**.  
    * *Reads (Context Retrieval):* Allowed in parallel via shared read locks.  
    * *Writes (Evolution):* Queued serially via an exclusive write lock.  
  * **CRUD Abstraction:** Exposes high-level methods for Agent Entities (create\_agent, get\_agent) and Preference Facts (search\_preferences, evolve\_preference).

### **3.2 The Evolution Pipeline (src/profiles/evolution.rs)**

This engine implements the "Mem0-like" logic required to keep the preference database clean and non-contradictory. It transforms the memory process from a simple "append-only" log into an active curation system.

* **Logic Flow:**  
  1. **Input:** The system receives a new behavioral fact (e.g., "I prefer vitest over jest").  
  2. **Recall:** The engine performs a semantic search on profile.db for existing facts related to "testing frameworks".  
  3. **Reasoning:** An LLM compares the **\[New Fact\]** against the **\[Existing Fact: "I use jest"\]**.  
  4. **Decision:** The LLM outputs an atomic action: UPDATE (replace "jest" with "vitest"), ADD (if new), or IGNORE (if redundant).  
  5. **Write:** The ProfileManager executes the SQL transaction.

### **3.3 Specification: The Evolution Prompt Schema (Structured JSON)**

To ensure the Evolution Pipeline is deterministic and machine-readable, the "Reasoning" step MUST output strict JSON adhering to a specific schema. We do not rely on free-text reasoning.

**Input Prompt Template:**

Plaintext

```

You are the Memory Manager for an AI coding assistant.
Current Memory State regarding topic: [
  { "id": "uuid-1", "content": "Prefer using Jest for unit tests", "recency": "2 weeks ago" }
]
New User Input: "We are switching to Vitest for this project."

Determine the correct memory operation.
1. ADD: The input is a new fact.
2. UPDATE: The input contradicts or refines an existing fact (provide target_id).
3. IGNORE: The input is conversational noise or already known.

Return ONLY a JSON object.

```

**Output Schema (Strict JSON):**

JSON

```

{
  "action": "UPDATE",               // Enum: "ADD" | "UPDATE" | "IGNORE"
  "target_preference_id": "uuid-1", // Nullable. Required if action is UPDATE.
  "new_content": "Prefer using Vitest for unit tests", // The refined fact to store.
  "reasoning": "User explicitly contradicted previous preference regarding testing frameworks."
}

```

*Constraint:* If the JSON parsing fails, the pipeline defaults to IGNORE to prevent database corruption.

### **3.4 Context Injection & The "Hierarchy of Truth"**

The Waterfall Orchestrator (v2.0) is modified to inject Profile Memory *upstream* of the standard RAG context. To mitigate the risk of hallucination or conflict, strict priority rules are enforced.

* The Hierarchy of Truth:  
  To prevent "Prompt Injection" where a preference contradicts repo reality (e.g., an agent preferring Python 2 in a Python 3 repo), the System Prompt construction follows this strict override order:  
  1. **System Prompt (Immutable):** Core identity and safety rails.  
  2. **Repo/Vector Memory (Technical Truth \- v2.0):** "Here is the actual code." *Overrides Profile Memory.*  
  3. **Profile Memory (Behavioral Preference \- v2.1):** "Act like a Senior Frontend Dev." *Applied only where it does not conflict with Technical Truth.*  
* Latency Management:  
  While reading preferences for context injection occurs on the critical path (blocking the response), the writing (Evolution Pipeline) occurs asynchronously (fire-and-forget). This ensures the user does not experience latency while the agent "thinks" about saving a memory.

---

## **4\. Data Management**

### **4.1 Directory Layout & Persistence**

The Profile system lives completely outside the repos/ directory to ensure global persistence and decouple behavioral memory from specific project state. This physical separation is the enabler for cross-project learning.

**File Structure:**

Plaintext

```

~/.docdex/state/
├── repos/                  # (v2.0) Repo-specific data (Immutable technical facts)
│   └── <fingerprint>/...
├── cache/                  # (v2.0) Web/Lib caches
└── profiles/               # (v2.1) NEW: Global Profile Data
    ├── main.db             # The SQLite database for Agents & Preferences
    ├── main.db-shm         # (WAL files for concurrency)
    └── sync/               # (v2.1) Staging area for Swarm Synchronization manifests

```

### **4.2 Database Schema (profile.db)**

We utilize a relational schema enhanced with vector embeddings (SQLite-vec) to support semantic retrieval of preferences.

Table: agents

Defines the distinct personas within the Mcoda swarm.

* id (TEXT PK): The unique agent identifier (e.g., mcoda\_frontend, mcoda\_qa).  
* role (TEXT): A brief description of responsibilities (e.g., "UI Implementation").  
* created\_at (INT): Epoch timestamp.

Table: preferences

Stores the learned rules and constraints.

* id (UUID PK): Unique ID.  
* agent\_id (TEXT FK): Links to agents.id.  
* content (TEXT): The natural language preference (e.g., "Always use strict type checking").  
* embedding (BLOB): Vector used for semantic similarity search during the **Recall** phase.  
* category (TEXT): Enum \[style, tooling, constraint, workflow\].  
* last\_updated (INT): Timestamp for recency weighting and conflict resolution.

### **4.3 Specification: Embedding Models & Dimension Alignment**

To prevent VRAM starvation, the Profile Memory system MUST NOT use the main Chat LLM for embeddings. It requires a dedicated, lightweight model.

* **Selected Model:** nomic-embed-text-v1.5 (or equivalent bge-m3-quantized).  
  * *Reasoning:* These models run efficiently on CPU or low VRAM (\~300MB), leaving the GPU available for the main Chat LLM.  
* **Dimension Constraint:** The embedding column in profile.db must match the model's output dimension exactly (typically **768 dimensions** for Nomic, **1024** for BGE). Mismatches will cause panic during vector search.  
* **Configuration:** The docdexd config will now include:  
* Ini, TOML

```

[memory.profile]
embedding_model = "nomic-embed-text-v1.5"
embedding_dim = 768

```

* 

### **4.4 Specification: Functional Logic of "Categories"**

The category column is not just a label; it dictates the *operational behavior* of the preference within the system.

| Category | Operational Behavior |
| :---- | :---- |
| **style** | **Soft Injection.** Injected into the System Prompt as advice (e.g., "Prefer functional components"). |
| **constraint** | **Blocking Enforcement.** Checked by the **Semantic Gatekeeper** (Section 5.1). Code violating these rules causes the pre-commit hook to fail (e.g., "No any types"). |
| **tooling** | **Search Heuristic.** Used by the **Project Mapper** to prioritize configuration files. (e.g., If pref is "Use Vitest", the mapper specifically hunts for vitest.config.ts). |
| **workflow** | **Process Guide.** Injected into the "Reasoning Trace" to guide multi-step planning (e.g., "Always write tests *before* implementation"). |

### **4.5 Swarm Synchronization: Conflict Resolution & Locking**

Status: High Risk Mitigation.

Running SQLite directly over a network drive (NFS/SMB) is prohibited due to file-locking risks. v2.1 implements a safer "Export/Merge" protocol.

* **Protocol:** **Manifest Sync (JSON)**  
  * **Export:** docdex profile export generates a profile\_sync.json containing all preferences with their last\_updated timestamps.  
  * **Transfer:** This JSON file is committed to the git repo or shared via a cloud drive.  
  * **Import:** docdex profile import profile\_sync.json reads the manifest.  
* **Conflict Resolution Strategy:** **Last Write Wins (LWW).**  
  * *Logic:* If Import contains a preference ID that already exists locally, the system compares last\_updated timestamps. The newer timestamp overwrites the older one.  
  * *Safety:* This avoids complex merge conflicts but requires clocks to be roughly synchronized.  
* **Locking:** During Import, the ProfileManager acquires an **Exclusive Write Lock** on profile.db, briefly queuing any read operations from running agents until the sync is complete.

---

## **5\. Advanced Capabilities (The "Perfect Tool" Suite)**

### **5.1 The "Semantic Gatekeeper" (Intelligent Hooks)**

We transform the pre-commit hook from a static script into an evolutionary guardian. However, to prevent developer friction caused by slow commit times, this feature uses a **Daemon-Client Architecture**.

* **The Architecture:**  
  * **The Client (Hook):** The docdex hook pre-commit command acts as a lightweight, thin client. It does *not* load the vector index or LLM. It simply gathers staged file paths and sends a JSON payload to the running docdexd daemon via HTTP or Unix Socket.  
  * **The Server (Daemon):** The existing docdexd process handles the request. It has the AST parsers and profile.db already loaded in memory, allowing it to perform the check in milliseconds rather than seconds.  
* **Mechanism:**  
  * **Request:** Client sends POST /v1/hooks/validate with staged filenames.  
  * **Lookup:** Daemon retrieves all preferences with category: constraint (e.g., "No circular dependencies").  
  * **Analysis:** Daemon uses its cached AST data to check for violations.  
  * **Response:** Returns status: "pass" or status: "fail" with a specific error message.  
* **Fallback Strategy (Fail-Open):**  
  * If the docdexd daemon is not running (connection refused), the hook prints a warning ("Docdex daemon not found; skipping semantic checks") and exits with code 0 (Success). This prevents blocking development due to tool downtime.

### **5.2 Context-Aware Project Mapping (Natural Language Map)**

To provide the LLM with architectural context without blowing the token budget, we implement a **Heuristic Skeleton Tree**. We do *not* ask the LLM to read the entire file system.

* **Scoring Algorithm (The "Spotlight" Heuristic):**  
  * **Keyword Extraction:** The system extracts keywords from the active Agent's role description (e.g., Role: "Frontend Dev" $\\to$ Keywords: \["react", "css", "component", "view"\]).  
  * **Vector Probe:** Query the Repo Memory (v2.0) for the top 50 file paths that semantically match these keywords.  
  * **Tree Reconstruction:** Build a directory tree structure that includes *only* these 50 paths and their parent directories.  
  * **Collapsing:** All other directories are collapsed into a single leaf node ... \[N hidden files\].  
* **Caching Strategy:**  
  * Because the project structure changes slowly, this "Mental Map" is generated once per session and cached in \~/.docdex/state/repos/\<hash\>/maps/\<agent\_id\>.json. It is invalidated only when the file watcher detects a directory creation/deletion event.
* **Indexing & Watcher Rules:**  
  * The indexer and watcher honor `.docdexignore` (first-party) alongside existing `.gitignore` rules to avoid ingesting unwanted files.  
  * Singleton daemons apply an LRU watcher lifecycle (stop after ~2h idle, hibernate after ~24h) while keeping state on disk for fast remounts.

### **5.3 Visual Impact Explorer (TUI/GUI)**

The standard textual impact-diagnostics are difficult to parse for large refactors. v2.1 introduces a visual layer to the TUI.

* **The Visualizer:**  
  * A new view in docdexd tui renders a node-link diagram (using Unicode box-drawing characters) representing the dependency graph.  
* **The "Risk Overlay":**  
  * The system overlays **Profile Memory** data onto the graph.  
  * *Example:* If a preference states "Avoid circular dependencies," any node participating in a cycle is rendered in **Red**.  
  * *Example:* If a preference states "Deprecate usage of moment.js," any file importing that library is flagged with a **Warning Icon**.  
* **Value:** Instant visual risk assessment that combines technical dependency data with behavioral team rules.

### **5.4 Zero-Config Persona Bootstrap & Seed Strategy**

To solve the "Cold Start" problem where a fresh installation has an empty database, v2.1 implements a **Factory Seed Strategy**.

* **Bootstrap Manifest:**  
  * The docdex binary includes an embedded defaults.json resource containing "Factory Default" personas (e.g., mcoda\_frontend, mcoda\_backend, mcoda\_security) and a baseline set of universally accepted preferences (e.g., "Use semantic versioning").  
* **Initialization Logic:**  
  * On startup, ProfileManager checks if the agents table is empty.  
  * If empty, it automatically hydrates the database with the Seed Manifest.  
* **Usage:**  
  * A new user can immediately run docdexd serve \--agent-id mcoda\_frontend and receive tailored, "Senior-level" assistance without ever explicitly configuring a profile.

---

## 

## **6\. Interfaces & Integration**

### **6.1 CLI Extensions**

New commands are added to the docdex binary to manage profiles manually, providing granular control over the agent's memory. These commands allow developers to inspect, debug, and manually override the "Evolution Pipeline."

* **docdex profile list**  
  * **Description:** Displays all registered agents within the system (e.g., mcoda\_frontend, mcoda\_qa).  
  * **Usage:** docdex profile list  
  * **Output:** JSON table showing agent\_id, role, and preference\_count.  
* **docdex profile add**  
  * **Description:** Manually teaches a specific agent a preference, bypassing the probabilistic nature of the LLM-driven Evolution Pipeline. This is useful for "Hard Rules" that must be learned immediately.  
  * **Usage:** docdex profile add \--agent \<id\> \--category \<cat\> "\<text\>"  
  * **Example:** docdex profile add \--agent frontend \--category constraint "Use CSS Modules"  
* **docdex profile search**  
  * **Description:** A debug tool to inspect what a specific agent "remembers" about a given topic. This is critical for verifying the state of the system when an agent appears to be hallucinating or ignoring a rule.  
  * **Usage:** docdex profile search \--agent \<id\> "\<query\>"  
  * **Output:** Returns a list of preferences with their similarity\_score and last\_updated timestamp.  
* **docdex profile export/import**  
  * **Description:** Facilitates the **Swarm Synchronization** protocol (Section 4.5).  
  * **Usage:** docdex profile export \--out \<file.json\> and docdex profile import \<file.json\>.

**Browser setup helpers (web tier dependency):**

* **docdexd browser list/setup/install**  
  * **Description:** Lists discovered headless-capable browsers, runs auto-discovery, and (on Linux) installs a pinned headless Chromium build when no browser is present.  
  * **Usage:** docdexd browser list \| docdexd browser setup \| docdexd browser install  
  * **Behavior:** Persists `web.scraper.chrome_binary_path` and `web.scraper.browser_kind` in `~/.docdex/config.toml`; `web.scraper.auto_install` defaults to true on Linux and false elsewhere (override with `DOCDEX_BROWSER_AUTO_INSTALL=0`).

### **6.2 HTTP API Extensions**

The Chat API is updated to accept an agent\_id context, enabling the **Waterfall Orchestrator** to perform persona-aware retrieval.

* **Endpoint:** POST /v1/chat/completions  
* **New Parameter:** x-docdex-agent-id (Header) or docdex.agent\_id (Body JSON).  
* **Behavior:**  
  * When this parameter is present, the system queries profile.db for preferences matching the agent\_id \+ user query.  
  * These retrieved preferences are then filtered by the **Token Budgeting Strategy** (Section 2.3) and prepended to the System Prompt, enforcing the "Hierarchy of Truth."

**Singleton Daemon Initialize (Install-and-Forget):**

* **Endpoint:** POST /v1/initialize  
* **Input:** { "rootUri": "file:///path/to/repo" }  
* **Behavior:**  
  * The singleton daemon resolves the repo fingerprint and mounts the repo state.  
  * If new or stale, it starts an async index crawl and returns status "indexing" or "stale".  
  * If ready, returns status "ready" and the repo_id for subsequent requests.
  * The singleton daemon runs as `docdexd daemon` and uses a lockfile at `~/.docdex/daemon.lock`; CLI entrypoints auto-start it when missing.
  * The npm installer auto-selects a port (prefers 3000, fallback 3210), updates `~/.docdex/config.toml`, injects MCP config into supported clients, and attempts OS startup registration (with a one-time warning if blocked).
  * The npm installer **does not** install Ollama/models directly. It launches a setup wizard (`docdex setup`) that requests user consent before installing Ollama and models.
  * If Ollama is installed but not running, the setup wizard will attempt to start it before pulling models.
  * Setup overrides: `DOCDEX_SETUP_FORCE`, `DOCDEX_OLLAMA_INSTALL`, `DOCDEX_OLLAMA_MODEL_PROMPT`, `DOCDEX_OLLAMA_MODEL_ASSUME_Y`.

### **6.3 MCP Tooling**

New tools are exposed to Mcoda agents via the Model Context Protocol (MCP), allowing them to self-manage their memory.

* **Transport:** Singleton daemons expose MCP over HTTP/SSE (`/sse`, `/v1/mcp`, `/v1/mcp/message`). Stdio MCP (`docdexd mcp`) remains for legacy/local-only clients.
* **Repo routing:** MCP `initialize` with `rootUri`/`workspace_root` calls `/v1/initialize` and binds the MCP session to that repo; per-request `project_root`/`repo_path` can override the bound repo for `/v1/mcp`.

* **docdex\_save\_preference**  
  * **Input Schema:**  
  * JSON

```

{
  "agent_id": "string",
  "preference": "string",
  "category": "style | tooling | constraint | workflow"
}

```

  *   
  * **Action:** Triggers the **Evolution Pipeline** (Add/Update/Delete). This allows the agent to explicitly "learn" a new rule based on user feedback (e.g., User says "Stop doing that," Agent calls docdex\_save\_preference to record the correction).  
* **docdex\_get\_profile**  
  * **Input Schema:**  
  * JSON

```
{
  "agent_id": "string",
  "query": "string"
}
```

  * **Action:** Performs a semantic search on profile.db. Agents use this to proactively retrieve relevant constraints for their current task *before* generating code, effectively "thinking" before acting.

---

## 

## **7\. Implementation Roadmap**

### **Phase 1: Storage Infrastructure (The Foundation)**

*Goal: Establish a persistent, thread-safe storage layer for global profiles.*

1. **Module Structure:**  
   * Create the src/profiles/ module.  
   * Define Rust structs for Profile, Preference, and Agent adhering to the schema defined in Section 4.2.  
2. **Database Initialization:**  
   * Implement profile\_db::init() to create \~/.docdex/state/profiles/main.db.  
   * Integrate sqlite-vec extension to enable vector columns on the preferences table.  
   * Implement the **Seed Strategy**: Check for an empty DB and populate it from the embedded defaults.json (Section 5.4).  
3. **Manager Service:**  
   * Implement ProfileManager with a **Single-Writer / Multi-Reader (SWMR) Mutex**.  
   * Create basic CRUD methods: create\_agent, get\_agent, add\_preference (raw insert), search\_preferences (vector query).

### **Phase 2: The "Evolution" Logic (The Brain)**

*Goal: Implement the intelligence layer that actively curates memory rather than just appending to it.*

1. **Embedding Integration:**  
   * Wire up the Ollama client to specifically target the nomic-embed-text-v1.5 model.  
   * Implement the dimension check: Panic or warn if the model returns vectors $\\ne$ 768 dimensions.  
2. **Evolution Engine:**  
   * Implement src/profiles/evolution.rs containing the EvolutionEngine struct.  
   * Implement the **Recall-Reason-Decide** loop defined in Section 3.2.  
3. **Prompt Engineering:**  
   * Implement the CUSTOM\_UPDATE\_PROMPT using the strict JSON schema defined in Section 3.3.  
   * Add error handling to retry the LLM call if the output is not valid JSON.

### **Phase 3: Integration & Tooling (The Body)**

*Goal: Connect the new memory system to the existing search/chat interfaces.*

1. **Orchestrator Update:**  
   * Modify WaterfallOrchestrator to accept an optional agent\_id.  
   * Implement **Tier 0 Retrieval**: Query ProfileManager $\\to$ Apply Token Budget $\\to$ Inject into System Prompt.  
2. **API Surface:**  
   * Update docdexd CLI to parse x-docdex-agent-id headers and pass them to the Orchestrator.  
   * Implement the CLI commands: docdex profile list, add, search, and export/import.  
3. **MCP Tooling:**  
   * Implement docdex\_save\_preference and docdex\_get\_profile tools.  
   * Register these tools in the MCP capabilities handshake so agents can discover them.

### **Phase 4: Advanced Features (The "Perfect Tool" Suite)**

*Goal: Deliver the differentiating features that make Docdex unique.*

1. **Semantic Gatekeeper:**  
   * Develop the docdex hook pre-commit client command.  
   * Implement the /v1/hooks/validate daemon endpoint that runs AST checks against constraint preferences (Section 5.1).  
2. **Project Mapper:**  
   * Implement the "Spotlight Heuristic" algorithm to generate and cache the skeletal file tree (Section 5.2).  
   * Inject this map into the System Prompt alongside the Profile Memory.  
3. **Visual TUI:**  
   * Update the docdex-tui crate to render the "Risk Overlay" graph (Section 5.3).  
4. **Swarm Sync:**  
   * Implement the JSON export/import logic with "Last Write Wins" conflict resolution (Section 4.5).

---

## 

## **8\. Risks & Mitigations**

### **8.1 Prompt Injection & Hallucination**

*Risk: The agent prioritizes its "personality" over the repository's reality, or "hallucinates" constraints that don't exist.*

* **Scenario:** An agent learns a strong preference (e.g., "Always use Python 2.7") that fundamentally conflicts with the technical reality of the current project (e.g., a Python 3.12 repo).  
* **Mitigation 1: The "Hierarchy of Truth" Prompt Construction**  
  * The System Prompt is constructed with strict injection slots that enforce priority.  
  * **Rule:** *"Repo context (v2.0) overrides Agent Preferences (v2.1) if they conflict."*  
  * **Implementation:** The {{repo\_context}} block is injected *after* the {{profile\_context}} block in the prompt, utilizing the LLM's "recency bias" to prioritize the technical facts found in the repo over the behavioral instructions.  
* **Mitigation 2: Token Budget Enforcement**  
  * To prevent the Profile from flooding the context window and pushing out relevant code, the ProfileManager strictly enforces the **1,000 token cap** defined in Section 2.3. Low-relevance preferences are silently dropped if this limit is exceeded.

### **8.2 Database Concurrency & Locking**

*Risk: Global state corruption in a multi-agent environment.*

* **Scenario:** Multiple Docdex instances (e.g., a CLI chat, an MCP server, and a pre-commit hook) attempt to write to the global profile.db simultaneously, causing SQLITE\_BUSY errors or database locks.  
* **Mitigation 1: WAL Mode**  
  * We explicitly enable SQLite's Write-Ahead Logging (PRAGMA journal\_mode=WAL). This allows readers to access the DB at the same time a writer is committing changes.  
* **Mitigation 2: Application-Layer Queuing**  
  * The ProfileManager implements a **Single-Writer / Multi-Reader (SWMR) Mutex**.  
  * *Read Operations* (Retrieval) acquire a shared lock and proceed in parallel.  
  * *Write Operations* (Evolution) acquire an exclusive lock. If a write is requested while locked, it is queued in a dedicated background thread, ensuring the main application thread never blocks on database I/O.

### **8.3 "Bad Apple" Propagation**

*Risk: A harmful or incorrect preference spreads to the entire team via synchronization.*

* **Scenario:** With Swarm Synchronization (Section 4.5), if one developer teaches their agent a harmful practice (e.g., "Disable all linters"), that preference propagates to the shared team profile and infects other agents.  
* **Mitigation 1: The Evolutionary Gate**  
  * The **Evolution Pipeline** (Section 3.2) includes a validation step. We prompt the LLM to reject preferences that are objectively harmful or nonsensical (e.g., "Ignore safety warnings").  
* **Mitigation 2: Timestamp-Based Rollback**  
  * If a "bad apple" preference spreads, a team lead can update the preference locally to the correct value (e.g., "Always enable linters"). Because the conflict resolution strategy is **Last Write Wins** (Section 4.5), this newer, correct timestamp will propagate out and overwrite the bad preference across the swarm during the next sync.

### **8.4 Performance & Latency Overheads**

*Risk: The addition of "Tier 0" retrieval and the "Evolution Pipeline" makes the tool feel sluggish compared to v2.0.*

* **Scenario:** The user asks a simple question, but the system pauses to generate embedding vectors for the Profile search and runs a reasoning step to save the context.  
* **Mitigation 1: Async Evolution (Fire-and-Forget)**  
  * The "Evolution Pipeline" (Reasoning \+ Writing) is completely decoupled from the chat response path. It runs in a background thread. The user receives their answer immediately, while the agent "learns" the lesson in the background.  
* **Mitigation 2: Cached Maps**  
  * The "Project Map" (Section 5.2) is expensive to generate. We strictly cache this JSON object. It is only regenerated if the file watcher detects a directory structure change (Create/Delete), never on simple file edits.

---
