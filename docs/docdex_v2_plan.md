Based on the provided SDS and the current file structure of `docdex` v0.1.10, here is the breakdown of the main features to add and the necessary changes to existing features to reach v2.0.

### 1. New Core Components

*These are substantial additions that likely require new modules or sub-directories.*

* **Repo Manager & Isolation Layer**
* **Functionality:** Centralized management of repository state using SHA256 fingerprints of normalized paths.
* **Key Logic:**
* Implement path normalization (case-insensitivity, realpath) and fingerprinting.
* Manage directory creation: `~/.docdex/state/repos/<fingerprint>/`.
* **LRU Eviction:** Implement the `max-open-repos` logic (default 12) to close file handles (indexes, DBs) for idle repos.
* **Registry:** Maintain a mapping of `repo_path` ↔ `fingerprint`.


* **Location:** New module, e.g., `src/repo_manager/`.


* **Web Discovery & Scraper Engine (Tier 2)**
* **Functionality:** A zero-cost web retrieval system.
* **Key Logic:**
* **Discovery:** DuckDuckGo HTML scraper with rate limiting (≥2s delay).
* **Scraper:** Headless Chrome integration (using a crate like `headless_chrome`) to fetch and render pages.
* **Guards:** "Zombie" process protection using lockfiles in `state/locks/` and strict timeouts (15s).
* **Cache:** Global `cache/web/` management for HTML/JSON.


* **Location:** New module, e.g., `src/web/` or `src/scraper/`.


* **Memory Service (Tier 3)**
* **Functionality:** Long-term memory storage using `sqlite-vec`.
* **Key Logic:**
* Manage per-repo `memory.db`.
* Implement `memory_store` (embed + save) and `memory_recall` (vector search).
* Prioritize memory context in the token budgeter.


* **Location:** New module, e.g., `src/memory/`.


* **Reasoning DAG (Directed Acyclic Graph)**
* **Functionality:** Session logging and reasoning visualization.
* **Key Logic:**
* Manage per-repo `dag.db`.
* Log node types: `UserRequest`, `Thought`, `ToolCall`, `Observation`, `Decision`.
* Implement `dag view` logic to render DOT/Text.


* **Location:** New module, e.g., `src/dag/`.


* **Hardware Awareness**
* **Functionality:** Detect system resources to guide configuration.
* **Key Logic:**
* Detect total RAM and GPU VRAM.
* Logic to recommend models (e.g., `<8GB` = ultra-light, `>16GB` = llama3.1:8b).


* **Location:** Likely inside `src/config.rs` or a utility module.



### 2. Changes to Existing Features

*Refactoring required to match the v2.0 "Waterfall" and "Repo-Scoped" architecture.*

* **Orchestrator (The Waterfall)**
* **Current State:** `src/orchestrator` likely handles simple flow.
* **Required Changes:**
* **Gating Logic:** Implement the `web_trigger_threshold` check. Only trigger Web Tier if Local Tier score < 0.45.
* **Context Assembly:** Enforce strict priority: `Memory > Repo Code > Library/Web`.
* **Token Budgeting:** Implement the specific budget split (10% system, 20% memory, 50% context, 20% gen).


* **Files:** `src/orchestrator/mod.rs` (heavy rewrite).


* **Indexing & Search**
* **Current State:** `src/index`, `src/search`.
* **Required Changes:**
* **Repo Scoping:** Ensure indexers read/write *only* to `state/repos/<fingerprint>/index`.
* **Symbol Extraction:** Add `Tree-sitter` parsing (Phase 6) to populate a new `symbols.db`.
* **Library Index:** Add logic to ingest cached library docs into a separate `libs_index`.


* **Files:** `src/index/mod.rs`, `src/indexer/`.


* **Config & State Management**
* **Current State:** `src/config.rs`.
* **Required Changes:**
* Update TOML structure to match SDS sections (`[core]`, `[llm]`, `[web]`, etc.).
* Add validation for the `global_state_dir` and default permissions.
* Implement "Check" logic (`docdexd check`) to validate external dependencies (Ollama, Chrome).




* **Daemon Lifecycle**
* **Current State:** `src/daemon.rs`, `internal/daemon`.
* **Required Changes:**
* Bind to `127.0.0.1:3210` by default.
* Implement `--expose` flag logic: strictly require a token for external binding.
* Integrate the "Repo Manager" initialization and cleanup into the daemon startup/shutdown.




* **LLM Gateway**
* **Required Changes:**
* Enforce **Ollama-only** provider (remove OpenAI/others if present, or hide them).
* Ensure all calls are streamed.
* Implement the hardware-aware model selection logic during setup.





### 3. Interface Updates

* **CLI (`src/cli/commands`)**
* **New Commands:**
* `docdexd check`: Run system readiness checks.
* `libs fetch --repo`: Fetch and ingest dependency docs.
* `web-search`, `web-fetch`, `web-rag`: Direct access to web tier.
* `dag view`: Visualize session logs.
* `llm-list`, `llm-setup`: Hardware-guided setup.


* **Updates:**
* **Strict Repo Flag:** Ensure almost every command (`chat`, `index`, etc.) fails if `--repo` is missing.




* **HTTP API (`src/api/http`)**
* **Updates:**
* **OpenAI Compatibility:** Ensure `POST /v1/chat/completions` matches OpenAI spec exactly, but *requires* a repo ID (header/body). Implemented in `src/api/v1/chat.rs`, routed from `src/search/mod.rs`.
* **New Endpoint:** `GET /v1/graph/impact` for the dependency graph (currently routed from `src/search/mod.rs`).
* **Auth:** Middleware to check Bearer token if `--expose` is active (currently in `src/search/mod.rs`; `src/api/http` re-exports the router).




* **MCP Server (`src/api/mcp`, `crates/mcp-server`)**
* **Updates:**
* **Single Server:** Ensure one server instance serves all repos.
* **Tool Params:** Update all tools (`docdex_search`, etc.) to require `repo_path` as a mandatory argument.
* **New Tools:** `docdex_web_research`, `docdex_memory_save`, `docdex_memory_recall`.





### Summary Checklist for Implementation

1. [ ] **Scaffolding:** Create `src/repo_manager`, `src/web`, `src/memory`, `src/dag`.
2. [ ] **Config:** Update `src/config.rs` with v2.0 schema and hardware checks.
3. [ ] **Repo Manager:** Implement fingerprinting and LRU logic.
4. [ ] **Web Tier:** Implement DDG scraper and Headless Chrome guard.
5. [ ] **Indexing:** Add Tree-sitter and `symbols.db` logic.
6. [ ] **Memory:** Integrate `sqlite-vec`.
7. [ ] **Orchestrator:** Rewrite flow for Waterfall (Local -> Web -> Memory) and Token Budgeting.
8. [ ] **API:** Update HTTP to OpenAI spec and enforce Auth/Repo headers.
9. [ ] **CLI:** Add `check`, `libs`, `dag`, `web-*` commands.

A. Repo Manager & State (src/repo_manager)
Path Normalization: The SDS explicitly requires the fingerprint to be the SHA256 of the normalized absolute path (resolving symlinks and case sensitivity). This is critical to prevent duplicate state for the same repo.

Repo Meta File: The SDS mentions maintaining a repo_meta.json at the repo root containing the fingerprint and version. The plan implies this in "Registry," but explicit file creation is needed.

B. Web Tier Guardrails (src/web)
Blocklist: The SDS mentions "blocklist support" for the DuckDuckGo DiscoveryService. The plan mentions rate limiting but should also include domain filtering.

Cache Ingestion: While the cache/web directory is global, the SDS stresses that ingestion must be repo-scoped. The orchestrator must copy/ingest cached content into the current repo's context, never linking directly to the global cache to prevent bleed.

C. Memory Schema (src/memory)
Strict Schema: The plan mentions memory.db, but the SDS dictates the exact schema: id UUID, content TEXT, embedding BLOB, created_at INT, metadata JSON. The implementation must match this exactly for future compatibility.

D. API & Middleware (src/api)
Repo ID Headers: The SDS allows the repo ID to be passed via header (x-docdex-repo-id), body (repo_id), or query parameter. The middleware in Step 8 must support all three lookup methods.


Based on the first step of the plan, you are establishing the module structure for the new core components. In Rust projects, this typically involves creating a directory for the component and adding a `mod.rs` file inside it to define the module's public interface.

Here is how the `src` directory of your folder tree will look after adding the scaffolding for **Repo Manager**, **Web**, **Memory**, and **DAG**.

### Updated Folder Tree (`src` directory only)

```text
src
├── api
│   ├── http
│   ├── mcp
│   └── v1
├── audit.rs
├── cli
│   └── commands
├── config.rs
├── crypto
├── daemon.rs
├── dag                 <-- NEW: Reasoning DAG (Phase 4)
│   └── mod.rs
├── guards
├── index
│   └── mod.rs
├── indexer
├── ingest
├── installers
├── main.rs
├── mcp.rs
├── mcp_server
│   └── tools
├── memory              <-- NEW: Memory Service / sqlite-vec (Phase 3)
│   └── mod.rs
├── orchestrator
├── repo_manager        <-- NEW: Isolation & Lifecycle (Phase 0)
│   └── mod.rs
├── search
│   └── mod.rs
├── tools
│   ├── recall
│   └── tools
├── util.rs
├── watcher.rs
└── web                 <-- NEW: Web Discovery & Scraper (Phase 2)
    └── mod.rs

```

### What happens in this step?

1. **`src/repo_manager/mod.rs`**: You will define the structs for `RepoRegistry` and `RepoContext`. This is where the logic for fingerprinting paths (SHA256) and enforcing the `max-open-repos` LRU eviction will eventually live.
2. **`src/web/mod.rs`**: You will scaffold the `DiscoveryService` (DuckDuckGo) and `ScraperEngine` (Headless Chrome). You will likely add submodules here later (e.g., `src/web/scraper.rs`).
3. **`src/memory/mod.rs`**: You will define the interface for `memory_store` and `memory_recall` using `sqlite-vec`. This prepares the application to handle per-repo embeddings.
4. **`src/dag/mod.rs`**: You will create the structs for the "Reasoning DAG" nodes (`UserRequest`, `Thought`, `Decision`) to support session logging.

**Next Action:** Once these directories are created, you must register them in your `main.rs` (or `lib.rs` if you refactor) using `pub mod repo_manager;`, `pub mod web;`, etc., to make them part of the compilation unit.

If we follow **Step 2** ("Config: Update `src/config.rs` with v2.0 schema and hardware checks"), the folder structure will typically expand slightly to accommodate the new "Hardware Awareness" component logic separately from the configuration parsing, to keep the code clean.

While `src/config.rs` will be heavily modified to support the new `[core]`, `[llm]`, and `[web]` TOML sections, it is best practice to place the hardware detection logic (RAM/GPU probing) in its own module (e.g., `src/hardware.rs`) rather than cluttering the config parser.

Here is the updated `src` tree after **Step 2**, building upon the scaffolding from Step 1:

```text
src
├── api
│   ├── http
│   ├── mcp
│   └── v1
├── audit.rs
├── cli
│   └── commands
├── config.rs           <-- UPDATED: v2.0 Schema (TOML structs) & validation
├── crypto
├── daemon.rs
├── dag                 <-- (From Step 1)
│   └── mod.rs
├── guards
├── hardware.rs         <-- NEW: RAM/VRAM detection logic (System probing)
├── index
│   └── mod.rs
├── indexer
├── ingest
├── installers
├── main.rs             <-- UPDATED: Registers `mod hardware;`
├── mcp.rs
├── mcp_server
│   └── tools
├── memory              <-- (From Step 1)
│   └── mod.rs
├── orchestrator
├── repo_manager        <-- (From Step 1)
│   └── mod.rs
├── search
│   └── mod.rs
├── tools
│   ├── recall
│   └── tools
├── util.rs
├── watcher.rs
└── web                 <-- (From Step 1)
    └── mod.rs

```

### Key Changes in this Step

1. **`src/config.rs`**: This file is updated to define the new configuration structs (`Config`, `CoreConfig`, `LlmConfig`, `WebConfig`, etc.) that match the v2.0 SDS. It will also include logic to load `~/.docdex/config.toml` and apply defaults (like `127.0.0.1` binding and `ollama` provider).
2. **`src/hardware.rs` (New)**: This file is created to handle the "Hardware Awareness" requirement. It will likely use a crate like `sysinfo` to detect:
* Total System RAM (to guide `<8GB` vs `>16GB` logic).
* GPU Presence/VRAM (to suggest `llama3.1:70b` vs `8b`).
* This module is then called by `config.rs` or the CLI commands (`llm-list`) to generate recommendations.


3. **`src/main.rs`**: Updated to declare `pub mod hardware;` so the new module is compiled.

Based on **Step 3** ("Repo Manager: Implement fingerprinting and LRU logic"), the `src/repo_manager` directory will expand to house the logic for path normalization, hashing, and managing the repository lifecycle.

At this stage, you are moving from empty scaffolding to implementing the specific isolation and eviction mechanics described in the SDS.

Here is the updated `src` tree:

```text
src
├── api
│   ├── http
│   ├── mcp
│   └── v1
├── audit.rs
├── cli
│   └── commands
├── config.rs
├── crypto
├── daemon.rs
├── dag
│   └── mod.rs
├── guards
├── hardware.rs
├── index
│   └── mod.rs
├── indexer
├── ingest
├── installers
├── main.rs
├── mcp.rs
├── mcp_server
│   └── tools
├── memory
│   └── mod.rs
├── orchestrator
├── repo_manager
│   ├── fingerprint.rs  <-- NEW: Path normalization & SHA256 logic
│   ├── mod.rs          <-- UPDATED: Exports Registry & Context structs
│   └── registry.rs     <-- NEW: LRU eviction, state dir creation, & handle management
├── search
│   └── mod.rs
├── tools
│   ├── recall
│   └── tools
├── util.rs
├── watcher.rs
└── web
    └── mod.rs

```

### Key Changes in this Step

1. **`src/repo_manager/fingerprint.rs`**: This module implements the "Identity" logic. It takes a raw repository path, resolves it to an absolute path (handling symlinks and case sensitivity), and computes the SHA256 hash to create the unique "Fingerprint" used for directory storage.
2. **`src/repo_manager/registry.rs`**: This module contains the `RepoRegistry` struct. It holds the state of all open repositories and enforces the `max-open-repos` limit (default 12).
* It implements the **LRU Eviction** algorithm: tracking which repo was accessed last and closing the file handles (indexes, DB connections) of the least recently used repo when the limit is reached.
* It handles **Lazy Initialization**: verifying and creating the `~/.docdex/state/repos/<fingerprint>/` directory structure upon the first access.


3. **`src/repo_manager/mod.rs`**: This file ties the submodules together and exposes the public API (like `get_repo_context(path)`) that the CLI and HTTP API will use to access repository data.

Based on **Step 4** ("Web Tier: Implement DDG scraper and Headless Chrome guard"), the `src/web` directory will be populated with the modules required for the zero-cost web retrieval system described in the SDS.

At this stage, you are adding the logic for the "DiscoveryService" (DuckDuckGo), the "ScraperEngine" (Headless Chrome), and the global web cache.

Here is the updated `src` tree:

```text
src
├── api
│   ├── http
│   ├── mcp
│   └── v1
├── audit.rs
├── cli
│   └── commands
├── config.rs
├── crypto
├── daemon.rs
├── dag
│   └── mod.rs
├── guards
├── hardware.rs
├── index
│   └── mod.rs
├── indexer
├── ingest
├── installers
├── main.rs
├── mcp.rs
├── mcp_server
│   └── tools
├── memory
│   └── mod.rs
├── orchestrator
├── repo_manager
│   ├── fingerprint.rs
│   ├── mod.rs
│   └── registry.rs
├── search
│   └── mod.rs
├── tools
│   ├── recall
│   └── tools
├── util.rs
├── watcher.rs
└── web
    ├── cache.rs        <-- NEW: Manage `cache/web` (HTML/JSON) & TTL
    ├── discovery.rs    <-- NEW: DuckDuckGo HTML scraper & rate limiting (≥2s)
    ├── mod.rs          <-- UPDATED: Exports Discovery & Scraper engines
    └── scraper.rs      <-- NEW: Headless Chrome logic & "Zombie" process guards

```

### Key Changes in this Step

1. **`src/web/discovery.rs`**: This module implements the `DiscoveryService`. It handles sending queries to DuckDuckGo's HTML endpoint, parsing the result links, and enforcing the **≥2s delay** between requests to avoid rate limits.
2. **`src/web/scraper.rs`**: This module implements the `ScraperEngine`.
* It wraps the `headless_chrome` crate to fetch pages.
* It implements the **Lifecycle Guard**: Creating lockfiles in `~/.docdex/state/locks/` to track active browser instances and ensure they are killed (preventing "zombie" processes) if the daemon crashes or exits.
* It handles readability cleanup of the fetched HTML.


3. **`src/web/cache.rs`**: This module manages the global web cache at `~/.docdex/state/cache/web/`. It saves raw HTML and cleaned JSON, keyed by a hash of the URL, and respects the `cache_ttl_secs` configuration.

Based on **Step 5** ("Indexing: Add Tree-sitter and `symbols.db` logic"), the `src/index` directory will be significantly expanded to support Code Intelligence and Library Context.

At this stage, you are adding the parsing logic (Tree-sitter) to extract symbols and the storage logic for the new per-repo databases (`symbols.db` and `libs_index`).

Here is the updated `src` tree:

```text
src
├── api
│   ├── http
│   ├── mcp
│   └── v1
├── audit.rs
├── cli
│   └── commands
├── config.rs
├── crypto
├── daemon.rs
├── dag
│   └── mod.rs
├── guards
├── hardware.rs
├── index
│   ├── libs.rs         <-- NEW: Manage per-repo `libs_index` (Phase 2.1)
│   ├── mod.rs          <-- UPDATED: Exports Symbols & Libs logic
│   └── symbols.rs      <-- NEW: Tree-sitter extraction & `symbols.db` (Phase 6)
├── indexer
│   └── mod.rs          <-- UPDATED: Coordinator to trigger symbol extraction during indexing
├── ingest
├── installers
├── main.rs
├── mcp.rs
├── mcp_server
│   └── tools
├── memory
│   └── mod.rs
├── orchestrator
├── repo_manager
│   ├── fingerprint.rs
│   ├── mod.rs
│   └── registry.rs
├── search
│   └── mod.rs
├── tools
│   ├── recall
│   └── tools
├── util.rs
├── watcher.rs
└── web
    ├── cache.rs
    ├── discovery.rs
    ├── mod.rs
    └── scraper.rs

```

### Key Changes in this Step

1. **`src/index/symbols.rs`**: This module handles the "Code Intelligence" layer.
* It integrates **Tree-sitter** parsers (for Rust, TS/JS, Python, Go) to extract function/class definitions and dependency imports.
* It manages the **`symbols.db`** (SQLite) schema, storing `files`, `deps` (for the Impact Graph), and symbol locations.


2. **`src/index/libs.rs`**: This module manages the "Library Context" layer.
* It handles the creation and writing of the **`libs_index`** (a separate Tantivy index inside `state/repos/<fp>/libs_index/`).
* It provides the logic to read cached docs from `cache/libs` and ingest them into this per-repo index so they can be searched locally.


3. **`src/indexer` (Existing)**: The main indexing loop (likely in `src/indexer/mod.rs` or similar) is updated to call `symbols::extract_and_store` and `libs::ingest` alongside the standard text indexing.

Based on **Step 6** ("Memory: Integrate `sqlite-vec`"), the `src/memory` directory will be populated to handle the long-term memory requirements described in the SDS.

At this stage, you are adding the database logic to manage the per-repo `memory.db` files and the vector operations (store/recall) that rely on Ollama embeddings.

Here is the updated `src` tree:

```text
src
├── api
│   ├── http
│   ├── mcp
│   └── v1
├── audit.rs
├── cli
│   └── commands
├── config.rs
├── crypto
├── daemon.rs
├── dag
│   └── mod.rs
├── guards
├── hardware.rs
├── index
│   ├── libs.rs
│   ├── mod.rs
│   └── symbols.rs
├── indexer
│   └── mod.rs
├── ingest
├── installers
├── main.rs
├── mcp.rs
├── mcp_server
│   └── tools
├── memory
│   ├── db.rs           <-- NEW: Manage `memory.db` connection & sqlite-vec loading
│   ├── mod.rs          <-- UPDATED: Exports store/recall interface
│   └── ops.rs          <-- NEW: Implement `memory_store` & `memory_recall` logic
├── orchestrator
├── repo_manager
│   ├── fingerprint.rs
│   ├── mod.rs
│   └── registry.rs
├── search
│   └── mod.rs
├── tools
│   ├── recall
│   └── tools
├── util.rs
├── watcher.rs
└── web
    ├── cache.rs
    ├── discovery.rs
    ├── mod.rs
    └── scraper.rs

```

### Key Changes in this Step

1. **`src/memory/db.rs`**: This module handles the raw database interactions.
* It manages the connection to the per-repo `state/repos/<fp>/memory.db`.
* It ensures the **`sqlite-vec`** extension is loaded.
* It creates the specific schema defined in the SDS: `memories(id UUID, content TEXT, embedding BLOB, created_at INT, metadata JSON)`.


2. **`src/memory/ops.rs`**: This module implements the high-level operations.
* **`memory_store`**: Accepts text, requests an embedding from the LLM provider (Ollama), and writes the row to SQLite.
* **`memory_recall`**: Accepts a query, generates an embedding, and performs the vector similarity search in `memory.db`.

Based on **Step 7** ("Orchestrator: Rewrite flow for Waterfall (Local -> Web -> Memory) and Token Budgeting"), the `src/orchestrator` directory will be restructured to handle the complex tiered retrieval and context assembly logic.

At this stage, you are transforming the simple orchestrator into the "Waterfall Orchestrator" that coordinates the local index, the web tier (on confidence drops), and the memory/LLM tiers.

Here is the updated `src` tree:

```text
src
├── api
│   ├── http
│   ├── mcp
│   └── v1
├── audit.rs
├── cli
│   └── commands
├── config.rs
├── crypto
├── daemon.rs
├── dag
│   └── mod.rs
├── guards
├── hardware.rs
├── index
│   ├── libs.rs
│   ├── mod.rs
│   └── symbols.rs
├── indexer
│   └── mod.rs
├── ingest
├── installers
├── main.rs
├── mcp.rs
├── mcp_server
│   └── tools
├── memory
│   ├── db.rs
│   ├── mod.rs
│   └── ops.rs
├── orchestrator
│   ├── budget.rs       <-- NEW: Token counting & priority pruning (10/20/50/20 split)
│   ├── mod.rs          <-- UPDATED: Main "Waterfall" logic (Tier 1 -> Tier 2 -> Tier 3)
│   └── plan.rs         <-- NEW: Execution plan logic (Gating: `web_trigger_threshold`)
├── repo_manager
│   ├── fingerprint.rs
│   ├── mod.rs
│   └── registry.rs
├── search
│   └── mod.rs
├── tools
│   ├── recall
│   └── tools
├── util.rs
├── watcher.rs
└── web
    ├── cache.rs
    ├── discovery.rs
    ├── mod.rs
    └── scraper.rs

```

### Key Changes in this Step

1. **`src/orchestrator/plan.rs`**: This module implements the **Gating Logic**.
* It defines the `ExecutionPlan` struct.
* It implements the check: `if top_local_score < web_trigger_threshold` (or `forced`), then add **Tier 2** (Web) to the plan; otherwise, stick to **Tier 1** (Local).


2. **`src/orchestrator/budget.rs`**: This module manages **Context Assembly**.
* It implements the tokenizer logic (likely wrapping a library like `tiktoken-rs` or similar).
* It enforces the strict priority order: **Memory > Repo Code > Library/Web**.
* It implements the budget allocation: 10% System, 20% Memory, 50% Context, 20% Generation.


3. **`src/orchestrator/mod.rs`**: The main entry point now orchestrates the calls:
* Call `search::search_local`.
* Pass results to `plan::decide`.
* If needed, call `web::discovery` and `web::scraper`.
* Call `memory::recall`.
* Pass everything to `budget::assemble`.
* Finally, stream to the LLM.



### Summary of the "Waterfall" Logic to be Implemented

* **Tier 1 (Local):** Always runs first. Queries `index/` (source) and `libs_index/` (libraries).
* **Gate:** Compares the top BM25 score from Tier 1 against `config.search.web_trigger_threshold` (default 0.45).
* **Tier 2 (Web):** Only runs if the Gate opens. Executes DuckDuckGo search + Chrome Fetch.
* **Tier 3 (Cognition):** Always runs. Assembles the final prompt using `budget.rs` and calls Ollama.

Based on **Step 8** ("API: Update HTTP to OpenAI spec and enforce Auth/Repo headers"), the `src/api` directory will undergo significant updates to align with the "Single-Daemon" and "Repo-Scoped" architecture.

At this stage, you are standardizing the communication layer. You will implement the OpenAI-compatible request/response structures, add the new Impact Graph endpoint, and strictly enforce security via middleware that checks for the `repo_id` and (if exposed) the Authorization token.

Here is the updated `src` tree:

```text
src
├── api
│   ├── http
│   │   ├── middleware.rs   <-- NEW: Auth (Bearer) & Repo ID extraction logic
│   │   └── mod.rs          <-- UPDATED: Route registration & middleware application
│   ├── mcp
│   │   └── mod.rs
│   ├── mod.rs
│   └── v1
│       ├── chat.rs         <-- UPDATED: OpenAI-compatible `/chat/completions` handler
│       ├── graph.rs        <-- NEW: Impact graph endpoint (`/v1/graph/impact`)
│       ├── mod.rs
│       └── models.rs       <-- NEW: Request/Response structs (OpenAI Spec)
├── audit.rs
├── cli
│   └── commands
├── config.rs
├── daemon.rs
├── dag
│   └── mod.rs
├── guards
├── hardware.rs
├── index
│   ├── libs.rs
│   ├── mod.rs
│   └── symbols.rs
├── indexer
│   └── mod.rs
├── ingest
├── installers
├── main.rs
├── mcp.rs
├── mcp_server
│   └── tools
├── memory
│   ├── db.rs
│   ├── mod.rs
│   └── ops.rs
├── orchestrator
│   ├── budget.rs
│   ├── mod.rs
│   └── plan.rs
├── repo_manager
│   ├── fingerprint.rs
│   ├── mod.rs
│   └── registry.rs
├── search
│   └── mod.rs
├── tools
│   ├── recall
│   └── tools
├── util.rs
├── watcher.rs
└── web
    ├── cache.rs
    ├── discovery.rs
    ├── mod.rs
    └── scraper.rs

```

### Key Changes in this Step

1. **`src/api/http/mod.rs`**: Re-exports the HTTP router and config types from `src/search/mod.rs` to keep the import path stable while handlers live there.
* **Repo/Auth Guardrails**: Request gating (repo/auth/rate limits) currently lives in `src/search/mod.rs` and is applied globally via router middleware.


2. **`src/api/v1/chat.rs`**: This file defines the OpenAI-compatible request/response structs inline and wires chat completions to the Waterfall.


3. **`src/search/mod.rs`**: The router still owns most HTTP handlers, including `GET /v1/graph/impact` and the middleware pipeline.


4. **`src/api/v1/graph.rs`**: Not yet split out; `GET /v1/graph/impact` remains in `src/search/mod.rs`.

Based on **Step 9** ("CLI: Add `check`, `libs`, `dag`, `web-*` commands"), the `src/cli/commands` directory will expand significantly. This step exposes the new daemon capabilities directly to the user through the command line.

At this stage, you are adding the specific command modules that invoke the logic built in previous steps (Repo Manager, Web Tier, Memory, etc.).

Here is the final updated `src` tree after all steps are complete:

```text
src
├── api
│   ├── http
│   │   └── mod.rs
│   ├── mcp
│   │   └── mod.rs
│   └── v1
│       ├── chat.rs
│       └── mod.rs
├── audit.rs
├── cli
│   ├── commands
│   │   ├── check.rs        <-- NEW: System readiness & dependency validation (Phase 0)
│   │   ├── dag.rs          <-- NEW: Session visualization (`dag view`) (Phase 4)
│   │   ├── libs.rs         <-- NEW: Library doc fetch & ingest (`libs fetch`) (Phase 2.1)
│   │   ├── llm.rs          <-- NEW: Hardware-guided setup (`llm-list`, `llm-setup`)
│   │   ├── mod.rs          <-- UPDATED: Registers all new modules
│   │   └── web.rs          <-- NEW: Tier 2 operations (`web-search`, `web-fetch`, `web-rag`)
│   └── mod.rs
├── config.rs
├── daemon.rs
├── dag
│   └── mod.rs
├── guards
├── hardware.rs
├── index
│   ├── libs.rs
│   ├── mod.rs
│   └── symbols.rs
├── indexer
│   └── mod.rs
├── ingest
├── installers
├── main.rs
├── mcp.rs
├── mcp_server
│   └── tools
├── memory
│   ├── db.rs
│   ├── mod.rs
│   └── ops.rs
├── orchestrator
│   ├── budget.rs
│   ├── mod.rs
│   └── plan.rs
├── repo_manager
│   ├── fingerprint.rs
│   ├── mod.rs
│   └── registry.rs
├── search
│   └── mod.rs
├── tools
│   ├── recall
│   └── tools
├── util.rs
├── watcher.rs
└── web
    ├── cache.rs
    ├── discovery.rs
    ├── mod.rs
    └── scraper.rs

```

### Key Changes in this Step

1. **`src/cli/commands/check.rs`**: This command implements the critical **Phase 0 Gate**.
* It runs `docdexd check` to validate that the configuration file is readable, the `global_state_dir` is writable, the repo registry is intact, and dependencies (Ollama, Headless Chrome) are reachable.


2. **`src/cli/commands/web.rs`**: This module groups the "Tier 2" commands.
* `web-search`: Invokes `web::discovery` to search DuckDuckGo (respecting the ≥2s delay).
* `web-fetch`: Invokes `web::scraper` to fetch and clean a URL (respecting the ≥1s delay and locking).
* `web-rag`: Runs a one-off retrieval augmented generation using only web context.


3. **`src/cli/commands/libs.rs`**: This command handles **Phase 2.1**.
* It scans the repo (e.g., `Cargo.toml`, `package.json`) to detect dependencies.
* It triggers the fetcher in `index::libs` to scrape documentation, cache it in `cache/libs`, and ingest it into the per-repo `libs_index`.


4. **`src/cli/commands/dag.rs`**: This command implements **Phase 4**.
* `dag view --repo <path> <session_id>`: It connects to the per-repo `dag.db` and renders the reasoning nodes as either plain text or Graphviz DOT format.


5. **`src/cli/commands/llm.rs`**: This command implements **Hardware Awareness**.
* `llm-list`: Calls `hardware::detect()` (from Step 2) to recommend models based on RAM/VRAM.
* `llm-setup`: Validates the `ollama` binary path and guides the user to pull the recommended models.


Based on the consolidated plan across all 9 steps, here is the **Final Folder Tree** for `docdex` v2.0. This structure supports the new **Waterfall Architecture**, **Repo Isolation**, **Hardware Awareness**, and the expanded **CLI/API** surfaces defined in the SDS.

### Final Folder Tree (v2.0 Target)

```text
src
├── api
│   ├── http
│   │   ├── middleware.rs   <-- NEW: Auth (Bearer) & Repo ID extraction logic
│   │   └── mod.rs          <-- UPDATED: Route registration & middleware application
│   ├── mcp
│   │   └── mod.rs
│   └── v1
│       ├── chat.rs         <-- UPDATED: OpenAI-compatible `/chat/completions` handler
│       ├── graph.rs        <-- NEW: Impact graph endpoint (`/v1/graph/impact`)
│       ├── mod.rs
│       └── models.rs       <-- NEW: Request/Response structs (OpenAI Spec)
├── audit.rs
├── cli
│   ├── commands
│   │   ├── check.rs        <-- NEW: System readiness & dependency validation (Phase 0)
│   │   ├── dag.rs          <-- NEW: Session visualization (`dag view`) (Phase 4)
│   │   ├── libs.rs         <-- NEW: Library doc fetch & ingest (`libs fetch`) (Phase 2.1)
│   │   ├── llm.rs          <-- NEW: Hardware-guided setup (`llm-list`, `llm-setup`)
│   │   ├── mod.rs          <-- UPDATED: Registers all new command modules
│   │   └── web.rs          <-- NEW: Tier 2 operations (`web-search`, `web-fetch`, `web-rag`)
│   └── mod.rs
├── config.rs               <-- UPDATED: v2.0 Schema, `[core]`, `[llm]`, `[web]` & defaults
├── crypto
├── daemon.rs               <-- UPDATED: Lifecycle: Bind 127.0.0.1, `--expose` check, RepoMgr init
├── dag                     <-- NEW: Reasoning DAG (Phase 4)
│   └── mod.rs              <-- Defines Node types (UserRequest, Thought, etc.) & SQLite logic
├── guards
├── hardware.rs             <-- NEW: RAM/VRAM detection for model recommendations
├── index
│   ├── libs.rs             <-- NEW: Manage per-repo `libs_index` ingestion
│   ├── mod.rs              <-- UPDATED: Exports Symbols & Libs logic
│   └── symbols.rs          <-- NEW: Tree-sitter extraction & `symbols.db` (Phase 6)
├── indexer
│   └── mod.rs              <-- UPDATED: Triggers symbol extraction during indexing
├── ingest
├── installers
├── main.rs                 <-- UPDATED: Registers all new modules (`mod repo_manager`, `mod web`, etc.)
├── mcp.rs
├── mcp_server
│   └── tools
├── memory                  <-- NEW: Memory Service / sqlite-vec (Phase 3)
│   ├── db.rs               <-- NEW: Manage `memory.db` connection & schema
│   ├── mod.rs
│   └── ops.rs              <-- NEW: Implement `memory_store` & `memory_recall`
├── orchestrator
│   ├── budget.rs           <-- NEW: Token counting & priority pruning (10/20/50/20 split)
│   ├── mod.rs              <-- UPDATED: Main "Waterfall" logic (Tier 1 -> Tier 2 -> Tier 3)
│   └── plan.rs             <-- NEW: Gating logic (`web_trigger_threshold`)
├── repo_manager            <-- NEW: Isolation & Lifecycle (Phase 0)
│   ├── fingerprint.rs      <-- NEW: Path normalization & SHA256 logic
│   ├── mod.rs
│   └── registry.rs         <-- NEW: LRU eviction, state dir creation, & handle management
├── search
│   └── mod.rs
├── tools
│   ├── recall
│   └── tools
├── util.rs
├── watcher.rs
└── web                     <-- NEW: Web Discovery & Scraper (Phase 2)
    ├── cache.rs            <-- NEW: Manage `cache/web` (HTML/JSON) & TTL
    ├── discovery.rs        <-- NEW: DuckDuckGo scraper & rate limiting (≥2s)
    ├── mod.rs
    └── scraper.rs          <-- NEW: Headless Chrome logic & "Zombie" process guards

```

### Summary of Major Architectural Changes

1. **Repo Manager (`src/repo_manager`)**: Centralizes the multi-repo isolation logic. It ensures that every operation is scoped to a specific repository via its SHA256 fingerprint, managing concurrent access and resource cleanup via LRU eviction.
2. **Web Tier (`src/web`)**: Introduces the zero-cost web retrieval capabilities. It provides a guarded, rate-limited way to fetch external context (DuckDuckGo + Headless Chrome) only when necessary.
3. **Memory & DAG (`src/memory`, `src/dag`)**: Adds long-term persistence and session reasoning logs, moving beyond simple stateless chat.
4. **Orchestrator (`src/orchestrator`)**: Evolves into a "Waterfall" controller that intelligently decides when to use local code, when to fetch from the web, and how to fit it all into a strict token budget.
5. **API Standardization (`src/api`)**: Realigns the HTTP interface to be OpenAI-compatible for easier integration with existing tools, while enforcing strict repository scoping and authentication rules.
