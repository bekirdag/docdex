# Docdex

[![smithery badge](https://smithery.ai/badge/@bekirdag/docdex)](https://smithery.ai/server/@bekirdag/docdex)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/bekirdag/docdex/main.yml?branch=main)
![GitHub License](https://img.shields.io/github/license/bekirdag/docdex)
![GitHub Release](https://img.shields.io/github/v/release/bekirdag/docdex)
![Made with Rust](https://img.shields.io/badge/Made%20with-Rust-orange?logo=rust)

Docdex is a local-first indexer and search daemon for docs and source code. It turns a repo into fast, private context that humans and AI can trust.

## The story
You open a new codebase. The README is stale, the docs are scattered, and the AI assistant tries to help but keeps guessing. Docdex reads the repo once, keeps it indexed, and makes answers real. It is the missing layer between your code and your assistant.

## What Docdex is
Docdex is a lightweight daemon that indexes your repo and serves context over CLI, HTTP, and MCP. It keeps everything local, fast, and consistent across tools.

## Why it matters (and how it compares)
Docdex is the layer between raw files and an AI assistant. It beats ad-hoc search and avoids sending your code to third-party services.

| Problem | Typical approach | What Docdex changes |
| --- | --- | --- |
| Find relevant context | `grep`/`rg` (fast, literal, noisy) | Ranked, structured results that match intent |
| AI needs repo context | Hosted RAG (upload code) | Local-only indexing, no upload required |
| Search is siloed | IDE-only search | Shared daemon for CLI, HTTP, and MCP clients |

## Where it fits
- Onboarding: understand a repo without archaeology.
- Daily dev: find answers fast without leaving the terminal.
- Agents and copilots: give them trustworthy context before they change code.
- Private environments: everything stays on your machine.

## What you get
- Local indexing for docs and code
- A shared daemon multiple tools can use
- HTTP, CLI, and MCP access
- Repo memory and agent memory (preferences)
- Optional web fallback when you want it

## Quick start

Full usage guide: [docs/usage.md](docs/usage.md)

Install:
```bash
npm i -g docdex
```

Index a repo:
```bash
docdexd index --repo /path/to/repo
```

Run the daemon (shared MCP + HTTP):
```bash
docdexd daemon --repo /path/to/repo --host 127.0.0.1 --port 3210 --log warn --secure-mode=false
```

Ask a question from the CLI:
```bash
docdexd chat --repo /path/to/repo --query "how does auth work?"
```

## Usage samples

### CLI search
```bash
docdexd chat --repo /path/to/repo --query "payment retry logic" --limit 5
```

### HTTP search
```bash
curl "http://127.0.0.1:3210/search?q=payment%20retry&limit=5"
```

### MCP client config (shared daemon)
JSON example (Cursor, Continue, Cline, Claude Desktop devtools):
```json
{
  "mcpServers": {
    "docdex": {
      "url": "http://localhost:3210/sse"
    }
  }
}
```

TOML example (Codex):
```toml
[mcp_servers]
docdex = { url = "http://localhost:3210/sse" }
```

## Code intelligence
Docdex exposes symbols, AST search, and impact graphs over HTTP. These endpoints help agents reason about structure, not just text.

Symbols:
```bash
curl "http://127.0.0.1:3210/v1/symbols?file=src/app.ts"
```

AST query:
```bash
curl "http://127.0.0.1:3210/v1/ast?name=handleRequest&pathPrefix=src"
```

Impact graph:
```bash
curl "http://127.0.0.1:3210/v1/graph/impact?file=src/app.ts&maxDepth=3"
```

## Web search (optional)
Docdex can enrich answers with web results when you want it to, while keeping your repo local.

Enable web mode:
```bash
DOCDEX_WEB_ENABLED=1 docdexd daemon --repo /path/to/repo --host 127.0.0.1 --port 3210
```

Tips:
- Set `DOCDEX_WEB_BROWSER` or `DOCDEX_CHROME_PATH` if a browser is not auto-detected.
- Use `DOCDEX_OFFLINE=1` to force offline behavior in CI or air-gapped environments.

## Local LLM + embeddings (Ollama)
Docdex pairs well with local Ollama for embeddings and optional chat.

First-time setup (recommended):
```bash
docdex setup
```
The setup wizard runs in a terminal UI and asks for consent before installing Ollama and models.

Skip auto-setup on install:
```bash
DOCDEX_SETUP_SKIP=1 npm i -g docdex
```

Manual setup:
```bash
ollama serve
ollama pull nomic-embed-text
```

Point Docdex at Ollama if needed:
```bash
DOCDEX_OLLAMA_BASE_URL=http://127.0.0.1:11434 docdexd daemon --repo /path/to/repo --host 127.0.0.1 --port 3210
```

## Memory (repo + agent)
Docdex keeps two memory layers: repo-scoped memory for project facts, and agent memory for long-lived preferences across repos. Memory uses local embeddings (Ollama).

Repo memory (enabled by default, disable with `DOCDEX_ENABLE_MEMORY=0`):
```bash
docdexd memory-store --repo /path/to/repo --text "Payments retry up to 3 times with backoff."
docdexd memory-recall --repo /path/to/repo --query "payments retry policy" --top-k 5
```

Agent memory (global profile preferences):
```bash
docdexd profile add --agent-id "default" --category style --content "Use concise bullet points."
docdexd profile search --agent-id "default" --query "style" --top-k 5
```

## Agent usage patterns
Docdex gives agents a consistent, local context source. Treat it as the repo brain they can query before changing code.

Sample agent prompts:
- "Use Docdex to find the authentication entry point, then summarize the flow."
- "Use Docdex impact graph to list downstream modules before refactoring."
- "Use Docdex to fetch relevant code snippets for this bug report."

## Real-world scenarios

### Onboarding a new repo
Goal: find the true entry points and data flow in minutes.

Sample prompts:
- "Where does user authentication start and what files are involved?"
- "Show me the data flow from API request to database write."
- "Which modules own billing and where are the tests?"

Example:
```bash
docdexd chat --repo /path/to/repo --query "auth entry point and flow" --limit 8
```

### Incident debugging
Goal: identify failure points quickly without grepping the whole repo.

Sample prompts:
- "Where is the retry logic for the payment webhook?"
- "What code path logs 'rate limit exceeded'?"
- "Which feature flag gates the new checkout?"

Example:
```bash
docdexd chat --repo /path/to/repo --query "rate limit exceeded log path" --limit 6
```

### Refactors and migrations
Goal: map what will break before you touch code.

Sample prompts:
- "Where is `UserProfile` serialized and deserialized?"
- "Which modules depend on `billing_v1`?"
- "Find all schema migrations touching orders."

Example:
```bash
docdexd chat --repo /path/to/repo --query "usage of UserProfile serialization" --limit 10
```

## Multi-repo setup
Run separate daemons for different repositories and connect both to your MCP client.

```bash
docdexd daemon --repo /path/to/repo-a --host 127.0.0.1 --port 3210 --log warn --secure-mode=false
docdexd daemon --repo /path/to/repo-b --host 127.0.0.1 --port 3220 --log warn --secure-mode=false
```

MCP client config (two servers):
```json
{
  "mcpServers": {
    "docdex-repo-a": { "url": "http://localhost:3210/sse" },
    "docdex-repo-b": { "url": "http://localhost:3220/sse" }
  }
}
```

## Daemon + MCP flow
```mermaid
flowchart LR
  Repo[Repo on disk] --> Indexer[Docdex indexer]
  Indexer --> Daemon[Docdex daemon]
  Daemon -->|HTTP + SSE| MCPClient[MCP client]
  MCPClient --> Host[AI app or agent]
```
SSE endpoint: `/sse`

## How it helps AI agents
Agents do better work when they see accurate, ranked context. Docdex gives them a stable, local source of truth so they do not hallucinate over stale docs or miss critical files. You run Docdex once, point your MCP client at it, and the same context is shared across tools and workflows.

## Learn more
- Detailed usage guide: `docs/usage.md`
- HTTP API reference: `docs/http_api.md`
- MCP errors and contracts: `docs/mcp/errors.md`

If Docdex clicks for you, start with the usage guide and wire it into your favorite agent or IDE.
