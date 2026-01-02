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
- Optional memory and web fallback when you want it

## Quick start

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
  Daemon -->|HTTP + SSE (/sse)| MCPClient[MCP client]
  MCPClient --> Host[AI app or agent]
```

## How it helps AI agents
Agents do better work when they see accurate, ranked context. Docdex gives them a stable, local source of truth so they do not hallucinate over stale docs or miss critical files. You run Docdex once, point your MCP client at it, and the same context is shared across tools and workflows.

## Learn more
- Detailed usage guide: `docs/usage.md`
- HTTP API reference: `docs/http_api.md`
- MCP errors and contracts: `docs/mcp/errors.md`

If Docdex clicks for you, start with the usage guide and wire it into your favorite agent or IDE.
