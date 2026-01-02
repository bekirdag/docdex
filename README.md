# Docdex

[![smithery badge](https://smithery.ai/badge/@bekirdag/docdex)](https://smithery.ai/server/@bekirdag/docdex)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/bekirdag/docdex/main.yml?branch=main)
![GitHub License](https://img.shields.io/github/license/bekirdag/docdex)
![GitHub Release](https://img.shields.io/github/v/release/bekirdag/docdex)
![Made with Rust](https://img.shields.io/badge/Made%20with-Rust-orange?logo=rust)

Docdex is a local-first indexer and search daemon for docs and source code. It turns a repo into a fast, private knowledge source that humans and AI can trust.

## The story
You open a new codebase and ask an AI assistant for help. It tries, but the real context is buried across docs, markdown, and source files. Docdex reads the repo once, keeps it indexed, and makes the answers real. It is the missing layer between your code and your assistant.

## Why Docdex exists
- `grep` and `rg` are literal, fast, and noisy. Docdex ranks and summarizes, so you get the most relevant context quickly.
- Hosted RAG systems require uploading code. Docdex stays on your machine.
- IDE search is siloed. Docdex is shared across CLI, HTTP, and MCP clients.

## Where it fits
- Onboarding: understand how a repo actually works without hunting.
- Agents and copilots: give them trustworthy context before they change code.
- Daily dev: find answers quickly without leaving your terminal.
- Private or offline environments: everything local, no external services needed.

## What you get
- Local indexing for docs and code
- A shared daemon multiple tools can use
- HTTP, CLI, and MCP access
- Optional memory and web fallback when you want it

## Learn more
- Detailed usage guide: `docs/usage.md`
- HTTP API reference: `docs/http_api.md`
- MCP errors and contracts: `docs/mcp/errors.md`

If Docdex clicks for you, start with the usage guide and wire it into your favorite agent or IDE.
