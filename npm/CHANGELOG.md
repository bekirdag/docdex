# Changelog

## Unreleased
- Remove legacy stdio MCP (`docdexd mcp` / `docdex-mcp-server`); MCP is served only over HTTP/SSE.
- Ensure npm tarballs include CLI wrapper entrypoints and restore missing wrappers during postinstall.
- Retry Windows file operations during install to reduce EPERM/EACCES failures.
- Nightly HTTP soak waits for index readiness before load testing.

## 0.2.23
- Add Smithery session config schema metadata (titles/descriptions, defaults, example config) for local MCP sessions.
- Enrich MCP tools with titles, descriptions, parameter descriptions, and annotations to improve Smithery scoring.
- Expose MCP prompts and resources (with titles/mime types/annotations) for onboarding, incident triage, and refactor planning.
- Switch web scraping to Chromium-only installs under `~/.docdex/state/bin/chromium/` and remove legacy browser tooling.

## 0.2.21
- Prompt for npm updates at CLI start (TTY-only, opt-out via `DOCDEX_UPDATE_CHECK=0`).

## 0.2.19
- Agents md adding command manually
- Agents md append repeat fix

## 0.2.16
- Repo memory now tags items with `repoId` and filters recalls to prevent cross-repo leakage in multi-repo daemons.
- MCP HTTP requires explicit repo selection when multiple repos are active.
- Postinstall banner now guides users to run `docdex setup`.
- Docs refreshed with memory, agent memory, code intelligence, web search, and Ollama guidance.

## 0.1.10
- smithery deployment work to get a bettwe score. enriched server.js, added mcp.json and an icon address.

## 0.1.9
- smithery deployment work

## 0.1.8
- smithery.yaml and Docker file fixes and added a entrypoint.sh to read environment variables and passes them as flags to docdexd

## 0.1.7
- Added smithery.yaml and Docker files for smithery.ai directory listing

## 0.1.6
- Align with MCP spec fixes (notification handling, CallToolResult content payloads, underscore tool names) so Codex and other clients stay stable.
- Publish npm wrapper with the latest MCP-compliant binary.

## 0.1.5
- Publish the MCP-enabled CLI wrapper and align docs with MCP mode.
- Keep npm version in sync with the MCP release for binary downloads.

## 0.1.4
- Version bump for republish (0.1.3 already exists on npm).

## 0.1.3
- Fixed npm trusted publishing configuration (environment + registry) and aligned version bump.

## 0.1.2
- Broadened platform coverage in the workflow (musl, Windows) and kept npm version aligned with release tags.

## 0.1.1
- Updated npm README with clearer install and usage details.

## 0.1.0
- Initial npm scaffold for the Docdex CLI (`docdex`/`docdexd` bin).
- Postinstall downloader to fetch platform-specific `docdexd` binaries.
- Supports macOS (arm64/x64) and Linux (arm64/x64, gnu/musl auto-detect).
