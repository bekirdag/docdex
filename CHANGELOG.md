# Changelog

## Unreleased
- Add global profile memory (HTTP profile endpoints, CLI profile commands, MCP profile tools).
- Add default profile agent selection via `server.default_agent_id`, `docdexd serve --agent-id`, and MCP initialize `agent_id`.
- Add semantic gatekeeper hooks (`/v1/hooks/validate`, `docdexd hook pre-commit`) with optional Unix socket transport.
- Add `reasoning_trace` metadata to chat completions and project map context injection.
- Add profile import/export schema checks and sync compatibility validation.
- Add singleton daemon mode (`docdexd daemon`) with daemon lock and CLI auto-spawn guardrails.
- Add `POST /v1/initialize` repo validation endpoint and OpenAPI docs.
- Accept boolish env values for `DOCDEX_ENABLE_MCP`/`DOCDEX_DISABLE_MCP`.
- Add quality gates doc plus load/bench/audit scripts for release validation.
- Add network fault, concurrency, property, and metrics baseline tests.
- Add fuzz targets for libs, hooks, profile sync, and MCP payload parsing.
- Installer supports http download mirrors via `DOCDEX_DOWNLOAD_BASE` and skips docker matrix when the daemon is unavailable.

## 0.2.12
- Add AST/symbols support for Java, C#, C/C++, PHP, Kotlin, Swift, Ruby, Lua, and Dart.
- Bump Tree-sitter dependencies and parser version metadata for the expanded language set.
- Extend `docdexd mcp-add` to support Windsurf, Roo Code, PearAI, Void, and Zed configs.
- Expand indexed code extensions and default exclude folders for the new language ecosystems.
- Document expanded AST language support and auto-detected MCP clients.

## 0.1.11
- Added glama support

## 0.1.10
- smithery deployment work to get a bettwe score. enriched server.js, added mcp.json and an icon address.

## 0.1.9
- smithery deployment work

## 0.1.8
- smithery.yaml and Docker file fixes and added a entrypoint.sh to read environment variables and passes them as flags to docdexd

## 0.1.7
- Added smithery.yaml and Docker files for smithery.ai directory listing

## 0.1.6
- Fix MCP stdio compliance: accept notifications, advertise underscore tool names, and return CallToolResult `content` payloads so Codex/other MCP clients stay connected.
- Keep docs/tests in sync with MCP spec responses ahead of npm publish.

## 0.1.5
- Ship MCP stdio mode (docdex.search/index/files/open/stats) with resource templates and docs for MCP-aware clients.
- Expand CLI/help and tests around MCP usage to make agent/editor integration reliable.
- Bump versions for the MCP release and upcoming npm publish.

## 0.1.4
- Bump version for republish after 0.1.3 was already on npm.
- Keep trusted publishing fixes and expanded platform targets.

## 0.1.3
- Fix npm trusted publishing setup (environment + registry configuration) and bump version for release.
- Add musl/Windows targets to the release workflow and doc updates for broader platform support.

## 0.1.2
- Add musl/Windows targets to the release workflow and align npm publish trigger on tags.
- Doc updates for broader platform support.

## 0.1.1
- Bump version for npm doc updates and release alignment.

## 0.1.0
- Initial release of docdexd.
