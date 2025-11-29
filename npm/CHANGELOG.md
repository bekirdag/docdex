# Changelog

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
- Align with MCP spec fixes (notification handling, CallToolResult content payloads, underscore tool names) so Codex and other clients stay stable.
- Publish npm wrapper with the latest MCP-compliant binary.

## 0.1.5
- Publish the MCP-enabled CLI wrapper (use `docdex mcp` for MCP clients) and align docs with the new stdio mode.
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
