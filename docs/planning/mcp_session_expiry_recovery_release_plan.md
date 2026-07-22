# MCP Session Expiry Recovery Release Plan

## Goal

Make Streamable HTTP MCP clients recover automatically when a Docdex session expires, then publish and verify the next patch release.

## Acceptance criteria

- Requests carrying an unknown or expired `Mcp-Session-Id` receive HTTP 404, as required by the MCP Streamable HTTP session contract.
- Requests missing a required session ID continue to receive HTTP 400.
- Explicit deletion of an already-missing session has documented, tested semantics.
- Existing initialization, unbound global-tool routing, repo isolation, and daemon lifecycle behavior remain intact.
- Version surfaces, changelogs, package metadata, and release assets are synchronized.
- Targeted, full, packaging, security, runtime, and pre-commit validation pass before publication.
- npm, GitHub Releases, and MCP Registry publication are independently verified.

## Work plan

1. Inspect session lookup/removal paths, existing tests, impact edges, and the release pipeline.
2. Confirm the authoritative MCP behavior for terminated sessions and translate it into HTTP response invariants.
3. Change unknown/expired supplied-session responses to HTTP 404 without changing missing-header HTTP 400 behavior.
4. Add regression coverage for direct POST calls and session deletion/expiry boundaries.
5. Run focused tests, full repo-native tests, package/security checks, and runtime HTTP recovery smoke tests.
6. Bump the patch version, update changelogs and all release surfaces, then run the staged semantic gate.
7. Commit, tag, push, monitor the release workflow, and verify registry/release metadata.

## Release safety

- Do not overwrite an existing npm version or release tag.
- Do not publish from a dirty or unvalidated release commit.
- Preserve HTTP 400 for malformed or missing-session requests; only terminated/unknown supplied IDs become 404.
- Stop publication if any full-suite, package, security, or immutable-artifact gate fails.
