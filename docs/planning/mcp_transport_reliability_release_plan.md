# MCP Transport Reliability Release Plan

## Goal

Determine whether repeated Streamable HTTP MCP send failures at `127.0.0.1:28491/v1/mcp` require a Docdex product release, close any source or packaging gap, and publish only after release-grade validation.

## Acceptance criteria

- Distinguish connection-level daemon unavailability from application-level MCP repo-binding errors.
- Confirm global profile tools work without a repo binding in multi-repo daemon mode.
- Confirm repo-scoped tools remain fail-closed when no repo is supplied.
- Verify daemon startup/readiness behavior and packaged npm behavior.
- Keep versions, changelogs, release metadata, and tests synchronized.
- Publish only a clean, validated commit and verify the npm registry result.

## Work plan

1. Inspect the current branch, release metadata, daemon health, relevant MCP dispatch code, and regression tests.
2. Use AST/symbol and impact/DAG evidence to identify the safe change and validation order.
3. Reproduce the profile and repo-scoped MCP cases against source-built or packaged binaries.
4. Patch code/tests/docs only if current source does not already contain the required fix.
5. Run targeted tests, package tests, version checks, and the repository pre-commit gate.
6. Compare local version/tag/commit with npm `latest`; publish the validated package only if it is not already present.
7. Verify registry metadata and a clean install/runtime smoke test, then record outcomes.

## Release safety

- Do not publish from a dirty worktree or with version drift.
- Do not overwrite an existing npm version.
- Preserve rollback evidence: prior npm `latest`, commit SHA, tag state, and validation logs.
- Stop if authentication, external release artifacts, or required validation is unavailable.
