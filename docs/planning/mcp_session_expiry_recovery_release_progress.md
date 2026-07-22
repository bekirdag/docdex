# MCP Session Expiry Recovery Release Progress

## Status

Implementation and local release validation complete; publication in progress.

## Evidence

- The worktree started clean on `main` at version `0.2.91`.
- The healthy daemon remained PID `9592` for almost 11 hours, excluding restart churn as the cause of the latest failure.
- `src/mcp.rs` expires idle router sessions after 3,600 seconds and checks every 600 seconds.
- `src/api/mcp_http.rs` currently returns HTTP 400 for an unknown or expired supplied session ID.
- A fresh `initialize` request returned HTTP 200 and a new session ID, confirming the daemon was healthy.
- The MCP Streamable HTTP contract requires HTTP 404 after server-side session termination so the client starts a new session.
- Impact analysis found `src/api/mcp_http.rs` is consumed by `src/api/mod.rs`; its direct outbound dependencies are initialize, auth, error, HTTP API, and search modules. The graph was complete and not truncated.
- AST inspection confirmed the HTTP handler/test module structure. DAG session `ccba8604-ffa3-46c7-b7e9-2a8e233d642a` captured the retrieval trace.
- `src/api/mcp_http.rs` now centralizes unknown/expired-session responses as HTTP 404 for both POST/tool calls and repeated DELETE, while missing session headers remain HTTP 400.
- Local delegation produced the expected 404/404/400 assertion outline; the implementation adds repository-native handler coverage without new dependencies.
- Focused tests passed for expired-session POST recovery and repeated DELETE reclamation behavior; formatting and diff checks passed.
- Release surfaces and changelogs are synchronized at version `0.2.92`.
- Full test attempt 1 found one stale auth-isolation expectation for a forged/unknown session ID (`400`); the corrected protocol requires `404`, so the expectation was updated before rerunning focused and full gates.
- Focused auth-isolation validation passed after that correction. Full test attempt 2 passed: 743 library tests plus all integration and documentation tests completed successfully through `docdexd run-tests`.
- Release metadata verification passed for `v0.2.92`; the 16 feature-matrix contract tests and two reproducible-packaging regressions passed.
- `cargo check --locked --all-targets` passed in isolation. The first concurrent attempt was terminated when npm's install hook replaced the local daemon, so it was rerun after npm validation to remove process interference.
- All 223 npm tests passed, packaging guardrails and `npm pack --dry-run` passed, and npm audit reported zero vulnerabilities.
- `scripts/security_audit.sh` passed, including Cargo audit, npm audit, and Rust/npm SBOM generation.
- The optimized release binary built successfully and passed all 24 verified release feature-matrix checks with zero failures.
- A black-box source-built runtime smoke test returned HTTP 200 for a fresh MCP initialize and HTTP 404 with `unknown or expired MCP session` for a forged stale session ID.

## Remaining

- Run the staged pre-commit gate.
- Publish and verify `v0.2.92`.

## Blockers

- None.
