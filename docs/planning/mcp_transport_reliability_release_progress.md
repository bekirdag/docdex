# MCP Transport Reliability Release Progress

## Status

Implementation and local release validation complete; publication in progress.

## Evidence

- The current branch is `main`, the worktree was clean at diagnosis start, and `HEAD` is `fbcca0b Fix MCP startup without default repo`.
- Current npm package metadata is version `0.2.90`.
- The live daemon accepts repo-scoped MCP calls, but an unbound `docdex_get_profile` call returned HTTP 400 `missing_repo`; this contradicts the global profile-tool contract and confirms an installed/runtime behavior gap.
- Repo memory identifies prior daemon readiness hardening and the current source changelog describes the 0.2.90 unbound Streamable HTTP MCP startup fix.
- The installed 0.2.90 daemon restarted during diagnosis (PID/lock timestamp changed) and an MCP delegation call received an empty HTTP reply, reproducing the lifecycle failure.
- `src/cli/daemon_spawn.rs` previously killed any matching live `docdexd` process after one 300 ms health-probe miss. It now trusts the held/running daemon lock and waits up to the configured readiness timeout instead.
- `src/api/mcp_http.rs` now routes unbound global profile read/write calls without binding a repository; `docdex_stats` and other repo-scoped tools still return `missing_repo`.
- Impact analysis: `src/cli/daemon_spawn.rs` has inbound dependencies from `src/cli/mod.rs` and `src/setup/mod.rs`; `src/api/mcp_http.rs` is consumed by `src/api/mod.rs`. Both impact traversals were complete (not truncated).
- AST inspection confirmed the edited functions and test module locations before implementation.
- Focused validation passed:
  - `cargo test --lib slow_live_daemon_is_waited_for_instead_of_replaced -- --nocapture`
  - `cargo test --lib mcp_http_multi_repo_initialize_without_root_allows_startup_but_not_repo_tools -- --nocapture`
  - `cargo fmt --check`
  - `git diff --check`
- Release metadata and changelogs are synchronized at version `0.2.91`; npm confirms that version is not yet published.
- Repo-native full test gate passed: `target/debug/docdexd run-tests --repo ...` completed 742 library tests plus all integration/doc tests with exit code 0.
- `cargo check --locked --all-targets` passed.
- All 223 npm tests and the npm tarball packaging guardrail passed.
- Release-version verification, 16 feature-matrix contract tests, reproducible packaging tests, npm dry-run packaging, and npm audit passed.
- `scripts/security_audit.sh` passed; Rust/npm audit and SBOM artifacts were generated, with zero npm vulnerabilities.
- Runtime lifecycle smoke: a source-built daemon was suspended beyond the 300 ms health probe; a CLI call timed out after the configured 1 second, the original daemon PID survived, and health recovered after resume.
- Runtime MCP smoke: an unbound source-built multi-repo session successfully saved/read a global profile preference, while unbound `docdex_stats` returned HTTP 400 `missing_repo`.

## Remaining

- Commit/tag/push the validated release and publish npm 0.2.91.
- Verify the published package and update this record.

## Blockers

- None yet.
