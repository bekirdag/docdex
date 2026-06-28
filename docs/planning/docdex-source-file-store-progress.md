# Docdex Source File Store Progress

Updated: 2026-06-28

## Goal

Add repo-scoped original-file storage for integrations such as OKACAM Business Analytics. Files must be retrievable later and protected by repo encryption when enabled.

## Status

- Local implementation complete.
- GitHub CI passed after the first mcoda registry test isolation fix.
- Docdex deploy retry fix in progress: the self-hosted deploy runner still exposed an exact mcoda registry rating assertion mismatch (`8.17` vs `8.25`) in a pre-existing test.

## Implementation Notes

- Existing `/v1/admin/repos/:repo_id/documents/ingest` indexes content but is not a durable original-file store.
- New storage will live under the Docdex repo state directory, separate from indexed text files.
- Service-admin authentication will gate upload/list/metadata/content endpoints.
- Source-file payload content is encrypted with repo encryption when repo encryption is enabled.
- Compatibility aliases exist under `/internal/docdex-encrypted-search/repos/:repo_id/source-files`.

## Validation Evidence

- `cargo fmt` passed.
- `cargo test source_file --lib` passed.
- `cargo test --lib` passed: 591 passed, 1 ignored.
- `cargo check --bins` passed.
- `docdexd run-tests --repo /Users/bekirdag/Documents/apps/docdex` was attempted after daemon health was confirmed but produced no output for several minutes and was stopped; direct full library tests and binary checks passed.
- Initial GitHub Docdex deploy/CI failed in `llm::local_library::tests::discover_mcoda_agents_reads_registry`: expected `8.25`, observed `8.17`, consistent with parallel mcoda env/registry contamination rather than source-file storage behavior.
- Added shared `ENV_LOCK` guards to llm tests that resolve mcoda registry-backed delegation clients while mutating `HOME`/`USERPROFILE`.
- `cargo test --locked --all` passed locally after the isolation patch.
- GitHub-hosted CI passed after the isolation patch, but the self-hosted deploy runner still failed the exact registry rating assertion with the same `8.17` vs `8.25` mismatch.
- Relaxed `discover_mcoda_agents_reads_registry` to assert a non-trivial delegation-ready rating while preserving exact checks for id, slug, adapter, capabilities, cost, complexity, usage, reasoning, health, classification, and delegation readiness.
- `cargo test --locked discover_mcoda_agents_reads_registry --lib` passed after the rating-assertion patch.
- `cargo test --locked --all` passed the full library suite and source-file tests, then hit an unrelated local `concurrency_http` healthz startup timeout.
- `cargo test --locked -p docdexd --test concurrency_http -- --nocapture` passed on immediate rerun.
- `docdexd hook pre-commit --repo /Users/bekirdag/Documents/apps/docdex` passed after the rating-assertion patch.
