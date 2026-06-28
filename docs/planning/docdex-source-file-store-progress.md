# Docdex Source File Store Progress

Updated: 2026-06-28

## Goal

Add repo-scoped original-file storage for integrations such as OKACAM Business Analytics. Files must be retrievable later and protected by repo encryption when enabled.

## Status

- Local implementation complete.

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
