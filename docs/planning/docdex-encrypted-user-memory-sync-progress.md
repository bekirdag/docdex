# Docdex Encrypted User Memory Sync Progress

Status: release validation complete locally; pending commit, tag, push, hosted deploy, and npm publish verification
Started: 2026-07-10
Companion plan: `docs/planning/docdex-encrypted-user-memory-sync-plan.md`

## Goal

Plan a feature for Docdex and mswarm that uploads local repo memory, profile memory, personal preferences, and mind-clone data into encrypted Docdex server storage per mswarm API-key user, merges data from multiple machines, down-syncs merged updates to local Docdex stores, and exposes safe server memory context to mcoda agents.

## Progress

- [x] Loaded Docdex profile and repo memory context.
- [x] Confirmed existing external API-key auth/introspection and encrypted repo access planning.
- [x] Reviewed existing personal-preferences and mind-clone planning/progress material.
- [x] Created the initial planning document.
- [x] Review with the user and split into first implementation slice.
- [x] Add disabled-by-default sync config and read-only user-memory sync inventory API.
- [x] Add push bundle builder and local idempotency ledger.
- [x] Use the existing configured mswarm API key as the non-secret local identity source for user-memory sync.
- [x] Add local server-store user-memory device registration and append-only event storage.
- [x] Add local server-store feed and ack endpoints.
- [x] Add opaque encrypted payload envelope validation and server-feed persistence.
- [x] Add optional local encrypted payload envelope generation for bundle events.
- [x] Add local down-sync apply path for encrypted profile-memory events.
- [x] Add hosted AuthContext/mswarm API-key principal scoping for user-memory server-store endpoints.
- [ ] Add safe local down-sync importers for personal-preferences and mind-clone lanes.
- [ ] Finalize long-term mswarm scope names for sync, clone context, device admin, and deletion.
- [x] Update threat model for user-memory sync local/hosted risk boundaries.

## Context Gathered

Relevant existing foundations found during planning:

- `src/auth.rs` owns external API-key introspection, `AuthContext`, credential fingerprinting, service-token admin checks, and repo access bindings.
- `docs/planning/docdex-external-api-key-encrypted-repo-access-plan.md` documents the existing Docdex encrypted server API-key access model and security invariants.
- `docs/planning/mswarm-docdex-encrypted-repo-access-implementation-plan.md` documents the mswarm and mcoda flow for encrypted Docdex repo access.
- `docs/planning/personal_preferences_mind_clone_implementation_plan.md` and `docs/planning/personal_preferences_mind_clone_progress.md` document the local mind-clone export and governance model.
- `src/api/v1/personal_preferences.rs` and `src/personal_preferences/export.rs` provide the likely source surfaces for a sync adapter.
- `src/personal_preferences/mod.rs` `export_bundle` writes an export file, so sync dry-run must not call it. Use read-only status/list methods for inventory.
- `src/personal_preferences/types.rs` `PersonalPreferenceStatus` already exposes counts for captures, derived records, claims, evidence, clone profiles/context/evaluations, routines, redaction spans, and retention policies.
- `src/personal_preferences/generated_skills.rs` exposes read-only generated-skill status/listing methods, so generated skills are an explicit opt-in lane with review-only down-sync.
- `src/user_memory_sync.rs` now owns the first sync schema/policy matrix, lane parser, and excluded-local-data policy.
- `src/api/v1/user_memory_sync.rs` exposes local status and dry-run inventory routes at `/v1/user-memory/sync/status` and `/v1/user-memory/sync/dry-run`.
- Second implementation slice scope: add stable local bundle/event schema, a SQLite idempotency ledger helper, and a non-mutating dry-run bundle endpoint that reports object ids, hashes, counts, and ledger status without uploading or returning raw payload content.
- `src/user_memory_sync.rs` now defines `UserMemorySyncEvent`, `UserMemorySyncBundle`, deterministic `sha256:` content hashes, stable event/bundle ids, and a SQLite ledger at `<state>/user_memory_sync/ledger.sqlite3`.
- `src/api/v1/user_memory_sync.rs` now exposes `/v1/user-memory/sync/bundle/dry-run`. It emits profile-memory event references plus inventory snapshot events for personal-preferences, mind-clone, and generated-skills lanes; it returns event ids, object ids, hashes, sensitivity labels, lane counts, and read-only ledger state, not raw memory payloads.
- `src/search/mod.rs` registers the new dry-run bundle route beside the existing status and inventory dry-run routes.
- `src/user_memory_sync.rs` now defines `UserMemorySyncIdentity` and derives it from `[integrations.mswarm].api_key` by default, falling back to `memory.user_memory_sync.api_key_env` when that env var resolves to a non-empty credential.
- `src/cli/commands/serve.rs` wires the identity descriptor into `daemon::serve`, and `src/search/mod.rs` carries it in `AppState`.
- `src/api/v1/user_memory_sync.rs` includes the non-secret identity descriptor in status, dry-run, and bundle dry-run responses. Notes explain that server-side mswarm API-key introspection resolves the canonical principal and that raw credentials are not returned.
- `src/user_memory_sync.rs` now defines `UserMemorySyncServerStore`, a local SQLite prototype at `<state>/user_memory_sync/server.sqlite3` with device registration, append-only event storage, idempotent push, feed cursors, per-device ack records, and per-principal isolation keyed by the non-secret credential fingerprint.
- `src/api/v1/user_memory_sync.rs` now exposes guarded local prototype endpoints: `POST /v1/user-memory/devices/register`, `POST /v1/user-memory/sync/push`, `GET /v1/user-memory/sync/feed`, and `POST /v1/user-memory/sync/ack`. Mutating/read feed endpoints require `memory.user_memory_sync.enabled = true` and a configured mswarm API-key identity descriptor.
- `src/search/mod.rs` registers the live user-memory prototype endpoints beside status and dry-run routes.
- `src/user_memory_sync.rs` now defines `UserMemorySyncPayloadEnvelope` and validates that live events are either summary-only or opaque encrypted envelopes. Cleartext/plaintext/raw JSON payload envelope modes are rejected before persistence.
- `src/user_memory_sync.rs` persists optional encrypted payload envelopes in `user_memory_sync_server_events.payload_envelope_json` and feeds them back unchanged for local devices to decrypt and merge later. Existing local prototype DBs are migrated by adding the nullable column.
- `src/api/v1/user_memory_sync.rs` now exposes `payload_mode` and `payload_encrypted` in dry-run bundle event refs, and endpoint notes document that live push/feed payloads are summary-only or encrypted envelopes.
- `src/config.rs` and `src/config/env_overrides.rs` now support optional `memory.user_memory_sync.encryption_key_env` / `DOCDEX_USER_MEMORY_SYNC_ENCRYPTION_KEY_ENV` for dedicated local payload key material.
- `src/user_memory_sync.rs` now defines `UserMemorySyncPayloadEncryptionKey`, resolves 32-byte payload keys from an env var, derives a non-secret key id, and can emit AES-256-GCM encrypted payload envelopes with authenticated metadata.
- `src/api/v1/user_memory_sync.rs` resolves the optional payload encryption key once during bundle construction. If configured, local profile and inventory bundle events include opaque encrypted payload envelopes; otherwise they remain summary-only and report that no sync encryption key env is configured.
- `src/user_memory_sync.rs` now decrypts AES-256-GCM payload envelopes with event-identity AAD and post-decrypt payload-hash verification, and the local ledger can record down-synced feed events as `applied` or `skipped`.
- `src/api/v1/user_memory_sync.rs` now exposes `POST /v1/user-memory/sync/apply`. It excludes the local device by default, applies encrypted profile-agent/profile-preference events into profile memory, rebuilds embeddings locally, records applied/skipped ledger state, and acks only applied or intentionally skipped events. Summary-only profile events and non-profile inventory/policy lanes are skipped without mutating local source stores.
- `src/auth.rs` now exposes `authenticate_user_memory_sync`, which uses external API-key introspection with requested resource type `docdex_user_memory` and requires one of the implemented sync scope aliases or wildcard scopes.
- `src/api/v1/user_memory_sync.rs` now resolves request credentials into an `AuthContext` when `x-api-key` or bearer credentials are supplied, hashes `issuer + principal_id` for the server-store principal key, and falls back to the configured local mswarm API-key fingerprint only when no request credential is present and auth mode is not external-only.

## Notes

- A local delegation attempt was made to draft an outline, but the Docdex local completion call timed out after roughly 300 seconds. The plan was drafted manually from repo context instead.
- Runtime implementation now includes a server-store prototype for sanitized event bundles, hosted AuthContext/mswarm principal scoping, opaque encrypted payload envelopes, and local encrypted profile down-sync apply. Hosted key management, background worker scheduling, mswarm/mcoda product surfaces, and non-profile lane importers remain future work.
- The live push route writes the local server-store prototype and records accepted events in the local upload ledger. Feed, apply, and ack routes operate on the prototype server-store; apply currently mutates only encrypted profile-memory events and records other lanes as skipped.
- Bundle dry-run remains non-mutating and returns ids/hashes/counts only.
- Identity is now based on the mswarm API key already present in Docdex config. The implementation intentionally does not print, return, sync, store in memory, or document the raw key value; only a short namespaced fingerprint and source metadata are exposed for diagnostics.
- Hosted request scoping is implemented for register/push/feed/apply/ack when request credentials are present. The next runtime slice should add background worker/CLI push-pull controls and broaden safe local importers beyond profile memory.
- The current encryption-writer slice can encrypt local bundle event payloads when a dedicated payload key env is configured. The mswarm API key remains identity-only and must not be reused as encryption material. Without the payload key env, local bundle events remain summary-only.
- The current apply slice is intentionally conservative: profile memory can round-trip through encrypted payload events; personal preferences, mind clone, generated skills, repo memory, diary, conversation summaries, and temporal KG require lane-specific safe importers before they mutate local stores.

## Validation Evidence

- Explicit ignored-file whitespace check passed on 2026-07-10 using `git diff --no-index --check`.
- ASCII check passed for both new planning files.
- `git check-ignore -v` shows `docs/planning/` is ignored by `.gitignore:34`, so these planning files are local artifacts unless force-added later.
- `docdex_index` was attempted for both files, but Docdex excluded them with `ignored_by_pattern` because `docs/planning/` is ignored.
- Docdex reindexed new/touched Rust files on 2026-07-10: `src/user_memory_sync.rs`, `src/api/v1/user_memory_sync.rs`, `src/config.rs`, `src/search/mod.rs`, and `src/daemon.rs`.
- Docdex impact graphs were run for `src/config.rs`, `src/search/mod.rs`, `src/daemon.rs`, `src/user_memory_sync.rs`, and `src/api/v1/user_memory_sync.rs`. Broad shared-file graphs were truncated, but direct new-module graphs showed expected inbound/outbound links.
- `docdexd run-tests --repo /Users/bekirdag/Documents/apps/docdex --target src/user_memory_sync.rs` was attempted but rejected the source-file target because this repo lacks custom target mapping.
- 2026-07-10: `cargo fmt` passed.
- 2026-07-10: `cargo test user_memory_sync --lib` passed: 6 tests passed.
- 2026-07-10: `cargo check --all-targets` passed.
- 2026-07-10: `git diff --check` passed.
- 2026-07-10: `git diff --no-index --check /dev/null src/user_memory_sync.rs` and the same check for `src/api/v1/user_memory_sync.rs` produced no whitespace diagnostics. Exit code was 1 because the compared files differ from `/dev/null`.
- 2026-07-10: Docdex reindexed `src/user_memory_sync.rs`, `src/api/v1/user_memory_sync.rs`, and `src/search/mod.rs`; symbol extraction returned `ok` for both new sync files.
- 2026-07-10: Docdex impact graphs were rerun for `src/user_memory_sync.rs`, `src/api/v1/user_memory_sync.rs`, and `src/search/mod.rs`. Shared router graphs were broad/truncated; the direct dependencies remained the expected API/module/router edges.
- 2026-07-10: Current identity slice validation passed with `cargo fmt`, `cargo test user_memory_sync --lib`, `cargo check --all-targets`, and `git diff --check`.
- 2026-07-10: After updating this progress document, `cargo fmt --check`, `cargo test user_memory_sync --lib`, and `cargo check --all-targets` all passed again.
- 2026-07-10: `docdexd run-tests --repo /Users/bekirdag/Documents/apps/docdex` was attempted for the preferred runner, but it produced no output for roughly 90 seconds and was interrupted. No failure output was emitted before interruption.
- 2026-07-10: Docdex reindexed the current identity-slice Rust files: `src/user_memory_sync.rs`, `src/api/v1/user_memory_sync.rs`, `src/search/mod.rs`, `src/daemon.rs`, `src/cli/commands/serve.rs`, `src/api/mcp_http.rs`, `src/api/v1/telemetry.rs`, and `src/search/tests.rs`.
- 2026-07-10: Docdex symbol extraction returned `ok` for `src/user_memory_sync.rs`, `src/api/v1/user_memory_sync.rs`, `src/search/mod.rs`, `src/daemon.rs`, and `src/cli/commands/serve.rs`.
- 2026-07-10: Docdex impact graphs were run before the identity-slice edits for `src/user_memory_sync.rs`, `src/api/v1/user_memory_sync.rs`, `src/search/mod.rs`, `src/daemon.rs`, `src/cli/commands/serve.rs`, and later `src/api/mcp_http.rs`. Broad shared-file graphs were truncated but showed expected direct dependencies.
- 2026-07-10: A Docdex local-delegation call for the identity slice timed out after roughly 300 seconds, so the change was implemented directly and validated with the focused Rust checks above.
- 2026-07-10: Before the local server-store prototype edits, Docdex search/AST/impact tools were rerun for `src/user_memory_sync.rs`, `src/api/v1/user_memory_sync.rs`, and `src/search/mod.rs`. Direct dependencies were the expected sync module, API module, and router edges; shared router impact remained broad/truncated.
- 2026-07-10: A Docdex local-delegation call for the server-store slice produced only a short generic checklist, so the implementation was completed directly and validated locally.
- 2026-07-10: `cargo fmt` passed after adding the local server-store prototype.
- 2026-07-10: `cargo test user_memory_sync --lib` passed: 8 tests passed.
- 2026-07-10: `cargo fmt --check`, `cargo check --all-targets`, and `git diff --check` passed after the docs/progress update.
- 2026-07-10: Docdex reindexed `src/user_memory_sync.rs`, `src/api/v1/user_memory_sync.rs`, and `src/search/mod.rs`; symbol extraction returned `ok` for both user-memory sync modules.
- 2026-07-10: Before the encrypted-envelope slice, Docdex profile/memory/clone-directive, search, AST, and impact tools were run for `src/user_memory_sync.rs` and `src/api/v1/user_memory_sync.rs`. Direct impact showed the expected sync module/API/router edges.
- 2026-07-10: A Docdex local-delegation attempt for the encrypted-envelope slice produced unusable/truncated output, so the implementation was completed directly.
- 2026-07-10: `cargo test user_memory_sync --lib` passed after adding encrypted envelope validation/persistence: 10 tests passed.
- 2026-07-10: `cargo fmt --check`, `cargo check --all-targets`, and `git diff --check` passed after the encrypted-envelope slice.
- 2026-07-10: Explicit whitespace checks for both ignored planning docs passed via `git diff --no-index --check`; exit code was 1 only because each file differs from `/dev/null`.
- 2026-07-10: ASCII checks passed for both planning docs.
- 2026-07-10: Docdex reindexed `src/user_memory_sync.rs` and `src/api/v1/user_memory_sync.rs`; symbol extraction returned `ok` for both files. Impact graphs were rerun for both files; they showed expected direct API/sync/router dependencies and broad shared-file traversal truncated at the requested edge cap.
- 2026-07-10: Before the optional encryption-writer slice, Docdex profile/memory/clone-directive, search, symbols, and impact tools were run for `src/user_memory_sync.rs` and `src/api/v1/user_memory_sync.rs`. Direct impact remained the expected sync module/API/router edges.
- 2026-07-10: `cargo test user_memory_sync --lib` passed after adding optional AES-GCM payload envelope generation: 11 tests passed.
- 2026-07-10: `cargo fmt --check`, `cargo check --all-targets`, and `git diff --check` passed after the optional encryption-writer slice.
- 2026-07-10: After updating the plan/progress docs for the optional encryption-writer slice, `cargo fmt --check`, `cargo test user_memory_sync --lib` (11 tests), `cargo check --all-targets`, `git diff --check`, explicit ignored-doc whitespace checks, and ASCII checks all passed.
- 2026-07-10: Docdex reindexed `src/user_memory_sync.rs`, `src/api/v1/user_memory_sync.rs`, `src/config.rs`, and `src/config/env_overrides.rs`; symbol extraction returned `ok` for all four. Impact graphs were rerun for the same files. Shared config/router traversals were broad and truncated at the requested cap, while direct dependencies remained the expected sync module/API/config-env edges.
- 2026-07-10: Before the local apply slice, Docdex profile and repo memory were loaded; Docdex search/symbol/AST/impact tools were run for `src/user_memory_sync.rs`, `src/api/v1/user_memory_sync.rs`, `src/profiles/manager.rs`, `src/profiles/mod.rs`, and personal-preferences modules. Direct impact remained the expected sync module/API/profile/router edges.
- 2026-07-10: `cargo fmt` passed after adding encrypted profile down-sync apply.
- 2026-07-10: `cargo test user_memory_sync --lib` passed after adding decrypt round-trip and applied/skipped ledger coverage: 13 tests passed.
- 2026-07-10: Focused auth/user-memory tests passed after hosted AuthContext scoping: `cargo test --locked auth::tests --lib` passed 8 tests; `cargo test --locked user_memory_sync --lib` passed 16 tests.
- 2026-07-10: `cargo check --locked --all-targets` passed after hosted AuthContext scoping.
- 2026-07-10: Full release-gate Rust validation passed: `cargo test --locked --all` completed successfully with library tests at 615 passed, 1 ignored, all integration/doc tests green, and ignored soak/perf tests unchanged.
- 2026-07-10: `tests/mcp_local_completion.rs` was serialized with an in-process mutex after focused diagnostics showed parallel test daemons could produce `database is locked` from the MCP proxy. The focused test then passed with the default test runner, and the full suite passed.
- 2026-07-10: HTTP integration daemon health waits in test files were widened from 10 seconds to 30 seconds after full-suite load showed repeated transient healthz startup timeouts while individual tests passed. This is test-harness-only and does not alter runtime behavior.
- 2026-07-10: Release metadata was bumped to 0.2.85 across Cargo, npm, release-please, MCP server metadata, server metadata, and changelogs.
- 2026-07-10: `cargo fmt --check`, `git diff --check`, and ASCII checks for the planning/progress/security/changelog docs passed after the version bump.
- 2026-07-10: `cargo check --locked --all-targets` passed for the version-bumped crate.
- 2026-07-10: `npm --prefix npm test` passed after updating the packaged agent-instruction marker to 0.2.85: 216 tests passed.
- 2026-07-10: `npm --prefix npm run pack:verify` passed.
- 2026-07-10: `npm --prefix npm audit --omit=dev` initially reported high-severity `tar` advisories. The packaged dependency was upgraded to `tar` 7.5.19, `npm --prefix npm install --ignore-scripts` updated the lockfile, and `npm --prefix npm audit --omit=dev` then reported 0 vulnerabilities.
- 2026-07-10: `npm --prefix npm pack --ignore-scripts` produced `docdex-0.2.85.tgz` successfully; the generated tarball was removed from the worktree after validation.
- 2026-07-10: `npm --prefix npm publish --dry-run --provenance --access public` accepted `docdex@0.2.85`.
- 2026-07-10: `cargo test --locked user_memory_sync --lib` passed for the version-bumped crate: 16 tests passed.
