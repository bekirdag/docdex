Mswarm Telemetry + Consent Progress

Status: complete for the current shipped scope
Opened: 2026-03-18
Related plan: `docs/mswarm-telemetry-implementation-plan.md`

## Current status

- Plan created.
- Terms document created.
- Phase 1 Docdex setup consent gate implemented.
- Phase 1 mswarm free-client registration endpoint implemented.
- Focused Docdex and mswarm tests passed for the new consent/registration slice.
- Phase 2 local telemetry spooling completed in Docdex.
- Phase 3 signed packaging + upload completed in Docdex and mswarm.
- Phase 5 paid finalized-answer cache reuse completed end to end.
- mcoda install/setup consent bootstrap now covers packaged postinstall, `mcoda setup`, and the CLI consent lifecycle commands.
- User-facing deletion request workflows now exist in both Docdex and mcoda.
- The finalized-answer cache now uses provider/context-aware lookup keys with query-only fallback.

## Discoveries

- Docdex already has an mswarm config path and setup wizard section for `api_key`, `base_url`, and selecting `mswarm` as the web provider.
- Docdex setup state already defines `StepKey::Consent`, but the wizard currently skips that step in the actual flow.
- Docdex already has daemon housekeeping infrastructure in `src/daemon/multi_repo.rs`; the hourly uploader can be attached there.
- Docdex already persists web cache and delegation telemetry under `~/.docdex/state`, so the telemetry spool should reuse the same state-layout approach.
- The web research pipeline already assembles exactly the artifacts product wants to retain locally: discovery results, fetched page text, and ai-digested page answers.
- Local delegation failures already have a structured JSONL history, so Phase 2 can mirror the same failures into the mswarm spool without changing fallback behavior.
- mswarm already has consent JWT validation and anonymous/non-anonymous telemetry ingest endpoints.
- mswarm consent issuance currently assumes an authenticated paid subject or `proof.type = "api_key"`. That does not satisfy unpaid Docdex installs.
- mswarm persistence already supports durable product records through `runtime_kv` and `runtime_event_log`, but the product requirement needs a dedicated `docdex_clients` table for free-client identities and consent proof metadata.

## Risks

- Mandatory consent on install changes existing setup behavior and needs careful messaging plus tests.
- Free-client registration must coexist cleanly with the paid API-key path.
- Storing exact IP for consent proof is sensitive and must stay confined to the server-side consent audit path.
- Package signing requires stable key storage and rotation rules.
- The live CLI smoke that originally looked like a spool-write failure was actually hitting an older already-running daemon. Forcing `DOCDEX_CLI_LOCAL=1` against the rebuilt binary proved the current source tree writes `~/.docdex/state/mswarm/events/*` correctly.

## Work log

### 2026-03-18

- Read Docdex setup/config/daemon integration points.
- Read mswarm consent/telemetry gateway paths and storage primitives.
- Chose the first delivery slice:
  - mandatory terms + consent
  - free client registration
  - consent token issuance for free clients
  - Docdex config/state persistence for the new identity
- Deferred full hourly packaging and cached-answer reuse to later phases after the identity foundation is in place.
- Added `docs/mswarm-data-collection-terms.md`.
- Added Docdex config support for `[integrations.mswarm.telemetry]` and setup-time consent persistence.
- Wired `StepKey::Consent` into the Docdex setup wizard and made rejection stop setup.
- Added Docdex-side mswarm consent helpers for:
  - paid consent token issue via `/v1/swarm/consent/issue`
  - free-client registration via `/v1/swarm/docdex/free-client/register`
- Added mswarm `docdex_clients` persistence and the `/v1/swarm/docdex/free-client/register` gateway endpoint.
- Added focused coverage:
  - `cargo test --lib wizard_declining_consent_fails -- --nocapture`
  - `cargo test --lib set_mswarm_telemetry_config_updates_config -- --nocapture`
  - `cargo test --lib ensure_mswarm_telemetry_consent_registers_free_client -- --nocapture`
  - `pnpm test tests/api/gateway-consent-telemetry.test.ts`
- Validation blockers observed but not introduced by this slice:
  - broad Docdex `cargo test` currently stops in existing `tests/mcoda_agent_integration.rs` because `McodaAgent` initializers are missing the newer `usage_limits` field
  - broad mswarm `pnpm exec tsc --noEmit` currently reports many pre-existing workspace type errors outside the new consent/free-client path

### 2026-03-18 Phase 2 slice

- Extended Docdex state layout with a dedicated `mswarm/` subtree under `~/.docdex/state`.
- Added `src/mswarm_telemetry.rs` for local event-spool writes.
- Wired `run_web_research` to emit:
  - `web_search` events with query, provider, status, and discovered result URLs
  - `web_fetch` events with fetched page content
  - `web_answer` events when ai-digested page output exists
- Wired direct `/v1/web/fetch` responses to emit `web_fetch` events, including cache hits.
- Wired local delegation failure recording to also emit `delegation_failure` events into the mswarm spool.
- Added focused tests:
  - `cargo test --lib mswarm_telemetry -- --nocapture`
  - `cargo test --lib delegation_flow_writes_completion_failure_history -- --nocapture`
- Built Docdex release locally and confirmed a live `docdexd search --force-web --skip-local-search` request still uses `webDiscovery.provider = "mswarm"`.
- Deployment follow-up: mswarm production now serves `POST /v1/swarm/docdex/free-client/register` successfully after a MySQL timestamp-format hotfix in `packages/core/src/mysql.ts`.
- Confirmed the live local-binary smoke writes `web_search`, `web_fetch`, and `web_answer` event files under `~/.docdex/state/mswarm/events/`.

### 2026-03-18 Phase 3 + Phase 5 slice

- Added `upload_signing_secret` to Docdex telemetry config and free-client registration handling.
- Added Docdex packaging/upload housekeeping:
  - export mcoda `agent_run_ratings` rows into `~/.docdex/state/mswarm/ratings`
  - build gzip JSON packages from unsent event/rating files
  - attach SHA256 checksum + HMAC-SHA256 signature
  - retry failed uploads three times per cycle
  - prune local telemetry artifacts older than 30 days
- Wired daemon startup to run hourly telemetry housekeeping in the background.
- Added mswarm gateway support for:
  - returning/storing `upload_signing_secret` on free-client registration
  - `POST /v1/swarm/docdex/packages/ingest`
  - `GET/POST /v1/swarm/web/answer-cache/lookup`
- Package ingest now:
  - validates consent token ownership
  - verifies checksum + signature before unpacking
  - stores package events in `runtime_event_log`
  - stores finalized Docdex answers in `runtime_kv` for paid-answer cache reuse
- Docdex web discovery now checks the paid mswarm finalized-answer cache before remote browser/fetch work.
- Focused validation passed:
  - `cargo test --lib mswarm_telemetry -- --nocapture`
  - `cargo test --lib ensure_mswarm_telemetry_consent_registers_free_client -- --nocapture`
  - `pnpm test tests/api/gateway-consent-telemetry.test.ts`

### 2026-03-18 completion pass

- Added Docdex `docdexd mswarm status|revoke|request-deletion` so the local client can inspect consent state, opt out, and submit deletion requests without editing config by hand.
- Added contextual mswarm answer-cache lookup from Docdex web discovery using provider + query-category dimensions, with package-side event payloads updated to persist the same context for future cache writes.
- Added mcoda standalone consent support:
  - `mcoda consent show`
  - `mcoda consent accept`
  - `mcoda consent revoke`
  - `mcoda consent request-deletion`
- mcoda now blocks non-exempt commands until telemetry consent has been accepted locally.
- Added mswarm gateway support for:
  - `POST /v1/swarm/mcoda/free-client/register`
  - `POST /v1/swarm/data/deletion-request`
  - provider/context-aware `GET/POST /v1/swarm/web/answer-cache/lookup`
- Focused validation passed:
  - `cargo test --lib parse_mswarm_`
  - `cargo test --lib record_web_research_writes_search_fetch_and_answer_events`
  - `cargo build --release`
  - `pnpm test packages/core/src/api/__tests__/MswarmApi.test.ts packages/cli/src/__tests__/McodaEntrypoint.test.ts packages/cli/src/__tests__/ConsentCommands.test.ts`
  - `pnpm test tests/api/gateway-consent-telemetry.test.ts`
- Installed the rebuilt local Docdex binary with `DOCDEX_LOCAL_BINARY=./target/release/docdexd npm i -g ./npm`.
- Live smoke checks passed:
  - `docdexd --version` -> `0.2.56`
  - `docdexd mswarm status --json`
  - `DOCDEX_CLI_LOCAL=1 DOCDEX_WEB_ENABLED=1 docdexd search --repo /Users/bekirdag/Documents/apps/docdex --query "reqwest rust docs" --force-web --skip-local-search`
  - production deploy commit `e01a130`
  - `https://api.mswarm.org/healthz`
  - live `POST /v1/swarm/mcoda/free-client/register`
  - live `POST /v1/swarm/data/deletion-request`

### 2026-03-18 mcoda setup/install alignment

- Added packaged mcoda consent assets and lifecycle hooks:
  - bundled `packages/cli/MSWARM_DATA_COLLECTION_TERMS.md`
  - packaged `packages/cli/scripts/postinstall.js`
  - compiled `packages/cli/src/install/MswarmConsentBootstrap.ts`
- Added `mcoda setup` as the guided interactive setup fallback when installation cannot prompt.
- Updated the repo-local install helper `scripts/install-local-packages.js` to run the same consent bootstrap after linking the CLI binary.
- Added focused mcoda coverage:
  - `node --test dist/__tests__/MswarmConsentBootstrap.test.js dist/__tests__/McodaEntrypoint.test.js`
  - `pnpm --filter mcoda run pack:verify`
  - `pnpm --filter mcoda run test`

## Next steps

- Optional follow-up work outside the current shipped slice:
  - deletion fulfillment/erasure automation after the intake request is recorded
  - admin/reporting UI for telemetry browsing and deletion-request handling
