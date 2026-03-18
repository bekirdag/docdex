Mswarm Telemetry + Consent Implementation Plan

Status: complete for the current shipped scope
Opened: 2026-03-18
Owners: Docdex, mcoda, mswarm

## Goal

Add a legally explicit, opt-in-required telemetry pipeline for Docdex and mcoda that:

- blocks initial product use until the user accepts terms and telemetry consent
- creates a stable free-client identity for unpaid Docdex installations
- stores consent proof on mswarm with network metadata
- captures product activity locally in `~/.docdex`
- packages, compresses, signs, checksums, uploads, retries, and ages out telemetry bundles
- lets mswarm verify integrity before ingest
- allows paid mswarm clients to reuse cached finalized answers

## Scope

In scope:

- Docdex setup/install consent gate
- mcoda install/setup consent gate
- free Docdex client identity and registration
- local telemetry spool and hourly daemon upload
- mswarm consent proof persistence and package ingest
- local and cloud mcoda rating export through Docdex daemon
- paid-answer cache reuse for Docdex web answers

Out of scope for the first shipped slice:

- full historical backfill of prior local activity
- admin UI for telemetry browsing
- deletion fulfillment automation beyond request intake, proof, and tracking

## Constraints

- Consent is mandatory. Rejecting the consent flow stops setup and blocks use.
- The server must preserve proof that the user accepted, including request IP and timestamp.
- Unpaid users still send anonymous product telemetry; a free client UUID anchors that data.
- mcoda has no daemon, so Docdex daemon must upload the shared package.
- Upload packages must be compressed, signed, and checksummed before upload.
- Failed uploads retry up to three times immediately per cycle, stay queued for the next hourly cycle, and are deleted after 30 days even if never uploaded.

## Architecture

### 1. Client identity and consent

Docdex:

- Add `docs/mswarm-data-collection-terms.md`.
- Extend setup wizard and npm postinstall flow to show the terms and require acceptance.
- Persist acceptance in `~/.docdex/config.toml`.
- Create a local free-client UUID for unpaid installs.
- If an mswarm API key is configured, bind telemetry to the paid subject instead of the free UUID.

mcoda:

- Mirror the consent requirement during install/setup.
- Persist its local consent state and client identity in `~/.mcoda`.
- Reuse Docdex daemon for hourly shipping instead of creating a background worker.

mswarm:

- Add free-client registration and consent issue endpoints.
- Store a durable client record keyed by UUID.
- Store consent proof with accepted policy version, source IP, user agent, and timestamps.
- Issue consent tokens for both paid and free clients.

### 2. Local telemetry capture

Docdex local spool under `~/.docdex/state/mswarm/`:

- `clients/`
- `consent/`
- `events/`
- `packages/pending/`
- `packages/failed/`
- `packages/sent/`
- `ratings/`

Captured locally:

- web search queries
- search result pages
- fetched page content
- ai-digested/finalized web answers
- local delegation failures
- mcoda local and cloud agent scoring/rating updates

### 3. Hourly packaging and upload

Docdex daemon:

- run an hourly uploader task
- collect unsent local records
- build a package manifest
- compress payload
- compute checksum
- sign package with a local private key
- upload to mswarm
- delete package after successful upload
- retry failed uploads up to three times per cycle
- keep failed packages for next cycle
- purge packages older than 30 days

mswarm:

- verify checksum
- verify signature against registered client public key or shared registration secret
- reject tampered or malformed packages
- store accepted package metadata and unpacked events

### 4. Paid answer cache reuse

Docdex web pipeline:

- before running remote search/fetch/digest, ask mswarm for a finalized cached answer when a paid client is configured
- if a valid cached answer exists, return that answer directly
- if no cached answer exists, execute the normal pipeline and store the finalized answer locally and remotely

mswarm:

- add finalized-answer cache lookup endpoint
- key by normalized query plus relevant provider/context dimensions
- return cached answer plus provenance/age metadata

## Phases

### Phase 1: Consent and identity foundation

Docdex:

- add terms document
- add mandatory consent step to setup
- persist local client identity and consent state
- add config surface for telemetry enablement and client metadata

mswarm:

- add free-client registration endpoint
- add free-client consent issue endpoint
- persist client records and consent proof

mcoda:

- document and scaffold matching consent requirements

Acceptance:

- fresh Docdex setup cannot complete without acceptance
- accepted setup registers a free client and receives a consent token
- paid setup can still bind to a paid identity

### Phase 2: Local telemetry spool

Docdex:

- add spool directories and schema
- record search/fetch/digest/delegation/rating events locally

Current slice completed:

- state layout now provisions `~/.docdex/state/mswarm/{clients,consent,events,ratings,packages/*}`
- web research writes local event files for:
  - search query + discovery results
  - fetched page content
  - ai-digested page answers
- direct `/v1/web/fetch` calls also write local fetch events
- local delegation failures are mirrored into the mswarm event spool
- mcoda rating/scoring export now flows into the same Docdex package build from the local mcoda SQLite store
- package manifests and gzip payloads are built during hourly housekeeping
- retention/pruning now deletes stale local event files and packages older than 30 days
- web-answer events now carry provider/context dimensions so the paid finalized-answer cache can key beyond raw query text

Acceptance:

- running a Docdex web search produces local spool records
- local delegation failures appear in the spool

### Phase 3: Signed hourly upload

Docdex:

- add hourly uploader task to daemon housekeeping
- package, compress, sign, checksum, retry, and prune

mswarm:

- add package ingest and verification endpoint

Acceptance:

- a queued local package uploads successfully and is deleted
- a failed upload stays queued until a later cycle

Status:

- completed for Docdex daemon + mswarm gateway

### Phase 4: mcoda rating export

mcoda:

- expose local/cloud scoring deltas for Docdex pickup

Docdex:

- include mcoda rating payloads in the hourly package

Acceptance:

- mcoda scoring changes arrive in mswarm via Docdex daemon uploads

Status:

- completed for rating export from the local mcoda SQLite store into Docdex packages
- completed for standalone mcoda consent bootstrap through `mcoda consent accept`, `mcoda consent revoke`, and `mcoda consent request-deletion`
- mcoda blocks non-exempt commands until telemetry consent has been accepted locally

### Phase 5: Paid finalized-answer cache reuse

Docdex:

- consult mswarm for finalized cached answers before doing remote work

mswarm:

- serve cached finalized answers

Acceptance:

- repeated paid searches can bypass the expensive fetch/digest path

Status:

- completed for mswarm-backed finalized-answer lookup before remote web discovery
- cache lookups and stored answers now support provider/context-aware keys with query-only fallback for older cached entries

## Data model

### Docdex config additions

Proposed `~/.docdex/config.toml` shape:

```toml
[integrations.mswarm]
base_url = "https://api.mswarm.org/"
api_key = ""

[integrations.mswarm.telemetry]
required = true
consent_accepted = false
consent_policy_version = ""
consent_token = ""
client_id = ""
client_type = "free_docdex_client"
registered_at_ms = 0
upload_signing_secret = ""
last_upload_at_ms = 0
```

### mswarm client record

Server-side durable record:

- `client_id`
- `client_type`
- `product`
- `product_version`
- `tenant_id` nullable
- `consent_policy_version`
- `consent_types`
- `consent_ip_address`
- `consent_user_agent`
- `latest_consent_jti`
- `latest_consent_token_hash`
- `registered_at`
- `last_consented_at`
- `updated_at`
- `metadata`

### mswarm consent proof

- `client_id`
- `policy_version`
- `accepted_at`
- `ip`
- `user_agent`
- `consent_types`
- `token_hash`

## Security

- free Docdex clients receive a server-issued per-client `upload_signing_secret`
- paid Docdex clients sign with their mswarm API key
- every package uploads a gzip-compressed JSON payload plus SHA256 checksum and HMAC-SHA256 signature
- server verifies checksum and signature before unpacking
- server stores consent/client audit metadata and rejects mismatched consent/upload identities

## Privacy and rights

- terms explain collected categories, retention, and transfer to mswarm
- consent revocation already blocks future uploads through the consent-token path
- local pending packages older than 30 days are deleted
- formal deletion request intake/workflow is implemented for both free and paid identities
- deletion fulfillment after intake remains an operational follow-up outside this shipped slice

## Testing strategy

Docdex:

- setup consent unit tests
- config persistence tests
- local spool tests
- hourly uploader tests with retry and pruning
- web-search capture tests

mswarm:

- free-client registration tests
- consent issuance tests
- package verification tests
- consent proof persistence tests

Integration:

- end-to-end free install flow
- end-to-end paid install flow
- signed package upload from Docdex to local mswarm
- finalized-answer cache hit flow

## Deployment order

1. Ship mswarm registration + consent server support. Done.
2. Ship Docdex consent gating against those endpoints. Done.
3. Ship local spool capture. Done.
4. Ship signed uploader. Done.
5. Ship finalized-answer cache reuse. Done.
