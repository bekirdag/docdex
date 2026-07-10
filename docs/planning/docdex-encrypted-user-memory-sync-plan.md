# Docdex Encrypted User Memory Sync Plan

Status: implementation in progress; local schema/config/dry-run bundle, mswarm-key identity, server-store push/feed/ack/apply routes, hosted AuthContext principal scoping, optional encrypted payload envelopes, and encrypted profile down-sync apply implemented
Started: 2026-07-10
Scope: Docdex local daemon, Docdex encrypted server service, mswarm API-key identity bridge, and mcoda/agent read access

## Summary

Docdex should be able to sync local memory lanes from multiple machines into the encrypted Docdex server service for the same user, merge them into one user-owned memory space, and feed safe updates back down to every opted-in local Docdex instance.

The user identity should come from the existing mswarm API-key flow. Local Docdex already has an mswarm API key in its config, and that key belongs to the user. Local Docdex and mcoda callers send the mswarm API key to the Docdex server using the existing accepted credential headers. The server introspects the key, resolves the tenant/user/API-key principal, authorizes the requested memory scope, and stores or reads only the data that principal is allowed to access.

The server should not become a raw transcript dump by default. The first version should sync structured, redacted, lane-aware memory records with explicit opt-in for sensitive lanes and raw evidence. Redactions, tombstones, and user review decisions must propagate back to local stores.

## Current Foundations

Existing repo work gives this feature a practical base:

- `src/auth.rs` already owns external API-key introspection, accepted `x-api-key` and bearer credential extraction, credential fingerprinting, `AuthContext`, service-token admin checks, and repo access bindings.
- `docs/planning/docdex-external-api-key-encrypted-repo-access-plan.md` defines the security invariants for mswarm API-key access to encrypted Docdex server data: raw API keys are not stored, raw keys are not encryption keys, and data-plane access must fail closed.
- `docs/planning/mswarm-docdex-encrypted-repo-access-implementation-plan.md` defines the mswarm module shape for letting mcoda call Docdex encrypted repo APIs with a user-owned mswarm API key.
- `src/api/v1/personal_preferences.rs` and the personal preferences MCP handlers already expose local preference and mind-clone surfaces.
- `src/personal_preferences/export.rs` and the mind-clone planning/progress docs define a rich export bundle with captures, claims, evidence, links, feedback, snapshots, decision patterns, style signals, clone profiles, timelines, goal graph, routines, override rules, redaction spans, and retention policies.
- The hosted server layout already has encrypted repo/source storage foundations and persistent state directories, including server-side personal-preferences storage.
- Current local implementation now includes disabled-by-default `memory.user_memory_sync` config, read-only status/inventory dry-run endpoints, a stable event/bundle schema, a local SQLite idempotency ledger helper, `/v1/user-memory/sync/bundle/dry-run` for hashes/counts-only bundle previews, and a local server-store prototype for device registration, push, feed, and ack.
- Current local implementation derives a non-secret identity descriptor from `[integrations.mswarm].api_key` by default, with `memory.user_memory_sync.api_key_env` as an override/fallback. Status and dry-run APIs expose only source/configured/fingerprint/principal-resolution metadata, never the raw credential.
- The server-store implementation persists only structured event metadata, payload summaries, and optional opaque encrypted payload envelopes in `<state>/user_memory_sync/server.sqlite3`. Cleartext payload envelopes are rejected before persistence. Local/offline calls fall back to the configured mswarm API-key fingerprint; hosted calls with `x-api-key` or bearer credentials use `AuthContext` from external API-key introspection and scope checks, then hash `issuer + principal_id` so multiple keys for the same user merge into one feed while different users remain isolated.
- Local bundle generation can emit opaque AES-256-GCM payload envelopes when `memory.user_memory_sync.encryption_key_env` names an environment variable containing 32-byte key material. This is a local prototype payload writer, not hosted key management. The mswarm API key remains only an identity credential and must not be reused as payload encryption material.
- Local down-sync apply is available for encrypted profile-memory events through `/v1/user-memory/sync/apply`. The apply path decrypts payload envelopes locally, verifies authenticated event metadata and payload hashes, rebuilds embeddings with the local profile embedder or deterministic fallback, imports profile agents/preferences with existing last-writer-wins semantics, records local ledger state, and acks applied or intentionally skipped feed events. Non-profile lanes remain inventory/policy events until safe lane-specific importers exist.

This plan extends those pieces into a multi-device, per-user sync product.

## Goals

- Sync local Docdex memory lanes from multiple machines into one encrypted, per-user server memory space.
- Support repo memory, profile memory, personal preferences, mind clone data, diary notes, conversation summaries, and temporal KG facts with lane-specific policies.
- Use mswarm API-key introspection to resolve the user and enforce scopes without storing raw API keys.
- Merge data deterministically and idempotently across devices.
- Down-sync merged server state to local Docdex stores so each machine can benefit from knowledge gathered elsewhere.
- Let mcoda agents and other authorized tools read safe user-memory context from the server using the same mswarm API-key identity model.
- Preserve local-first operation: local Docdex must keep working when the server is unavailable.
- Make sync inspectable, reversible, and opt-in per device and per lane.

## Non-Goals

- Do not use the mswarm API key as an encryption key.
- Do not upload raw transcripts, repo source files, terminal logs, secrets, or full evidence blobs by default.
- Do not merge data across users, tenants, or unrelated API-key principals.
- Do not let service-token admin APIs bypass data-plane user authorization.
- Do not make server sync required for local memory or clone features.
- Do not introduce conflict resolution that silently overrides explicit user redactions or deletions.

## Product Model

### User Memory Space

The server stores memory under a canonical user memory space resolved from introspection:

- `tenant_id`
- `owner_user_id` or equivalent user/principal id
- `api_key_id` for audit and authorization
- optional `workspace_id` or organization id if mswarm exposes one

The memory space is user-owned. API keys grant scoped access to that space, but the API key itself is not the memory identity.

Locally, Docdex should treat the configured mswarm API key as the credential that proves which user is attached to the sync request. The server remains responsible for turning that credential into the canonical user/principal id through introspection; local APIs should only report a non-secret descriptor so operators can see whether identity is configured.

### Devices

Each local Docdex instance that opts in registers a sync device:

- stable `device_id`
- display name chosen locally
- first seen and last seen timestamps
- enabled lanes
- sync cursor per lane
- local schema version
- optional public signing key for event integrity

Device registration should be revocable from the server. Revocation stops future sync and can optionally enqueue a local wipe command for server-originated data on that device.

### Memory Lanes

The sync system should model each memory family as a lane with its own adapter, sensitivity policy, merge behavior, and retention defaults.

| Lane | Default Direction | Default Payload | Merge Rule |
| --- | --- | --- | --- |
| Repo memory | opt-in push/pull per repo | structured technical facts and supersession metadata | merge by repo fingerprint, stable memory id, content hash, and supersedes chain |
| Profile memory | opt-in push/pull | global agent/user preferences and constraints | merge by stable preference id/category with last-writer-wins only for exact preference records |
| Personal preferences | opt-in push/pull | captures, derived records, claims, feedback, review state | merge by stable claim/version ids, evidence hash, confidence, and review status |
| Mind clone | opt-in push/pull | clone profiles, routines, style signals, decision patterns, goal graph, evaluations | merge by canonical object id, version, provenance, and sensitivity labels |
| Diary | opt-in push/pull | concise handoff notes and session outcomes | append-only with tombstones |
| Conversation memory | opt-in summaries only by default | summaries, episodic rollups, selected facts | append-only summaries; raw transcripts require explicit lane option |
| Temporal KG | opt-in push/pull | nodes, edges, episodes, provenance links | merge by entity/edge ids and provenance; tombstones win |
| Generated skills | opt-in push/pull, review-only down-sync | generated skill metadata, versions, validations, install policy, activation feedback | merge by skill id and version id; quarantine/review states win over install states |

Redaction spans, retention policies, tombstones, and user feedback are control-plane records. They must take precedence over ordinary content in every lane.

### Local Data Excluded by Default

These local data families are collected or produced locally but must not enter the default server sync payload:

- raw conversation transcripts and verbatim snippets
- full evidence blobs
- repo source files
- terminal logs and raw terminal context
- secrets and raw API keys
- raw connector payloads
- local indexes, embeddings, caches, and export files
- build and test artifacts

Generated skills are now an explicit sync lane, but down-sync must stage remote skills for local review. It must not auto-install a remotely learned skill.

## Architecture

### Local Sync Worker

Docdex local daemon gets a background sync worker plus explicit CLI/MCP controls.

Responsibilities:

- read local lane stores through lane adapters
- build deterministic delta bundles
- redact and classify records before upload
- push bundles with idempotency keys
- poll or long-poll the server feed
- apply down-sync events idempotently
- prevent echo loops by tracking source `device_id` and event ids
- expose dry-run and preview commands before first upload
- keep local memory usable while offline

Local config should support:

- `memory.user_memory_sync.enabled`
- `memory.user_memory_sync.server_base_url`
- `memory.user_memory_sync.api_key_env`
- `memory.user_memory_sync.encryption_key_env`
- `memory.user_memory_sync.device_id`
- `memory.user_memory_sync.enabled_lanes`
- `memory.user_memory_sync.raw_evidence_enabled`
- `memory.user_memory_sync.max_upload_bytes_per_cycle`
- `memory.user_memory_sync.pull_interval_seconds`
- future `memory.user_memory_sync.redaction_policy`

By default, the sync worker should use the already configured `[integrations.mswarm].api_key` as its user identity credential. `memory.user_memory_sync.api_key_env` remains useful for deployments that want to provide a separate runtime secret source, but the common local Docdex setup should not require a second user key.

Payload encryption is separate from identity. `memory.user_memory_sync.encryption_key_env` should point to dedicated payload key material, never the mswarm API key. If it is absent, local bundle events remain summary-only and upload no decryptable record body. Hosted server key wrapping, rotation, device key exchange, and recovery flows remain future design work.

### Server Sync API

Add a user-memory sync API under a new route group, for example `/v1/user-memory`.

Proposed endpoints:

- `POST /v1/user-memory/devices/register`
- `GET /v1/user-memory/sync/status`
- `POST /v1/user-memory/sync/push`
- `GET /v1/user-memory/sync/feed?cursor=...&lanes=...`
- `POST /v1/user-memory/sync/apply`
- `POST /v1/user-memory/sync/ack`
- `POST /v1/user-memory/sync/tombstone`
- `GET /v1/user-memory/export`
- `GET /v1/user-memory/clone/context`

The current implementation includes status, dry-run, bundle dry-run, device register, push, feed, apply, and ack under this route family. It uses the configured mswarm API key only for local/offline identity fallback. Hosted requests that present accepted credentials use server-side external API-key introspection to map the credential to `AuthContext`, require user-memory sync scope, and resolve the canonical user feed from `issuer + principal_id`.

All endpoints require user data-plane auth. The server resolves the user memory space from `AuthContext`, then verifies scopes such as:

- `docdex:user_memory:sync`
- `docdex:user_memory:*`
- `docdex:user-memory:sync`
- `docdex:memory:sync`

The exact long-term scope names should still be finalized with mswarm. The current implementation accepts the above sync aliases or wildcard scopes.

### Push Bundle Shape

Every upload should be append-only and idempotent.

```json
{
  "schema_version": "user-memory-sync.v1",
  "device_id": "local-device-id",
  "bundle_id": "stable-idempotency-key",
  "base_cursor": "last-server-cursor-seen",
  "created_at_ms": 1783699200000,
  "lanes": ["profile", "personal_preferences"],
  "events": [
    {
      "event_id": "stable-event-id",
      "lane": "personal_preferences",
      "operation": "upsert",
      "object_id": "claim-or-capture-id",
      "object_version": "version-id",
      "content_hash": "sha256:...",
      "sensitivity": "normal",
      "payload_kind": "personal_preference_claim",
      "payload_summary": {
        "content_bytes": 421,
        "review_status": "approved"
      },
      "payload_envelope": {
        "mode": "encrypted",
        "algorithm": "AES-256-GCM",
        "key_id": "server-or-device-key-id",
        "nonce_b64": "...",
        "ciphertext_b64": "...",
        "aad_b64": "...",
        "payload_hash": "sha256:..."
      },
      "provenance": {
        "source_device_id": "local-device-id",
        "source_store": "personal_preferences",
        "source_record_id": "local-record-id"
      }
    }
  ]
}
```

`payload_envelope` can be omitted or set to `{"mode": "summary_only"}` for inventory/hash-only events. Current local bundle generation emits encrypted AES-256-GCM envelopes for supported profile and inventory payloads only when a dedicated payload key env is configured. Cleartext/plaintext/raw JSON payload envelope modes are rejected. The server returns accepted event ids, rejected event ids with reasons, and the next cursor.

### Feed Shape

The server feed is the authoritative stream for down-sync.

```json
{
  "cursor": "current-request-cursor",
  "next_cursor": "next-server-cursor",
  "events": [],
  "has_more": false,
  "server_time_ms": 1783699200000
}
```

Clients acknowledge applied cursors. Failed local applies should not advance the cursor for that lane.

## Merge Semantics

### General Rules

- Event ids are globally stable and idempotent.
- Server storage is append-only first, then projected into lane-specific current views.
- Tombstones and redactions win over upserts.
- User review decisions win over inferred clone facts.
- More specific scoped facts do not overwrite global facts unless explicitly linked.
- Server-generated canonical ids are returned to clients so later local sync cycles can converge.
- Conflicts produce review records rather than silently discarding useful facts.

### Repo Memory

Repo memory must remain repo isolated. Server-side repo memories should include:

- repo fingerprint
- remote origin hash or repository binding id when available
- memory text hash
- source file/path references when safe
- supersedes and superseded-by links

Repo memory from two machines should merge only when repo identity matches. If two local clones have different paths but the same repo fingerprint, they can share facts. If repo identity cannot be proven, the server should keep separate repo namespaces.

### Profile Memory

Profile memory is global and agent-bound. It should sync preferences and constraints like:

- `agent_id`
- category
- content
- source
- timestamps
- active/superseded state

Last-writer-wins is acceptable only for the same stable preference record. Similar but different preferences should coexist until reviewed or superseded.

### Personal Preferences And Mind Clone

The existing export bundle is the best starting point. The sync adapter should map export sections into stable event objects:

- captures and derived records
- claims and versions
- evidence and links
- feedback and review state
- snapshots
- decision patterns and style signals
- clone profiles and clone context
- evaluations
- timelines and goal graph
- routines, routine steps, playbooks, and override rules
- redaction spans and retention policies

The server should maintain both:

- the raw synchronized object store for audit and replay
- a projected clone context optimized for agent retrieval

The projected clone context must respect sensitivity, redactions, confidence thresholds, and stale-record handling.

### Conversation And KG Data

Conversation sync should default to summaries, durable notes, KG facts, and episodic rollups. Raw transcripts require explicit opt-in because they are likely to contain sensitive material.

KG sync should preserve provenance so a user can inspect why a relationship exists and delete the originating episode or edge.

## Encryption And Privacy

Minimum requirements:

- TLS in transit.
- Existing encrypted server storage at rest.
- User memory encrypted under a server-managed per-user or per-tenant key, not an API key.
- No raw API keys in logs, DB rows, traces, sync payload echoes, or audit records.
- No secrets in exported bundles; local redaction runs before upload.
- Sensitivity labels per event and per object.
- Lane-level opt-in, raw-evidence opt-in, and per-device pause.
- Server-side delete, export, retention, and revocation controls.
- Down-sync redactions and tombstones to every device.
- Fail closed on auth, missing scopes, unknown user, ambiguous credentials, or introspection failure.

Open security design item: decide whether to add client-side envelope encryption for high-sensitivity lanes before upload. If added, mcoda/server-side agent context may need a separate decrypt authorization flow or a server-side trusted execution boundary.

## mswarm Responsibilities

mswarm should provide the identity and consent bridge:

- API-key introspection returns stable tenant/user/API-key identifiers and memory sync scopes.
- A Docdex memory sync module lets the user enable server memory sync and choose scopes.
- The module stores only configuration and consent state, not raw API keys, encryption keys, or memory content.
- mswarm exposes setup status to mcoda and Docdex clients: server URL, enabled scopes, and user-visible consent.
- Key revocation should immediately block Docdex server memory access.

The exact introspection response should be documented before implementation. Docdex needs a stable user principal that survives API-key rotation.

## mcoda And Agent Access

mcoda agents should read server memory through scoped Docdex APIs using the user's mswarm API key.

Initial agent-facing surface:

- `GET /v1/user-memory/clone/context` for compact clone context
- `GET /v1/user-memory/sync/status` for diagnostics
- later MCP tools for server-backed user memory recall

Agent context should be filtered by:

- requesting API-key scopes
- requested purpose
- sensitivity threshold
- confidence threshold
- recency
- source provenance
- user review state

Agents should not receive raw evidence or transcripts unless a dedicated scope and explicit user consent allow it.

## Implementation Phases

### Phase 0: Requirements And Threat Model

- Finalize lane list, default opt-ins, and raw evidence policy.
- Define the mswarm introspection user identity contract, using the existing configured Docdex mswarm API key as the credential presented to the server.
- Update threat model docs for per-user server memory, device sync, and agent access.
- Define retention and deletion semantics for each lane.

Exit criteria:

- initial sync scope aliases implemented locally
- user-principal scoping implemented with `issuer + principal_id`
- threat-model review completed
- product defaults documented

### Phase 1: Sync Schema And Local Export Adapters

- Add canonical sync event and bundle structs.
- Add lane adapters for repo memory, profile memory, personal preferences, mind clone, diary, conversation summaries, and KG.
- Add local dry-run export command showing counts, bytes, sensitivity labels, and excluded records.
- Add deterministic ids and content hashes.
- Add local sync metadata store for device id, cursors, and server canonical ids.

Exit criteria:

- local dry-run can produce a redacted bundle for each enabled lane
- bundle replay is idempotent in tests
- raw evidence is excluded by default

### Phase 2: Server User Memory Store

- Add server tables/files for user memory spaces, devices, events, projections, cursors, tombstones, and audit records.
- Add authenticated push, feed, ack, status, and device endpoints.
- Enforce auth scopes through `AuthContext`.
- Add request size limits, per-user rate limits, idempotency, and replay protection.
- Add server export and delete controls.

Exit criteria:

- two bundles with the same idempotency key do not duplicate data
- unauthorized or scope-missing requests fail closed
- profile-memory events can push/feed/apply without cross-user leakage
- tombstones and redactions project correctly

### Phase 3: Merge And Projection Engine

- Implement lane-specific merge strategies.
- Build projected current views for profile memory and personal preferences.
- Build projected clone context for agent retrieval.
- Add conflict records and review queues.
- Add provenance inspection for user-facing debugging.

Exit criteria:

- two devices can upload conflicting profile/preference facts and get deterministic conflict records
- redactions and deletes dominate existing projections
- clone context excludes low-confidence or sensitive records by policy

### Phase 4: Local Down-Sync

- Add feed polling and apply logic in the local worker. The explicit `/v1/user-memory/sync/apply` profile-memory path exists; background scheduling and non-profile importers remain future work.
- Add echo-loop prevention using source device ids and event ids.
- Add per-lane apply transactions and cursor advancement only after successful apply.
- Add CLI/MCP commands for status, pause, resume, dry-run pull, and conflict review.

Exit criteria:

- two local state dirs can exchange memory through the server
- local offline mode continues to work
- replaying the same feed is idempotent

### Phase 5: mswarm Module Integration

- Add or update the mswarm Docdex module to expose memory sync consent and scopes.
- Extend API-key introspection fields if needed.
- Add setup/status UX for server URL, enabled scopes, and key health.
- Add revocation behavior and tests.

Exit criteria:

- Docdex can resolve a stable user memory space from an mswarm API key
- revoking the key blocks sync and clone-context reads
- mswarm does not store memory content

### Phase 6: mcoda Runtime Access

- Add mcoda configuration for server clone context retrieval.
- Use `x-api-key` consistently when calling Docdex server memory APIs.
- Add agent context budgeting and filtering.
- Add diagnostics when memory context is unavailable due to auth, scope, or server status.

Exit criteria:

- an mcoda agent can fetch safe server clone context for the user
- missing scope produces a clear diagnostic
- raw evidence is not sent to agents by default

### Phase 7: Observability And Rollout

- Add sync metrics: events pushed, events pulled, conflicts, redactions, bytes, failures, lag, last success.
- Add audit logs that never include raw API keys or sensitive payload content.
- Add admin and user-facing status commands.
- Ship behind disabled-by-default or private-preview config.
- Run staged rollout with two-machine simulations before enabling by default.

Exit criteria:

- docs include setup, privacy, recovery, and rollback instructions
- server and local metrics explain sync health
- private-preview feedback is captured before broad rollout

## Expected Docdex Changes

Likely Docdex files or areas:

- `src/auth.rs`: confirm user-principal fields and scope mapping from introspection.
- `src/config.rs` and `src/config/env_overrides.rs`: sync config and server-side limits.
- `src/api/v1/mod.rs`: route registration for user memory sync.
- `src/api/v1/user_memory_sync.rs`: new server sync endpoints.
- `src/personal_preferences/`: export adapter, merge projection, clone-context filtering.
- `src/memory/` or current repo-memory modules: repo memory adapter and apply logic.
- profile-memory modules: profile export/apply adapter.
- conversation and KG modules: summary/KG event adapters.
- CLI command modules: `docdexd memory sync status|dry-run|push|pull|pause|resume`.
- MCP server: optional sync status and clone-context tools after HTTP surfaces stabilize.
- `server/README.md` and env examples: hosted memory sync setup.
- security docs and planning docs: threat model, privacy, and rollout notes.

## Expected mswarm Changes

Likely mswarm work, in its own repo:

- introspection response contract for stable user principal and memory scopes
- Docdex memory sync module consent/config state
- scope management for read, write, clone read, and device admin
- setup/status response that Docdex and mcoda can consume
- revocation propagation and tests
- docs that make clear mswarm stores no memory content, raw API keys, or encryption keys

## Expected mcoda Changes

Likely mcoda work, in its own repo:

- optional Docdex server clone-context provider
- pass the user's mswarm API key as `x-api-key`
- context budget, sensitivity, and confidence filters
- diagnostics for unavailable server memory
- tests using mock Docdex server and mock introspection

## Validation Plan

Unit tests:

- sync event id stability
- bundle idempotency
- lane adapter redaction behavior
- merge rules per lane
- tombstone and redaction precedence
- scope enforcement and auth failures
- same user with rotated/different API keys maps to one principal feed

Integration tests:

- two local Docdex state dirs sync through one test server
- same user on two devices converges after push/pull
- different users cannot see each other's memory
- revoked API key cannot push, pull, or read clone context
- raw transcripts are excluded unless explicitly enabled
- repo memory does not cross repo fingerprints

Security tests:

- no raw API key in logs, DB, audit records, or error responses
- fail closed on introspection outage
- service-token admin cannot read data-plane memory without user auth
- down-sync redaction removes projected local data

Operational tests:

- large personal-preferences bundle stays within limits or chunks safely
- repeated push/feed/ack cycles are idempotent
- server can export and delete a user's memory space
- sync lag and failure metrics are visible

## Open Questions

- Which exact long-term scope names should mswarm expose for user-memory sync, clone context reads, device admin, and deletion?
- Should high-sensitivity lanes use client-side envelope encryption, server-managed per-user encryption, or both?
- Which lanes should be enabled by default for the first private preview?
- Do raw transcripts ever sync, or should the system only sync summaries and KG facts?
- What review UI or CLI should users use for conflicts and clone claims?
- Should mcoda read only projected clone context, or also query lane-specific memory recall endpoints?
- How should server-side deletion propagate to machines that are offline for a long time?
- What are the storage quotas and retention defaults per user and per lane?

## First Build Slice

The smallest useful vertical slice is partly implemented:

1. Done: define `user-memory-sync.v1` event and bundle structs.
2. Done: implement profile-memory events and personal-preferences/mind-clone inventory dry-run adapters.
3. Done: add server-store `register`, `push`, `feed`, `apply`, `ack`, `status`, and dry-run endpoints behind config.
4. Done: resolve hosted user memory space through existing API-key introspection when request credentials are present, with local configured-key fallback.
5. Partly done: store events append-only and apply encrypted profile-memory events; personal-preference current views remain future work.
6. Pending: add local explicit `docdexd memory sync push` and `docdexd memory sync pull` commands or equivalent worker loop.
7. Pending: prove two local state dirs converge through one server using a mock mswarm introspection response.

This slice avoids raw transcripts, KG merge complexity, background scheduling, and mcoda runtime changes until the core sync contract is proven.
