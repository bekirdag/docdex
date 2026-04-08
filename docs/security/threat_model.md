# Docdex Threat Model (v2.1)

## Scope
- Local daemon, CLI, and MCP server.
- Repo-scoped state, profile memory, and cached web artifacts.
- Conversation archives, diary entries, hook payloads, and derived knowledge facts.
- Installer + release artifact chain (npm + GitHub assets).

## Assets
- Repository contents (source code, docs).
- Profile memory (behavioral preferences).
- Repo memory (technical context).
- Conversation transcript archives in `conversation.db`.
- Derived temporal facts in `knowledge.db`.
- Diary entries and append-only hook events.
- Access tokens (HTTP auth, MCP auth).
- Release artifacts + checksums.

## Threat Actors
- Malicious local user on the same machine.
- Compromised dependency or supply-chain mirror.
- Untrusted repo content (prompt injection).
- Network attacker between daemon and external services.

## Trust Boundaries
- Local filesystem (state dir, repo path, config).
- HTTP API / MCP interface.
- Repo-scoped archives under `repos/<state_key>`.
- Explicit global conversation namespaces under the shared state root.
- External web/LLM services (Ollama, web fetch).

## Key Risks & Mitigations
- Prompt injection: enforce profile categories, constraints gate, and tool allowlists.
- Cross-repo leakage: repo-scoped state dirs and repo id validation.
- Repo-less archive leakage: require an explicit `conversation_namespace`; never silently reuse repo state for repo-less sessions.
- Transcript retention risk: `archive_raw_transcripts`, per-source allow/deny lists, redact/delete flows, and bounded wake-up retrieval keep raw logs optional and narrow.
- Derived-fact drift: knowledge facts carry provenance, confidence, invalidation, and session linkage so prune/redact can remove them with the source archive.
- Hook ingestion abuse: conversation hooks validate payload shape, enforce source policy, and write append-only events before background processing.
- Lifecycle growth and stale context: sweeper intervals, working-memory cleanup, diary trimming, episodic rollups, and compaction reduce state sprawl while preserving recent continuity.
- Supply chain: checksum verification, manifest validation, and audit scripts.
- Unauthorized access: localhost bind by default, auth token required on expose.
- Data corruption: SQLite export/merge for network shares, atomic state writes.
- Advisory exceptions: `RUSTSEC-2025-0009` ignored because Docdex does not enable QUIC; tracked in `audit.toml`.

## Assumptions
- Daemon runs on trusted host with least privilege.
- Users manage OS-level access to the repo and state directories.
- External services are explicitly configured by the operator.
- Redaction/export/prune are administrative actions and should be exposed only to trusted local callers.

## Security Testing
- `scripts/security_audit.sh` for dependency CVEs + SBOMs.
- Hook and MCP contract tests for stable auth/error behavior.
- Conversation-memory tests cover namespace isolation, redaction behavior, wake-up budgeting, and retention sweeps.
- Fuzz targets (manifest, hooks, profile import/export, MCP payloads).
