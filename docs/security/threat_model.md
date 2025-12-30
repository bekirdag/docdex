# Docdex Threat Model (v2.1)

## Scope
- Local daemon, CLI, and MCP server.
- Repo-scoped state, profile memory, and cached web artifacts.
- Installer + release artifact chain (npm + GitHub assets).

## Assets
- Repository contents (source code, docs).
- Profile memory (behavioral preferences).
- Repo memory (technical context).
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
- External web/LLM services (Ollama, web fetch).

## Key Risks & Mitigations
- Prompt injection: enforce profile categories, constraints gate, and tool allowlists.
- Cross-repo leakage: repo-scoped state dirs and repo id validation.
- Supply chain: checksum verification, manifest validation, and audit scripts.
- Unauthorized access: localhost bind by default, auth token required on expose.
- Data corruption: SQLite export/merge for network shares, atomic state writes.

## Assumptions
- Daemon runs on trusted host with least privilege.
- Users manage OS-level access to the repo and state directories.
- External services are explicitly configured by the operator.

## Security Testing
- `scripts/security_audit.sh` for dependency CVEs + SBOMs.
- Hook and MCP contract tests for stable auth/error behavior.
- Fuzz targets (manifest, hooks, profile import/export, MCP payloads).
