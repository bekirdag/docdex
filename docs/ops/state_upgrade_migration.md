# State upgrade, migration, and recovery

This guide covers on-disk state, repo identity metadata, and compatibility behavior for
Docdex. It does not cover installer upgrades or downgrades; see
`docs/ops/installer_upgrade_downgrade.md`.

## Compatibility and versioning

- State layout is stable across upgrades; Docdex does not auto-migrate indexes or
  metadata. When schemas change, the supported upgrade path is reindexing.
- Shared-state metadata is versioned JSON:
  - `repos/repo_registry.json` (version 1)
  - `repos/<state_key>/repo_meta.json` (version 1, stored under the shared state base dir)
  Docdex fails closed if metadata does not match the current repo identity.
- Code intelligence payloads include a `schema` block with `version` and
  `compatible` range; clients should validate compatibility before consuming
  `docdex.symbols` or `docdex.impact_graph` payloads. See
  `docs/contracts/code_intelligence_schema_v1.md`.
- `impact_graph.json` persists per-file impact graphs with schema metadata.
  Legacy formats are read with warnings, but future schema versions are rejected;
  reindex to persist upgrades.

## State directory resolution (shared across CLI/HTTP/MCP)

- Repo paths are normalized via canonicalization and slash normalization.
- Default state base dir: `~/.docdex/state` (per-repo state under `repos/<state_key>/index`).
- Relative `--state-dir` values are resolved under the repo root.
- Absolute `--state-dir` values outside the repo root are treated as a shared base
  directory; per-repo state lives under `<state-dir>/repos/<state_key>/index`.
- Legacy in-repo state dirs (such as `.docdex/index` or `.gpt-creator/docdex/index`) are only used when explicitly passed via `--state-dir`.

### Repo fingerprint and registry

- Fingerprint is computed from filesystem identity metadata of `.git` (or the repo
  root when `.git` is missing). Renames within the same filesystem keep the
  fingerprint; new clones or cross-filesystem moves change it.
- Shared base dir metadata:
  - `repos/repo_registry.json` maps fingerprint -> state_key + canonical path +
    prior paths.
- Repo metadata:
  - `repos/<state_key>/repo_meta.json` under the shared base dir (default
    `~/.docdex/state`) records fingerprint + canonical path + timestamps.
- Docdex refuses to reuse a state directory if the metadata does not match the
  current repo identity, preventing cross-repo data mixing.

## Migration workflows

### Repo-local state dir (custom --state-dir)

1) If you move the repo and keep your custom state dir (for example `.docdex/index`) with it,
   update `--repo` and re-run with the same `--state-dir`.
2) If the state dir did not move, rebuild it: `docdexd index --repo <repo> --state-dir <path>`.
3) To migrate off a repo-local state dir, remove it and reindex to the default shared base:
   - Stop the daemon.
   - Remove or archive the repo-local directory.
   - Run `docdexd index --repo <repo>` to create the default shared state.

### Shared state dir (absolute --state-dir)

1) After a repo move/rename, expect `repo_state_mismatch`.
2) Diagnose with `docdexd repo inspect --repo <new_path> --state-dir <shared_state_dir>`.
3) Recovery:
   - Reassociate the moved repo to existing state:
     `docdexd repo reassociate --repo <new_path> --state-dir <shared_state_dir> --old-path <knownCanonicalPath>`
     or `--fingerprint <attemptedFingerprint>`.
   - Or choose a new shared state dir and reindex.

Note: If the repo fingerprint changes (for example, a new clone or cross-filesystem
move), reassociation is refused; reindex into a new state dir.

## Failure modes and recovery (error-aligned)

Docdex uses the same underlying error codes for CLI/HTTP/MCP; see
`docs/mcp/errors.md` for envelope details.

| Docdex code | Common surfaces | Typical cause | Recovery |
| --- | --- | --- | --- |
| `missing_repo_path` | CLI/HTTP/MCP | repo path missing on disk | Use the current repo path; restart `docdexd serve`/MCP if needed. Reindex if the state dir was not moved. |
| `unknown_repo` | MCP only | `project_root` does not match MCP server `--repo` | Pass `project_root` matching the MCP server repo or restart MCP with the correct `--repo`. |
| `repo_state_mismatch` | CLI/MCP; `docdexd serve` reports `startup_state_invalid` | shared `--state-dir` identity mismatch, moved repo | Run `docdexd repo inspect`; re-associate or reindex to a new state dir. |
| `missing_index` | CLI/MCP | chat/open before indexing | Run `docdexd index --repo <repo>`. |
| `backoff_required` | CLI/MCP | index writer locked or in use | Retry after the lock clears. |
| `internal_error` | any | corrupted index/metadata or IO failure | Stop the daemon, back up the state dir, remove only the affected component, then reindex. |

## Partial migration and corruption playbook

- If library ingest reports corruption or write failures, rebuild the libs index:
  1) Stop docdexd.
  2) Back up the state dir.
  3) Remove the libs index directory (sibling to the index dir):
     `<state_dir>/../libs_index`.
  4) Re-run your libs ingestion workflow or reindex.
- If symbols payloads are missing or stale after enabling symbols:
  1) Run `docdexd symbols-status --repo <repo>` to confirm parser drift.
  2) Remove `<state_dir>/symbols.db` if you want a clean rebuild (optional).
  3) Run `docdexd index --repo <repo>` to regenerate symbols/AST and `impact_graph.json`.
- For persistent corruption in the main index, remove the affected index dir and
  rebuild:
  - Shared base: remove `~/.docdex/state/repos/<repo_id>/index` (or the index dir
    reported by `docdexd repo inspect`).
  - Repo-local: remove the custom `--state-dir` directory you used (for example
    `.docdex/index` under the repo root).
