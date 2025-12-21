# Installer Upgrade/Downgrade Guarantees, Repair, and Troubleshooting

Scope: the npm installer/downloader (`npm/lib/install.js`) and CLI wrapper (`npm/bin/docdex.js`) that install and run a platform-specific `docdexd` binary from GitHub Releases.

Assumptions (explicit):
- You install via npm (`npm i -g docdex` or `npx docdex --version`) on Node.js >= 18.
- “Expected version” is the npm package version (or `DOCDEX_VERSION` if set).
- The installer uses the published release manifest/checksums contracts when it needs to fetch an archive; see `docs/contracts/release_manifest_schema_v1.md`.
<<<<<<< HEAD
- Default integrity policy is `DOCDEX_INTEGRITY_POLICY=required` (fail closed on missing integrity metadata; verify archive SHA-256 before install). Explicit overrides (`allow-missing|off`) are insecure and never silent.

## Version sync contract (summary)

- Expected version is the npm package version (or `DOCDEX_VERSION` if set; leading `v` is stripped) and exact match is required.
- If a different version is detected locally, the installer replaces it; if integrity mismatches are detected, the installer repairs it.
- Release source/tag/asset selection is deterministic; see `docs/contracts/version_sync_contract_v1.md`.
=======
- Release assets live under the repo in `DOCDEX_DOWNLOAD_REPO` (or `package.json.repository.url`) with a tag `vX.Y.Z` that matches the expected version.

## Version compatibility rule (npm wrapper ↔ docdexd)

- The npm package version `X.Y.Z` maps to the GitHub Release tag `vX.Y.Z` in the download repo.
- On install, the wrapper always targets `docdexd` `X.Y.Z` (or `DOCDEX_VERSION` if set). No cross-version compatibility is assumed.
- If a different version is already installed (as recorded in `docdexd-install.json`), the installer replaces it so the final state is version-aligned.

## Installer selection + install workflow (deterministic)

1) Resolve the release source:
   - Repo slug from `DOCDEX_DOWNLOAD_REPO` (or `package.json.repository.url`)
   - Version from `DOCDEX_VERSION` (or `package.json`), then the tag `v<version>`
2) Detect the runtime and compute `platformKey` + `targetTriple` (Linux includes libc selection; see `docs/ops/installer_supported_platforms.md`).
3) Inspect local state in `dist/<platformKey>/` + `docdexd-install.json` to choose `no-op`, `update`, `repair`, or `reinstall_unknown`.
4) If an install is needed, resolve exactly one asset deterministically:
   - Try manifest candidates first; if a manifest is present but has no match/ambiguous matches, fail closed.
   - Otherwise fall back to `docdexd-<platformKey>.tar.gz` with `SHA256SUMS`/`SHA256SUMS.txt` (or legacy `<archive>.sha256`).
5) Download from GitHub Releases (or `DOCDEX_DOWNLOAD_BASE` if overridden), verify SHA-256, and extract into `dist/<platformKey>/`.
6) Write `docdexd-install.json` with the resolved version, platform, hashes, and source. The existing install is removed only after a verified download.
>>>>>>> mcoda/task/ops-01-us-03-t25

## Deterministic installer outcomes

The installer converges to a single final state: the installed `docdexd` under `dist/<platformKey>/` matches the expected version for this npm package install.

Decision outcomes (stable strings; used by the installer decision engine):

| Outcome | Meaning | Deterministic trigger (local state) |
|---|---|---|
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
| `no-op` | Nothing changes. | A previous verified install metadata file exists and its recorded `binary.sha256` matches the currently installed binary for the expected version. |
| `install` | Install the expected version. | No binary exists for the detected platform. |
| `upgrade` | Replace the binary with a newer expected version. | Install metadata indicates an older version than expected. |
| `downgrade` | Replace the binary with an older expected version. | Install metadata indicates a newer version than expected. |
| `replace` | Replace the binary, but ordering can’t be determined. | Installed version differs from expected, but versions are not comparable as SemVer. |
=======
| `no-op` | Nothing changes. | A previous verified install metadata file exists, its recorded `binary.sha256` matches the currently installed binary for the expected version, and (when executable) the binary reports the expected version. |
| `update` | Install/reinstall the expected version. (Includes first install, upgrade, downgrade.) | No binary exists, install metadata indicates a different version than expected, or a hash-verified binary reports a different version than expected. |
>>>>>>> mcoda/task/ops-01-us-06-t41
=======
| `no-op` | Nothing changes. | A previous install metadata file exists for the expected version, the recorded `binary.sha256` matches the currently installed binary, **and** the metadata’s recorded `archive.sha256` matches the release-provided SHA-256 for the expected platform archive (resolved via manifest/checksum metadata without downloading the archive). |
| `update` | Install/reinstall the expected version. (Includes first install, upgrade, downgrade.) | No binary exists, or install metadata indicates a different version than expected. |
>>>>>>> mcoda/task/ops-01-us-06-t03
=======
| `no-op` | Nothing changes; no network/download occurs. | A previous verified install metadata file exists and its recorded `binary.sha256` matches the currently installed binary for the expected version. |
| `update` | Install/reinstall the expected version. (Includes first install, upgrade, downgrade.) | No binary exists, or a valid install metadata file indicates a different `version` than expected. |
>>>>>>> mcoda/task/ops-01-us-06-t08
| `repair` | Reinstall the expected version due to a local integrity mismatch. | Metadata exists for the expected version, but the current binary’s SHA-256 does not match the recorded `binary.sha256`. |
| `reinstall_unknown` | Reinstall because current state can’t be verified deterministically. | Binary exists but install metadata is missing/unreadable/invalid, the metadata `platformKey` mismatches the detected platform, or the binary hash cannot be computed/read. |

<<<<<<< HEAD
User-facing outcome codes (stable; suitable for automation):

| Outcome code | Maps from decision outcome | Meaning |
|---|---|---|
| `skipped_noop` | `no-op` | Already correct and verified; no download/install work was performed. |
| `updated` | `update` | Version was aligned to the expected version. |
| `repaired` | `repair` | Binary was replaced due to an integrity verification failure. |
| `reinstalled_unknown` | `reinstall_unknown` | State could not be verified deterministically; forced reinstall. |

The installer logs both legacy and automation-friendly outcomes:
- `[docdex] Install outcome: <outcome>`
- `[docdex] Install outcome code: <outcomeCode>`

Optional structured output (for automation):
- Set `DOCDEX_INSTALLER_OUTPUT=json` to emit a single JSON object to stdout (and suppress other installer logs).

## Install plan (normalized action)

For operators who want a single 4-way “what will happen” decision (including upgrade vs downgrade), the installer also computes an install plan action:

| Plan | Meaning |
|---|---|
| `no-op` | Already at the expected version and locally verified; installer does not download. |
| `upgrade` | Replace the currently installed binary with the expected version (includes first install and version increases). |
| `downgrade` | Replace the currently installed binary with the expected version (version decreases). |
| `repair` | Replace the currently installed binary because the local state is corrupted or cannot be verified deterministically. |

Notes:
- This plan is derived from local state + versions and is intended for convergent behavior. It does not change the stable `outcome` strings above; it adds upgrade/downgrade signal on top of them.
- Internally, `update` maps to `upgrade`/`downgrade` depending on version comparison, and `repair`/`reinstall_unknown` both map to `repair`.

## Installer observability (structured events)

The installer also emits **structured local log events** (no remote telemetry) as JSON lines prefixed with:
- `[docdex] event `

These events support deterministic troubleshooting and include decisioning + integrity results + actions taken.

### Stable outcome codes (support-facing)

For supportability, structured events include `details.outcomeCode` with stable values:

| Outcome code | Meaning | Maps from installer `outcome` |
|---|---|---|
| `noop` | No changes; no download attempted. | `no-op` |
| `repair` | Replaced due to local integrity mismatch. | `repair` |
| `replace` | Installed/reinstalled expected version. | `update`, `reinstall_unknown` |

### Key event codes

- `DOCDEX_INSTALL_START` (computed platform/version/paths)
- `DOCDEX_INSTALL_DECISION` (local state + decision outcome/reason)
- `DOCDEX_INSTALL_INTEGRITY_LOCAL` (local binary verification result when checked)
- `DOCDEX_INSTALL_PLAN` (resolved asset + integrity metadata source)
- `DOCDEX_INSTALL_INTEGRITY_ARCHIVE` (downloaded archive verification result)
- `DOCDEX_INSTALL_REPLACE_START` / `DOCDEX_INSTALL_REPLACE_OK` (replacement performed)
- `DOCDEX_INSTALL_OUTCOME` (final outcome with stable `outcomeCode`)

### No-redownload and caching rules (important for idempotency)

- For `no-op`, the installer does **not** fetch the release manifest, does **not** download any archive, and does **not** touch `dist/<platformKey>/` other than reading the binary/metadata to verify integrity.
- For `update` / `repair` / `reinstall_unknown`, the installer resolves an archive from the expected GitHub Release, downloads it to an OS temp file, verifies integrity, then replaces `dist/<platformKey>/` and writes fresh install metadata.
- The installer does **not** keep a persistent “binary download cache” of archives across runs. The only persistent optimization is the on-disk installed binary + `docdexd-install.json` metadata, which enables `no-op`.
=======
The installer logs the outcome as a single line:
- `[docdex] Install outcome: <status> (outcome=<outcome>, reason=<reason>)`

Where:
- `status` is one of `skipped`, `updated`, `repaired`, `reinstalled`.
- `outcome` is the stable internal outcome string (`no-op`, `update`, `repair`, `reinstall_unknown`).
- `reason` is a stable reason code for why the outcome was chosen (see below).

### Outcome reason codes

Reason codes (stable strings, derived from local state):

- `binary_missing`: no installed binary was found.
- `metadata_missing`: install metadata file is missing.
- `metadata_unreadable`: install metadata exists but could not be read.
- `metadata_invalid`: install metadata is present but invalid.
- `existsSync_unavailable`: filesystem checks were unavailable in the current runtime.
- `platform_mismatch`: metadata platform does not match the detected platform.
- `version_mismatch`: installed version differs from expected.
- `expected_integrity_missing`: no expected sha256 available to verify.
- `binary_integrity_mismatch`: local binary hash does not match expected.
- `verified`: local binary hash verified for the expected version.
- `integrity_unverifiable`: integrity check could not be completed.
>>>>>>> mcoda/task/bck-05-us-06-t47

## Upgrade vs downgrade

<<<<<<< HEAD
The installer always targets the expected version for the current npm package install:
- If the installed version differs, the installer **replaces** `dist/<platformKey>/` so the final state equals the expected version (reported as `upgrade`, `downgrade`, or `replace`).
- If the expected version is already installed and verified, the installer is a `no-op` and does not download anything.
=======
The installer does not treat “upgrade” and “downgrade” differently. It always targets the expected version for the current npm package install:
<<<<<<< HEAD
- If the installed version differs, the installer replaces the `docdexd` binary under `dist/<platformKey>/` so the final state equals the expected version.
=======
- If the installed version differs, the installer extracts into a staging directory and atomically swaps `dist/<platformKey>/` so the final state equals the expected version.
>>>>>>> mcoda/task/ops-01-us-03-t44
- If the expected version is already installed and verified, the installer is a `no-op`.
>>>>>>> mcoda/task/ops-01-us-05-t41

This makes repeated installs idempotent: once the system is in the verified `no-op` state for a given version/platform, running the installer repeatedly converges without additional downloads and leaves the installed binary + metadata unchanged.

## Rollback-safe staged install (what changes, when)

Docdex installs `docdexd` using a staged/atomic approach so that a previously working `docdexd` is not removed during a failed install attempt. Details (including cleanup + interrupted install expectations) are in:
- `docs/ops/installer_rollback_guarantees.md`

## Repair/reinstall triggers (unknown / corrupt / stale)

These terms map to deterministic outcomes and observable runtime states:

- Unknown state → `reinstall_unknown`: install metadata is missing/unreadable/invalid, or the metadata `platformKey` does not match the detected platform.
- Corrupt state → `repair`: metadata exists for the expected version, but the local binary hash does not match `binary.sha256`.
- Stale runtime → the daemon process is still running an older binary that was started before the upgrade/downgrade; restart the process to load the new `docdexd`.

These triggers are based on local metadata + hash checks only. Repo-scoped daemon dependencies (indexes, symbols) are not modified by the installer.

## Integrity verification and repair behavior

There are two relevant integrity checks:

1) **Remote archive integrity (when installing)**  
<<<<<<< HEAD
<<<<<<< HEAD
   When the installer needs to install (`install`, `upgrade`, `downgrade`, `replace`, `repair`, `reinstall_unknown`), it resolves a single release asset and (when available) a SHA-256 for that asset via:
=======
   When the installer needs to install (`update`, `repair`, `reinstall_unknown`), it resolves a single release asset and a required SHA-256 for that asset via:
>>>>>>> mcoda/task/ops-01-us-04-t40
=======
   When the installer needs to install (`update`, `repair`, `reinstall_unknown`), it resolves a single release asset and its SHA-256 via:
>>>>>>> mcoda/task/ops-01-us-06-t08
   - Release manifest (preferred), then
   - `SHA256SUMS`/`SHA256SUMS.txt`, then
   - legacy `<archive>.sha256` sidecar.

<<<<<<< HEAD
   With the default integrity policy (`DOCDEX_INTEGRITY_POLICY=required`), the installer requires SHA-256 integrity metadata and verifies the downloaded archive against the expected SHA-256. If verification fails, installation fails closed with:
=======
   The downloaded archive is verified against the expected SHA-256. If integrity metadata cannot be obtained, installation fails closed with `DOCDEX_CHECKSUM_UNUSABLE`. If verification fails, installation fails closed with:
>>>>>>> mcoda/task/ops-01-us-06-t08
   - Error code: `DOCDEX_INTEGRITY_MISMATCH` (see `docs/ops/installer_error_codes.md`)
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
   - Safety property: the existing `dist/<platformKey>/docdexd` (or `docdexd.exe`) is not modified until a new binary has been downloaded, verified, extracted, and is ready to be atomically swapped into place.
=======
   - Safety property: the installer performs a staged install and only replaces the final `docdexd` path after the archive is successfully fetched, verified, and extracted into a staging directory (see `docs/ops/installer_atomic_replace.md`).
>>>>>>> mcoda/task/ops-01-us-05-t22
=======
   - Safety property: the existing `dist/<platformKey>/` is not replaced until after the archive is fetched + verified **and** fully extracted into a staging directory (with install metadata written), at which point the installer swaps directories via rename (rollback-safe).
>>>>>>> mcoda/task/ops-01-us-05-t27
=======
   - Safety property: the installer stages downloads/extraction under `dist/.staging/<platformKey>/...` and only swaps the verified staging directory into `dist/<platformKey>/` after extraction + verification complete (atomic rename). If install fails, the previous `dist/<platformKey>/` remains runnable.
>>>>>>> mcoda/task/ops-01-us-05-t07
=======
   - Safety property: the installer stages extraction and only activates the new `dist/<platformKey>/` via atomic rename after download + verification + extraction succeed (so failures do not leave a partial runnable `docdexd` behind).
>>>>>>> mcoda/task/ops-01-us-04-t40
=======
   - Safety property: the existing `dist/<platformKey>/` is only replaced after the archive is successfully fetched, SHA-256 verified, extracted to a staging directory, and the expected `docdexd` binary is present.
>>>>>>> mcoda/task/ops-01-us-04-t13
=======
   - Safety property: the existing `dist/<platformKey>/` is only replaced after the archive is successfully fetched, verified, and the staged binary passes the version check.
>>>>>>> mcoda/task/ops-01-us-03-t44

<<<<<<< HEAD
<<<<<<< HEAD
=======
   If integrity metadata is missing, default behavior is a fatal `DOCDEX_CHECKSUM_UNUSABLE` (exit `24`). Explicit policy overrides (`allow-missing|off`) can proceed unverified (insecure; warnings are emitted).

>>>>>>> mcoda/task/ops-01-us-04-t17
2) **Local binary integrity (no-op vs repair)**  
   For a `no-op`, the installer verifies the existing binary by hashing it and comparing to the recorded `binary.sha256` from the last successful, verified install.
   - If this local check fails, the outcome becomes `repair` and the installer reinstalls a verified binary.
<<<<<<< HEAD
   - If the local hash check succeeds, the installer may also run the binary with `--version` to confirm it reports the expected version; a mismatch triggers `update`.
=======
2) **Installed binary integrity (no-op vs repair)**  
   For a `no-op`, the installer verifies the existing installation using two checks:
   - **Binary hash check (local):** hash the installed `docdexd` and compare to the recorded `binary.sha256` from the last successful install.
   - **Release provenance check (metadata vs release):** resolve the expected platform archive SHA-256 for the current version (manifest → checksum fallback) and compare it to the recorded `archive.sha256` in `docdexd-install.json`.

   If either check fails (or can’t be performed deterministically), the installer re-installs a verified binary (`repair` when a mismatch is detected; otherwise `reinstall_unknown`).
>>>>>>> mcoda/task/ops-01-us-06-t03
=======
   - Note: `no-op` integrity verification is intentionally local-first and does not require network access; it verifies the binary has not changed since the last verified install, not “re-checking” the release every time.
>>>>>>> mcoda/task/ops-01-us-06-t08

3) **Post-extract version verification (install/repair only)**  
   Before swapping in a staged install, the installer runs `docdexd --version` and verifies it matches the expected npm version.
   - If the version check fails or does not match, installation fails and the previous `dist/<platformKey>/` remains intact.

## Install metadata: what it is and where it lives

The installer writes a small JSON metadata file next to the installed binary:
- `dist/<platformKey>/docdexd-install.json`
- Binary path: `dist/<platformKey>/docdexd` (or `docdexd.exe` on Windows).

This metadata enables deterministic `no-op` and `repair` decisions without downloading a new asset.
Note: the installer may still fetch release metadata (manifest/checksums) to verify the recorded `archive.sha256`, but it does not re-download the platform archive when the outcome is `no-op`.

### Metadata fields (stable + additive)

The metadata is designed to be backward-compatible (new fields are additive). Common fields include:
- `version` (legacy) plus explicit `expectedVersion` and `installedVersion`
- `installedAt` (ISO timestamp)
- `releaseTag` (e.g., `v0.1.2`) and `archive.tag`
- `archive.name`, `archive.source`, `archive.downloadUrl`, `archive.sha256`
- `binary.sha256`, `platformKey`, `targetTriple`, `repoSlug`

When metadata is missing or unreadable, the installer may probe `docdexd --version` (short timeout) to report the detected daemon version in errors.

### Locate it (safe, cross-platform)

Local install (project dependency):
- Package root: `<repo>/node_modules/docdex/`
- Metadata: `<repo>/node_modules/docdex/dist/<platformKey>/docdexd-install.json`
- Binary: `<repo>/node_modules/docdex/dist/<platformKey>/docdexd` (or `docdexd.exe`)

Global install:
- Find global `node_modules`: `npm root -g`
- Metadata: `$(npm root -g)/docdex/dist/<platformKey>/docdexd-install.json`
- Binary: `$(npm root -g)/docdex/dist/<platformKey>/docdexd` (or `docdexd.exe`)

OS notes (common defaults; prefer `npm root -g` over guessing):
- macOS/Linux: often under `/usr/local/lib/node_modules/docdex/...` or `~/.nvm/.../lib/node_modules/docdex/...`
- Windows: often under `%APPDATA%\\npm\\node_modules\\docdex\\...`

## Troubleshooting missing-release and mismatch errors

### Missing release asset or tag (`DOCDEX_ASSET_MISSING`, `DOCDEX_ASSET_NO_MATCH`)

What it means:
- The expected release for `v<expected version>` does not contain the required asset for your `platformKey`/`targetTriple`.
- The error report includes the expected target triple and asset naming pattern; `DOCDEX_ASSET_MISSING` also includes the expected version, download repo, and URL tried.

Risk-mitigated checks:
1) Confirm your platform + expected asset with `docdex doctor`.
2) Verify the release tag `v<expected version>` exists in the target repo and includes:
   - `docdexd-<platformKey>.tar.gz`
   - `docdex-release-manifest.json` and/or `SHA256SUMS`
3) If installing from a fork, set `DOCDEX_DOWNLOAD_REPO=<owner/repo>`.
4) If you installed from a local folder, ensure the package version is set (or `DOCDEX_VERSION` is defined).

### Version or integrity mismatch (`Install outcome: update`, `DOCDEX_INTEGRITY_MISMATCH`)

What it means:
- `Install outcome: update` indicates the installed version (from `docdexd-install.json`) did not match the expected version.
- `DOCDEX_INTEGRITY_MISMATCH` indicates the downloaded archive failed SHA-256 verification.

Risk-mitigated checks:
1) Inspect `docdexd-install.json` to see the detected installed version and platform.
2) Re-run the installer after stopping any running `docdexd` process.
3) For integrity mismatches, bypass proxies/caches and confirm the repo + version are correct; do not manually extract unverified downloads.

## Troubleshooting stale/corrupt daemon installs (risk-mitigated)

If install failed with a missing artifact/version sync error, see `docs/contracts/version_sync_contract_v1.md` and `docs/ops/installer_supported_platforms.md` for release asset checks and remediation.

### 1) Confirm which `docdexd` you are running

- Platform diagnostics (offline): `docdex doctor`
- Installed daemon version: `docdexd --version` (wrapper) or read `dist/<platformKey>/docdexd-install.json` (field `version`).
- Wrapper expects the binary at: `dist/<platformKey>/docdexd` (or `docdexd.exe` on Windows).

If you upgraded/downgraded but the daemon still behaves like an older build, you may be running an already-started process.

### 2) Restart the daemon process

Reinstalling updates the on-disk binary, but it does not replace a currently running `docdexd` process.

Low-risk approach:
- Stop the process you started (e.g., terminate the terminal/service that launched `docdexd serve`), then start it again.

<<<<<<< HEAD
Windows note:
- Upgrading `docdexd.exe` while it is running commonly fails because the binary is locked. Stop `docdexd.exe` first, then reinstall.
=======
### 2.5) Why does install keep downloading (no `no-op`)?

Common deterministic causes:
- `reinstall_unknown`: install metadata is missing/unreadable/invalid, or the metadata `platformKey` does not match the detected platform.
- `update`: the metadata `version` differs from the expected npm package version.
- `repair`: the binary hash does not match the recorded `binary.sha256` (possible tampering, partial write, or disk corruption).

Low-risk checks:
- Confirm the metadata exists and is valid JSON at `dist/<platformKey>/docdexd-install.json`.
- Confirm you are not installing with `npm install --ignore-scripts` (that skips the postinstall downloader and leaves you without a verified `docdexd`).
- If you are in a read-only filesystem or constrained environment, ensure the `docdex` package directory is writable so metadata can be written atomically.
>>>>>>> mcoda/task/ops-01-us-06-t08

### 3) If installs keep “repairing” or look inconsistent, reset only installer state

Safe reset options (in increasing destructiveness). Note: interrupted installs should not require manual cleanup; prefer re-running the install first (see `docs/ops/installer_rollback_guarantees.md`).

1) Delete only install metadata (forces `reinstall_unknown` next run):
   - Remove: `dist/<platformKey>/docdexd-install.json`
2) Delete the platform install directory (forces a clean reinstall for that platform):
   - Remove: `dist/<platformKey>/`
3) Uninstall and reinstall the npm package:
   - Global: `npm uninstall -g docdex && npm i -g docdex`
   - Local: `npm uninstall docdex && npm install` (or your lockfile-friendly equivalent, e.g. `npm ci`)

Risk notes:
- Double-check you’re deleting paths under the installed `docdex` package directory (avoid deleting unrelated files).
- If you see `DOCDEX_INTEGRITY_MISMATCH`, treat it as a potential tampering/proxy/cache corruption signal; avoid manual extraction of unverified downloads and prefer a clean reinstall or building from source.

### 4) If the daemon runs but indexing/search looks wrong

This is usually a repo state issue, not an installer issue:
- Rebuild the index: `docdexd index --repo <path>`
<<<<<<< HEAD
- If you intentionally want a clean state, delete only the repo’s index directory under `~/.docdex/state/repos/<fingerprint>/index` (see `docdexd repo inspect --repo <path>` for the resolved path). This forces a full reindex next run.
=======
- If you intentionally want a clean state, delete only the repo’s index directory under the state root (see `docdexd repo inspect --repo <path>` for `indexDir`, typically `~/.docdex/state/repos/<fingerprint>/index`). This forces a full reindex next run.
>>>>>>> mcoda/task/ops-01-us-03-t02

### 5) If MCP/CLI report dependency state errors

These signals come from repo-scoped state (index/symbols), not the installer. Common codes:

- `missing_index`: no index exists yet (or no symbols record for a path); run `docdexd index --repo <path>`. For symbols, enable `DOCDEX_ENABLE_SYMBOL_EXTRACTION=1` and reindex.
- `missing_dependency`: optional dependency disabled (currently symbol extraction); enable the dependency or avoid the tool that requires it.
- `stale_index`: reserved (not currently emitted); treat it as a reindex signal.

Assumption: there is no explicit corrupt-state code today; if you repeatedly see `internal_error` after reindexing, remove only the affected state dir (e.g. `<repo>/.docdex/index` or `<state_dir>/symbols.db`) and rebuild.
See `docs/mcp/errors.md` for the canonical MCP/CLI codes and details.

## See also

- `docs/contracts/npm_daemon_version_contract_v1.md`
- Installer supported platforms + safe cleanup: `docs/ops/installer_supported_platforms.md`
- Atomic staged install + rollback behavior: `docs/ops/installer_atomic_install_and_rollback.md`
- Installer error codes + remediation: `docs/ops/installer_error_codes.md`
- Version sync contract: `docs/contracts/version_sync_contract_v1.md`
- Release manifest contract: `docs/contracts/release_manifest_schema_v1.md`
- Installer error contract: `docs/contracts/installer_error_contract_v1.md`
