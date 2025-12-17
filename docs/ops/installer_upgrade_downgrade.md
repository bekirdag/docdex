# Installer Upgrade/Downgrade Guarantees, Repair, and Troubleshooting

Scope: the npm installer/downloader (`npm/lib/install.js`) and CLI wrapper (`npm/bin/docdex.js`) that install and run a platform-specific `docdexd` binary from GitHub Releases.

Assumptions (explicit):
- You install via npm (`npm i -g docdex` or `npx docdex --version`) on Node.js >= 18.
- “Expected version” is the npm package version (or `DOCDEX_VERSION` if set).
- The installer uses the published release manifest/checksums contracts when it needs to fetch an archive; see `docs/contracts/release_manifest_schema_v1.md`.

## Deterministic installer outcomes

The installer converges to a single final state: the installed `docdexd` under `dist/<platformKey>/` matches the expected version for this npm package install.

Decision outcomes (stable strings; used by the installer decision engine):

| Outcome | Meaning | Deterministic trigger (local state) |
|---|---|---|
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
| `repair` | Reinstall the expected version due to a local integrity mismatch. | Metadata exists for the expected version, but the current binary’s SHA-256 does not match the recorded `binary.sha256`. |
| `reinstall_unknown` | Reinstall because current state can’t be verified deterministically. | Binary exists but install metadata is missing/unreadable/invalid, or metadata does not match the detected `platformKey`. |

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

## Upgrade vs downgrade

<<<<<<< HEAD
The installer always targets the expected version for the current npm package install:
- If the installed version differs, the installer **replaces** `dist/<platformKey>/` so the final state equals the expected version (reported as `upgrade`, `downgrade`, or `replace`).
- If the expected version is already installed and verified, the installer is a `no-op` and does not download anything.
=======
The installer does not treat “upgrade” and “downgrade” differently. It always targets the expected version for the current npm package install:
- If the installed version differs, the installer replaces the `docdexd` binary under `dist/<platformKey>/` so the final state equals the expected version.
- If the expected version is already installed and verified, the installer is a `no-op`.
>>>>>>> mcoda/task/ops-01-us-05-t41

This makes repeated installs idempotent: running the installer multiple times converges to the same installed binary and the same metadata for a given version/platform.

## Rollback-safe staged install (what changes, when)

Docdex installs `docdexd` using a staged/atomic approach so that a previously working `docdexd` is not removed during a failed install attempt. Details (including cleanup + interrupted install expectations) are in:
- `docs/ops/installer_rollback_guarantees.md`

## Integrity verification and repair behavior

There are two relevant integrity checks:

1) **Remote archive integrity (when installing)**  
   When the installer needs to install (`install`, `upgrade`, `downgrade`, `replace`, `repair`, `reinstall_unknown`), it resolves a single release asset and (when available) a SHA-256 for that asset via:
   - Release manifest (preferred), then
   - `SHA256SUMS`/`SHA256SUMS.txt`, then
   - legacy `<archive>.sha256` sidecar.

   The downloaded archive is verified against the expected SHA-256. If verification fails, installation fails closed with:
   - Error code: `DOCDEX_INTEGRITY_MISMATCH` (see `docs/ops/installer_error_codes.md`)
<<<<<<< HEAD
<<<<<<< HEAD
   - Safety property: the existing `dist/<platformKey>/docdexd` (or `docdexd.exe`) is not modified until a new binary has been downloaded, verified, extracted, and is ready to be atomically swapped into place.
=======
   - Safety property: the installer performs a staged install and only replaces the final `docdexd` path after the archive is successfully fetched, verified, and extracted into a staging directory (see `docs/ops/installer_atomic_replace.md`).
>>>>>>> mcoda/task/ops-01-us-05-t22
=======
   - Safety property: the existing `dist/<platformKey>/` is not replaced until after the archive is fetched + verified **and** fully extracted into a staging directory (with install metadata written), at which point the installer swaps directories via rename (rollback-safe).
>>>>>>> mcoda/task/ops-01-us-05-t27

<<<<<<< HEAD
2) **Local binary integrity (no-op vs repair)**  
   For a `no-op`, the installer verifies the existing binary by hashing it and comparing to the recorded `binary.sha256` from the last successful, verified install.
   - If this local check fails, the outcome becomes `repair` and the installer reinstalls a verified binary.
   - If the local hash check succeeds, the installer may also run the binary with `--version` to confirm it reports the expected version; a mismatch triggers `update`.
=======
2) **Installed binary integrity (no-op vs repair)**  
   For a `no-op`, the installer verifies the existing installation using two checks:
   - **Binary hash check (local):** hash the installed `docdexd` and compare to the recorded `binary.sha256` from the last successful install.
   - **Release provenance check (metadata vs release):** resolve the expected platform archive SHA-256 for the current version (manifest → checksum fallback) and compare it to the recorded `archive.sha256` in `docdexd-install.json`.

   If either check fails (or can’t be performed deterministically), the installer re-installs a verified binary (`repair` when a mismatch is detected; otherwise `reinstall_unknown`).
>>>>>>> mcoda/task/ops-01-us-06-t03

## Install metadata: what it is and where it lives

The installer writes a small JSON metadata file next to the installed binary:
- `dist/<platformKey>/docdexd-install.json`

This metadata enables deterministic `no-op` and `repair` decisions without downloading a new asset.
Note: the installer may still fetch release metadata (manifest/checksums) to verify the recorded `archive.sha256`, but it does not re-download the platform archive when the outcome is `no-op`.

### Locate it (safe, cross-platform)

Local install (project dependency):
- Package root: `<repo>/node_modules/docdex/`
- Metadata: `<repo>/node_modules/docdex/dist/<platformKey>/docdexd-install.json`

Global install:
- Find global `node_modules`: `npm root -g`
- Metadata: `$(npm root -g)/docdex/dist/<platformKey>/docdexd-install.json`

OS notes (common defaults; prefer `npm root -g` over guessing):
- macOS/Linux: often under `/usr/local/lib/node_modules/docdex/...` or `~/.nvm/.../lib/node_modules/docdex/...`
- Windows: often under `%APPDATA%\\npm\\node_modules\\docdex\\...`

## Troubleshooting stale/corrupt daemon installs (risk-mitigated)

### 1) Confirm which `docdexd` you are running

- Platform diagnostics (offline): `docdex doctor`
- Wrapper expects the binary at: `dist/<platformKey>/docdexd` (or `docdexd.exe` on Windows).

If you upgraded/downgraded but the daemon still behaves like an older build, you may be running an already-started process.

### 2) Restart the daemon process

Reinstalling updates the on-disk binary, but it does not replace a currently running `docdexd` process.

Low-risk approach:
- Stop the process you started (e.g., terminate the terminal/service that launched `docdexd serve`), then start it again.

Windows note:
- Upgrading `docdexd.exe` while it is running commonly fails because the binary is locked. Stop `docdexd.exe` first, then reinstall.

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
- If you intentionally want a clean state, delete only the repo’s index directory: `<repo>/.docdex/index` (this forces a full reindex next run).

## See also

- Installer supported platforms + safe cleanup: `docs/ops/installer_supported_platforms.md`
- Atomic staged install + rollback behavior: `docs/ops/installer_atomic_install_and_rollback.md`
- Installer error codes + remediation: `docs/ops/installer_error_codes.md`
- Release manifest contract: `docs/contracts/release_manifest_schema_v1.md`
- Installer error contract: `docs/contracts/installer_error_contract_v1.md`
