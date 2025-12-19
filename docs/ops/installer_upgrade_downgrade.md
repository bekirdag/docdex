# Installer Upgrade/Downgrade Guarantees, Repair, and Troubleshooting

Scope: the npm installer/downloader (`npm/lib/install.js`) and CLI wrapper (`npm/bin/docdex.js`) that install and run a platform-specific `docdexd` binary from GitHub Releases.

Assumptions (explicit):
- You install via npm (`npm i -g docdex` or `npx docdex --version`) on Node.js >= 18.
- “Expected version” is the npm package version (or `DOCDEX_VERSION` if set).
- The installer uses the published release manifest/checksums contracts when it needs to fetch an archive; see `docs/contracts/release_manifest_schema_v1.md`.
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

## Deterministic installer outcomes

The installer converges to a single final state: the installed `docdexd` under `dist/<platformKey>/` matches the expected version for this npm package install.

Outcomes (stable strings):

| Outcome | Meaning | Deterministic trigger (local state) |
|---|---|---|
| `no-op` | Nothing changes. | A previous verified install metadata file exists and its recorded `binary.sha256` matches the currently installed binary for the expected version. |
| `update` | Install/reinstall the expected version. (Includes first install, upgrade, downgrade.) | No binary exists, or install metadata indicates a different version than expected. |
| `repair` | Reinstall the expected version due to a local integrity mismatch. | Metadata exists for the expected version, but the current binary’s SHA-256 does not match the recorded `binary.sha256`. |
| `reinstall_unknown` | Reinstall because current state can’t be verified deterministically. | Binary exists but install metadata is missing/unreadable/invalid, or metadata does not match the detected `platformKey`. |

The installer logs the outcome as a single line:
- `[docdex] Install outcome: <outcome>`

## Upgrade vs downgrade

The installer does not treat “upgrade” and “downgrade” differently. It always targets the expected version for the current npm package install:
- If the installed version differs, the installer replaces `dist/<platformKey>/` so the final state equals the expected version.
- If the expected version is already installed and verified, the installer is a `no-op`.

This makes repeated installs idempotent: running the installer multiple times converges to the same installed binary and the same metadata for a given version/platform.

## Integrity verification and repair behavior

There are two relevant integrity checks:

1) **Remote archive integrity (when installing)**  
   When the installer needs to install (`update`, `repair`, `reinstall_unknown`), it resolves a single release asset and (when available) a SHA-256 for that asset via:
   - Release manifest (preferred), then
   - `SHA256SUMS`/`SHA256SUMS.txt`, then
   - legacy `<archive>.sha256` sidecar.

   The downloaded archive is verified against the expected SHA-256. If verification fails, installation fails closed with:
   - Error code: `DOCDEX_INTEGRITY_MISMATCH` (see `docs/ops/installer_error_codes.md`)
   - Safety property: the existing `dist/<platformKey>/` is only removed after the archive is successfully fetched and verified.

2) **Local binary integrity (no-op vs repair)**  
   For a `no-op`, the installer verifies the existing binary by hashing it and comparing to the recorded `binary.sha256` from the last successful, verified install.
   - If this local check fails, the outcome becomes `repair` and the installer reinstalls a verified binary.

## Install metadata: what it is and where it lives

The installer writes a small JSON metadata file next to the installed binary:
- `dist/<platformKey>/docdexd-install.json`
- Binary path: `dist/<platformKey>/docdexd` (or `docdexd.exe` on Windows).

This metadata enables deterministic `no-op` and `repair` decisions without downloading a new asset.

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

### 1) Confirm which `docdexd` you are running

- Platform diagnostics (offline): `docdex doctor`
- Wrapper expects the binary at: `dist/<platformKey>/docdexd` (or `docdexd.exe` on Windows).

If you upgraded/downgraded but the daemon still behaves like an older build, you may be running an already-started process.

### 2) Restart the daemon process

Reinstalling updates the on-disk binary, but it does not replace a currently running `docdexd` process.

Low-risk approach:
- Stop the process you started (e.g., terminate the terminal/service that launched `docdexd serve`), then start it again.

### 3) If installs keep “repairing” or look inconsistent, reset only installer state

Safe reset options (in increasing destructiveness):

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
- Installer error codes + remediation: `docs/ops/installer_error_codes.md`
- Release manifest contract: `docs/contracts/release_manifest_schema_v1.md`
- Installer error contract: `docs/contracts/installer_error_contract_v1.md`
