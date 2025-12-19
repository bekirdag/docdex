# Version Sync Contract (npm wrapper <-> docdexd) v1

Scope: the npm wrapper + installer (`npm/bin/docdex.js`, `npm/lib/install.js`) that install and run `docdexd`.

This document defines the version sync contract between the npm package and the `docdexd` daemon, plus a concise troubleshooting playbook.

## Contract: expected version and exact match

- Expected version is derived from `DOCDEX_VERSION` if set, otherwise the npm package version in `npm/package.json` (leading `v` is stripped).
- Exact match is required by default: the installed `docdexd` version MUST equal the expected version.
- There is no semver range or compatibility shim in effect. If a compatibility rule is introduced, it must be deterministic and documented here.

## Mismatch handling (replace/repair)

The installer converges to a single final state: `docdexd` under `dist/<platformKey>/` matches the expected version.

- If the daemon is missing, the installer downloads and installs the expected version.
- If a different version is detected locally, the installer replaces it (update/upgrade/downgrade all share this path).
- If the expected version is present but fails integrity checks, the installer repairs it (reinstall after verification).
- If local metadata is missing/invalid, the installer performs a deterministic reinstall.

## Deterministic release source, tag, and asset selection

The installer resolves a single release asset deterministically:

1) Release source (repo slug):
   - `DOCDEX_DOWNLOAD_REPO` if set, otherwise `package.json.repository.url` (`owner/repo`).
2) Download base:
   - `DOCDEX_DOWNLOAD_BASE` if set, otherwise `https://github.com/<repo>/releases/download`.
3) Release tag:
   - `v<expectedVersion>`.
4) Platform mapping:
   - `platformKey` + `targetTriple` from `npm/lib/platform_matrix.js` and `npm/lib/platform.js`.
5) Asset selection:
   - Prefer release manifest candidates (see `docs/contracts/release_manifest_schema_v1.md`).
   - If no usable manifest exists, fall back to `docdexd-<platformKey>.tar.gz` and checksum discovery (`SHA256SUMS`/`SHA256SUMS.txt`, then `<archive>.sha256`).
6) Download, verify SHA-256 when available, extract, and confirm the `docdexd` binary exists.

## User-facing errors for missing release assets

If the expected tag/asset does not exist, installation fails with a "missing artifact/version sync issue" error. The error report includes (when available):

- Expected version (`v<expectedVersion>`).
- Detected installed version (from `docdexd-install.json`, if present).
- Release source queried (repo slug and/or download URL).
- Expected target triple and asset naming pattern.

See `docs/ops/installer_error_codes.md` for the stable error codes.

## Troubleshooting (common version sync failures)

### Identify the expected version

- If `DOCDEX_VERSION` is set, that is the expected version.
- Otherwise, read the installed npm package version:
  - Local: `<repo>/node_modules/docdex/package.json`
  - Global: `$(npm root -g)/docdex/package.json`

### Identify the detected daemon version

- Read install metadata: `dist/<platformKey>/docdexd-install.json` (field `version`).
- Or run the binary: `docdexd --version` (wrapper) or `<package>/dist/<platformKey>/docdexd --version`.

### Remediate

1) Reinstall to converge on the expected version:
   - Global: `npm i -g docdex`
   - Local: `npm install docdex` (or your lockfile-friendly install command, e.g. `npm ci`)
2) If you hit a missing asset/version sync error:
   - Verify `DOCDEX_DOWNLOAD_REPO` and `DOCDEX_VERSION`.
   - Confirm GitHub Release `v<expectedVersion>` exists and includes:
     - `docdex-release-manifest.json` (or `SHA256SUMS`/`SHA256SUMS.txt`)
     - `docdexd-<platformKey>.tar.gz`
   - If assets are missing, publish them or build from source (`cargo build --release --locked`).

## See also

- `docs/ops/installer_upgrade_downgrade.md`
- `docs/ops/installer_supported_platforms.md`
- `docs/ops/installer_error_codes.md`
- `docs/contracts/release_manifest_schema_v1.md`
- `docs/contracts/installer_error_contract_v1.md`
