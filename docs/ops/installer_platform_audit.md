# Installer Platform Detection + Release Asset Naming (Audit)

Task: `ops-01-us-07-t34`

Operator-facing platform support + troubleshooting:
- `docs/ops/installer_supported_platforms.md`

Single source of truth:
- `npm/lib/platform_matrix.js` (runtime detection → `platformKey` → Rust target triple → release asset naming)

## What “platform detection” means (installer + wrapper)

Inputs (Node.js runtime):
- OS: `process.platform` (`darwin`, `linux`, `win32`)
- CPU arch: `process.arch` (`x64`, `arm64`)
- Linux libc: derived by `npm/lib/platform.js`:
  - Override: `DOCDEX_LIBC=gnu|musl|glibc` (glibc is normalized to `gnu`)
  - Otherwise: `process.report.getReport().header.glibcVersionRuntime` → `gnu`
  - Otherwise: `process.report.getReport().header.musl` / `/etc/alpine-release` / ELF interpreter inspection
  - Fallback: `musl` (most portable directionally, but can be overridden)

Output:
- `platformKey` (suffix used in artifacts): e.g. `linux-x64-gnu`
- `targetTriple` (Rust target triple): e.g. `x86_64-unknown-linux-gnu`

## Release asset naming expectations for `docdexd`

The npm postinstall installer (`npm/lib/install.js`) expects GitHub Release assets:
- Binary archive: `docdexd-<platformKey>.tar.gz`
- Release checksums (fallback when manifest missing): `SHA256SUMS` (or `SHA256SUMS.txt`)
- Legacy per-asset checksum (compat): `docdexd-<platformKey>.tar.gz.sha256`
- Release manifest (preferred): `docdex-release-manifest.json` (+ `docdex-release-manifest.json.sha256`)

If a platform is unsupported, install exits non-zero and does not download.
If a platform is supported but an artifact is missing, install exits non-zero with a “missing artifact/version sync issue” message (not “unsupported platform”) and includes the expected triple and asset pattern.

### Manifest + checksum resolution order (current)

- Manifest candidates (override via `DOCDEX_MANIFEST_NAMES` / `DOCDEX_MANIFEST_NAME`):
  - `docdex-release-manifest.json`
  - `docdexd-manifest.json`
  - `docdex-manifest.json`
  - `manifest.json`
- Checksums candidates (override via `DOCDEX_CHECKSUMS_NAMES` / `DOCDEX_CHECKSUMS_NAME`):
  - `SHA256SUMS`
  - `SHA256SUMS.txt`
- Deterministic fallback archive name: `docdexd-<platformKey>.tar.gz`
- Pattern string shown in errors: `docdexd-<platformKey>.tar.gz (e.g. docdexd-linux-x64-gnu.tar.gz)`

Contracts:
- `docs/contracts/installer_error_contract_v1.md`
- `docs/contracts/release_manifest_schema_v1.md`
- Remediation playbook: `docs/ops/installer_error_codes.md`

## Published support matrix (what releases currently ship)

These are the platforms marked `published: true` in `npm/lib/platform_matrix.js` and built by `.github/workflows/release.yml`:

| Detected runtime | `platformKey` | Rust `targetTriple` | Expected asset |
|---|---|---|---|
| `darwin/arm64` | `darwin-arm64` | `aarch64-apple-darwin` | `docdexd-darwin-arm64.tar.gz` |
| `darwin/x64` | `darwin-x64` | `x86_64-apple-darwin` | `docdexd-darwin-x64.tar.gz` |
| `linux/x64` + glibc | `linux-x64-gnu` | `x86_64-unknown-linux-gnu` | `docdexd-linux-x64-gnu.tar.gz` |
| `linux/x64` + musl | `linux-x64-musl` | `x86_64-unknown-linux-musl` | `docdexd-linux-x64-musl.tar.gz` |
| `linux/arm64` + glibc | `linux-arm64-gnu` | `aarch64-unknown-linux-gnu` | `docdexd-linux-arm64-gnu.tar.gz` |
| `win32/x64` | `win32-x64` | `x86_64-pc-windows-msvc` | `docdexd-win32-x64.tar.gz` |

## Known gaps / mismatches (recognized but not published)

These mappings exist (to keep the intent explicit) but are marked `published: false`, and are treated as **unsupported** so the installer does not attempt downloads:

| Detected runtime | `platformKey` | Rust `targetTriple` | Expected asset (if/when published) |
|---|---|---|---|
| `linux/arm64` + musl | `linux-arm64-musl` | `aarch64-unknown-linux-musl` | `docdexd-linux-arm64-musl.tar.gz` |
| `win32/arm64` | `win32-arm64` | `aarch64-pc-windows-msvc` | `docdexd-win32-arm64.tar.gz` |

Implication:
- These targets should either be added to `.github/workflows/release.yml` (and `scripts/generate_release_manifest.cjs` will pick them up automatically), or remain unsupported with actionable guidance.

## Current failure modes (installer behavior)

Platform detection / mapping:
- `DOCDEX_UNSUPPORTED_PLATFORM` when the runtime is unknown or maps to a `published: false` entry (e.g. `linux/arm64` + musl, `win32/arm64`). Includes the candidate platform key + target triple and notes when a target is recognized but not published.
- `DOCDEX_INSTALL_FAILED` (generic) if `DOCDEX_LIBC` is set to an invalid value (throws before the installer can map to a `platformKey`).

Manifest resolution:
- `DOCDEX_ASSET_NO_MATCH` when a manifest is present but has no entry for the detected `targetTriple` (fails closed; no fallback).
- `DOCDEX_ASSET_MULTI_MATCH` when a manifest has multiple entries for the same `targetTriple` (fails closed; no fallback).
- Manifest present but missing asset name or integrity is treated as unusable; the installer records `DOCDEX_MANIFEST_UNUSABLE` and continues to the next candidate/fallback.
- Oversized or invalid manifests are skipped with `DOCDEX_MANIFEST_TOO_LARGE` / `DOCDEX_MANIFEST_JSON_INVALID` events and fallback continues.

Checksum / archive resolution:
- `DOCDEX_CHECKSUM_UNUSABLE` when no usable manifest exists and no checksum candidate (or per-asset `.sha256`) provides integrity metadata.
- `DOCDEX_ASSET_MISSING` when the resolved asset name returns 404 (manifest or fallback).
- `DOCDEX_DOWNLOAD_FAILED` for non-404 download failures (network/proxy/token issues).
- `DOCDEX_INTEGRITY_MISMATCH` when SHA-256 verification fails.
- `DOCDEX_ARCHIVE_INVALID` when the archive extracts without the expected `docdexd` binary.
