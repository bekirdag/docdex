# Installer Platform Detection + Release Asset Naming (Audit)

Task: `ops-01-us-07-t28`

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
- Release tag (version): `v<version>`
- Binary archive filename: `docdexd-<platformKey>.tar.gz`
- Canonical release asset id (tag + filename): `v<version>/docdexd-<platformKey>.tar.gz`
- Release checksums (fallback when manifest missing): `SHA256SUMS` (or `SHA256SUMS.txt`)
- Legacy per-asset checksum (compat): `docdexd-<platformKey>.tar.gz.sha256`
- Release manifest (preferred): `docdex-release-manifest.json` (+ `docdex-release-manifest.json.sha256`)

If a platform is unsupported, install exits non-zero and does not download.
If a platform is supported but an artifact is missing, install exits non-zero with a “missing artifact/version sync issue” message (not “unsupported platform”) and includes the expected triple and asset pattern.

Contracts:
- `docs/contracts/installer_asset_metadata_contract_v1.md`
- `docs/contracts/installer_error_contract_v1.md`
- `docs/contracts/release_manifest_schema_v1.md`
- Remediation playbook: `docs/ops/installer_error_codes.md`

## Failure modes that can look like “unsupported platform”

- **Unknown runtime**: `process.platform`/`process.arch` not in the matrix → `DOCDEX_UNSUPPORTED_PLATFORM` (no download attempted).
- **Recognized but unpublished**: mapping exists with `published: false` (currently `linux-arm64-musl`, `win32-arm64`) → `DOCDEX_UNSUPPORTED_PLATFORM` (no download attempted).
- **Linux libc misclassification**: if libc detection falls back to `musl` on an otherwise glibc runtime, `linux/arm64` can map to the unpublished `linux-arm64-musl` and appear unsupported; retry with `DOCDEX_LIBC=gnu` to confirm.

## Failure modes that should *not* be labeled “unsupported platform”

- **Supported platform, missing artifact**: 404 for the expected asset (`DOCDEX_ASSET_MISSING`) → message must include detected OS/arch, expected `targetTriple`, and `docdexd-<platformKey>.tar.gz` naming pattern.
- **Manifest present, but no entry for target**: `DOCDEX_ASSET_NO_MATCH` → treated as “missing artifact/version sync issue” (fails closed) and includes the expected triple + naming pattern.

## Published support matrix (what releases currently ship)

These are the platforms marked `published: true` in `npm/lib/platform_matrix.js` and built by `.github/workflows/release.yml`:

| Detected runtime | `platformKey` | Rust `targetTriple` | Expected asset filename |
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
