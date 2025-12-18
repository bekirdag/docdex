# Release Manifest Schema (v1)

Scope: the machine-readable manifest attached to each GitHub Release and consumed by the npm installer (`npm/lib/install.js` + `npm/lib/release_manifest.js`) to deterministically resolve exactly one platform asset and verify integrity.

This document is the contract for:
- Manifest shape and required fields (schema version v1; published manifests set `manifestVersion: 1`).
- Canonical asset naming and the supported target triples a release is expected to publish.
- Deterministic installer resolution rules (manifest → documented fallback) and how to manually verify checksums.

## Where it is published (per release)

For each tag `vX.Y.Z`, the release workflow uploads the manifest and checksums as **GitHub Release assets**:
- Manifest: `docdex-release-manifest.json`
- Manifest checksum: `docdex-release-manifest.json.sha256`
- Fallback checksums bundle: `SHA256SUMS` and `SHA256SUMS.txt`
- Optional detached signatures over integrity metadata (when enabled): `*.sig` (see `docs/contracts/release_integrity_signatures_v1.md`)

The release workflow that generates and uploads these is `.github/workflows/release.yml` (step “Generate release manifest”, implemented by `scripts/generate_release_manifest.cjs`).

Signature policy: this repo’s default integrity mechanism is SHA-256 checksums (no signature verification by the npm installer). If you need signatures in your environment/fork, see `docs/ops/release_integrity.md`.

## Asset naming (canonical identifiers)

Docdex publishes one tarball per supported platform, named deterministically:

- Archive: `docdexd-<platformKey>.tar.gz`
- Per-asset checksum sidecar (legacy fallback): `docdexd-<platformKey>.tar.gz.sha256`

`platformKey` is the installer’s stable platform identifier (see `npm/lib/platform_matrix.js` and `docs/ops/installer_supported_platforms.md`).

## Supported target triples (published artifacts)

Published targets are the `published: true` entries in `npm/lib/platform_matrix.js` and are the ones the manifest for a release is expected to include under `targets`:

| Rust target triple | `platformKey` | Canonical archive asset |
|---|---|---|
| `aarch64-apple-darwin` | `darwin-arm64` | `docdexd-darwin-arm64.tar.gz` |
| `x86_64-apple-darwin` | `darwin-x64` | `docdexd-darwin-x64.tar.gz` |
| `aarch64-unknown-linux-gnu` | `linux-arm64-gnu` | `docdexd-linux-arm64-gnu.tar.gz` |
| `x86_64-unknown-linux-gnu` | `linux-x64-gnu` | `docdexd-linux-x64-gnu.tar.gz` |
| `x86_64-unknown-linux-musl` | `linux-x64-musl` | `docdexd-linux-x64-musl.tar.gz` |
| `x86_64-pc-windows-msvc` | `win32-x64` | `docdexd-win32-x64.tar.gz` |

If additional targets are added in the platform matrix, the manifest generator (`scripts/generate_release_manifest.cjs`) will include them automatically for published entries.

## Artifact names (manifest + fallbacks)

### Manifest filenames (candidates)

The installer tries manifest candidates in a deterministic order (see `npm/lib/install.js:manifestCandidateNames()`):

1) `docdex-release-manifest.json` (recommended / default)
2) `docdexd-manifest.json` (legacy/compat)
3) `docdex-manifest.json` (legacy/compat)
4) `manifest.json` (legacy/compat)

The candidate list can be overridden by setting `DOCDEX_MANIFEST_NAMES` (comma-separated) or `DOCDEX_MANIFEST_NAME`.

You can also control whether the installer uses the manifest at all (and whether it falls back to other integrity sources) via:
- `DOCDEX_INTEGRITY_METADATA_SOURCES` (order matters; includes/excludes `manifest`)
- `DOCDEX_INTEGRITY_MISSING_POLICY` (`fallback` or `abort`)

### Checksums filenames (fallback candidates)

When no usable manifest is available, the installer can derive integrity metadata from checksum files in the same release (see `npm/lib/install.js:checksumCandidateNames()`):

1) `SHA256SUMS` (recommended fallback bundle)
2) `SHA256SUMS.txt`

The candidate list can be overridden by setting `DOCDEX_CHECKSUMS_NAMES` (comma-separated) or `DOCDEX_CHECKSUMS_NAME`.

## Required schema (v1)

The manifest is a UTF-8 JSON document whose top-level value MUST be an object. The installer enforces a 1 MiB size cap for manifest downloads (`MAX_MANIFEST_BYTES` in `npm/lib/install.js`).

This repo publishes the `targets` form described below. The installer also tolerates a legacy `assets` array shape for compatibility.

### Top-level fields

Preferred (published by this repo’s release workflow):
- `manifestVersion` (number|string, recommended): when present, MUST be `1` for this schema; current releases publish `1`.
- `targets` (object, required for the preferred form): map of Rust target triple → entry object.

Optional (metadata; ignored by the installer unless noted):
- `repo` (string): `owner/repo` the release belongs to.
- `tag` (string): release tag, typically `vX.Y.Z`.
- `version` (string): `X.Y.Z`.
- `generatedAt` (string): ISO-8601 timestamp.
- `publishedAssets` (array): `{name, sha256}` pairs for release automation auditing (installer ignores this).

### `targets` entry object (required fields)

For each target triple key `T` in `targets`:
- `targets[T].asset.name` (string): canonical GitHub Release asset name (e.g. `docdexd-linux-x64-gnu.tar.gz`).
- `targets[T].integrity.sha256` (string): lowercase 64-hex SHA-256 of the asset file bytes for `asset.name`.

Optional fields (tolerated by the installer):
- `targets[T].asset.id` (string|number): provider-specific asset id (not used for resolution).
- Additional keys are permitted but ignored by the installer.

### Legacy-compatible shape (`assets` array)

If `targets` is absent, the installer will accept:
- `assets` (array): each entry MUST contain a target triple field under one of:
  - `targetTriple`, `target_triple`, `target`, `triple`, or `platform`
and MUST include a canonical asset identifier/name plus SHA-256 under one of the tolerated shapes (see `npm/lib/release_manifest.js:extractAssetAndIntegrity()`).

## Example manifest (v1)

```json
{
  "manifestVersion": 1,
  "repo": "bekirdag/docdex",
  "tag": "v0.1.6",
  "version": "0.1.6",
  "generatedAt": "2025-12-16T12:34:56.000Z",
  "targets": {
    "x86_64-unknown-linux-gnu": {
      "asset": { "name": "docdexd-linux-x64-gnu.tar.gz" },
      "integrity": { "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }
    }
  }
}
```

## Deterministic installer resolution (manifest → fallback)

The npm installer resolves an install plan deterministically (see `npm/lib/install.js:resolveInstallerDownloadPlan()`):

1) Detect runtime and compute:
   - `platformKey` (e.g. `linux-x64-gnu`)
   - `targetTriple` (e.g. `x86_64-unknown-linux-gnu`)
2) Try to fetch and parse the manifest using the candidate list above.
   - If a candidate returns HTTP 200 and resolves exactly one entry for `targetTriple` with `integrity.sha256`, the installer uses that asset name and SHA-256.
   - If the release provides a detached signature for the selected manifest (`<manifest>.sig`), the installer verifies it **before** trusting any `integrity.sha256` values.
   - If a manifest is present (HTTP 200) but does not support the target triple (`DOCDEX_ASSET_NO_MATCH`) or is ambiguous (`DOCDEX_ASSET_MULTI_MATCH`), the installer fails closed and does not attempt fallback.
   - If a candidate is missing (404), invalid JSON, too large, or missing required fields, the installer continues to the next candidate; if none are usable, it falls back.
3) Fallback (when no usable manifest exists): use the deterministic archive name `docdexd-<platformKey>.tar.gz` and attempt to obtain integrity metadata by:
   - Prefer `SHA256SUMS` / `SHA256SUMS.txt` entries for that filename.
   - If the release provides a detached signature for the selected checksums file (`SHA256SUMS.sig` / `SHA256SUMS.txt.sig`), the installer verifies it **before** trusting any checksum entries.
   - Legacy fallback: `<archive>.sha256` sidecar for that filename.
   - If integrity metadata is still unavailable, behavior is controlled by `DOCDEX_INTEGRITY_POLICY`:
     - Default (`required`): fail closed with `DOCDEX_CHECKSUM_UNUSABLE` (exit `24`).
     - Overrides (`allow-missing|off`): warn and proceed unverified (insecure; never silent).
4) Download, verify SHA-256 (fatal on mismatch unless `DOCDEX_INTEGRITY_POLICY=off`), extract, and confirm the expected `docdexd` binary exists.

Integrity policy (fail-closed):
- If SHA-256 integrity metadata cannot be obtained from the manifest or fallback checksums, the installer aborts with `DOCDEX_CHECKSUM_UNUSABLE` (no “silent” install).
- There is no supported mode that installs a downloaded `docdexd` archive without SHA-256 verification.

If installation fails, fatal errors are deterministic and include whether fallback was attempted; see `docs/contracts/installer_error_contract_v1.md` and `docs/ops/installer_error_codes.md`.

## Manual checksum verification (audit / debugging)

All checks below assume you have downloaded release assets locally from the intended repo + tag. Prefer verifying the manifest first, then the platform archive.

### 1) Verify the manifest checksum

- macOS/Linux: `shasum -a 256 -c docdex-release-manifest.json.sha256`
- Linux (alt): `sha256sum -c docdex-release-manifest.json.sha256`
- Windows (PowerShell):
  - `Get-FileHash -Algorithm SHA256 .\\docdex-release-manifest.json | Format-List`
  - Compare to the hash inside `.\\docdex-release-manifest.json.sha256`

### 2) Verify a platform archive against the manifest

1) Read `targets["<targetTriple>"].asset.name` and `targets["<targetTriple>"].integrity.sha256` from `docdex-release-manifest.json`.
2) Compute the archive hash locally and compare:
   - macOS/Linux: `shasum -a 256 <archive>`
   - Linux: `sha256sum <archive>`
   - Windows (PowerShell): `Get-FileHash -Algorithm SHA256 .\\<archive>`

### 3) Verify via `SHA256SUMS` (fallback parity)

- macOS/Linux: `shasum -a 256 -c SHA256SUMS`
- Linux: `sha256sum -c SHA256SUMS`

This confirms the fallback checksum bundle matches the released assets (and should align with the manifest’s per-asset SHA-256 values).

## See also

- Installer supported platforms + mapping: `docs/ops/installer_supported_platforms.md`
- Installer error codes + remediation: `docs/ops/installer_error_codes.md`
- Installer error contract: `docs/contracts/installer_error_contract_v1.md`
- Manifest generator: `scripts/generate_release_manifest.cjs`
