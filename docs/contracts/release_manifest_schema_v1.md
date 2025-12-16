# Release Manifest Schema (v1)

Scope: the machine-readable manifest attached to each GitHub Release and consumed by the npm installer (`npm/lib/install.js` + `npm/lib/release_manifest.js`) to deterministically resolve exactly one platform asset and verify integrity.

## Artifact names

- Manifest filename (recommended / default): `docdex-release-manifest.json`
- Manifest checksum filename: `docdex-release-manifest.json.sha256`
- Fallback checksums (when manifest is missing): `SHA256SUMS` (or `SHA256SUMS.txt`)

Legacy/compatibility (installer still supports these manifest names when configured/needed):
- `docdexd-manifest.json`
- `docdex-manifest.json`
- `manifest.json`

## Required shape

Top-level JSON object with either:

- `targets` (object): maps Rust target triple → entry object (preferred), or
- `assets` (array): list of entries with `targetTriple`/`target_triple` fields (legacy-compatible)

This repo publishes `targets`.

### `targets` entry object (required fields)

- `asset.name` (string): canonical GitHub Release asset name (e.g. `docdexd-linux-x64-gnu.tar.gz`)
- `integrity.sha256` (string): lowercase 64-hex SHA-256 of `asset.name`

### Optional fields

- `manifestVersion` (number|string)
- `repo` (string, `owner/repo`)
- `tag` (string, `vX.Y.Z`)
- `version` (string, `X.Y.Z`)
- `generatedAt` (string, ISO-8601)
- `publishedAssets` (array): `{name, sha256}` for release automation auditing (installer ignores this)

## See also

- Installer error codes + remediation: `docs/ops/installer_error_codes.md`
- Installer error contract: `docs/contracts/installer_error_contract_v1.md`
