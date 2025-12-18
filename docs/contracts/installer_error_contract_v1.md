# Installer / Manifest Error Contract (v1)

Scope: the npm postinstall downloader (`npm/lib/install.js`) that resolves a platform-specific `docdexd` release asset (optionally via a release manifest) and verifies integrity.

Assumptions (explicit):
- The installer runs in Node.js >= 18 and exits with a single process exit code (0–255).
- A “manifest” is a JSON file attached to the GitHub Release (candidate names are installer-configurable; default is `docdex-release-manifest.json`).
- `manifestVersion` is optional in current manifests; when absent it is reported as `null`.
- Integrity policy is configurable via `DOCDEX_INTEGRITY_POLICY`:
  - Default: `required` (fail closed on missing integrity metadata; verify archive SHA-256 before install).
  - Overrides: `allow-missing` (continue unverified if metadata is missing) or `off` (disable verification).
  - This error contract describes the default `required` behavior unless explicitly stated otherwise.

## Goals

- Deterministic installer behavior for supported platforms.
- Stable, machine-readable error `code` plus deterministic `exitCode`.
- Actionable user-facing messages that indicate whether manifest fallback was attempted and why.
- Minimum structured fields on every fatal error: `targetTriple`, `manifestVersion`, `assetName` (may be `null` when unknown).
- Concrete remediation guidance lives in `docs/ops/installer_error_codes.md`.

## Canonical error envelope

Fatal errors are represented internally as an `Error` instance with:

- `code` (string, required): canonical machine-readable code.
- `exitCode` (number, required): deterministic process exit code.
- `details` (object, required): structured context (see minimum fields below).
- `cause` (Error, optional): underlying error.

`npm/lib/install.js` converts fatal errors into a printable report via `describeFatalError(err)`, which returns:

- `code` (string)
- `exitCode` (number)
- `details` (object)
- `lines` (string[]): user-facing, stable messages (stderr)

## Minimum structured fields (fatal errors)

`details` includes these keys on every fatal error (values may be `null` if unknown):

- `targetTriple` (string|null)
- `manifestVersion` (string|number|null)
- `assetName` (string|null)

Additional common keys (when available):

- `platformKey` (string|null)
- `repoSlug` (string|null)
- `version` (string|null)
- `downloadUrl` (string|null)
- `manifestName` (string|null)
- `source` (`"manifest:<name>"|"fallback"|null`)
- `fallbackAttempted` (boolean)
- `fallbackReason` (string|null)
- `statusCode` (number|null)
- `expectedSha256` (string|null)
- `actualSha256` (string|null)

## Canonical codes + exit codes

Exit codes are stable and grouped by failure class:

### Target/platform resolution

- `DOCDEX_UNSUPPORTED_PLATFORM` → exit `3`
  - The detected OS/arch/libc cannot be mapped to a supported `platformKey`/`targetTriple`.

### Manifest discovery/parsing (non-fatal when fallback succeeds)

These are emitted as structured “events” on the resolution attempt and may appear in logs, but do not cause install failure if a documented fallback succeeds:

- `DOCDEX_MANIFEST_NOT_FOUND` (all manifest candidates 404)
- `DOCDEX_MANIFEST_FETCH_FAILED` (non-404 failure fetching a manifest candidate)
- `DOCDEX_MANIFEST_JSON_INVALID` (invalid JSON in a fetched manifest candidate)
- `DOCDEX_MANIFEST_TOO_LARGE` (manifest response exceeds size cap)
- `DOCDEX_MANIFEST_UNUSABLE` (manifest was present but missing required fields; installer continues to next candidate or falls back)
- `DOCDEX_FALLBACK_USED` (fallback selected; includes `fallbackReason`)

### Manifest target resolution (fail-closed)

- `DOCDEX_ASSET_NO_MATCH` → exit `12`
  - Manifest does not contain an entry for the detected `targetTriple`.
- `DOCDEX_ASSET_MULTI_MATCH` → exit `13`
  - Manifest contains multiple entries for the same `targetTriple`.

Rationale: if a manifest is present but resolution is unsupported/ambiguous for the current target, the installer fails closed (no fallback), because a “fallback” would be non-deterministic relative to a present-but-contradictory manifest.

### Manifest schema/entry issues (fallbackable)

These codes exist in the manifest resolver (`npm/lib/release_manifest.js`) and map to stable exit codes, but in the installer’s current behavior they are treated as “manifest unusable” and trigger a documented fallback path when possible:

- `DOCDEX_MANIFEST_MALFORMED` → exit `10`
  - Manifest JSON object is present but has an unsupported top-level shape.
- `DOCDEX_ASSET_MALFORMED` → exit `14`
  - Manifest entry exists for the target but is missing required fields (canonical asset name and/or SHA-256).
- `DOCDEX_TARGET_TRIPLE_INVALID` → exit `11`
  - Contract violation: target triple is missing/empty.

If all fallback paths fail (e.g., checksums are also unavailable), the resulting fatal error is typically `DOCDEX_CHECKSUM_UNUSABLE` (exit `24`) with `details.fallbackAttempted=true`.

### Download / verification (fatal)

- `DOCDEX_DOWNLOAD_FAILED` → exit `20`
  - Network/download error for the selected asset (non-404 HTTP status or transport failure).
- `DOCDEX_ASSET_MISSING` → exit `21`
  - Selected asset returned 404 (release is missing the expected artifact).
- `DOCDEX_INTEGRITY_MISMATCH` → exit `22`
  - SHA-256 verification failed for the downloaded archive.
- `DOCDEX_ARCHIVE_INVALID` → exit `23`
  - Archive extracted but the expected binary is missing.
- `DOCDEX_CHECKSUM_UNUSABLE` → exit `24`
  - The installer could not obtain SHA-256 integrity metadata for the selected asset (manifest missing/unusable and checksum fallback missing/malformed).
  - Note: with `DOCDEX_INTEGRITY_POLICY=allow-missing|off`, this condition is handled deterministically but may not be fatal (installer warns and proceeds unverified).

### Installer configuration (fatal)

- `DOCDEX_INSTALLER_CONFIG` → exit `2`
  - Required config (repo slug, version, etc.) is missing or invalid.

## User-facing message requirements

All fatal reports:

- Start with `[docdex] install failed: ...`
- Include `[docdex] error code: <CODE>` and (when helpful) a short “Next steps” section.
- For manifest-related failures, include whether fallback was attempted (`details.fallbackAttempted`) and why it was not used.
- Integrity policy is configurable via `DOCDEX_INTEGRITY_POLICY`:
  - Default: `required` (fail closed on missing integrity metadata; verify archive SHA-256 before install).
  - Overrides: `allow-missing` (continue unverified if metadata is missing) or `off` (disable verification).
  - This error contract describes the default `required` behavior unless explicitly stated otherwise.
  - Note: with `DOCDEX_INTEGRITY_POLICY=allow-missing|off`, this condition is handled deterministically but may not be fatal (installer warns and proceeds unverified).
