# Installer Asset + Metadata Discovery Contract (v1)

Scope: the npm installer/downloader (`npm/lib/install.js`) and platform resolver (`npm/lib/platform.js`) that fetch and verify a platform-specific `docdexd` archive from GitHub Releases.

Goal: define the deterministic rules for (1) resolving a release asset, (2) finding integrity metadata, and (3) installing the verified binary. This contract is implementation-ready and mirrors current behavior.

Sources of truth:
- `npm/lib/install.js`
- `npm/lib/platform.js`
- `npm/lib/platform_matrix.js`
- `docs/contracts/release_manifest_schema_v1.md`
- `docs/contracts/installer_error_contract_v1.md`

## Inputs and environment overrides

Required inputs:
- Repo slug: `DOCDEX_DOWNLOAD_REPO` or `package.json.repository.url` (owner/repo)
- Version: `DOCDEX_VERSION` or `package.json.version` (normalized to `X.Y.Z`)

Optional overrides:
- `DOCDEX_DOWNLOAD_BASE` (default: `https://github.com/<owner>/<repo>/releases/download`)
- `DOCDEX_GITHUB_TOKEN` or `GITHUB_TOKEN` (adds `Authorization: Bearer <token>` header)
- `DOCDEX_LIBC=gnu|musl|glibc` (Linux libc override)
- `DOCDEX_MANIFEST_NAMES` / `DOCDEX_MANIFEST_NAME` (comma-separated manifest filenames)
- `DOCDEX_CHECKSUMS_NAMES` / `DOCDEX_CHECKSUMS_NAME` (comma-separated checksum filenames)

HTTP behavior:
- `User-Agent: docdex-installer`
- Up to 5 redirects
- Manifest download size cap: 1 MiB

## Platform mapping (OS/arch/libc -> platformKey -> targetTriple)

Published (supported) targets are the entries in `npm/lib/platform_matrix.js` with `published: true`.

| Detected runtime | libc | platformKey | Rust target triple | Expected archive asset |
|---|---|---|---|---|
| darwin/arm64 | n/a | darwin-arm64 | aarch64-apple-darwin | docdexd-darwin-arm64.tar.gz |
| darwin/x64 | n/a | darwin-x64 | x86_64-apple-darwin | docdexd-darwin-x64.tar.gz |
| linux/x64 | gnu | linux-x64-gnu | x86_64-unknown-linux-gnu | docdexd-linux-x64-gnu.tar.gz |
| linux/x64 | musl | linux-x64-musl | x86_64-unknown-linux-musl | docdexd-linux-x64-musl.tar.gz |
| linux/arm64 | gnu | linux-arm64-gnu | aarch64-unknown-linux-gnu | docdexd-linux-arm64-gnu.tar.gz |
| win32/x64 | n/a | win32-x64 | x86_64-pc-windows-msvc | docdexd-win32-x64.tar.gz |

Recognized but unpublished targets (treated as unsupported; no download attempted):
- linux/arm64 + musl -> linux-arm64-musl -> aarch64-unknown-linux-musl
- win32/arm64 -> win32-arm64 -> aarch64-pc-windows-msvc

## Asset naming and archive layout

Archive naming:
- `docdexd-<platformKey>.tar.gz` (canonical asset for each supported platform)

Archive contents (required):
- Must extract a binary named `docdexd` (or `docdexd.exe` on Windows) at the archive root.
- The installer extracts directly into `dist/<platformKey>/` and expects the binary at:
  - macOS/Linux: `dist/<platformKey>/docdexd`
  - Windows: `dist/<platformKey>/docdexd.exe`

## Download URLs

All assets are fetched from:
- `${DOCDEX_DOWNLOAD_BASE or https://github.com/<repo>/releases/download}/v<version>/<assetName>`

This applies to:
- Archive asset (`docdexd-<platformKey>.tar.gz`)
- Manifest candidates
- Checksum candidates
- Legacy per-asset checksum sidecars (`<archive>.sha256`)

## Integrity metadata discovery (deterministic)

Order of operations:

1) Resolve `platformKey` + `targetTriple`.
   - If unsupported, fail with `DOCDEX_UNSUPPORTED_PLATFORM`.
   - No download is attempted.

2) Manifest resolution (preferred):
   - Candidates (default order):
     1. `docdex-release-manifest.json`
     2. `docdexd-manifest.json`
     3. `docdex-manifest.json`
     4. `manifest.json`
   - For the first candidate that returns HTTP 200 and parses as JSON:
     - If it resolves exactly one entry for `targetTriple` with `integrity.sha256`, use:
       - `asset.name` as the archive filename
       - `integrity.sha256` as the expected SHA-256
       - `source = "manifest:<name>"`
     - If the manifest is present but does not support the target (no match or multiple matches),
       fail closed with `DOCDEX_ASSET_NO_MATCH` or `DOCDEX_ASSET_MULTI_MATCH` (no fallback).
   - If all candidates are missing (404) or unusable (invalid JSON, too large, malformed),
     proceed to fallback (step 3).

3) Fallback resolution (deterministic asset naming):
   - Archive filename = `docdexd-<platformKey>.tar.gz`.
   - Resolve expected SHA-256 via checksum candidates:
     - `SHA256SUMS`, then `SHA256SUMS.txt` (overridable by env).
     - Parse lines of the form `<hex>  <filename>` (optional `*` before filename).
   - If no checksum entry exists, try legacy `<archive>.sha256`.
   - If no SHA-256 is found, fail with `DOCDEX_CHECKSUM_UNUSABLE`.

## Download + install semantics (paths and permissions)

Temporary download:
- Temp dir: `os.tmpdir()`
- Temp filename: `${archive}.${process.pid}.tgz`
- Temp file is always removed in a `finally` block.

Verification and extraction:
1) Download the archive to the temp file.
   - 404 -> `DOCDEX_ASSET_MISSING`
   - non-200 / transport error -> `DOCDEX_DOWNLOAD_FAILED`
2) Verify SHA-256 of the downloaded file.
   - Mismatch -> `DOCDEX_INTEGRITY_MISMATCH`
3) Only after verification succeeds:
   - Remove `dist/<platformKey>/` recursively.
   - Extract the tarball into `dist/<platformKey>/`.
   - If expected binary missing -> `DOCDEX_ARCHIVE_INVALID`
   - Attempt `chmod 0o755` on the binary (best-effort; errors ignored).

Install metadata:
- Written to `dist/<platformKey>/docdexd-install.json` (atomic write + rename).
- Includes:
  - `binary.sha256` (actual binary hash)
  - `archive.sha256` (expected hash from manifest/checksums, if any)
  - `source`, `downloadUrl`, `version`, `targetTriple`, `platformKey`

No persistent download cache:
- The installer does not cache the archive outside the temp file.
- The only persistent artifacts are `dist/<platformKey>/` and the install metadata JSON.

## Integrity metadata inventory (current)

Release assets used by the installer:
- Manifest: `docdex-release-manifest.json` (preferred)
- Manifest checksum: `docdex-release-manifest.json.sha256` (published but not verified by installer)
- Checksums bundle: `SHA256SUMS`, `SHA256SUMS.txt`
- Legacy per-asset checksum: `docdexd-<platformKey>.tar.gz.sha256`

Local metadata (post-install):
- `dist/<platformKey>/docdexd-install.json` (not a release artifact)

## Feasible metadata extensions (not implemented)

Potential additions (requires installer + release pipeline changes):
- `checksums.json`: machine-readable checksums bundle; would require a new parser and selection rules.
- Detached signatures (e.g., minisign, cosign): would require a published public key and signature verification.
- SBOM or provenance files: could be recorded but are not currently consumed by the installer.

Any new metadata type MUST define:
- Deterministic discovery order (including explicit failure policy when present but unusable).
- Hash/signature algorithms and canonical encodings.
- Whether fallback is allowed when a signature or manifest is present but invalid.

## Deterministic failure policy (summary)

- Unsupported platform -> fail, no download.
- Manifest present but no match/ambiguous -> fail closed (no fallback).
- Manifest absent/unusable -> fallback to checksum discovery.
- Missing/invalid integrity metadata -> fail closed (`DOCDEX_CHECKSUM_UNUSABLE`).
- Integrity mismatch -> fail closed, do not leave a runnable binary in place.
