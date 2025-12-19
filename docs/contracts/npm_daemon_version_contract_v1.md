# npm Wrapper <-> Daemon Version Contract (v1)

Scope: the npm postinstall downloader (`npm/lib/install.js`) and CLI wrapper (`npm/bin/docdex.js`) that install and run a platform-specific `docdexd` from GitHub Releases.

Assumptions (explicit):
- Install via npm on Node.js >= 18.
- "Expected version" is the npm package version or `DOCDEX_VERSION` if set (leading `v` is stripped).
- Release assets live under the repo in `DOCDEX_DOWNLOAD_REPO` (or `package.json.repository.url`) and are tagged as `vX.Y.Z`.

## Deterministic compatibility rule (version alignment)

- For npm package version `X.Y.Z`, the installer targets the GitHub Release tag `vX.Y.Z` and installs `docdexd` from that release.
- The installed binary under `dist/<platformKey>/docdexd` (or `docdexd.exe`) must be version `X.Y.Z`.
- If a local binary exists but its install metadata records a different version (or metadata is missing/invalid), the installer replaces it; repeated installs are idempotent.
- The detected/installed version (when present) is read from `dist/<platformKey>/docdexd-install.json`.

## Release source and tag format

- Repo slug resolution:
  - `DOCDEX_DOWNLOAD_REPO=<owner/repo>` overrides everything.
  - Otherwise, parse `package.json.repository.url` (GitHub URL).
- Download base:
  - `DOCDEX_DOWNLOAD_BASE` overrides the default.
  - Default base: `https://github.com/<owner/repo>/releases/download`.
- Tag format: `v<expectedVersion>` where `expectedVersion` is normalized (leading `v` stripped).

## Platform keys and required asset names

- The installer resolves a `platformKey` + Rust `targetTriple` from `npm/lib/platform_matrix.js` and `npm/lib/platform.js`.
- Required archive name for a published platform: `docdexd-<platformKey>.tar.gz`.
- Linux libc selection:
  - `DOCDEX_LIBC=gnu|musl|glibc` overrides auto-detection (`glibc` normalizes to `gnu`).

Published platforms (current `published: true` entries):

| Detected runtime | Linux libc | platformKey | Rust targetTriple | Required asset name |
|---|---|---|---|---|
| `darwin/arm64` | n/a | `darwin-arm64` | `aarch64-apple-darwin` | `docdexd-darwin-arm64.tar.gz` |
| `darwin/x64` | n/a | `darwin-x64` | `x86_64-apple-darwin` | `docdexd-darwin-x64.tar.gz` |
| `linux/x64` | `gnu` | `linux-x64-gnu` | `x86_64-unknown-linux-gnu` | `docdexd-linux-x64-gnu.tar.gz` |
| `linux/x64` | `musl` | `linux-x64-musl` | `x86_64-unknown-linux-musl` | `docdexd-linux-x64-musl.tar.gz` |
| `linux/arm64` | `gnu` | `linux-arm64-gnu` | `aarch64-unknown-linux-gnu` | `docdexd-linux-arm64-gnu.tar.gz` |
| `win32/x64` | n/a | `win32-x64` | `x86_64-pc-windows-msvc` | `docdexd-win32-x64.tar.gz` |

Entries marked `published: false` in the platform matrix are treated as unsupported (no download attempted).

## Installer query order (deterministic)

All queries are to `<downloadBase>/v<expectedVersion>/...` in the configured repo.

1) Manifest candidates (first usable wins):
   - Default names (in order): `docdex-release-manifest.json`, `docdexd-manifest.json`, `docdex-manifest.json`, `manifest.json`.
   - Override order via `DOCDEX_MANIFEST_NAMES` (comma-separated) or `DOCDEX_MANIFEST_NAME`.
   - If a manifest exists but does not contain a single matching entry for `targetTriple`, the installer fails closed (`DOCDEX_ASSET_NO_MATCH` / `DOCDEX_ASSET_MULTI_MATCH`) and does not fall back.
2) Checksum bundle fallback (if no usable manifest):
   - Default names (in order): `SHA256SUMS`, `SHA256SUMS.txt`.
   - Override order via `DOCDEX_CHECKSUMS_NAMES` or `DOCDEX_CHECKSUMS_NAME`.
3) Legacy per-asset checksum fallback:
   - `<archive>.sha256` alongside the archive.
4) Download + verify:
   - Archive: `docdexd-<platformKey>.tar.gz`.
   - SHA-256 must verify before extracting; otherwise the install fails closed.

## Failure signaling for missing release artifacts

If the expected release tag/asset does not exist, installation fails with:

- `DOCDEX_ASSET_MISSING` when the archive 404s, or
- `DOCDEX_CHECKSUM_UNUSABLE` when the installer cannot obtain SHA-256 metadata for the selected asset.

Fatal reports include:
- Expected version (`vX.Y.Z`) and, when install metadata exists, the detected installed version.
- Release source queried (repo slug and/or URL).
- Platform/target triple and expected asset naming details.
- Manifest name/version and whether fallback was attempted (when applicable).

## See also

- `docs/contracts/release_manifest_schema_v1.md`
- `docs/contracts/installer_error_contract_v1.md`
- `docs/ops/installer_supported_platforms.md`
- `docs/ops/installer_upgrade_downgrade.md`
