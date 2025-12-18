# Installer Error Codes + Remediation (npm postinstall)

Scope: the npm installer (`npm/lib/install.js`) that downloads a platform-specific `docdexd` binary from GitHub Releases.

This document explains:
- The **canonical fatal installer error codes** (`DOCDEX_*`) and their **exit codes**.
- What each error means.
- Whether the installer **attempted a manifest/fallback path**.
- Concrete remediation steps for users and release publishers.

Assumptions (explicit):
- You are installing via `npm i -g docdex` (or `npx docdex --version`) with Node.js `>= 18`.
- The installer is allowed to reach GitHub Releases for the target repo (`DOCDEX_DOWNLOAD_REPO`).
- Integrity verification is **always enforced** using SHA-256 checksums, and the installer **fails closed** if SHA-256 integrity metadata is missing or invalid (manifest or checksum fallback).

Related contracts:
- `docs/contracts/installer_error_contract_v1.md`
- `docs/contracts/release_manifest_schema_v1.md`
- `docs/ops/installer_platform_audit.md`
- `docs/ops/installer_supported_platforms.md`
- `docs/ops/installer_upgrade_downgrade.md`

---

## How the installer resolves an asset (manifest → fallback)

1) Detect runtime → `platformKey` + Rust `targetTriple` (see `npm/lib/platform.js`).
2) Try a release manifest (defaults to `docdex-release-manifest.json` plus legacy candidates).
   - If the manifest deterministically resolves **exactly one** asset and includes `integrity.sha256`, use it.
   - If a manifest is present but **does not support** the current `targetTriple` (or is ambiguous), the installer **fails closed** (no fallback).
   - Otherwise, the installer falls back.
3) Fallback: deterministic asset naming `docdexd-<platformKey>.tar.gz` and checksum discovery:
   - Prefer `SHA256SUMS` / `SHA256SUMS.txt` from the same release.
   - Legacy fallback: `docdexd-<platformKey>.tar.gz.sha256` sidecar.
4) Download, verify SHA-256 (when available), extract, and verify the expected `docdexd` binary exists.

When install fails, output includes `[docdex] error code: <CODE>` and the process exits with a stable numeric exit code.

---

## Quick triage (low-risk first)

1) Re-run once to rule out transient network/cache corruption:
   - `npm i -g docdex`
2) Confirm you are targeting the intended repo + version:
   - `echo $DOCDEX_DOWNLOAD_REPO` (should be `owner/repo`)
   - `echo $DOCDEX_VERSION` (if set; otherwise uses the npm package version)
3) On Linux, confirm libc selection:
   - If you’re unsure, try `DOCDEX_LIBC=gnu npm i -g docdex` (or `DOCDEX_LIBC=musl ...`)
4) If downloads fail due to GitHub rate limiting/private repos, set a token:
   - `export DOCDEX_GITHUB_TOKEN=...` (or `GITHUB_TOKEN`)

---

## Canonical fatal error codes (what you’ll see as “error code”)

Legend:
- **Fallback attempted**: whether the installer attempted a documented fallback path after manifest resolution.
  - For some errors this is always `false` (fail-closed) or always `true` (fallback-only).
  - When available, the installer prints `Fallback attempted: true/false`.

| Error code | Exit | Meaning | Fallback attempted | Remediation (user) | Remediation (publisher) |
|---|---:|---|---|---|---|
| `DOCDEX_INSTALLER_CONFIG` | 2 | Installer cannot determine repo/version/config (e.g., missing `repository.url` and no `DOCDEX_DOWNLOAD_REPO`). | N/A | Set `DOCDEX_DOWNLOAD_REPO=<owner/repo>`; avoid installing from an incomplete local package folder. | Ensure `package.json.repository.url` is set and not a placeholder. |
| `DOCDEX_UNSUPPORTED_PLATFORM` | 3 | Current OS/arch/libc is not supported or not published. No download occurs. | N/A | Use a supported platform from `docs/ops/installer_supported_platforms.md`; or build from source: `cargo build --release --locked`. On Linux, set `DOCDEX_LIBC=gnu|musl` to override detection. | Publish binaries for the missing `platformKey`/target triple (see `docs/ops/installer_platform_audit.md`). |
| `DOCDEX_ASSET_NO_MATCH` | 12 | A manifest was present, but it contains **no entry** for the detected `targetTriple`. Installer fails closed. | `false` | Install a version that supports your platform; or build from source. If installing from a fork, ensure you’re pointing at the correct repo. | Fix the release manifest to include the missing target triple and asset mapping for that release. |
| `DOCDEX_ASSET_MULTI_MATCH` | 13 | A manifest was present, but it contains **multiple entries** for the same `targetTriple`. Installer fails closed. | `false` | Install a different version; or build from source. | Deduplicate the manifest so each `targetTriple` resolves to exactly one asset. |
| `DOCDEX_DOWNLOAD_FAILED` | 20 | Download failed for the selected asset (non-404 HTTP status or transport failure). | `true/false` (printed when available) | Check network/proxy/firewall; retry; set `DOCDEX_GITHUB_TOKEN` if rate limited; verify `DOCDEX_DOWNLOAD_REPO` and (if set) `DOCDEX_DOWNLOAD_BASE`. | Ensure release assets are publicly readable (or document token usage for private releases). |
| `DOCDEX_ASSET_MISSING` | 21 | The expected asset returned HTTP 404 (release is missing the artifact or version is out of sync). | `true/false` (printed when available) | Confirm you’re installing a version whose GitHub Release contains the expected asset name; set `DOCDEX_DOWNLOAD_REPO` if using a fork; consider installing a different version. | Upload the missing release asset(s) and ensure npm version ↔ release tag are in sync. |
| `DOCDEX_INTEGRITY_MISMATCH` | 22 | SHA-256 verification failed for the downloaded archive. | `true/false` (printed when available) | Re-run install; bypass/disable proxies/caches; verify you are using the intended repo/version. Treat as a potential tampering signal; do not “work around” integrity failures by manual extraction. | Regenerate and re-upload correct checksums/manifest for the release; invalidate any cached/mirrored corrupted artifacts. |
| `DOCDEX_ARCHIVE_INVALID` | 23 | Archive extracted, but the expected `docdexd` binary was missing from the extracted directory. | `true/false` (printed when available) | Install a different version; or build from source. | Fix packaging (ensure tarball contains `docdexd`/`docdexd.exe` at the expected path). |
| `DOCDEX_CHECKSUM_UNUSABLE` | 24 | Installer could not obtain SHA-256 integrity metadata (no usable manifest + no usable checksum fallback). | `true` | Install a different version; or build from source. If installing from a fork, confirm the fork’s releases publish checksums/manifest. | Ensure the release includes `docdex-release-manifest.json` (with `integrity.sha256`) or `SHA256SUMS`/`SHA256SUMS.txt` with an entry for the asset; see `scripts/generate_release_manifest.cjs`. |

Notes:
- If you see an unknown `DOCDEX_*` code, treat it as a bug/regression; capture the full install log and open an issue with the code + platform details.

---

## Manifest/fallback diagnostics (when you need to know “why fallback happened”)

The installer may log structured “event” codes during manifest/checksum resolution (these are not the top-level fatal `error code` unless the install ultimately fails):

Manifest resolution events:
- `DOCDEX_MANIFEST_NOT_FOUND` (404 for a manifest candidate)
- `DOCDEX_MANIFEST_FETCH_FAILED` (non-404 fetch failure)
- `DOCDEX_MANIFEST_JSON_INVALID` (invalid JSON)
- `DOCDEX_MANIFEST_TOO_LARGE` (manifest exceeded size cap)
- `DOCDEX_MANIFEST_UNUSABLE` (manifest present but missing required fields, so installer continues to next candidate or falls back)
- `DOCDEX_FALLBACK_USED` (manifest candidates exhausted; deterministic asset naming selected)

Checksum fallback events:
- `DOCDEX_CHECKSUM_NOT_FOUND` (404 for a checksum candidate)
- `DOCDEX_CHECKSUM_FETCH_FAILED` (non-404 fetch failure)
- `DOCDEX_CHECKSUM_TOO_LARGE` (checksum file exceeded size cap)
- `DOCDEX_CHECKSUM_ENTRY_MISSING` (checksum file exists but lacks an entry for the desired asset)

If a fatal error includes `fallbackAttempted`/`fallbackReason`, use those fields first; they’re intended to be the stable “did fallback happen?” signal.
