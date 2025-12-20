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
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
- Integrity verification is **always enforced** when SHA-256 metadata is available (manifest or checksum fallback).
- Signature verification for integrity metadata is optional and policy-driven; see `docs/contracts/release_integrity_signatures_v1.md`.
=======
- Integrity verification is **always enforced** using SHA-256 checksums, and the installer **fails closed** if SHA-256 integrity metadata is missing or invalid (manifest or checksum fallback).
>>>>>>> mcoda/task/ops-01-us-04-t40
=======
- Integrity verification is **required by default** (SHA-256) and missing integrity metadata is treated deterministically:
  - Default (`DOCDEX_INTEGRITY_POLICY=required`): missing metadata is a fatal `DOCDEX_CHECKSUM_UNUSABLE` (exit `24`).
  - Explicit overrides (`DOCDEX_INTEGRITY_POLICY=allow-missing|off`) are allowed but **insecure** and are never silent (the installer warns).
>>>>>>> mcoda/task/ops-01-us-04-t17
=======
- Integrity verification is **mandatory**; if SHA-256 metadata is missing or invalid, the installer fails closed with `DOCDEX_CHECKSUM_UNUSABLE`.
>>>>>>> mcoda/task/ops-01-us-04-t38

Related contracts:
- `docs/contracts/installer_error_contract_v1.md`
- `docs/contracts/version_sync_contract_v1.md`
- `docs/contracts/release_manifest_schema_v1.md`
- `docs/ops/installer_platform_audit.md`
- `docs/ops/installer_supported_platforms.md`
- `docs/ops/installer_upgrade_downgrade.md`
- `docs/ops/installer_rollback_guarantees.md`

---

## How the installer resolves an asset (integrity sources → fallback)

1) Detect runtime → `platformKey` + Rust `targetTriple` (see `npm/lib/platform.js`).
<<<<<<< HEAD
2) Try a release manifest (defaults to `docdex-release-manifest.json` plus legacy candidates).
   - If the manifest deterministically resolves **exactly one** asset and includes `integrity.sha256`, use it.
   - If the release provides a detached signature for the selected manifest (`<manifest>.sig`), the installer verifies it **before** trusting any checksums.
   - If a manifest is present but **does not support** the current `targetTriple` (or is ambiguous), the installer **fails closed** (no fallback).
   - Otherwise, the installer falls back.
3) Fallback: deterministic asset naming `docdexd-<platformKey>.tar.gz` and checksum discovery:
   - Prefer `SHA256SUMS` / `SHA256SUMS.txt` from the same release.
   - If the release provides a detached signature for the selected checksums file (`SHA256SUMS.sig` / `SHA256SUMS.txt.sig`), the installer verifies it **before** trusting any checksum entries.
   - Legacy fallback: `docdexd-<platformKey>.tar.gz.sha256` sidecar.
<<<<<<< HEAD
<<<<<<< HEAD
4) Download, verify SHA-256 (when available), extract, and verify the expected `docdexd` binary exists.
=======
2) Resolve integrity metadata by trying `DOCDEX_INTEGRITY_METADATA_SOURCES` in order (default: `manifest,checksums,sidecar`).
   - `manifest`: try a release manifest (defaults to `docdex-release-manifest.json` plus legacy candidates).
     - If the manifest deterministically resolves **exactly one** asset and includes `integrity.sha256`, use it.
     - If a manifest is present but **does not support** the current `targetTriple` (or is ambiguous), the installer **fails closed** (no fallback).
   - `checksums`: deterministic asset naming `docdexd-<platformKey>.tar.gz` and checksum discovery via `SHA256SUMS` / `SHA256SUMS.txt`.
   - `sidecar`: legacy `<archive>.sha256` sidecar for the deterministic archive name.
3) If integrity metadata is missing/unavailable, apply `DOCDEX_INTEGRITY_MISSING_POLICY`:
   - `fallback` (default): try the next configured source.
   - `abort`: fail deterministically without trying later sources.
4) Download, verify SHA-256, extract, and verify the expected `docdexd` binary exists.
>>>>>>> mcoda/task/ops-01-us-04-t21
=======
4) Download, verify SHA-256 (required; missing metadata is fatal), extract, and verify the expected `docdexd` binary exists.
>>>>>>> mcoda/task/ops-01-us-04-t38
=======
4) Download, verify SHA-256 (when available), extract, and verify the expected `docdexd` binary exists and passes a lightweight smoke check (`--version`).
>>>>>>> mcoda/task/ops-01-us-01-t41

When install fails, output includes `[docdex] error code: <CODE>` and the process exits with a stable numeric exit code.

---

<<<<<<< HEAD
## Integrity verification (download-time)

Integrity verification is **mandatory** for `docdexd` downloads:

- The installer only installs a downloaded archive after it obtains an expected SHA-256 (manifest → `SHA256SUMS` → legacy `.sha256`) and verifies the downloaded bytes against it.
- If integrity metadata is missing/unusable, the installer fails closed with `DOCDEX_CHECKSUM_UNUSABLE` (exit `24`) and does not install a binary.
- If the SHA-256 does not match, the installer fails closed with `DOCDEX_INTEGRITY_MISMATCH` (exit `22`) and prints:
  - Which **asset** failed (archive filename),
  - The **verification method/source** used (`Source: manifest:<name>` or `Source: fallback`),
  - `Expected sha256` and `Actual sha256`,
  - Whether a fallback path was attempted.

Safety property (upgrade/repair): an existing `dist/<platformKey>/` is only removed **after** the archive is successfully downloaded and verified, so a verification failure does not replace an existing runnable `docdexd`.

---

## Configure sources and policy (safe defaults)

The installer’s integrity policy is “fail closed”. Configuration only affects *where* it fetches assets/metadata and *which* manifest/checksum filenames it tries.

Environment variables (all optional unless you’re installing from a fork/local copy):

- `DOCDEX_DOWNLOAD_REPO=<owner/repo>`: repo that hosts the GitHub Release assets to download (recommended for forks).
- `DOCDEX_DOWNLOAD_BASE=<full_base_url>`: full base URL for assets, including the repo slug and `releases/download`, e.g. `https://github.com/<owner/repo>/releases/download`. Use only for GitHub Enterprise/mirrors you trust.
- `DOCDEX_GITHUB_TOKEN` (or `GITHUB_TOKEN`): token for rate limiting/private releases.
- `DOCDEX_VERSION=<x.y.z>`: override the expected version/tag (`v<version>`).
- `DOCDEX_MANIFEST_NAME` / `DOCDEX_MANIFEST_NAMES` (comma-separated): override manifest candidate asset names.
- `DOCDEX_CHECKSUMS_NAME` / `DOCDEX_CHECKSUMS_NAMES` (comma-separated): override checksum candidate asset names.
- `DOCDEX_LIBC=gnu|musl|glibc`: override Linux libc detection (glibc is normalized to `gnu`).

Examples:

```bash
# Install from a fork that publishes releases
DOCDEX_DOWNLOAD_REPO=myfork/docdex npm i -g docdex

# Use custom/legacy manifest names (tried in order)
DOCDEX_MANIFEST_NAMES=docdex-release-manifest.json,docdexd-manifest.json,manifest.json npm i -g docdex

# Restrict checksum discovery to a single filename
DOCDEX_CHECKSUMS_NAME=SHA256SUMS npm i -g docdex
```
=======
## Integrity configuration (explicit)

The installer’s integrity behavior is explicitly configurable via environment variables (defaults are safe and deterministic).

Integrity metadata sources (order matters):
- `DOCDEX_INTEGRITY_METADATA_SOURCES=manifest,checksums,sidecar`
  - Allowed values: `manifest`, `checksums`, `sidecar`
  - Default: `manifest,checksums,sidecar` (manifest first, then checksum files, then legacy `<archive>.sha256`)

Missing/unavailable metadata policy:
- `DOCDEX_INTEGRITY_MISSING_POLICY=fallback|abort`
  - Default: `fallback` (try the next configured source if the current source cannot provide SHA-256 metadata)
  - `abort`: do not try later sources; fail deterministically if the current source cannot provide SHA-256 metadata

Related knobs (filename candidates):
- `DOCDEX_MANIFEST_NAMES` / `DOCDEX_MANIFEST_NAME` — override manifest asset filename candidates (comma-separated).
- `DOCDEX_CHECKSUMS_NAMES` / `DOCDEX_CHECKSUMS_NAME` — override checksum bundle filename candidates (comma-separated).

Examples:
- Require a manifest (no checksum/sidecar fallback): `DOCDEX_INTEGRITY_METADATA_SOURCES=manifest`
- Use checksums only (skip manifest): `DOCDEX_INTEGRITY_METADATA_SOURCES=checksums,sidecar`
- Abort on missing manifest rather than falling back: `DOCDEX_INTEGRITY_METADATA_SOURCES=manifest,checksums,sidecar DOCDEX_INTEGRITY_MISSING_POLICY=abort`
>>>>>>> mcoda/task/ops-01-us-04-t21

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
| `DOCDEX_INTEGRITY_SIGNATURE_MISSING` | 15 | Signature policy is `required` and the release did not include the expected `.sig` file for integrity metadata (manifest/checksums). | `true/false` (printed when available) | Retry; confirm you are using the intended repo/version; if you trust unsigned releases, set `DOCDEX_SIGNATURE_POLICY=optional` or `DOCDEX_SIGNATURE_POLICY=disabled`. | Enable release signing and upload the expected `.sig` assets (see `docs/contracts/release_integrity_signatures_v1.md`). |
| `DOCDEX_INTEGRITY_SIGNATURE_INVALID` | 16 | A `.sig` file was present but signature verification failed (possible tampering or wrong key). | `true/false` (printed when available) | Retry; bypass proxies/mirrors; treat as a tampering signal. If you control the releases, re-sign and re-upload integrity metadata; otherwise install from a trusted source/version. | Ensure the pinned public key and release signing private key match; regenerate and upload the `.sig` files alongside `SHA256SUMS`/manifest. |
| `DOCDEX_INTEGRITY_SIGNATURE_FETCH_FAILED` | 17 | Signature policy is `required` and fetching the `.sig` file failed (non-404). | `true/false` (printed when available) | Check network/proxy/firewall and retry; set `DOCDEX_GITHUB_TOKEN` if rate limited. | Ensure `.sig` assets are publicly readable and uploaded for the release; avoid transient upload race conditions. |
| `DOCDEX_ASSET_NO_MATCH` | 12 | A manifest was present, but it contains **no entry** for the detected `targetTriple`. Installer fails closed. | `false` | Install a version that supports your platform; or build from source. If installing from a fork, ensure you’re pointing at the correct repo. | Fix the release manifest to include the missing target triple and asset mapping for that release. |
| `DOCDEX_ASSET_MULTI_MATCH` | 13 | A manifest was present, but it contains **multiple entries** for the same `targetTriple`. Installer fails closed. | `false` | Install a different version; or build from source. | Deduplicate the manifest so each `targetTriple` resolves to exactly one asset. |
| `DOCDEX_DOWNLOAD_FAILED` | 20 | Download failed for the selected asset (non-404 HTTP status or transport failure). | `true/false` (printed when available) | Check network/proxy/firewall; retry; set `DOCDEX_GITHUB_TOKEN` if rate limited; verify `DOCDEX_DOWNLOAD_REPO` and (if set) `DOCDEX_DOWNLOAD_BASE`. | Ensure release assets are publicly readable (or document token usage for private releases). |
| `DOCDEX_ASSET_MISSING` | 21 | The expected asset returned HTTP 404 (release is missing the artifact or version is out of sync). | `true/false` (printed when available) | Confirm you’re installing a version whose GitHub Release contains the expected asset name; set `DOCDEX_DOWNLOAD_REPO` if using a fork; consider installing a different version. | Upload the missing release asset(s) and ensure npm version ↔ release tag are in sync. |
| `DOCDEX_INTEGRITY_MISMATCH` | 22 | SHA-256 verification failed for the downloaded archive. | `true/false` (printed when available) | Re-run install; bypass/disable proxies/caches; verify you are using the intended repo/version. Treat as a potential tampering signal; do not “work around” integrity failures by manual extraction. | Regenerate and re-upload correct checksums/manifest for the release; invalidate any cached/mirrored corrupted artifacts. |
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
| `DOCDEX_ARCHIVE_INVALID` | 23 | Archive extracted, but the expected `docdexd` binary was missing from the extracted directory. | `true/false` (printed when available) | Install a different version; or build from source. | Fix packaging (ensure tarball contains `docdexd`/`docdexd.exe` at the expected path). |
<<<<<<< HEAD
=======
| `DOCDEX_ARCHIVE_INVALID` | 23 | Archive extracted, but the expected `docdexd` binary was missing or did not report the expected version. | `true/false` (printed when available) | Install a different version; or build from source. | Fix packaging (ensure tarball contains `docdexd`/`docdexd.exe` at the expected path and the binary reports the correct version). |
>>>>>>> mcoda/task/ops-01-us-03-t44
=======
| `DOCDEX_ARCHIVE_INVALID` | 23 | Archive extracted, but the expected `docdexd` binary was missing or reports an unexpected version. | `true/false` (printed when available) | Install a different version; or build from source. | Fix packaging (ensure tarball contains `docdexd`/`docdexd.exe` at the expected path). |
>>>>>>> mcoda/task/ops-01-us-03-t06
=======
| `DOCDEX_ARCHIVE_INVALID` | 23 | Archive extracted, but the expected `docdexd` binary was missing or failed the executable smoke check (`--version`). | `true/false` (printed when available) | Install a different version; or build from source. | Fix packaging (ensure tarball contains `docdexd`/`docdexd.exe` at the expected path and runs). |
>>>>>>> mcoda/task/ops-01-us-01-t41
| `DOCDEX_CHECKSUM_UNUSABLE` | 24 | Installer could not obtain SHA-256 integrity metadata (no usable manifest + no usable checksum fallback). | `true` | Install a different version; or build from source. If installing from a fork, confirm the fork’s releases publish checksums/manifest. | Ensure the release includes `docdex-release-manifest.json` (with `integrity.sha256`) or `SHA256SUMS`/`SHA256SUMS.txt` with an entry for the asset; see `scripts/generate_release_manifest.cjs`. |
<<<<<<< HEAD
| `DOCDEX_REPLACE_FAILED` | 25 | Installer could not safely place the verified binary into the final install location (e.g., permission denied, or `docdexd.exe` locked/running on Windows). | `true/false` (printed when available) | Stop any running `docdexd` process and retry; ensure the install directory is writable (global installs may require elevation). On Windows, upgrading while the daemon is running commonly fails. | If packaging for a service/daemon, stop the service before replacing binaries; ensure installer uses staged install + atomic finalization (`docs/ops/installer_atomic_replace.md`). |
=======
| `DOCDEX_INSTALL_SWAP_FAILED` | 25 | Installer could not atomically swap the verified staged install into `dist/<platformKey>/` (permissions or a locked/running binary). | `true/false` (printed when available) | Stop any running `docdexd` processes, ensure the install directory is writable (global installs may require elevated permissions), then retry. | Avoid shipping release packaging that requires in-place mutation while the binary is running; document stop/restart procedures for upgrades if needed. |
>>>>>>> mcoda/task/ops-01-us-05-t07
=======
| `DOCDEX_CHECKSUM_UNUSABLE` | 24 | Installer could not obtain SHA-256 integrity metadata under the configured sources/policy. | `true/false` (printed when available) | Install a different version; or build from source. If installing from a fork, confirm the fork’s releases publish checksums/manifest. | Ensure the release includes `docdex-release-manifest.json` (with `integrity.sha256`) or `SHA256SUMS`/`SHA256SUMS.txt` with an entry for the asset; see `scripts/generate_release_manifest.cjs`. |
>>>>>>> mcoda/task/ops-01-us-04-t21

Notes:
- If you see an unknown `DOCDEX_*` code, treat it as a bug/regression; capture the full install log and open an issue with the code + platform details.

---

## Responding to verification failures (without unsafe workarounds)

### `DOCDEX_INTEGRITY_MISMATCH` (exit `22`)

What it means:
- The downloaded archive’s SHA-256 did not match the expected SHA-256 from the manifest/checksums source.

Example output excerpt:

```text
[docdex] install failed: Integrity check failed for docdexd-linux-x64-gnu.tar.gz: expected sha256=<expected> got sha256=<actual>
[docdex] error code: DOCDEX_INTEGRITY_MISMATCH
[docdex] Asset: docdexd-linux-x64-gnu.tar.gz
[docdex] Source: manifest:docdex-release-manifest.json
[docdex] Fallback attempted: false
```

What you should do:
- Retry once (transient caches/proxies can corrupt downloads).
- Verify you’re downloading from the intended repo/tag (`DOCDEX_DOWNLOAD_REPO`, `DOCDEX_VERSION`) and that any mirror/proxy is bypassed.
- If needed, manually verify the release assets locally; see `docs/contracts/release_manifest_schema_v1.md`.
- If it still fails, build from source (`cargo build --release --locked`).

What you should *not* do:
- Do not manually extract and run an unverified archive as a “workaround”.
- Do not try to bypass postinstall integrity checks; if you can’t get a verified release asset, prefer building from source.

### `DOCDEX_CHECKSUM_UNUSABLE` (exit `24`)

What it means:
- The installer could not obtain any expected SHA-256 for the selected archive (no usable manifest and no usable checksum fallback), so it will not install.

Example output excerpt:

```text
[docdex] install failed: Missing SHA-256 integrity metadata for docdexd-linux-x64-gnu.tar.gz (...)
[docdex] error code: DOCDEX_CHECKSUM_UNUSABLE
[docdex] Asset: docdexd-linux-x64-gnu.tar.gz
[docdex] Checksum candidates tried: SHA256SUMS, SHA256SUMS.txt
```

What you should do:
- Install a different version with published manifest/checksums, or build from source.
- If you control the release, ensure it publishes `docdex-release-manifest.json` (with `integrity.sha256`) or `SHA256SUMS` with an entry for the archive.

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
<<<<<<< HEAD
| `DOCDEX_REPLACE_FAILED` | 25 | Installer could not safely place the verified binary into the final install location (e.g., permission denied, or `docdexd.exe` locked/running on Windows). | `true/false` (printed when available) | Stop any running `docdexd` process and retry; ensure the install directory is writable (global installs may require elevation). On Windows, upgrading while the daemon is running commonly fails. | If packaging for a service/daemon, stop the service before replacing binaries; ensure installer uses staged install + atomic finalization (`docs/ops/installer_atomic_replace.md`). |
=======
| `DOCDEX_INSTALL_SWAP_FAILED` | 25 | Installer could not atomically swap the verified staged install into `dist/<platformKey>/` (permissions or a locked/running binary). | `true/false` (printed when available) | Stop any running `docdexd` processes, ensure the install directory is writable (global installs may require elevated permissions), then retry. | Avoid shipping release packaging that requires in-place mutation while the binary is running; document stop/restart procedures for upgrades if needed. |
>>>>>>> mcoda/task/ops-01-us-05-t07
