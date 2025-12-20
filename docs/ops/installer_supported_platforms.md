# Installer Supported Platforms, Manual Install, and Troubleshooting

Scope: the npm installer/downloader (`npm/lib/install.js`) and CLI wrapper (`npm/bin/docdex.js`) that resolve and run a platform-specific `docdexd` binary from GitHub Releases.

Source of truth for platform mapping + published support:
- `npm/lib/platform_matrix.js` (detected runtime → `platformKey` → Rust target triple → published?)
- `docs/contracts/installer_platform_mapping_v1.md` (canonical runtime → `platformKey`/`targetTriple` contract)
- `npm/lib/platform.js` (Linux libc detection + `DOCDEX_LIBC` override; `platformKey` resolution)
- `docs/contracts/release_manifest_schema_v1.md` (manifest + asset naming expectations)
- `docs/contracts/installer_error_contract_v1.md` and `docs/ops/installer_error_codes.md` (how failures are reported)
- `docs/ops/installer_upgrade_downgrade.md` (upgrade/downgrade guarantees, repair, install metadata)

Assumptions (explicit):
- You install via npm (`npm i -g docdex` or `npx docdex --version`) on Node.js >= 18.
- Release assets live under the repo in `DOCDEX_DOWNLOAD_REPO` (or `package.json.repository.url`) and a tag `vX.Y.Z` matching the npm package version.
- On Linux, the installer may need to choose between glibc (`gnu`) and musl (`musl`).

---

## Installation + postinstall asset selection

The npm tarball does **not** include platform-native `docdexd` binaries. During `npm install`, the postinstall step (`npm/lib/install.js`) downloads the correct daemon binary from GitHub Releases for the npm package version.

Resolution flow (deterministic):
1) Determine version: `DOCDEX_VERSION` if set, otherwise the npm package `package.json` version (release tag `vX.Y.Z`).
2) Determine repo: `DOCDEX_DOWNLOAD_REPO` if set, otherwise `package.json.repository.url` (parsed to `owner/repo`).
3) Detect runtime → `platformKey` + `targetTriple` (see next section).
4) Resolve a single asset for that `targetTriple`:
   - Prefer the release manifest (`docdex-release-manifest.json`), then fallback to deterministic asset naming.
5) Download `docdexd-<platformKey>.tar.gz` from the release tag `v<version>`, verify SHA-256, extract into `dist/<platformKey>/`, and record `docdexd-install.json`.

Installer output you can expect:
- `[docdex] Fetching docdexd-<platformKey>.tar.gz for <platformKey> (<targetTriple>) via <source>...`
- `[docdex] Installed binary to <.../dist/<platformKey>/docdexd>`
- On errors, additional lines include detected OS/arch, expected target triple, version, and asset naming pattern.

---

## Installation + postinstall asset selection

The npm tarball does **not** include platform-native `docdexd` binaries. During `npm install`, the postinstall step (`npm/lib/install.js`) downloads the correct daemon binary from GitHub Releases for the npm package version.

Resolution flow (deterministic):
1) Determine version: `DOCDEX_VERSION` if set, otherwise the npm package `package.json` version (release tag `vX.Y.Z`).
2) Determine repo: `DOCDEX_DOWNLOAD_REPO` if set, otherwise `package.json.repository.url` (parsed to `owner/repo`).
3) Detect runtime → `platformKey` + `targetTriple` (see next section).
4) Resolve a single asset for that `targetTriple`:
   - Prefer the release manifest (`docdex-release-manifest.json`), then fallback to deterministic asset naming.
5) Download `docdexd-<platformKey>.tar.gz` from the release tag `v<version>`, verify SHA-256, extract into `dist/<platformKey>/`, and record `docdexd-install.json`.

Installer output you can expect:
- `[docdex] Fetching docdexd-<platformKey>.tar.gz for <platformKey> (<targetTriple>) via <source>...`
- `[docdex] Installed binary to <.../dist/<platformKey>/docdexd>`
- On errors, additional lines include detected OS/arch, expected target triple, version, and asset naming pattern.

---

## Platform identifiers the installer uses

Inputs (Node runtime):
- OS: `process.platform` (`darwin`, `linux`, `win32`)
- CPU arch: `process.arch` (`x64`, `arm64`)
- Linux libc (only when `process.platform === "linux"`):
  - Override: `DOCDEX_LIBC=gnu|musl|glibc` (glibc is normalized to `gnu`)
  - Otherwise: detected by Node report + Alpine hints + ELF interpreter inspection (see `npm/lib/platform.js`)

Outputs:
- `platformKey` — the installer’s platform identifier (used in artifact names), e.g. `linux-x64-gnu`
- `targetTriple` — Rust target triple for the platform, e.g. `x86_64-unknown-linux-gnu`
- Offline diagnostics (no download): `docdex doctor` (or `docdex diagnostics`) prints detected OS/arch(/libc), whether the platform is supported, and the expected `targetTriple` + release asset naming pattern.

Release asset naming (expected):
- Release tag (version): `v<version>` (matches the npm package version unless `DOCDEX_VERSION` is set)
- Archive filename: `docdexd-<platformKey>.tar.gz`
- Canonical release asset id (tag + filename): `v<version>/docdexd-<platformKey>.tar.gz`
- Pattern string shown in errors: `docdexd-<platformKey>.tar.gz (e.g. docdexd-linux-x64-gnu.tar.gz)`

Note:
- The filename itself does not include the version; the version comes from the release tag.
- The `platformKey` maps 1:1 to the Rust `targetTriple` in the table below.

---

<<<<<<< HEAD
## Validate installation

After install, confirm the wrapper and daemon are in place:
- `docdex --version` (or `npx docdex --version`) should succeed.
- `docdex doctor` (or `docdex diagnostics`) prints detected OS/arch/libc, `platformKey`, and expected `targetTriple`.
- The daemon should exist and be executable at `dist/<platformKey>/docdexd` (or `docdexd.exe` on Windows).

Locate the install safely:
- Local dependency: `<repo>/node_modules/docdex/dist/<platformKey>/`
- Global install: `$(npm root -g)/docdex/dist/<platformKey>/`

Tip: `dist/<platformKey>/docdexd-install.json` records the resolved version, repo, target triple, and asset name for the last verified install.

---

## Validate installation

After install, confirm the wrapper and daemon are in place:
- `docdex --version` (or `npx docdex --version`) should succeed.
- `docdex doctor` (or `docdex diagnostics`) prints detected OS/arch/libc, `platformKey`, and expected `targetTriple`.
- The daemon should exist and be executable at `dist/<platformKey>/docdexd` (or `docdexd.exe` on Windows).

Locate the install safely:
- Local dependency: `<repo>/node_modules/docdex/dist/<platformKey>/`
- Global install: `$(npm root -g)/docdex/dist/<platformKey>/`

Tip: `dist/<platformKey>/docdexd-install.json` records the resolved version, repo, target triple, and asset name for the last verified install.
=======
## Version + asset resolution (postinstall)

- The npm package ships JS only; platform-native `docdexd` binaries are downloaded at install time.
- Version selection: `DOCDEX_VERSION` overrides; otherwise use `package.json` version (leading `v` is stripped).
- Release tag for assets: `v<version>` (example: npm `0.1.6` -> GitHub Release `v0.1.6`).
- Asset naming: `docdexd-<platformKey>.tar.gz` (or manifest-provided asset names when a release manifest is present).
- Download URL shape: `https://github.com/<repo>/releases/download/v<version>/docdexd-<platformKey>.tar.gz`.
- Deterministic mapping from runtime (`process.platform`/`process.arch` + Linux libc) to `platformKey` and `targetTriple` is defined in `npm/lib/platform_matrix.js` and summarized in the tables below.

---

## Version + asset resolution (postinstall)

- The npm package ships JS only; platform-native `docdexd` binaries are downloaded at install time.
- Version selection: `DOCDEX_VERSION` overrides; otherwise use `package.json` version (leading `v` is stripped).
- Release tag for assets: `v<version>` (example: npm `0.1.6` -> GitHub Release `v0.1.6`).
- Asset naming: `docdexd-<platformKey>.tar.gz` (or manifest-provided asset names when a release manifest is present).
- Download URL shape: `https://github.com/<repo>/releases/download/v<version>/docdexd-<platformKey>.tar.gz`.
- Deterministic mapping from runtime (`process.platform`/`process.arch` + Linux libc) to `platformKey` and `targetTriple` is defined in `npm/lib/platform_matrix.js` and summarized in the tables below.
>>>>>>> mcoda/task/ops-01-us-01-t33

---

## Supported platforms (published artifacts)

These are the entries marked `published: true` in `npm/lib/platform_matrix.js`. The installer treats only these as supported and will attempt to download/install `docdexd`.

| Detected runtime | Linux libc | `platformKey` | Rust `targetTriple` | Expected asset filename |
|---|---|---|---|---|
| `darwin/arm64` | n/a | `darwin-arm64` | `aarch64-apple-darwin` | `docdexd-darwin-arm64.tar.gz` |
| `darwin/x64` | n/a | `darwin-x64` | `x86_64-apple-darwin` | `docdexd-darwin-x64.tar.gz` |
| `linux/x64` | `gnu` | `linux-x64-gnu` | `x86_64-unknown-linux-gnu` | `docdexd-linux-x64-gnu.tar.gz` |
| `linux/x64` | `musl` | `linux-x64-musl` | `x86_64-unknown-linux-musl` | `docdexd-linux-x64-musl.tar.gz` |
| `linux/arm64` | `gnu` | `linux-arm64-gnu` | `aarch64-unknown-linux-gnu` | `docdexd-linux-arm64-gnu.tar.gz` |
| `win32/x64` | n/a | `win32-x64` | `x86_64-pc-windows-msvc` | `docdexd-win32-x64.tar.gz` |

---

## Unsupported platforms (installer exits without downloading)

Two common cases:

1) **Unknown runtime** (not in the matrix): e.g. `freebsd/x64`, `linux/ppc64`, etc.
2) **Recognized but not published yet** (in the matrix with `published: false`): the installer treats these as unsupported to prevent partial installs.

Recognized-but-unpublished as of `npm/lib/platform_matrix.js`:

| Detected runtime | Linux libc | `platformKey` | Rust `targetTriple` | Expected asset filename (if/when published) |
|---|---|---|---|---|
| `linux/arm64` | `musl` | `linux-arm64-musl` | `aarch64-unknown-linux-musl` | `docdexd-linux-arm64-musl.tar.gz` |
| `win32/arm64` | n/a | `win32-arm64` | `aarch64-pc-windows-msvc` | `docdexd-win32-arm64.tar.gz` |

If your platform is unsupported, you should see an error code `DOCDEX_UNSUPPORTED_PLATFORM` and a line like: `No download was attempted for this platform.`

---

## Deterministic mapping + failure modes (wrapper + installer)

The wrapper (`npm/bin/docdex.js`) and the installer (`npm/lib/install.js`) share the same platform policy (`npm/lib/platform.js`), so the mapping is deterministic.

1) Detect runtime → `platformKey` + `targetTriple`
   - Inputs: OS + arch (+ Linux libc `gnu`/`musl`, with `DOCDEX_LIBC` override).
   - If the runtime is unknown or mapped to a `published: false` entry, install exits with `DOCDEX_UNSUPPORTED_PLATFORM` and **no download is attempted**.
2) Resolve assets via manifest (if present)
   - Exactly one asset per `targetTriple` is required.
   - No entry for the detected triple → `DOCDEX_ASSET_NO_MATCH` (fail closed; no fallback).
   - Multiple entries for the detected triple → `DOCDEX_ASSET_MULTI_MATCH` (ambiguous; fail closed).
3) Fallback when no usable manifest exists
   - Uses the deterministic filename `docdexd-<platformKey>.tar.gz`.
   - If the asset is missing (404), the installer fails with `DOCDEX_ASSET_MISSING` and reports the detected platform, `platformKey`, `targetTriple`, and the expected asset naming pattern.

See also: `docs/ops/installer_error_codes.md` for exact error output fields.

---

## Manual build/run for unsupported platforms (no release artifact)

This bypasses the npm downloader and runs `docdexd` directly.

1) Install Rust (stable) and required build tooling for your OS.
2) Build from source:
   - `cargo build --release --locked`
3) Run the binary:
   - macOS/Linux: `./target/release/docdexd --help`
   - Windows (PowerShell): `.\target\release\docdexd.exe --help`

Operational note:
- Building from source is the safest workaround when your platform is unsupported because it does not depend on release assets or artifact naming conventions.

### Optional: manual install into the npm wrapper (supported platform + missing artifact)

If your platform is supported but the expected release artifact is missing (e.g. `DOCDEX_ASSET_MISSING` / version sync), you can keep using the `docdex` wrapper by placing a trusted `docdexd` binary where it expects it.

1) Build `docdexd` from source (same as above).
2) Determine your `platformKey`:
   - Prefer `docdex doctor` (offline), or use the support table above.
3) Copy the built binary into the installed package:
   - Target directory: `dist/<platformKey>/`
   - Expected filename: `docdexd` (or `docdexd.exe` on Windows)

Risk note:
- This bypasses the installer’s download + integrity verification flow; only do this with binaries you built yourself (or otherwise fully trust). Prefer fixing the release assets for long-term correctness.
- Do **not** use this as a workaround for `DOCDEX_INTEGRITY_MISMATCH`; an integrity mismatch means a downloaded archive did not match the published SHA-256 (potential cache corruption or tampering). Prefer a clean reinstall (without proxies/caches) or building from source.

---

## Troubleshooting: “unsupported platform” vs “missing artifact/version sync issue”

### A) Unsupported platform

What it means:
- Your detected `process.platform`/`process.arch` (+ `DOCDEX_LIBC` on Linux) does not map to a published `platformKey`.

What to expect:
- Error code: `DOCDEX_UNSUPPORTED_PLATFORM`
- Message includes detected OS/arch (and libc on Linux).
- **No download/install is attempted** (by design).

What to do:
- Use a supported platform from the table above, or build from source (previous section).
- On Linux, if libc detection is ambiguous, retry with an explicit override:
  - `DOCDEX_LIBC=gnu npm i -g docdex`
  - `DOCDEX_LIBC=musl npm i -g docdex`

### B) Supported platform, but artifact is missing (release/version sync issue)

What it means:
- Your platform is supported, but the expected release assets for your version/tag are missing or inconsistent.

Common fatal error codes:
- `DOCDEX_ASSET_MISSING` (404 downloading the expected archive)
- `DOCDEX_ASSET_NO_MATCH` (a manifest exists but has no entry for your `targetTriple`; fails closed)

What to expect:
- Message includes **expected target triple** and **asset naming pattern** (so you can verify the release).
- Depending on failure point, the installer may have fetched metadata (manifest/checksums) but should not install a binary unless the archive was downloaded and (under the default `DOCDEX_INTEGRITY_POLICY=required`) verified.

How to verify release assets (publisher/operator checklist):
1) Confirm the repo slug and version the installer is using:
   - `echo $DOCDEX_DOWNLOAD_REPO` (if set)
   - `echo $DOCDEX_VERSION` (if set; otherwise uses the npm package version)
2) If you have a local install, note the detected daemon version:
   - Read `dist/<platformKey>/docdexd-install.json` (field `version`) or run `docdexd --version`.
3) Confirm the GitHub Release tag exists for `v<version>` and contains:
   - `docdex-release-manifest.json` and `docdex-release-manifest.json.sha256` (preferred), or
   - `SHA256SUMS` / `SHA256SUMS.txt` (fallback)
4) Confirm the expected asset name is present:
   - `docdexd-<platformKey>.tar.gz` (example in the support table above)
5) If using a manifest, confirm it includes an entry for your expected Rust `targetTriple` and that the entry’s `asset.name` matches the asset filename.

See also:
- `docs/contracts/release_manifest_schema_v1.md`
- `docs/ops/installer_error_codes.md`

---

### C) Network/proxy download failures

What it means:
- The installer could not fetch a manifest, checksum, or archive (`DOCDEX_DOWNLOAD_FAILED`, `DOCDEX_MANIFEST_FETCH_FAILED`, `DOCDEX_CHECKSUM_FETCH_FAILED`).

What to do:
- Verify you can reach GitHub Releases from this environment (corporate proxies/firewalls often block direct HTTPS downloads).
- If rate limited, set `DOCDEX_GITHUB_TOKEN` (or `GITHUB_TOKEN`) and retry.
- If you use a mirror, set `DOCDEX_DOWNLOAD_BASE` to the releases base URL for your mirror.

### D) Permissions / filesystem errors

What it means:
- The install could not write to the package directory or temp dir (common for global installs on locked-down systems).

What to do:
- Prefer installing with a user-writable Node/npm prefix (or a Node version manager) instead of running as root.
- As a low-risk check, install locally in a project (`npm install docdex`) to confirm the environment can write `node_modules/`.

### E) Checksum/integrity failures

What it means:
- SHA-256 verification failed (`DOCDEX_INTEGRITY_MISMATCH`) or no usable checksum metadata exists (`DOCDEX_CHECKSUM_UNUSABLE`).

What to do:
- Re-run install to rule out transient proxy/cache corruption.
- Treat persistent integrity failures as a potential tampering signal; do not manually extract unverified archives.
- If you control the release, ensure the manifest or `SHA256SUMS` includes a checksum entry for the expected asset.

---

### C) Network/proxy download failures

What it means:
- The installer could not fetch a manifest, checksum, or archive (`DOCDEX_DOWNLOAD_FAILED`, `DOCDEX_MANIFEST_FETCH_FAILED`, `DOCDEX_CHECKSUM_FETCH_FAILED`).

What to do:
- Verify you can reach GitHub Releases from this environment (corporate proxies/firewalls often block direct HTTPS downloads).
- If rate limited, set `DOCDEX_GITHUB_TOKEN` (or `GITHUB_TOKEN`) and retry.
- If you use a mirror, set `DOCDEX_DOWNLOAD_BASE` to the releases base URL for your mirror.

### D) Permissions / filesystem errors

What it means:
- The install could not write to the package directory or temp dir (common for global installs on locked-down systems).

What to do:
- Prefer installing with a user-writable Node/npm prefix (or a Node version manager) instead of running as root.
- As a low-risk check, install locally in a project (`npm install docdex`) to confirm the environment can write `node_modules/`.

### E) Checksum/integrity failures

What it means:
- SHA-256 verification failed (`DOCDEX_INTEGRITY_MISMATCH`) or no usable checksum metadata exists (`DOCDEX_CHECKSUM_UNUSABLE`).

What to do:
- Re-run install to rule out transient proxy/cache corruption.
- Treat persistent integrity failures as a potential tampering signal; do not manually extract unverified archives.
- If you control the release, ensure the manifest or `SHA256SUMS` includes a checksum entry for the expected asset.

---

## Recover from partial/failed installs (safe cleanup)

The wrapper looks for the binary under the installed package at:
- `dist/<platformKey>/docdexd` (or `docdexd.exe` on Windows) — see `npm/bin/docdex.js`

Staged/atomic install behavior (what “partial install” means here):
- The installer extracts into `dist/<platformKey>.stage.*` and only swaps into `dist/<platformKey>/` after verification + staging complete.
- If a previous install existed, the installer may temporarily rename it to `dist/<platformKey>.backup.*` during the final swap.
- The installer cleans up `.stage.*` and `.backup.*` best-effort; if an interruption leaves a `.backup.*` behind, the next installer run restores the newest backup automatically.

See also:
- Atomic staged installs + rollback guarantees: `docs/ops/installer_atomic_install_and_rollback.md`
- QA checklist for interrupted installs: `docs/ops/installer_atomic_install_qa_checklist.md`

Low-risk recovery steps:
1) Remove the installed package (global or local), then reinstall:
   - Global: `npm uninstall -g docdex && npm i -g docdex`
   - Local: `npm uninstall docdex && npm install` (or your lockfile-friendly install command, e.g. `npm ci`)
2) If you suspect a partial extraction, delete only the platform directory and reinstall:
   - Delete: `.../docdex/dist/<platformKey>/`
   - Then re-run: `npm i -g docdex` (or `npm i docdex`)

Risk note:
- If you see `DOCDEX_INTEGRITY_MISMATCH`, treat it as a potential tampering/caching issue and avoid “working around” it by manually extracting an unverified download. Prefer a clean reinstall and/or building from source.
- If you delete `dist/<platformKey>/` manually, double-check you are removing a path under the installed `docdex` package directory (to avoid deleting unrelated files).
