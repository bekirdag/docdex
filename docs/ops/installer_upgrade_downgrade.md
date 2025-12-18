# Installer Upgrade/Downgrade Guarantees, Repair, and Troubleshooting

Scope: the npm installer/downloader (`npm/lib/install.js`) and CLI wrapper (`npm/bin/docdex.js`) that install and run a platform-specific `docdexd` binary from GitHub Releases.

Assumptions (explicit):
- You install via npm (`npm i -g docdex` or `npx docdex --version`) on Node.js >= 18.
- “Expected version” is the npm package version (or `DOCDEX_VERSION` if set).
- The installer uses the published release manifest/checksums contracts when it needs to fetch an archive; see `docs/contracts/release_manifest_schema_v1.md`.

## Deterministic installer outcomes

The installer converges to a single final state: the installed `docdexd` under `dist/<platformKey>/` matches the expected version for this npm package install.

Outcomes (stable strings):

| Outcome | Meaning | Deterministic trigger (local state) |
|---|---|---|
| `no-op` | Nothing changes; no network/download occurs. | A previous verified install metadata file exists and its recorded `binary.sha256` matches the currently installed binary for the expected version. |
| `update` | Install/reinstall the expected version. (Includes first install, upgrade, downgrade.) | No binary exists, or a valid install metadata file indicates a different `version` than expected. |
| `repair` | Reinstall the expected version due to a local integrity mismatch. | Metadata exists for the expected version, but the current binary’s SHA-256 does not match the recorded `binary.sha256`. |
| `reinstall_unknown` | Reinstall because current state can’t be verified deterministically. | Binary exists but install metadata is missing/unreadable/invalid, the metadata `platformKey` mismatches the detected platform, or the binary hash cannot be computed/read. |

The installer logs the outcome as a single line:
- `[docdex] Install outcome: <outcome>`

### No-redownload and caching rules (important for idempotency)

- For `no-op`, the installer does **not** fetch the release manifest, does **not** download any archive, and does **not** touch `dist/<platformKey>/` other than reading the binary/metadata to verify integrity.
- For `update` / `repair` / `reinstall_unknown`, the installer resolves an archive from the expected GitHub Release, downloads it to an OS temp file, verifies integrity, then replaces `dist/<platformKey>/` and writes fresh install metadata.
- The installer does **not** keep a persistent “binary download cache” of archives across runs. The only persistent optimization is the on-disk installed binary + `docdexd-install.json` metadata, which enables `no-op`.

## Upgrade vs downgrade

The installer does not treat “upgrade” and “downgrade” differently. It always targets the expected version for the current npm package install:
- If the installed version differs, the installer replaces `dist/<platformKey>/` so the final state equals the expected version.
- If the expected version is already installed and verified, the installer is a `no-op`.

This makes repeated installs idempotent: once the system is in the verified `no-op` state for a given version/platform, running the installer repeatedly converges without additional downloads and leaves the installed binary + metadata unchanged.

## Integrity verification and repair behavior

There are two relevant integrity checks:

1) **Remote archive integrity (when installing)**  
   When the installer needs to install (`update`, `repair`, `reinstall_unknown`), it resolves a single release asset and its SHA-256 via:
   - Release manifest (preferred), then
   - `SHA256SUMS`/`SHA256SUMS.txt`, then
   - legacy `<archive>.sha256` sidecar.

   The downloaded archive is verified against the expected SHA-256. If integrity metadata cannot be obtained, installation fails closed with `DOCDEX_CHECKSUM_UNUSABLE`. If verification fails, installation fails closed with:
   - Error code: `DOCDEX_INTEGRITY_MISMATCH` (see `docs/ops/installer_error_codes.md`)
   - Safety property: the existing `dist/<platformKey>/` is only removed after the archive is successfully fetched and verified.

2) **Local binary integrity (no-op vs repair)**  
   For a `no-op`, the installer verifies the existing binary by hashing it and comparing to the recorded `binary.sha256` from the last successful, verified install.
   - If this local check fails, the outcome becomes `repair` and the installer reinstalls a verified binary.
   - Note: `no-op` integrity verification is intentionally local-first and does not require network access; it verifies the binary has not changed since the last verified install, not “re-checking” the release every time.

## Install metadata: what it is and where it lives

The installer writes a small JSON metadata file next to the installed binary:
- `dist/<platformKey>/docdexd-install.json`

This metadata enables deterministic `no-op` and `repair` decisions without downloading a new asset.

### Locate it (safe, cross-platform)

Local install (project dependency):
- Package root: `<repo>/node_modules/docdex/`
- Metadata: `<repo>/node_modules/docdex/dist/<platformKey>/docdexd-install.json`

Global install:
- Find global `node_modules`: `npm root -g`
- Metadata: `$(npm root -g)/docdex/dist/<platformKey>/docdexd-install.json`

OS notes (common defaults; prefer `npm root -g` over guessing):
- macOS/Linux: often under `/usr/local/lib/node_modules/docdex/...` or `~/.nvm/.../lib/node_modules/docdex/...`
- Windows: often under `%APPDATA%\\npm\\node_modules\\docdex\\...`

## Troubleshooting stale/corrupt daemon installs (risk-mitigated)

### 1) Confirm which `docdexd` you are running

- Platform diagnostics (offline): `docdex doctor`
- Wrapper expects the binary at: `dist/<platformKey>/docdexd` (or `docdexd.exe` on Windows).

If you upgraded/downgraded but the daemon still behaves like an older build, you may be running an already-started process.

### 2) Restart the daemon process

Reinstalling updates the on-disk binary, but it does not replace a currently running `docdexd` process.

Low-risk approach:
- Stop the process you started (e.g., terminate the terminal/service that launched `docdexd serve`), then start it again.

### 2.5) Why does install keep downloading (no `no-op`)?

Common deterministic causes:
- `reinstall_unknown`: install metadata is missing/unreadable/invalid, or the metadata `platformKey` does not match the detected platform.
- `update`: the metadata `version` differs from the expected npm package version.
- `repair`: the binary hash does not match the recorded `binary.sha256` (possible tampering, partial write, or disk corruption).

Low-risk checks:
- Confirm the metadata exists and is valid JSON at `dist/<platformKey>/docdexd-install.json`.
- Confirm you are not installing with `npm install --ignore-scripts` (that skips the postinstall downloader and leaves you without a verified `docdexd`).
- If you are in a read-only filesystem or constrained environment, ensure the `docdex` package directory is writable so metadata can be written atomically.

### 3) If installs keep “repairing” or look inconsistent, reset only installer state

Safe reset options (in increasing destructiveness):

1) Delete only install metadata (forces `reinstall_unknown` next run):
   - Remove: `dist/<platformKey>/docdexd-install.json`
2) Delete the platform install directory (forces a clean reinstall for that platform):
   - Remove: `dist/<platformKey>/`
3) Uninstall and reinstall the npm package:
   - Global: `npm uninstall -g docdex && npm i -g docdex`
   - Local: `npm uninstall docdex && npm install` (or your lockfile-friendly equivalent, e.g. `npm ci`)

Risk notes:
- Double-check you’re deleting paths under the installed `docdex` package directory (avoid deleting unrelated files).
- If you see `DOCDEX_INTEGRITY_MISMATCH`, treat it as a potential tampering/proxy/cache corruption signal; avoid manual extraction of unverified downloads and prefer a clean reinstall or building from source.

### 4) If the daemon runs but indexing/search looks wrong

This is usually a repo state issue, not an installer issue:
- Rebuild the index: `docdexd index --repo <path>`
- If you intentionally want a clean state, delete only the repo’s index directory: `<repo>/.docdex/index` (this forces a full reindex next run).

## See also

- Installer supported platforms + safe cleanup: `docs/ops/installer_supported_platforms.md`
- Installer error codes + remediation: `docs/ops/installer_error_codes.md`
- Release manifest contract: `docs/contracts/release_manifest_schema_v1.md`
- Installer error contract: `docs/contracts/installer_error_contract_v1.md`
