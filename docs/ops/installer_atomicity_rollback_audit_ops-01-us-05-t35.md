# Installer Atomicity/Rollback/Cleanup Audit (ops-01-us-05-t35)

Task: `ops-01-us-05-t35` (Epic `ops-01`, Story `ops-01-us-05`)

## Scope + assumptions (explicit)

- Scope is the npm postinstall installer/downloader (`npm/lib/install.js`) and CLI wrapper (`npm/bin/docdex.js`) that install and run a platform-specific `docdexd` binary from GitHub Releases.
- “Install/upgrade” means running `node npm/lib/install.js` via npm `postinstall` (and optionally re-running the same installer to “repair”).
- `docdexd` is not managed as a system service by this installer. If a user has a running `docdexd serve` process, reinstalling updates the on-disk binary but does not stop/restart the running process (see `docs/ops/installer_upgrade_downgrade.md`).

Install location (dist base directory):
- macOS: `~/Library/Application Support/docdex/dist/<platformKey>/`
- Linux: `$XDG_DATA_HOME/docdex/dist/<platformKey>/` (fallback `~/.local/share/docdex/dist/<platformKey>/`)
- Windows: `%LOCALAPPDATA%\\docdex\\dist\\<platformKey>\\`
- Override with `DOCDEX_DIST_DIR`. In this doc, `dist/<platformKey>` refers to `${DOCDEX_DIST_DIR:-<docdex data dir>/dist}/<platformKey>`.

## Supported platforms covered by this audit

Per `docs/ops/installer_supported_platforms.md` and `npm/lib/platform_matrix.js` (published targets):

- macOS: `darwin-arm64`, `darwin-x64`
- Linux: `linux-x64-gnu`, `linux-x64-musl`, `linux-arm64-gnu`
- Windows: `win32-x64`

Notes:
- Linux chooses `gnu` vs `musl` via runtime detection + `DOCDEX_LIBC` override (`npm/lib/platform.js`).
- The wrapper expects `docdexd` on POSIX and `docdexd.exe` on Windows (`npm/bin/docdex.js`).

### Per-platform install targets (current contract)

All platforms use the same installer flow; what varies is the resolved `platformKey`, Rust target triple, and the expected binary filename.

| OS | `platformKey` | Rust `targetTriple` | Release asset (archive) | Expected binary | Final location (dist base) |
|---|---|---|---|---|---|
| macOS (arm64) | `darwin-arm64` | `aarch64-apple-darwin` | `docdexd-darwin-arm64.tar.gz` | `docdexd` | `dist/darwin-arm64/` |
| macOS (x64) | `darwin-x64` | `x86_64-apple-darwin` | `docdexd-darwin-x64.tar.gz` | `docdexd` | `dist/darwin-x64/` |
| Linux (x64, glibc) | `linux-x64-gnu` | `x86_64-unknown-linux-gnu` | `docdexd-linux-x64-gnu.tar.gz` | `docdexd` | `dist/linux-x64-gnu/` |
| Linux (x64, musl) | `linux-x64-musl` | `x86_64-unknown-linux-musl` | `docdexd-linux-x64-musl.tar.gz` | `docdexd` | `dist/linux-x64-musl/` |
| Linux (arm64, glibc) | `linux-arm64-gnu` | `aarch64-unknown-linux-gnu` | `docdexd-linux-arm64-gnu.tar.gz` | `docdexd` | `dist/linux-arm64-gnu/` |
| Windows (x64) | `win32-x64` | `x86_64-pc-windows-msvc` | `docdexd-win32-x64.tar.gz` | `docdexd.exe` | `dist/win32-x64/` |

## Current end-to-end flow (download → verify → replace → run)

The installer logic is shared across platforms; the only platform-specific differences are platform detection, target triple selection, and the expected binary filename.

Important: the current npm installer does **not** manage `docdexd` as a system service. There is no stop/restart/start step for any currently supported platform.

### 0) Resolve platform + local state

1. Detect `platformKey` and `targetTriple` (`npm/lib/platform.js` + matrix).
2. Compute `distDir`: `${DOCDEX_DIST_DIR:-<docdex data dir>/dist}/<platformKey>/`.
3. Determine local outcome (`npm/lib/install.js:determineLocalInstallerOutcome`):
   - `no-op`: if `dist/<platformKey>/docdexd*` exists AND `dist/<platformKey>/docdexd-install.json` is valid AND binary SHA matches metadata.
   - otherwise: `update`, `repair`, or `reinstall_unknown` (all cause a download/install attempt).

### 1) Resolve the release asset + checksum material (manifest → fallback)

The installer resolves one deterministic archive name + (when available) an expected SHA-256 (see `docs/contracts/release_manifest_schema_v1.md` and `docs/ops/installer_error_codes.md`):

1. Prefer release manifest `docdex-release-manifest.json` (plus legacy candidates) for:
   - archive asset name (`docdexd-<platformKey>.tar.gz`)
   - expected archive SHA-256
2. If no usable manifest is available, fall back to:
   - deterministic archive name `docdexd-<platformKey>.tar.gz`
   - checksum material from `SHA256SUMS` / `SHA256SUMS.txt`, or legacy `<archive>.sha256`

If a manifest exists but does not support the target triple (or is ambiguous), the installer fails closed (no fallback).

### 2) Download the archive to a temp file

1. Build the download URL: `.../releases/download/v<version>/<archive>`.
2. Download to a temp file in the OS temp directory:
   - `<os.tmpdir()>/<archive>.<pid>.tgz`

### 3) Verify archive integrity (when expected SHA-256 exists)

- Hash the downloaded archive and compare to the expected SHA-256.
- On mismatch, abort with `DOCDEX_INTEGRITY_MISMATCH`.

### 4) Replace the installed binary (current behavior)

After the archive is downloaded + verified, the installer:

1. Deletes the entire `dist/<platformKey>/` directory recursively.
2. Extracts the tarball into `dist/<platformKey>/`.
3. Verifies `dist/<platformKey>/docdexd*` exists.
4. `chmod 755` best-effort (POSIX).
5. Computes the installed binary SHA-256 and writes `dist/<platformKey>/docdexd-install.json` via an atomic rename.

### 4b) Stop daemon / start daemon (not implemented)

The current workflow does not stop or restart a running `docdexd serve` process. It only updates the on-disk binary under `dist/<platformKey>/`. Any already-running process continues to run until it is restarted by the operator.

### 5) Run the installed binary (wrapper behavior)

The wrapper (`npm/bin/docdex.js`) does not perform any integrity/metadata checks at runtime:

1. Detect `platformKey`.
2. Require existence of `dist/<platformKey>/docdexd*`.
3. `spawn(binaryPath, argv)` and exit with the child exit code.

## Atomicity/rollback/cleanup gap list (against acceptance criteria)

Acceptance criteria (story `ops-01-us-05`):

1) Verified `docdexd` is only put into the final location after verification completes.  
2) Interrupted/failed installs clean up temporary artifacts and do not leave a partially downloaded binary runnable.  
3) If an old working `docdexd` existed, a failed install does not leave the system worse off (old remains runnable).  
4) Reinstall after interrupted install succeeds without manual cleanup.

### A) Non-atomic replacement can delete a working install (high severity)

Current behavior deletes `dist/<platformKey>/` before extraction completes.

Failure modes that can leave the system worse off:

- Disk full / permission errors / tar extraction errors after the recursive delete.
- Power loss / process kill after delete but before extraction (or before the binary exists).

Impact:
- Violates (3): old binary can be removed even though the new install did not complete.
- Violates (4) in practice for end users: while a reinstall may succeed later, the system is still left broken until rerun.

### B) “Final location” can contain unverified/partial content (high severity)

The installer extracts directly into `dist/<platformKey>/` (the final location), and the wrapper runs the binary solely based on existence.

Failure/interrupt modes:

- Process killed during extraction could leave `dist/<platformKey>/docdexd*` present but incomplete/corrupt.
- Metadata (`docdexd-install.json`) may be missing or invalid, but the wrapper will still run the binary if it exists.

Impact:
- Violates (1): binary can appear in the final path before the “install verification” phase (presence checks + metadata write) finishes.
- Violates (2): a partially extracted binary can be runnable via `docdex` even though install did not complete.

### C) Temporary artifacts are best-effort cleaned, but not crash-safe (medium severity)

The archive is downloaded into the OS temp directory and removed in a `finally` block.

Failure/interrupt modes:

- `SIGKILL`/power loss leaves `<archive>.<pid>.tgz` behind.

Impact:
- Typically does not violate (2) because a `.tgz` is not runnable, but it does violate the “cleaned up” intent and can accumulate in shared temp dirs.
- Does not block (4) because filenames are pid-scoped and do not collide.

### D) No “interrupted install recovery” sweep (medium severity)

There is no explicit recovery logic for interrupted/partial installs beyond the next run’s normal flow.

Missing behaviors that would reduce user risk:

- Detect and remove stale staging directories (if introduced) and stale temp artifacts under the package.
- Detect “half-swapped” installs (e.g., backup exists, final missing) and restore the last known-good binary automatically.

### E) No daemon restart coordination (low severity, but operator-impacting)

Because `docdexd` is not installed as a managed service by this workflow, the installer cannot ensure that an existing running process is restarted onto the newly installed binary.

Impact:
- Does not directly violate the story acceptance criteria (which are about rollback/cleanup and keeping the system no-worse-off), but it can surprise users who expect an upgrade to affect an already-running daemon without a restart.

## Recommended staged/atomic approach (aligned to acceptance)

This section describes a staged install design that keeps behavior backward-compatible (same final on-disk location and wrapper interface) while meeting the acceptance criteria.

### Goals

- Never remove/overwrite the existing `dist/<platformKey>/docdexd*` until the new binary is fully downloaded, verified, extracted, and post-extract validated.
- Ensure `dist/<platformKey>/docdexd*` only ever points to a “complete” binary (no partial extraction in place).
- Ensure interruptions leave behind only non-runnable staging artifacts (and that subsequent installs clean them up).

### Proposed staged install algorithm (directory-level promotion)

Definitions:

- Final location (current contract): `dist/<platformKey>/`
- Staging base: `dist/.staging/`
- Backup base: `dist/.backup/`

Algorithm:

1) Create a unique staging directory on the same filesystem as `dist/`, e.g.:
   - `dist/.staging/<platformKey>.<pid>.<timestamp>/`
2) Download the archive into the staging directory (or a package-local temp dir), then verify SHA-256.
   - Example: `dist/.staging/<platformKey>.<pid>.<timestamp>/<archive>.tgz`
   - Rationale: makes cleanup/recovery deterministic on subsequent installs (no reliance on shared OS temp dirs).
3) Extract into the staging directory (not the final directory).
4) Validate staging contents:
   - Ensure `docdexd`/`docdexd.exe` exists in staging.
   - Best-effort `chmod 755` on POSIX.
   - (Optional, higher assurance) Run `docdexd --version` from staging and require success.
5) Write `docdexd-install.json` into the staging directory (atomic rename is already implemented for JSON writes).
6) Promote staging → final via an atomic directory swap:
   - If `dist/<platformKey>/` exists, rename it to `dist/.backup/<platformKey>.<pid>.<timestamp>/`.
   - Rename the staging directory to `dist/<platformKey>/`.
   - After promotion succeeds, delete the backup directory (best-effort).
7) Cleanup:
   - Always delete the downloaded archive (from staging/package-local temp) (best-effort).
   - Always delete any leftover staging directories for this platform (best-effort).

Why this aligns to acceptance:

- (1) The final location is only populated after download + verification + extraction + validation completes.
- (2) Interrupted installs can only leave behind staging dirs and temp archives, neither of which the wrapper runs.
- (3) The old install remains intact until promotion succeeds; on any failure before promotion, nothing changes.
- (4) If an install is interrupted after the old dir was renamed to backup but before the new dir is promoted, the next installer run can restore the backup automatically (see next section).

Daemon stop/start (if/when added in the future):

- Do not stop a running daemon until the new binary is fully downloaded and verified (to avoid turning transient failures into downtime).
- If a service manager integration is added later, restart should happen only after a successful promotion (directory swap), and failures should keep the previous binary available for immediate restart/rollback.

### Required “recovery sweep” at installer start

To satisfy (4) and harden (3) in the presence of process kills, add an early recovery step before any download:

- If `dist/<platformKey>/` is missing but `dist/.backup/<platformKey>.*` exists:
  - Restore the most recent backup back to `dist/<platformKey>/` (best-effort), then continue normal installer flow.
- Remove stale `dist/.staging/<platformKey>.*` directories (best-effort).
- Remove any stale `.tgz` files left under `dist/.staging/` (best-effort).
- Remove stale `dist/.backup/<platformKey>.*` directories after a successful verified install (best-effort, keep at most one most-recent backup if operator debugging is desired).

### Windows-specific risk note

Windows commonly prevents renaming/removing executables while they are running. A staged install should treat this as a “fail safe” condition:

- If renaming `dist/<platformKey>/` to a backup fails due to file locks, the installer should abort without changing the existing installation (still satisfies (3)).
- Fully atomic file replacement on Windows may require platform-specific primitives (e.g., Win32 `ReplaceFile`) if directory swapping is not reliable; if those are not available, directory swap + recovery sweep is the safest attainable behavior in pure Node.js.

### Optional hardening (wrapper/runtime)

To reduce the chance that users run an incomplete/unknown binary, consider tightening the wrapper behavior:

- Require both:
  - `dist/<platformKey>/docdexd*` exists, and
  - `dist/<platformKey>/docdexd-install.json` exists and is valid, and
  - the binary SHA-256 matches the metadata’s `binary.sha256`.

This is offline and deterministic (no network), and it makes “partial install artifacts” non-runnable even if they somehow land in `dist/<platformKey>/`.

## Actionable implementation checklist (next PR)

- `npm/lib/install.js`
  - Replace `rm(distDir)` + `extractTarball(tmpFile, distDir)` with staging extraction + promote + recovery sweep.
  - Ensure cleanup removes staging dirs + tmp archives on both success and failure.
- `npm/bin/docdex.js` (optional)
  - Refuse to execute binaries lacking valid metadata (and/or mismatching metadata hash).
- Tests (`npm/test/*`)
  - Add a failure injection test where extraction throws and assert the old binary remains present and runnable.
  - Add an interrupted-promotion recovery test (simulate existing backup + missing final) and assert the installer restores the backup without manual cleanup.
