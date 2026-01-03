# Atomic (Staged) Installs and Rollback Guarantees

Scope: the npm installer/downloader (`npm/lib/install.js`) that installs a platform-specific `docdexd` binary from GitHub Releases into the npm package directory.

This doc describes what operators should expect during upgrades/downgrades and how failed/interrupted installs behave.

Assumptions (explicit):
- Install path is the npm wrapper (global or local): `npm i -g docdex` / `npm install docdex`.
- “Final location” means the wrapper’s runtime lookup path: `dist/<platformKey>/docdexd` (or `docdexd.exe` on Windows) inside the installed package.
- “Interrupted install” means the installer process receives a graceful signal (`SIGINT`/`SIGTERM`) or throws an error; `SIGKILL`/power loss cannot guarantee cleanup.

## Final install layout (what the wrapper runs)

Inside the installed npm package directory:
- Binary: `dist/<platformKey>/docdexd` (or `dist/<platformKey>/docdexd.exe`)
- Install metadata: `dist/<platformKey>/docdexd-install.json`

The wrapper (`npm/bin/docdex.js`) runs the binary from that `dist/<platformKey>/` directory.

## Staged install design (high level)

When an install/update is required (first install, upgrade, downgrade, repair), the installer uses a staged directory and an atomic swap:

1) **Download** the release archive to a temporary file:
   - `tmpFile = <tmpDir>/<archive>.<pid>.tgz` (default `tmpDir` is the OS temp directory)
2) **Verify** the downloaded archive SHA-256 (manifest preferred; checksums fallback).
3) **Extract to staging** (not the final location):
   - `stageDir = dist/<platformKey>.stage.<pid>.<timestamp>/`
4) **Validate staged payload**:
   - Ensure `docdexd` (or `docdexd.exe`) exists in `stageDir`
   - `chmod 0755` best-effort on Unix
5) **Write install metadata into the staged directory**:
   - `stageDir/docdexd-install.json` (written via atomic rename)
6) **Atomically swap into place** (same parent directory, so rename is atomic on typical filesystems):
   - If an existing `dist/<platformKey>/` exists, rename it to:
     - `backupDir = dist/<platformKey>.backup.<pid>.<timestamp>/`
   - Rename `stageDir` → `dist/<platformKey>/`
   - Remove `backupDir` (best-effort)
7) **Cleanup temporary artifacts** (best-effort):
   - Remove the downloaded `tmpFile`
   - Remove any leftover `stageDir` (on failures)

## Rollback guarantees

### A verified `docdexd` is only placed into the final location

`dist/<platformKey>/docdexd` is only created/updated after:
- the archive is downloaded and passes SHA-256 verification, and
- the archive is fully extracted into a staging directory, and
- the staged binary is present and metadata is written.

### Failed installs do not leave a “new but unverified” runnable binary

On failure before the final swap:
- The existing `dist/<platformKey>/` (if present) is not modified.
- Any staging directory is cleaned up (best-effort).
- The temporary downloaded archive file is cleaned up (best-effort).

### Failed installs do not leave the system in a worse state

If a previously working `dist/<platformKey>/docdexd` existed:
- The installer keeps it untouched until the staged install is ready to swap.
- If the final swap fails, the installer attempts to restore the backup directory back to `dist/<platformKey>/`.
- If an interruption happens during the swap window and a backup directory remains, the next installer run restores the newest backup automatically.

Operational note:
- Reinstalling replaces the on-disk binary; it does not restart a currently running `docdexd` process.

## Where to look when debugging

- Installer implementation: `npm/lib/install.js`
- Wrapper lookup path: `npm/bin/docdex.js`
- Upgrade/downgrade semantics: `docs/ops/installer_upgrade_downgrade.md`
- Error codes + remediation: `docs/ops/installer_error_codes.md`

