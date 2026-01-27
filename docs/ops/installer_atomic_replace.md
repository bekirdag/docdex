# Atomic Replace Semantics (docdexd installer)

Task context: ops-01-us-05-t22 (interrupted/partial installs roll back cleanly).

Scope: npm installer/downloader (`npm/lib/install.js`) that installs a platform-specific `docdexd` binary from GitHub Releases into the dist base directory (`dist/<platformKey>/` relative to that base).

Assumptions (explicit):
- The installed artifact is a single binary (`docdexd` or `docdexd.exe`) packaged as a `.tar.gz` containing only that binary (see `.github/workflows/release.yml`).
- Node.js `>= 18`.
- The installer is not allowed to elevate privileges; it runs with the permissions of the current npm install.

## Install location (dist base directory)

The installer writes the daemon under the Docdex data directory (not inside the npm package):
- macOS: `~/Library/Application Support/docdex/dist/<platformKey>/`
- Linux: `$XDG_DATA_HOME/docdex/dist/<platformKey>/` (fallback `~/.local/share/docdex/dist/<platformKey>/`)
- Windows: `%LOCALAPPDATA%\\docdex\\dist\\<platformKey>\\`

Override with `DOCDEX_DIST_DIR` to point at the `dist` base directory. In this doc, `dist/<platformKey>` refers to `${DOCDEX_DIST_DIR:-<docdex data dir>/dist}/<platformKey>`.

## Why “atomic replace” matters

We want a safe upgrade primitive with these properties:
- A verified `docdexd` is only placed at the final path after verification completes.
- A failed or interrupted install never leaves a runnable *partial* binary at the final path.
- If a previous `docdexd` existed, a failed install does not leave the system in a worse state (the old daemon remains runnable).
- A subsequent reinstall after interruption succeeds without manual cleanup.

## Cross-platform primitives and constraints

### POSIX (macOS/Linux)

Useful primitive:
- `rename(newPath, finalPath)` on the **same filesystem** is atomic and (on POSIX) replaces the destination if it already exists.

Important behaviors:
- Replacing a running executable is generally allowed: the running process keeps the old inode; new launches use the new path contents.
- Deleting/renaming the directory that contains the binary is riskier than replacing the file entry: directory operations can fail if files are open and can introduce larger “missing binary” windows.

Implication:
- Prefer **file-level atomic replace** (`rename` to the final filename) rather than deleting the whole install directory.

### Windows

Hard constraint:
- A running `.exe` is typically locked. Attempts to delete or rename `docdexd.exe` while it’s running commonly fail with `EPERM`/`EACCES`.

Missing primitive (from Node core):
- Node’s `fs.rename` cannot do a single-call “replace existing + create backup” equivalent to `ReplaceFileW`; Windows “atomic swap” is not available in pure JS in a fully interruption-proof way.

Implication:
- The installer must coordinate with lifecycle: either the daemon is stopped first, or the installer must fail safely without altering the existing `docdexd.exe`.
- To mitigate interruption between multi-step renames, the installer should implement **recovery on next run** (detect `*.old`/`*.new` artifacts and restore/complete).

## Installer strategy (current design)

The npm installer implements a staged install with platform-specific finalization:

1) **Download** the release archive to a temp file (OS temp dir).
2) **Verify integrity** of the downloaded archive (SHA-256 from manifest/checksum contract).
3) **Extract** the archive into a **staging directory adjacent to the final install dir**:
   - `dist/<platformKey>.staging.<pid>.<timestamp>/`
   - This avoids partially-extracted binaries appearing at the final path.
4) **Validate** the extracted binary exists at the expected path inside staging.
5) **Copy** the extracted binary into `dist/<platformKey>/` under a temp filename (not runnable at the final name).
6) **Finalize replace**:
   - POSIX: `rename(tempBinary, finalBinary)` (atomic file replacement).
   - Windows: rename temp to `docdexd.exe.__docdex_new__`, then:
     - `docdexd.exe` → `docdexd.exe.__docdex_old__`
     - `docdexd.exe.__docdex_new__` → `docdexd.exe`
     - remove the `__docdex_old__` backup (best-effort)
7) **Write install metadata** (`dist/<platformKey>/docdexd-install.json`) via “write temp then rename”.
8) **Cleanup**: remove the temp archive and staging directory. On startup, also remove stale staging directories; on Windows, attempt recovery of `__docdex_new__/__docdex_old__` artifacts before deciding “no-op/update/repair”.

## Daemon / service coordination

- The installer does not (and should not) attempt to forcibly kill processes.
- macOS/Linux: upgrades can succeed while `docdexd` is running; the running process continues using the old binary until restarted.
- Windows: upgrades may require stopping `docdexd.exe` first. If replacement fails due to locking, the installer fails with `DOCDEX_REPLACE_FAILED` and leaves the old binary intact.

If Docdex is packaged as an OS service (outside the npm installer), the recommended lifecycle is:
- Stop the service/daemon.
- Perform the same staged + atomic replace within the service install directory.
- Start the service/daemon.

## Privilege boundaries

Global npm installs may target directories that require elevation (admin/root). The installer must:
- Fail safely if it cannot write the install location.
- Never delete an existing working binary before a verified replacement is ready.
