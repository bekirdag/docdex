# Installer Rollback Guarantees (Staged/Atomic Install) + Troubleshooting

Scope: the npm postinstall downloader (`npm/lib/install.js`) that installs a platform-specific `docdexd` binary, and the CLI wrapper (`npm/bin/docdex.js`) that runs the installed binary.

Assumptions (explicit):
- You install via npm (`npm i -g docdex` or `npm install docdex`) on Node.js >= 18.
- Release assets live on GitHub Releases for the tag `vX.Y.Z` matching the npm package version (or `DOCDEX_VERSION` if set).
- Integrity verification uses the release manifest/checksums contract when available; see `docs/contracts/release_manifest_schema_v1.md`.

Related docs:
- Error codes + remediation: `docs/ops/installer_error_codes.md`
- Upgrade/downgrade outcomes: `docs/ops/installer_upgrade_downgrade.md`
- Supported platforms + mapping: `docs/ops/installer_supported_platforms.md`
- Error contract: `docs/contracts/installer_error_contract_v1.md`

---

## Guarantees (what “rollback-safe” means)

### 1) Staged install: verified binary only becomes runnable at the end

When the installer needs to install (`update`, `repair`, `reinstall_unknown`), it uses a staged workflow:

1) Download the expected release archive to a temporary file.
2) Verify the archive SHA-256 (when expected SHA is available).
3) Extract the archive into a staging directory (not the final install directory).
4) Verify the extracted binary exists where expected (`docdexd` or `docdexd.exe`).
5) Compute the extracted binary’s SHA-256 for local install metadata.
6) Atomically swap the staged binary into the final location.
7) Write install metadata (`docdexd-install.json`) via an atomic write+rename.

Operationally: `docdexd` only changes once steps (1–5) have succeeded.

### 2) Rollback behavior when a prior working `docdexd` exists

If a previously working `docdexd` exists at `dist/<platformKey>/docdexd` (or `docdexd.exe`), then:

- Any failure before the final atomic swap leaves the existing binary untouched and runnable via `docdex`/`docdexd`.
- A subsequent reinstall converges without requiring manual cleanup (the installer cleans up stale staging artifacts on the next run).

### 3) No partially downloaded binary is left runnable

- Partially downloaded archives never land in `dist/<platformKey>/`.
- The wrapper only runs `dist/<platformKey>/docdexd` (or `docdexd.exe`), and that path is only updated after verification and successful extraction.

---

## What is verified before finalization

Before placing a new binary at the wrapper’s final path, the installer verifies:

- **Release asset selection is deterministic** (manifest preferred; documented checksum fallbacks).
- **Archive SHA-256** matches expected integrity metadata (when available from manifest/checksums).
- **Archive structure** contains the expected binary name for the platform (`docdexd` / `docdexd.exe`).
- **Local integrity metadata**: the installer hashes the extracted binary and records it in `dist/<platformKey>/docdexd-install.json` so later runs can be `no-op` or `repair` deterministically.

---

## What gets cleaned up on failure

On a normal failure (process exits via an error path), the installer removes:

- The temporary download file (in the OS temp directory, or `--tmpDir` when provided).
- The staging extraction directory (under `dist/`).
- Any partially staged `*.new` binary file in `dist/<platformKey>/` (best-effort).

On an interrupted install (SIGKILL/power loss), cleanup cannot run. On the next installer run, Docdex performs best-effort cleanup of stale artifacts under `dist/` before installing.

---

## Interrupted installs: safe re-run expectations

Expected behavior after an interruption:

- Re-running the install (`npm i -g docdex` or your normal install command) is safe and should succeed without manual cleanup.
- If a previous `docdexd` existed, it should still run (the installer does not remove it during the staged portion of install).

Important operational note:
- Reinstalling updates the on-disk binary, but it does not stop a currently running `docdexd` process. Restart the process to pick up the new binary.

---

## Troubleshooting common failure modes

For all cases: capture the printed `[docdex] error code: DOCDEX_...` and use `docs/ops/installer_error_codes.md` for the exact remediation checklist.

### Verification / integrity failures (`DOCDEX_INTEGRITY_MISMATCH`)

What it usually means:
- Download corruption, proxy/caching interference, or a release publishing issue.

Safe actions:
- Re-run the install once (transient corruption happens).
- Avoid manually extracting/running unverified downloads.
- If you are installing from a fork, confirm `DOCDEX_DOWNLOAD_REPO=<owner/repo>` points to the repo that published the matching release assets.

### Interrupted install

What it usually means:
- The process ended mid-download or mid-extract.

Safe actions:
- Re-run the same install command. The installer is designed to converge and will clean up stale staging artifacts under `dist/`.

### Archive issues (`DOCDEX_ARCHIVE_INVALID`)

What it usually means:
- The release asset exists, but the archive content is missing the expected `docdexd` binary (packaging/publishing error), or a tampered/corrupted archive.

Safe actions:
- Re-run once; if it persists, treat it as a release issue and install a different version or build from source.

### Unsupported platform (`DOCDEX_UNSUPPORTED_PLATFORM`)

Safe actions:
- Run `docdex doctor` to see the detected platform key/target triple.
- On Linux, try `DOCDEX_LIBC=gnu` or `DOCDEX_LIBC=musl` to override libc selection (see `docs/ops/installer_supported_platforms.md`).

---

## When to do manual cleanup (last resort)

Manual deletion should not be required for interrupted installs. Use it only if you are blocked and understand the path you are deleting:

1) Delete only install metadata (forces `reinstall_unknown` next run):
   - `dist/<platformKey>/docdexd-install.json`
2) Delete the platform install directory (forces a clean reinstall for that platform):
   - `dist/<platformKey>/`

Risk note:
- Prefer `npm root -g` (or inspecting your local `node_modules/`) to confirm you are deleting paths under the installed `docdex` package directory.
