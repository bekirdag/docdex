# QA Checklist — Atomic Installs, Interrupted Installs, and Rollback

Scope: npm postinstall installer (`npm/lib/install.js`) and wrapper runtime lookup (`npm/bin/docdex.js`).

Goal: validate that installs are staged/atomic and that failure/interrupt scenarios do not leave runnable partial binaries and do not regress an already-working install.

Assumptions (explicit):
- You can run installs on each target OS/arch you care about (macOS, Linux gnu/musl, Windows).
- Network is available for download scenarios (unless you are testing only the unit tests).

## Preflight (all platforms)

- Record current version: `docdex --version` (or `docdexd --version`).
- Find the installed package root:
  - Global: `npm root -g` then look under `.../docdex/`
  - Local: `node_modules/docdex/`
- Determine `platformKey` without downloading:
  - `docdex doctor` (or `docdex diagnostics`)
- Identify the final binary location:
  - `dist/<platformKey>/docdexd` (or `docdexd.exe`) under the installed package root

## A. Success-path checks

- Fresh install (no existing `dist/<platformKey>/`):
  - Install: `npm i -g docdex` (or local install)
  - Expect: `dist/<platformKey>/docdexd*` exists and runs (`--help` / `--version`)
  - Expect: `dist/<platformKey>/docdexd-install.json` exists and is valid JSON
- Reinstall idempotency:
  - Re-run install of the same version
  - Expect: installer logs `Install outcome: no-op` and does not redownload
- Upgrade/downgrade:
  - Install version N, then install version M
  - Expect: final `docdexd-install.json.version` matches the expected version (M)

## B. Failure-path checks (no interruption)

Run these with a *known-good existing install* already present.

- Integrity mismatch (corrupt download / checksum mismatch):
  - Trigger by using a test repo/release where checksums do not match, or by forcing a proxy/cache corruption scenario.
  - Expect: install fails with `DOCDEX_INTEGRITY_MISMATCH`
  - Expect: existing `dist/<platformKey>/docdexd*` is unchanged and still runnable
  - Expect: no `dist/<platformKey>.stage.*` directories remain
- Archive missing binary (invalid release artifact):
  - Trigger by using a test artifact missing `docdexd` inside the tarball.
  - Expect: install fails with `DOCDEX_ARCHIVE_INVALID` (or equivalent fatal error)
  - Expect: existing install remains runnable and unchanged

## C. Interrupted install checks (SIGINT/SIGTERM)

Run these with a *known-good existing install* already present, then repeat with *no existing install*.

How to interrupt:
- Start install in a terminal and press Ctrl+C (SIGINT), or terminate the process (SIGTERM).

Scenarios:
- Interrupt during download:
  - Expect: no partial `dist/<platformKey>/docdexd*` appears (fresh install), or existing binary remains (upgrade)
  - Expect: no `dist/<platformKey>.stage.*` remains
- Interrupt during extract-to-staging:
  - Expect: existing binary remains runnable (upgrade case)
  - Expect: staging directory is removed (best-effort) or cleaned up on the next install run
- Interrupt during final swap window:
  - Expect: either `dist/<platformKey>/` remains intact, or a subsequent reinstall restores from `dist/<platformKey>.backup.*` automatically

Post-conditions (all interrupted scenarios):
- A subsequent reinstall succeeds **without manual cleanup**.
- There are no lingering `dist/<platformKey>.stage.*` directories.
- If a `dist/<platformKey>.backup.*` directory remains, the next reinstall restores/cleans it.

## D. Automated regression coverage (recommended in CI)

- Run npm unit tests: `cd npm && npm test`
  - Includes explicit rollback coverage in `npm/test/installer_atomic_rollback.test.js`.

