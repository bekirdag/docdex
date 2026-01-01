# Multi-Browser Support Plan

## Goal
Provide headless web scraping without requiring Chrome pre-installation. If Chrome is missing, docdex should:
- macOS + Windows: discover and use alternative headless-capable browsers.
- Linux: auto-download/install a headless-capable Chromium build and register its path.
- Persist the resolved binary path so subsequent runs use a known working executable.

## Phase 0: Audit + Baseline
- Map all browser discovery/usage paths:
  - `src/util.rs` (`detect_chrome_binary`).
  - `src/config.rs` (`apply_browser_defaults`).
  - `src/web/chrome.rs` (`ChromeFetchConfig`).
  - `src/orchestrator/web.rs` (`resolve_browser_available`).
  - `src/cli/commands/check.rs` (preflight checks).
- Identify where to inject fallback detection, auto-install hooks, and config persistence.
- Validate existing env overrides: `DOCDEX_CHROME_PATH`, `CHROME_PATH`, `DOCDEX_WEB_BROWSER`.

## Phase 1: Cross-Platform Browser Discovery
### macOS
- Extend detection to include:
  - Google Chrome, Chrome Beta, Chrome Canary
  - Chromium
  - Microsoft Edge (Stable/Beta/Dev/Canary)
  - Brave Browser (Stable/Beta/Nightly)
  - Vivaldi
- Discovery priority: Chrome/Chromium first, then Edge, then Brave/Vivaldi.

### Windows
- Extend detection to include:
  - Chrome (Stable/Beta/Canary)
  - Chromium
  - Edge (Stable/Beta/Dev/Canary)
  - Brave (Stable/Beta/Nightly)
  - Vivaldi
- Use `PROGRAMFILES`, `PROGRAMFILES(X86)`, `LOCALAPPDATA` for candidate roots.
- Prefer Chrome/Chromium if present, else Edge, then Brave/Vivaldi.

### Linux (non-musl)
- Keep existing checks for system Chrome/Chromium binaries.
- Add fallback discovery for:
  - `google-chrome`, `chromium`, `chromium-browser` via `which`.
  - Known paths like `/usr/bin/`, `/opt/`, `/snap/bin`.

### Implementation Notes
- Replace `detect_chrome_binary` with a broader `detect_browser_binary` that returns:
  - Binary path
  - Candidate name
  - Optional browser kind (chrome/chromium/edge/brave/vivaldi)
- Preserve env override behavior; explicit env always wins.
- Add a `BrowserCandidate` struct and a ranked list builder:
  - `name` (display), `kind` (enum), `path`, `source` (env, known_path, which), `priority`.
  - Provide `detect_browser_candidates()` for diagnostics and `detect_browser_binary()` for first match.
- Env precedence (highest to lowest):
  - `DOCDEX_WEB_BROWSER` (absolute path or command name).
  - `DOCDEX_CHROME_PATH` / `CHROME_PATH`.
  - Config value `[web.scraper].chrome_binary_path`.
  - Auto-discovery.

## Phase 2: Linux Auto-Install (Headless Chromium)
- If no browser is found on Linux:
  - Download a known-good Chromium headless build.
  - Install into `~/.docdex/state/bin/chromium/`.
  - Verify checksum and version.
  - Ensure executable permissions and path registration.

### Installation Mechanics
- Add a small downloader/installer module:
  - Supports resume + checksum verification.
  - Uses a lock file in `~/.docdex/state/locks/browser_install.lock`.
  - Cleans up partial installs on failure.
- Store manifest metadata (version, checksum, install path).
- Default source:
  - Prefer Chrome for Testing (CFT) or Chromium snapshot URL with published checksums.
  - Pin version in code with an override via env (`DOCDEX_BROWSER_VERSION`).
  - Allow `DOCDEX_BROWSER_DOWNLOAD_BASE` to override the base URL for air-gapped mirrors.
- Auto-install is on for Linux by default, with opt-out via:
  - `DOCDEX_BROWSER_AUTO_INSTALL=0`
  - or config `[web.scraper].auto_install = false` (new optional flag).
- Install path layout:
  - `~/.docdex/state/bin/chromium/<version>/chrome` (or `chromium`).
  - `~/.docdex/state/bin/chromium/current` symlink (or a small manifest file) for upgrades.
- Installer must be safe:
  - Use `fs4` lock to prevent concurrent installs.
  - Verify checksum before swapping `current`.
  - Ensure executable bit is set on Linux.

## Phase 3: Configuration Wiring
- If `chrome_binary_path` is empty:
  - Run discovery.
  - If Linux and discovery fails, trigger auto-install.
  - Persist resolved path into config.
- Update config load path in `src/config.rs`:
  - `apply_browser_defaults` should become idempotent and write-through.
- Ensure `DOCDEX_WEB_BROWSER` can override discovery/auto-install.
- Add optional config fields:
  - `[web.scraper] auto_install = true|false` (Linux only, default true).
  - `[web.scraper] browser_kind = \"chromium\"` (optional, informational).
- Introduce a CLI command for explicit setup:
  - `docdexd browser setup` (runs discovery + Linux install, prints resolved path).
  - `docdexd browser install` (Linux-only install).
  - `docdexd browser list` (prints candidates + selected path).

## Phase 4: Runtime Behavior + Guardrails
- Update `resolve_browser_available` to:
  - Use new discovery results.
  - Provide clear hints when missing.
- Update error messages in:
  - `src/orchestrator/web.rs`
  - `src/api/v1/web.rs`
  - `src/cli/commands/web.rs`
- If browser missing:
  - Return stable error with guidance (Linux install path; macOS/Windows candidates).
- Add a structured hint object for API clients:
  - `browser_available=false`, `browser_hint`, `install_action`, `candidates`.
- Ensure tier-2 web flows never crash if browser is absent:
  - Return `ERR_INVALID_ARGUMENT` or a stable `ERR_DEPENDENCY_MISSING` code.
- `docdexd check` should report:
  - Selected browser path and kind.
  - Whether auto-install is enabled.
  - If missing, emit the exact install command.

## Phase 5: Tests
### Unit Tests
- Discovery ordering for macOS/Windows/Linux.
- Env override precedence.
- Config persistence behavior.
- Candidate list formatting and selection behavior.

### Integration Tests
- Linux install path simulated with temp dirs/mocks.
- Ensure fallback logic does not block other web tier logic.
- New CLI tests:
  - `docdexd browser list` outputs candidates.
  - `docdexd browser setup` writes config with resolved path.

### CI Safety
- All browser detection tests must be hermetic (mock file system or env).
- Linux auto-install tests should be behind an opt-in env flag.
- Avoid network in CI by default; install tests should use a mocked downloader or a local fixture.

## Phase 6: Documentation
- Update:
  - `docs/sds/sds.md` and `docs/sds/sdsv2.1.md` to note multi-browser fallback and Linux auto-install.
  - `docs/quality_gates.md` (browser availability requirement).
  - `README.md` with user-facing behavior.
  - CLI help and `docdexd check` descriptions.
- Add `docs/ops/browser_install.md`:
  - How auto-install works.
  - How to override download sources.
  - How to opt out.

## Acceptance Criteria
- No hard Chrome requirement on macOS/Windows if other headless-capable browsers are available.
- Linux auto-installs Chromium when no browser is present, and docdex persists path.
- Config is updated with resolved browser path, and future runs reuse it.
- Clear error messages when no browser is available and install fails.
- All new tests pass and CI stays green.
