# Multi-Browser Support Tasks

## Phase 0: Audit + Baseline

### Task 0.1: Browser usage audit
- **Slug:** `mbs-0-1-audit-browser-usage`
- **Title:** Inventory browser detection + usage surfaces
- **Description:** Build a definitive map of where browser discovery, configuration, and launch logic lives so the new detection + auto-install flow can be injected consistently.
- **Files to review/edit:**
  - `src/util.rs`
  - `src/config.rs`
  - `src/web/chrome.rs`
  - `src/orchestrator/web.rs`
  - `src/cli/commands/check.rs`
  - `src/cli/commands/web.rs`
- **Dependencies:** none
- **Deliverables:**
  - Update this task file with a short “flow map” summary.
- **Flow map summary (implemented):**
  - `AppConfig::load_default` → `apply_browser_defaults` (detect browser, Linux auto-install, persist config).
  - `WebConfig::from_env` pulls `web.scraper.chrome_binary_path` for runtime; `ChromeFetchConfig::from_web_config` resolves the final binary via discovery.
  - CLI `check` uses `detect_browser_binary` for diagnostics; `docdexd browser` commands surface candidates/setup/install.
  - Orchestrator WebGate uses env/config hint to report availability; API `/v1/web/fetch` surfaces missing dependency details.
- **Acceptance criteria:**
  - Entry points, detection flow, and config persistence points are identified.
- **Status:** done
- **Tests:** none

## Phase 1: Cross-Platform Browser Discovery

### Task 1.1: Candidate model + detection API
- **Slug:** `mbs-1-1-candidate-model`
- **Title:** Create browser candidate and detection APIs
- **Description:** Replace `detect_chrome_binary` with a structured discovery API that returns candidates and a selected binary with metadata.
- **Files to edit:**
  - `src/util.rs`
- **Dependencies:** `mbs-0-1-audit-browser-usage`
- **Implementation details:**
  - Add `BrowserKind` enum and `BrowserCandidate` struct.
  - Add `detect_browser_candidates()` and `detect_browser_binary()`.
  - Env precedence: `DOCDEX_WEB_BROWSER` > `DOCDEX_CHROME_PATH`/`CHROME_PATH` > config path > discovery.
- **Acceptance criteria:**
  - New API returns ordered candidates and a selected path with kind + source.
  - Old `detect_chrome_binary` is removed or made a shim.
- **Status:** done
- **Tests to add:**
  - `tests/browser_detection.rs` (unit): candidate ordering, env override precedence.
- **Test commands:**
  - `cargo test --locked --test browser_detection`

### Task 1.2: macOS discovery expansion
- **Slug:** `mbs-1-2-macos-discovery`
- **Title:** Add macOS browser candidates
- **Description:** Add Chrome/Chromium/Edge/Brave/Vivaldi discovery for macOS.
- **Files to edit:**
  - `src/util.rs`
- **Dependencies:** `mbs-1-1-candidate-model`
- **Implementation details:**
  - Add /Applications path checks for Edge (Stable/Beta/Dev/Canary), Brave (Stable/Beta/Nightly), Vivaldi.
  - Keep Chrome/Chromium prioritized.
- **Acceptance criteria:**
  - Candidate list includes the new browsers in the defined order.
- **Status:** done
- **Tests to add:**
  - Extend `tests/browser_detection.rs` with macOS cases.
- **Test commands:**
  - `cargo test --locked --test browser_detection`

### Task 1.3: Windows discovery expansion
- **Slug:** `mbs-1-3-windows-discovery`
- **Title:** Add Windows browser candidates
- **Description:** Add Chrome/Chromium/Edge/Brave/Vivaldi discovery for Windows paths.
- **Files to edit:**
  - `src/util.rs`
- **Dependencies:** `mbs-1-1-candidate-model`
- **Implementation details:**
  - Search `PROGRAMFILES`, `PROGRAMFILES(X86)`, `LOCALAPPDATA` for known browser exe paths.
  - Prioritize Chrome/Chromium, then Edge, then Brave/Vivaldi.
- **Acceptance criteria:**
  - Candidate list includes all expected Windows paths with correct order.
- **Status:** done
- **Tests to add:**
  - Extend `tests/browser_detection.rs` with Windows cases.
- **Test commands:**
  - `cargo test --locked --test browser_detection`

### Task 1.4: Linux discovery expansion
- **Slug:** `mbs-1-4-linux-discovery`
- **Title:** Expand Linux browser candidates
- **Description:** Add additional Chromium/Chrome candidates for Linux systems.
- **Files to edit:**
  - `src/util.rs`
- **Dependencies:** `mbs-1-1-candidate-model`
- **Implementation details:**
  - Use `which` for common binaries and check known paths.
- **Acceptance criteria:**
  - Candidate list includes `google-chrome`, `chromium`, `chromium-browser` when present.
- **Status:** done
- **Tests to add:**
  - Extend `tests/browser_detection.rs` with Linux cases.
- **Test commands:**
  - `cargo test --locked --test browser_detection`

### Task 1.5: Update detection call sites
- **Slug:** `mbs-1-5-update-callsites`
- **Title:** Wire new detection API into config + runtime
- **Description:** Replace `detect_chrome_binary` with the new API across all call sites and ensure error messaging includes browser kind + source.
- **Files to edit:**
  - `src/config.rs`
  - `src/orchestrator/web.rs`
  - `src/cli/commands/check.rs`
  - `src/web/chrome.rs`
- **Dependencies:** `mbs-1-1-candidate-model`
- **Acceptance criteria:**
  - All discovery is routed through the new API.
  - Old API is unused in runtime paths.
- **Status:** done
- **Tests:** existing test suites + `browser_detection`.
- **Test commands:**
  - `cargo test --locked --test browser_detection`
  - `cargo test --locked --test smoke -- non_loopback_plain_http_requires_tls_or_opt_out`

## Phase 2: Linux Auto-Install

### Task 2.1: Installer module scaffold
- **Slug:** `mbs-2-1-installer-skeleton`
- **Title:** Add browser installer module
- **Description:** Create a Linux-only installer module for headless Chromium.
- **Files to add/edit:**
  - `src/web/browser_install.rs` (new)
  - `src/web/mod.rs`
- **Dependencies:** `mbs-1-1-candidate-model`
- **Acceptance criteria:**
  - Module compiles and exposes a minimal API for install + resolve.
- **Status:** done
- **Tests:** none (scaffold only)

### Task 2.2: Linux install flow
- **Slug:** `mbs-2-2-linux-install-flow`
- **Title:** Implement Linux auto-install
- **Description:** Download + verify a pinned Chromium build into the docdex state dir.
- **Files to edit:**
  - `src/web/browser_install.rs`
  - `src/util.rs` (helpers for state/bin paths)
- **Dependencies:** `mbs-2-1-installer-skeleton`
- **Implementation details:**
  - Use checksum verification, lockfile guard, and manifest tracking.
  - Allow mirror override via `DOCDEX_BROWSER_DOWNLOAD_BASE`.
- **Acceptance criteria:**
  - Install resolves to a valid executable path with a manifest.
- **Status:** done
- **Tests to add:**
  - `tests/browser_install.rs` (opt-in env)
- **Test commands:**
  - `DOCDEX_TEST_ENABLE_BROWSER_INSTALL=1 cargo test --locked --test browser_install`

### Task 2.3: Auto-install opt-out
- **Slug:** `mbs-2-3-auto-install-opt-out`
- **Title:** Respect auto-install opt-out
- **Description:** Add config/env flags to disable auto-install.
- **Files to edit:**
  - `src/config.rs`
  - `src/web/browser_install.rs`
- **Dependencies:** `mbs-2-2-linux-install-flow`
- **Acceptance criteria:**
  - Auto-install skipped when disabled.
- **Status:** done
- **Tests:** update `browser_install` test to validate opt-out.

## Phase 3: Config Wiring

### Task 3.1: Config persistence
- **Slug:** `mbs-3-1-config-persistence`
- **Title:** Persist resolved browser path
- **Description:** When discovery/auto-install succeeds, update config with resolved path.
- **Files to edit:**
  - `src/config.rs`
- **Dependencies:** `mbs-1-5-update-callsites`, `mbs-2-2-linux-install-flow`
- **Acceptance criteria:**
  - Config updated after detection/install; idempotent on reload.
- **Status:** done
- **Tests to add:**
  - `tests/browser_config.rs`
- **Test commands:**
  - `cargo test --locked --test browser_config`

### Task 3.2: CLI helpers
- **Slug:** `mbs-3-2-cli-helpers`
- **Title:** Add browser CLI commands
- **Description:** Add `docdexd browser list/setup/install` commands to manage browser detection/install.
- **Files to add/edit:**
  - `src/cli/commands/browser.rs` (new)
  - `src/cli/mod.rs`
  - `src/cli/commands/check.rs` (help text)
- **Dependencies:** `mbs-3-1-config-persistence`
- **Acceptance criteria:**
  - CLI commands return structured output and exit cleanly.
- **Status:** done
- **Tests to add:**
  - `tests/browser_cli.rs`
- **Test commands:**
  - `cargo test --locked --test browser_cli`

## Phase 4: Runtime Behavior + Guardrails

### Task 4.1: Web tier availability errors
- **Slug:** `mbs-4-1-web-availability-errors`
- **Title:** Improve browser missing errors
- **Description:** Return stable, actionable errors with candidate hints when browser is missing.
- **Files to edit:**
  - `src/orchestrator/web.rs`
  - `src/api/v1/web.rs`
  - `src/cli/commands/web.rs`
- **Dependencies:** `mbs-1-5-update-callsites`, `mbs-3-1-config-persistence`
- **Acceptance criteria:**
  - Error payload includes browser hint + install action.
- **Status:** done
- **Tests:** extend `tests/network_faults.rs` or add a new error contract test.

### Task 4.2: Preflight updates
- **Slug:** `mbs-4-2-preflight-updates`
- **Title:** Extend `docdexd check` browser diagnostics
- **Description:** Report browser kind/path/auto-install status in preflight.
- **Files to edit:**
  - `src/cli/commands/check.rs`
- **Dependencies:** `mbs-1-5-update-callsites`
- **Acceptance criteria:**
  - `docdexd check` reports browser availability and resolution.
- **Status:** done
- **Tests:** extend `tests/check_bind.rs` or add new `tests/check_browser.rs`.

## Phase 5: Tests

### Task 5.1: Browser detection tests
- **Slug:** `mbs-5-1-browser-detection-tests`
- **Title:** Unit tests for detection ordering
- **Description:** Add hermetic detection tests for each OS path ordering and env overrides.
- **Files to add:**
  - `tests/browser_detection.rs`
- **Dependencies:** `mbs-1-1-candidate-model`
- **Acceptance criteria:**
  - Tests cover env precedence + per-OS candidate order.
- **Status:** done
- **Test commands:**
  - `cargo test --locked --test browser_detection`

### Task 5.2: Config persistence tests
- **Slug:** `mbs-5-2-browser-config-tests`
- **Title:** Config persistence coverage
- **Description:** Verify detected paths persist into config and reload correctly.
- **Files to add:**
  - `tests/browser_config.rs`
- **Dependencies:** `mbs-3-1-config-persistence`
- **Acceptance criteria:**
  - Tests prove idempotent persistence.
- **Status:** done
- **Test commands:**
  - `cargo test --locked --test browser_config`

### Task 5.3: Linux install tests (opt-in)
- **Slug:** `mbs-5-3-browser-install-tests`
- **Title:** Linux install flow tests
- **Description:** Mock download + verify install + manifest with opt-in env.
- **Files to add:**
  - `tests/browser_install.rs`
- **Dependencies:** `mbs-2-2-linux-install-flow`
- **Acceptance criteria:**
  - Install returns executable path and writes manifest.
- **Status:** done
- **Test commands:**
  - `DOCDEX_TEST_ENABLE_BROWSER_INSTALL=1 cargo test --locked --test browser_install`

### Task 5.4: CLI command tests
- **Slug:** `mbs-5-4-browser-cli-tests`
- **Title:** CLI helpers tests
- **Description:** Validate list/setup/install command outputs.
- **Files to add:**
  - `tests/browser_cli.rs`
- **Dependencies:** `mbs-3-2-cli-helpers`
- **Acceptance criteria:**
  - CLI tests pass with deterministic output checks.
- **Status:** done
- **Test commands:**
  - `cargo test --locked --test browser_cli`

## Phase 6: Documentation

### Task 6.1: SDS updates
- **Slug:** `mbs-6-1-sds-updates`
- **Title:** Update SDS docs for multi-browser support
- **Description:** Document multi-browser fallback and Linux auto-install in SDS v2.0 and v2.1.
- **Files to edit:**
  - `docs/sds/sds.md`
  - `docs/sds/sdsv2.1.md`
- **Dependencies:** `mbs-1-5-update-callsites`, `mbs-2-2-linux-install-flow`
- **Acceptance criteria:**
  - SDS sections reflect new browser behavior.

### Task 6.2: README + ops docs
- **Slug:** `mbs-6-2-readme-ops`
- **Title:** Document user-facing behavior
- **Description:** Update README and create browser install ops doc.
- **Files to add/edit:**
  - `README.md`
  - `docs/ops/browser_install.md`
- **Dependencies:** `mbs-3-2-cli-helpers`
- **Acceptance criteria:**
  - Users can understand browser setup, fallback, and opt-out.
