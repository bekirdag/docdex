# Local LLM Setup TUI Tasks (Expanded)

Historical note: this task list was originally written for an Ollama-first wizard. Current acceptance is provider-neutral: setup detects supported local services and models first, then offers Ollama only as the fallback setup path.

Each task includes: slug, title, deep description, dependencies, files to touch, acceptance criteria, documentation updates, and tests.

---

## Task 1
- **Slug:** `postinstall-decouple-deps`
- **Title:** Remove install-time Ollama/model/chromium actions from npm postinstall
- **Description:**  
  Ensure the npm postinstall script **does not** install Ollama, models, or Chromium. The postinstall step should only attempt to launch the setup wizard (or print manual instructions). Remove any lingering logic that installs dependencies from Node during `npm i -g docdex`. Confirm that Linux Chromium auto-install is not triggered from npm postinstall. This task must be completed before any TUI launch logic is considered stable.
- **Dependencies:** None
- **Files to Touch:**
  - `npm/lib/postinstall_setup.js`
  - `npm/lib/install.js`
  - `docs/usage.md`
- **Acceptance Criteria:**
  - `npm i -g docdex` does not call Ollama installers or model pulls.
  - Postinstall never attempts to install Chromium.
  - Postinstall still prints instructions or launches setup.
  - Setup can reuse an existing local LLM service without prompting to install Ollama.
- **Docs to Touch:**
  - `docs/usage.md`
- **Tests to Write:**
  - Unit: postinstall path does not call install functions.

---

## Task 2
- **Slug:** `cli-setup-command-wireup`
- **Title:** Add `docdex setup` command entry
- **Description:**  
  Add a new CLI subcommand `setup` under the `docdex` binary. The command should be discoverable in `--help` and `help all`. It should dispatch into a new Rust module (`src/setup`) without changing existing CLI semantics. The command must accept flags:
  - `--non-interactive`: print a one-line instruction and exit 0.
  - `--json`: print a JSON summary (status, timestamps, models, errors).
  - `--force`: ignore setup markers and always run the wizard.
  The implementation should also support an alias `docdexd llm-setup` and keep behavior aligned across both entry points.
- **Dependencies:** None
- **Files to Touch:**
  - `src/cli/mod.rs`
  - `src/cli/commands/mod.rs`
  - `src/cli/commands/llm.rs` (extend for alias) or `src/cli/commands/setup.rs` (new)
  - `src/cli/help_all.rs`
- **Acceptance Criteria:**
  - `docdex setup --help` shows flags and description.
  - `docdex setup --non-interactive` prints instructions and exits 0.
  - `docdex setup --json` emits valid JSON (one line).
  - `docdexd llm-setup` runs the same code path.
- **Docs to Touch:**
  - `README.md` (CLI overview)
  - `docs/usage.md`
- **Tests to Write:**
  - Unit: argument parsing for new flags.
  - Integration: `docdex setup --non-interactive` output contains `docdex setup` hint.

---

## Task 3
- **Slug:** `setup-status-store`
- **Title:** Setup status persistence + markers
- **Description:**  
  Implement a small state store for setup status markers in `~/.docdex/state`:
  - `setup_status.json`: `{ status, timestamp, details }`
  - `setup_pending.json`: created when postinstall cannot launch TUI
  - `setup_failed.json`: created when wizard fails
  The CLI should read these markers and decide whether to run the wizard. `--force` should bypass them.
- **Dependencies:** `cli-setup-command-wireup`
- **Files to Touch:**
  - `src/setup/state_store.rs` (new)
  - `src/setup/mod.rs` (new)
  - `src/state_paths.rs`
- **Acceptance Criteria:**
  - Writing status is atomic (write temp + rename).
  - `setup_pending.json` cleared on success.
  - `setup_failed.json` recorded on failure with error text.
- **Docs to Touch:**
  - `docs/usage.md` (status markers)
- **Tests to Write:**
  - Unit: marker read/write.
  - Unit: `--force` ignores markers.

---

## Task 4
- **Slug:** `setup-hardware-detection`
- **Title:** Gather hardware + disk metrics for recommendations
- **Description:**  
  Reuse existing hardware detection (`docdexd check`) to derive RAM and CPU info, and implement disk free detection similar to npm helper. These values are used by the wizard to recommend models.
- **Dependencies:** `setup-status-store`
- **Files to Touch:**
  - `src/setup/hardware.rs` (new)
  - `src/hardware.rs` (reuse / factor)
  - `src/setup/mod.rs`
- **Acceptance Criteria:**
  - Returns free disk in bytes for the primary volume.
  - Returns RAM in GiB and CPU count.
  - Returns a “recommended model class” string.
- **Docs to Touch:** None
- **Tests to Write:**
  - Unit: compute thresholds (disk >= 3 GiB, RAM >= 8 GiB).

---

## Task 5
- **Slug:** `setup-state-machine-core`
- **Title:** Wizard state machine + transitions
- **Description:**  
  Define a state machine that covers all wizard steps. Each state must be serializable for logs and `--json` output. The state machine must allow:
  - Consent decline -> deferred status.
  - Install errors -> failed status with retry.
  - Model selection -> set default model or skip.
  Provide explicit events and transitions so the TUI can be purely a renderer.
- **Dependencies:** `setup-hardware-detection`
- **Files to Touch:**
  - `src/setup/state.rs` (new)
  - `src/setup/model.rs` (new)
  - `src/setup/mod.rs`
- **Acceptance Criteria:**
  - All states have transitions for success/failure paths.
  - State snapshot can render JSON summary.
- **Docs to Touch:** None
- **Tests to Write:**
  - Unit: transitions (accept/decline/retry).

---

## Task 6
- **Slug:** `setup-ollama-core`
- **Title:** Ollama fallback install + model pull (Rust)
- **Description:**  
  Implement OS-specific commands to install the Ollama fallback (brew/winget/curl|wget). Ensure these run only with explicit consent and only after provider-neutral detection fails to find usable defaults. Provide functions to:
  - Check if `ollama` exists.
  - Run `ollama pull` for `nomic-embed-text` and `phi3.5:3.8b`.
  - Validate model list output.
  Include clear error messages for missing package managers.
- **Dependencies:** `setup-state-machine-core`
- **Files to Touch:**
  - `src/setup/ollama.rs` (new)
  - `src/setup/mod.rs`
- **Acceptance Criteria:**
  - Detects `ollama` on PATH.
  - `ollama pull` results recorded for summary.
  - Existing vLLM, llama.cpp-compatible OpenAI endpoints, LM Studio, LocalAI, SGLang, TGI-compatible deployments, or healthy local mcoda agents can be selected without entering the Ollama fallback path.
  - Errors include copy/paste remediation.
- **Docs to Touch:** None
- **Tests to Write:**
  - Unit: per-OS command selection.
  - Integration: `ollama` missing -> expected error code.

---

## Task 7
- **Slug:** `setup-config-write`
- **Title:** Write provider-neutral defaults to config.toml
- **Description:**  
  Update config handling so the setup wizard can set provider, base URL, embedding model, default model, and lane-specific delegation defaults when the user chooses detected candidates. Preserve explicit existing config unless user overrides; migrate only old generated Ollama defaults. Follow existing TOML update patterns in npm helper to avoid breaking formatting.
- **Dependencies:** `setup-state-machine-core`
- **Files to Touch:**
  - `src/setup/config.rs` (new)
  - `src/config.rs`
- **Acceptance Criteria:**
  - Config updated only when user opts in.
  - Existing values preserved if user skips.
  - Explicit custom provider/base/model/delegation settings are preserved.
  - Old generated Ollama defaults can migrate to better detected local defaults.
- **Docs to Touch:** None
- **Tests to Write:**
  - Unit: config update preserves unrelated sections.

---

## Task 8
- **Slug:** `tui-renderer-core`
- **Title:** TUI renderer with ratatui + crossterm
- **Description:**  
  Implement a lightweight TUI renderer to display wizard state, progress, and prompts. Handle keyboard input and exit cleanly. Keep a minimal layout:
  - Left: status list
  - Right: main step content
  - Bottom: action hints
- **Dependencies:** `setup-state-machine-core`
- **Files to Touch:**
  - `Cargo.toml` (add `ratatui`, `crossterm`)
  - `src/setup/ui.rs` (new)
  - `src/setup/mod.rs`
- **Acceptance Criteria:**
  - TUI responds to Y/N, arrows, enter, esc.
  - Clean terminal cleanup on exit.
- **Docs to Touch:** None
- **Tests to Write:**
  - Unit: render for each state does not panic.

---

## Task 9
- **Slug:** `setup-runner`
- **Title:** Orchestrate TUI + state + installer
- **Description:**  
  Wire up the TUI runner that drives the state machine, applies detected local defaults, calls Ollama fallback install only when chosen, triggers fallback model pulls, writes markers, and prints final summary. Must honor `--json`, `--non-interactive`, and `--force`.
- **Dependencies:** `tui-renderer-core`, `setup-ollama-core`, `setup-status-store`
- **Files to Touch:**
  - `src/setup/mod.rs`
  - `src/cli/commands/setup.rs`
- **Acceptance Criteria:**
  - Full happy path produces `setup_status.json` with `complete`.
  - Decline produces `deferred` without side effects.
  - Errors produce `failed` marker.
- **Docs to Touch:** None
- **Tests to Write:**
  - Integration: setup declines, setup completes.

---

## Task 10
- **Slug:** `postinstall-launcher`
- **Title:** Postinstall launches TUI (no installs)
- **Description:**  
  Update npm postinstall to launch the setup wizard in a **new terminal window** on macOS, Linux, and Windows. Do not install Ollama/models in Node. If launch fails, create `setup_pending.json` and print `docdex setup`. Respect `DOCDEX_SETUP_SKIP=1`.
- **Dependencies:** `cli-setup-command-wireup`, `setup-status-store`
- **Files to Touch:**
  - `npm/lib/postinstall_setup.js`
  - `npm/test/postinstall_setup.test.js`
- **Acceptance Criteria:**
  - Postinstall never installs Ollama/models.
  - Best-effort terminal launch by OS.
  - Failure path prints manual command and writes marker.
- **Docs to Touch:**
  - `README.md`
  - `docs/usage.md`
- **Tests to Write:**
  - Unit: OS launcher picks correct command.
  - Unit: `DOCDEX_SETUP_SKIP=1` skips launch.

---

## Task 11
- **Slug:** `docs-and-help`
- **Title:** Docs + help alignment
- **Description:**  
  Update docs and help to reflect new setup flow. Ensure SDS v2.1 states “no install-time dependency prompts” and describes wizard.
- **Dependencies:** `cli-setup-command-wireup`
- **Files to Touch:**
  - `README.md`
  - `docs/usage.md`
  - `docs/sds/sdsv2.1.md`
  - `src/cli/help_all.rs`
- **Acceptance Criteria:**
  - `docdex setup` documented in README and usage.
  - SDS v2.1 updated with correct flow.
- **Docs to Touch:** (as above)
- **Tests to Write:**
  - Doc lint or snapshot (if present).
