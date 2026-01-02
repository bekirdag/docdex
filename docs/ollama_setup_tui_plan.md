# Ollama Setup TUI Plan (Post-Install Wizard)

## Goals
- Do **not** install Ollama or models during `npm i -g docdex`.
- Provide a cross-platform **TUI window** that can be launched after install to guide non-technical users.
- Obtain explicit user consent before installing Ollama and models.
- Recommend models (nomic-embed-text, phi3.5:3.8b) based on hardware capacity and available disk.
- Keep the solution OS-agnostic across macOS, Windows, and Linux.
- Ensure the setup flow is **idempotent** and safe to re-run.
- Allow enterprise/CI to opt out cleanly.

## Non-Goals
- No background daemon prompts (daemon has no interactive UI).
- No forced installs during npm lifecycle hooks.
- No GUI app bundle or Electron UI.

## High-Level UX Flow
1. `npm i -g docdex` completes.
2. A **TUI wizard** launches in a new terminal window (best-effort).
3. Wizard explains Ollama and optional models, requests consent.
4. User chooses:
   - Install Ollama
   - Skip
   - View details (disk cost, model sizes, detection info)
5. If Ollama install succeeds, prompt to install:
   - `nomic-embed-text` (default for embeddings)
   - `phi3.5:3.8b` (chat model), gated by free disk and hardware guidance
6. Wizard sets default model in `~/.docdex/config.toml` when chosen.
7. Wizard exits with a summary and next steps.

## Architecture
### New CLI Command
- Add `docdex setup` (alias: `docdexd llm-setup`) to run the wizard.
- Must be safe to run multiple times (idempotent).
- Expose `--non-interactive` to print instructions and exit with code 0.
- Expose `--json` to emit a machine-readable summary (for support/debug).

### Post-Install Trigger (Best Effort)
- During npm postinstall, **do not install Ollama**.
- Only attempt to launch the TUI wizard in a new terminal window.
- If terminal launch fails, write a marker and print: `Run: docdex setup`.
- Postinstall should never fail the npm install if setup launch fails.

### TUI Implementation
- Use Rust `ratatui` + `crossterm` within the existing `docdexd` binary.
- TUI runs in a new terminal window for postinstall (macOS, Windows, Linux) and executes `docdex setup`.
- Provide minimal UI:
  - Status panel (Ollama installed? Models installed? Disk free?)
  - Stepper (Consent → Install → Model selection → Summary)
- All user actions are explicit and confirm before installing.

## Detailed TUI Screens
1. **Welcome**
   - Explain Ollama usage and why models are needed.
   - Show detected OS + hardware summary + free disk.
2. **Consent**
   - "Install Ollama now?" [Yes/No]
   - If No: record deferred marker and exit with instructions.
3. **Install Progress**
   - Real-time log output from installer.
   - Failure state with retry + manual instructions.
4. **Model Selection**
   - Show installed models list (if any).
   - Recommend `nomic-embed-text` if missing.
   - Recommend `phi3.5:3.8b` if disk >= 3 GiB and RAM >= 8 GiB.
   - Allow skip or choose other installed model as default.
5. **Summary**
   - Installed items, default model selection, next steps.
   - Remind `docdexd serve` usage.

## Cross-Platform Terminal Launch
### macOS
- Open a **new terminal window** and run `docdex setup`.
- If no interactive TTY is available, print the manual command and create the pending marker.

### Windows
- Use `cmd /c start` or PowerShell `Start-Process` to open a console and run `docdex setup`.
- Prefer PowerShell for proper quoting; fallback to `cmd`.

### Linux
- Open a **new terminal window** and run `docdex setup`.
- If no interactive TTY is available, print the manual command and create the pending marker.

## Detection & Recommendations
- Disk free: use platform-specific checks (already in postinstall helper).
- Hardware: reuse existing `docdexd check` hardware summary logic.
- Recommend models:
  - Always recommend `nomic-embed-text` if missing.
  - Recommend `phi3.5:3.8b` only if disk free > 3 GiB and RAM >= 8 GiB.
- If disk space is low, show warning and default to skip.

## Consent & Safety
- Wizard must always ask explicit consent before installation.
- Provide clear description of what will be installed and disk usage.
- Safe exit on decline.
- Avoid running installers as root unless explicitly invoked as root.

## Persistence
- Record completion marker (e.g., `~/.docdex/state/setup_complete.json`).
- Record “deferred” marker if user declines so CLI does not re-prompt on every run.
- Record “failed” marker with error details for debugging.

## Config & State Files
- `~/.docdex/config.toml`: set `[llm].default_model` when user chooses.
- `~/.docdex/state/setup_status.json`: `{ status: "complete|deferred|failed", timestamp, details }`
- `~/.docdex/state/setup_pending.json`: created by postinstall if wizard could not launch.

## Environment Overrides
- `DOCDEX_SETUP_SKIP=1`: skip wizard launch and prompts.
- `DOCDEX_SETUP_FORCE=1`: always run wizard, ignoring deferred marker.
- `DOCDEX_OLLAMA_INSTALL=1|0`: force install/skip inside wizard.
- `DOCDEX_OLLAMA_MODEL_PROMPT=1|0`: force model selection.
- `DOCDEX_OLLAMA_MODEL_ASSUME_Y=1`: auto-accept phi3.5 install when recommended.

## Logging
- Log to stderr with `[docdex]` prefix.
- Write a short JSON summary to `setup_status.json`.
- Never fail npm install due to setup launch errors.

## Error Handling
- If terminal launch fails: print `docdex setup` command and write `setup_pending.json`.
- If Ollama install fails: show error, link to https://ollama.com/download, and allow retry.
- If model pull fails: allow skip and provide copy/paste `ollama pull` command.

## Testing Plan
- Unit tests:
  - TUI state machine transitions.
  - Consent logic (accept/decline).
  - Model recommendation rules.
- Integration tests:
  - `docdex setup` no-tty path prints fallback instructions.
  - `docdex setup` respects markers and is idempotent.
- Manual QA:
  - macOS Terminal launch.
  - Windows `cmd`/PowerShell launch.
  - Linux terminal launch in common desktops.

## Docs Updates
- `README.md`: add “First-time setup” section with `docdex setup`.
- `docs/usage.md`: add wizard flow and CLI command reference.
- `docs/sds/sdsv2.1.md`: update install flow to reference TUI wizard (no postinstall installs).
