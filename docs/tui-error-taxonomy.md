# TUI Error Taxonomy and Remediation Copy

Scope: docdexd TUI error surfaces for chat, context, and graph flows (EP-11-US-04). Aligns with SDS section cli-commands and configuration safeguards, plus the RFP local-first mandate. Copy reviewed with TUI PM and Docs/UX; tone is calm, action-first, and keeps offline-by-default behavior explicit.

## Copy principles
- Keep repo-scoped language and never blame the user; reference the active repo when available.
- Default to local-first and zero-cost paths; only propose online escalation as an explicit opt-in.
- Offer a short action plus a single-key retry/exit choice; preserve scrollback and the input buffer when showing a banner.

## Error taxonomy (banner text and remediation)

### Daemon unreachable (MCP/HTTP refused)
- Trigger: TUI cannot reach the single docdexd instance (port closed, token mismatch, or process stopped).
- Banner copy: "Docdex daemon is not reachable on <host>:<port>. Start it locally and retry."
- Remediation: Show start hint `docdexd serve --repo <path> --log warn` or `docdexd check` for health. Keep TUI running; allow `[r] Retry` and `[q] Quit` without clearing panes. Remind loopback is expected; if exposed, note token is required per SDS.

### Unknown repo
- Trigger: repo path/id is not registered or not indexed.
- Banner copy: "Repo is not attached. Index or pick a known repo before continuing."
- Remediation: List discovered repos (fingerprints) when available; hint `docdexd index --repo <path>` or `docdexd check --repo <path>` to attach. Do not drop the current chat; keep input editable and allow repo switch.
- Retry: `[r] Retry` after switching or attaching; `[s] Select repo` opens selector.

### Missing model backend
- Trigger: Ollama is not installed/running or the requested model is absent.
- Banner copy: "Model backend unavailable. Start Ollama and pull the requested model."
- Remediation: Suggest `ollama serve` and `ollama pull <model>`; remind that provider must be Ollama per SDS. Allow other panes (history, repo selector) to stay interactive.
- Retry: `[r] Retry` once backend is up; `[d] Defer` returns to chat without blocking other repos.

### Offline refusal
- Trigger: Web escalation blocked because offline flag is set or network is down.
- Banner copy: "Offline-only mode is blocking web fetches. Stay local or allow a one-time fetch?"
- Remediation: Default to local-only; offer `[o] Override once` (explicit consent) or `[c] Cancel` to continue with local results. Reference the offline-first stance from the RFP. If override is chosen, log the one-time decision to stderr for audit.

### Malformed inputs
- Trigger: bad flags, invalid repo path, unsupported command syntax, or missing required values.
- Banner copy: "Input is not valid. Fix the highlighted field and try again."
- Remediation: Echo the validation error and point to `docdexd tui --help` or `docdexd help-all` for the failing flag. Keep the cursor in the input box; no panics or clearing buffers.
- Retry: `[enter]` after editing re-validates; `[esc]` cancels.

### Unexpected exception
- Trigger: any uncaught runtime error inside the TUI loop.
- Banner copy: "Something went wrong. State is preserved; details were logged."
- Remediation: Log stack trace to stderr (not the banner), keep panes intact, and offer `[r] Retry last action` plus `[q] Quit`. If repeated, suggest `docdexd check` and filing the log path shown. Ensure banner text never leaks prompts or secrets.

## Banner layout guidelines (resize-safe)
- Reserve a fixed-height banner strip at the top (2-4 lines) that re-computes widths on every draw; do not overlay the input box.
- Wrap text using string width (not byte count) and re-wrap on resize before flushing to stdout to avoid mid-line tearing.
- Keep a consistent left margin and padding; truncate long paths with `...` instead of breaking ASCII art mid-glyph.
- When the window shrinks below ~60 columns, collapse the banner into a single-line summary plus a `[?]` key to expand details in a modal pane.
- Banners should never clear chat/history buffers; rerenders must be idempotent so a resize redraw does not drop selected repo or context rows.
- Render action keys on the last banner line with spacing that fits the current width; hide optional actions rather than wrapping to a new line.

Stakeholder sign-off: reviewed with TUI PM and Docs/UX for tone and SDS alignment; ready for engineering handoff.
