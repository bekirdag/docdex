# Ollama Model Prompt Plan

## Goal
Add a post-install step that (1) shows available disk space, (2) prompts for a default LLM model when Ollama is present, and (3) installs `phi3.5:3.8b` (2.2 GB) if the user opts in.

## Scope
- npm postinstall flow in `npm/lib/postinstall_setup.js`.
- Interactive prompt only when a TTY is available and not in CI.
- Config updates in `~/.docdex/config.toml` for `[llm].default_model`.
- Model selection only affects the chat model; embedding model remains `nomic-embed-text`.

## Non-goals
- Do not auto-install models in non-interactive environments unless explicitly opted in.
- Do not change `[llm].embedding_model` or other config sections.
- Do not require Ollama for installation to succeed.

## User Flows
1) **Fresh install, no Ollama**: postinstall asks to install Ollama + `nomic-embed-text` (already implemented), then prompts for `phi3.5:3.8b` if no models are present.
2) **Ollama installed, no models**: prompt shows free disk space and `phi3.5:3.8b` size and offers install.
3) **Ollama installed with models**: prompt shows installed models and lets the user set a default or install `phi3.5:3.8b`.
4) **Non-interactive/CI**: skip prompts, leave config untouched, emit a one-line warning.

## Implementation Steps

1) Add model selection prompt
- Location: `npm/lib/postinstall_setup.js` (after `maybeInstallOllama()` returns).
- Behavior: only prompt when TTY is available and `DOCDEX_OLLAMA_MODEL_PROMPT` is not disabled.
- Environment overrides:
  - `DOCDEX_OLLAMA_MODEL_PROMPT=0` -> skip prompt.
  - `DOCDEX_OLLAMA_DEFAULT_MODEL=<model>` -> preselect default when prompting.
  - `DOCDEX_OLLAMA_MODEL_ASSUME_Y=1` -> auto-accept install for the prompt.
  - `DOCDEX_OLLAMA_MODEL=<model>` -> force install/pick this model, skip prompt.

2) Detect installed models
- Command: `ollama list`.
- Parse model names into an array of strings.
- Normalize names to match config (case-insensitive comparison).
- If list fails, skip prompt with a warning (do not fail install).

3) Compute free disk space
- Unix/macOS: use `fs.statfs` on the home directory (fallback to `/` if needed).
- Windows: use PowerShell (`Get-PSDrive -Name C`) or `wmic` fallback to read free bytes for `%SystemDrive%`.
- Surface free space in GiB (one decimal).
- Handle errors by showing "unknown" (do not fail install).

4) Prompting logic
- If no models installed:
  - Show free space and the size required for `phi3.5:3.8b` (2.2 GB).
  - Ask: "Install phi3.5:3.8b now? [Y/n]".
  - If yes, run `ollama pull phi3.5:3.8b`.
  - If no, leave config unchanged.
- If models exist:
  - Show list of installed models.
  - Offer choice: select a default model from the list or install `phi3.5:3.8b` (if missing).
  - If `DOCDEX_OLLAMA_DEFAULT_MODEL` is set and present in the list, preselect it.
  - Update `[llm].default_model` in config if user chooses a model.

5) Update config
- If the user selects a model, update `~/.docdex/config.toml` under `[llm].default_model`.
- Preserve comments and unrelated sections; use existing config writer helpers if available or a minimal upsert that only touches `[llm].default_model`.
- Leave the embedding model (`nomic-embed-text`) untouched.

6) Documentation
- Update `README.md` and `npm/README.md` with the new prompt behavior and env overrides.
- Update `docs/http_api.md` or `docs/sds/sdsv2.1.md` if model defaults are mentioned there.

7) Tests
- Add node tests in `npm/test/postinstall_setup.test.js`:
  - prompt skipped in CI / non-interactive.
  - model list parsing.
  - default model selection updates config.
  - prompt path for empty model list.
  - environment overrides (`DOCDEX_OLLAMA_MODEL`, `DOCDEX_OLLAMA_DEFAULT_MODEL`, `DOCDEX_OLLAMA_MODEL_ASSUME_Y`).

## Files to Touch
- `npm/lib/postinstall_setup.js` (prompt + detection + config update).
- `npm/test/postinstall_setup.test.js` (new tests).
- `README.md`, `npm/README.md` (docs).
- Optional: `docs/sds/sdsv2.1.md` (if model prompt is documented).

## Acceptance Criteria
- Postinstall prompts only in TTY and not in CI.
- Free space and model size are displayed when prompting.
- `phi3.5:3.8b` installs on acceptance.
- Default model is stored in config when user selects a model.
- Tests cover prompt decision and model selection logic.
- Install succeeds even if Ollama install/model pull fails (with warning only).
