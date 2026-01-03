# Ollama Model Prompt Tasks

## Task 1
- slug: ollama-model-prompt-detection
- title: Detect Ollama models and disk space
- description: Add helpers to detect installed Ollama models, parse their names, and compute free disk space for the main disk. Provide human-readable GiB values and graceful error handling.
- dependencies: []
- tags: [npm, installer, ollama, diagnostics]
- files_to_touch:
  - npm/lib/postinstall_setup.js
  - npm/test/postinstall_setup.test.js
- acceptance_criteria:
  - `ollama list` output is parsed into a stable array of model names.
  - Disk free space is shown as GiB (one decimal) and never crashes on failure.
  - Non-interactive/CI environments do not attempt to read from stdin.
- tests_to_write:
  - Unit test for model list parsing with sample `ollama list` output.
  - Unit test for disk free helper fallback path (returns "unknown" on error).
- documentation_update:
  - None.

## Task 2
- slug: ollama-model-prompt-flow
- title: Add interactive model selection prompt
- description: Implement the postinstall prompt that shows free disk space and offers to install/select `phi3.5:3.8b` when Ollama is present. Respect env overrides and non-interactive skips.
- dependencies: [ollama-model-prompt-detection]
- tags: [npm, installer, ollama, prompt]
- files_to_touch:
  - npm/lib/postinstall_setup.js
  - npm/test/postinstall_setup.test.js
  - README.md
  - npm/README.md
- acceptance_criteria:
  - If no models exist, user is prompted to install `phi3.5:3.8b` and told it uses ~2.2 GB.
  - If models exist, user can pick a default model or install `phi3.5:3.8b`.
  - `DOCDEX_OLLAMA_MODEL_PROMPT=0` skips the prompt.
  - `DOCDEX_OLLAMA_MODEL_ASSUME_Y=1` auto-accepts when prompting.
  - `DOCDEX_OLLAMA_MODEL=<model>` forces selection without prompt.
- tests_to_write:
  - Unit tests for prompt decision mode (TTY vs non-TTY, CI).
  - Unit tests for env overrides: prompt skip, auto-accept, forced model.
- documentation_update:
  - Update `README.md` and `npm/README.md` with prompt behavior and env overrides.

## Task 3
- slug: ollama-model-config-update
- title: Persist selected default model to config
- description: Update `~/.docdex/config.toml` `[llm].default_model` when a model is selected or installed. Preserve unrelated sections and leave embedding model unchanged.
- dependencies: [ollama-model-prompt-flow]
- tags: [npm, config, ollama]
- files_to_touch:
  - npm/lib/postinstall_setup.js
  - npm/test/postinstall_setup.test.js
- acceptance_criteria:
  - Selected model is persisted to config and survives reinstall.
  - Embedding model (`nomic-embed-text`) is untouched.
  - Config updates are no-ops if the selected model matches the current value.
- tests_to_write:
  - Unit test that updates `[llm].default_model` without altering other sections.
  - Unit test that no-op update preserves file contents.
- documentation_update:
  - None.

## Task 4
- slug: ollama-model-install-integration
- title: Install phi3.5 model when accepted
- description: If user accepts, run `ollama pull phi3.5:3.8b` and report success or a non-fatal warning on failure.
- dependencies: [ollama-model-prompt-flow]
- tags: [npm, installer, ollama, model-install]
- files_to_touch:
  - npm/lib/postinstall_setup.js
  - npm/test/postinstall_setup.test.js
- acceptance_criteria:
  - `ollama pull phi3.5:3.8b` is executed on acceptance.
  - Failures are logged as warnings without failing npm install.
- tests_to_write:
  - Unit test for command invocation with mocked `spawnSync`.
- documentation_update:
  - Mention install flow and model size in `README.md` and `npm/README.md`.

## Task 5
- slug: ollama-model-docs-and-tests
- title: Docs + regression coverage
- description: Update docs and ensure npm tests cover the prompt flow and config updates.
- dependencies: [ollama-model-config-update, ollama-model-install-integration]
- tags: [docs, tests, npm]
- files_to_touch:
  - npm/test/postinstall_setup.test.js
  - README.md
  - npm/README.md
  - docs/sds/sdsv2.1.md
- acceptance_criteria:
  - `README.md` and `npm/README.md` mention the model prompt, model size, and env overrides.
  - `npm/test/postinstall_setup.test.js` includes prompt and config tests.
  - All npm tests pass locally.
- tests_to_write:
  - Extend existing postinstall tests to cover prompt and config paths.
- documentation_update:
  - `README.md`
  - `npm/README.md`
  - Optional: `docs/sds/sdsv2.1.md` if defaults are documented.
