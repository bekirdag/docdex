# Chromium Browser Support Plan

## Goal
Provide consistent headless web scraping across macOS, Windows, and Linux using a single, Docdex-managed Chromium download. Persist the resolved binary path and keep user profile data stable.

## Current Approach
- Detection priority: env overrides → config → Docdex Chromium manifest → system Chromium paths.
- Auto-install downloads Chrome for Testing (Chromium) into `~/.docdex/state/bin/chromium/` and writes `manifest.json`.
- Config persistence: `web.scraper.chrome_binary_path` + `web.scraper.browser_kind = "chromium"`.
- Profiles: `web.scraper.user_data_dir` remains stable (default `~/.docdex/state/browser_profiles/chrome`).

## Controls
- `DOCDEX_BROWSER_AUTO_INSTALL=0` disables Chromium auto-install.
- `DOCDEX_BROWSER_INSTALL=chromium|skip` preselects Chromium installation during setup.

## CLI Helpers
- `docdexd browser list` — show candidates and selected binary.
- `docdexd browser setup` — run discovery + auto-install and persist config.
- `docdexd browser install` — force Chromium install.

## Tests
- Detection ordering + env precedence.
- Manifest parsing + diagnostics.
- Config persistence without overwriting `user_data_dir`.
