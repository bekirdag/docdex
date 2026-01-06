# Multi-Browser Support Plan

## Goal
Provide consistent headless web scraping across macOS, Windows, and Linux using Playwright-managed browsers. Chromium is installed by default; Firefox/WebKit are optional. Persist the resolved binary path and keep user profile data stable.

## Current Approach
- Detection priority: env overrides → config → Playwright manifest → system browsers.
- Auto-install uses Playwright on all OSes and writes a manifest under `~/.docdex/state/bin/playwright/`.
- Config persistence: `web.scraper.chrome_binary_path` + `web.scraper.browser_kind`.
- Profiles: `web.scraper.user_data_dir` remains stable (default `~/.docdex/state/browser_profiles/chrome`).

## Phases
1. **Discovery + config wiring**: multi-browser detection (Chrome/Chromium/Edge/Brave/Vivaldi), env overrides, config persistence.
2. **Playwright installer**: helper for Chromium default + optional Firefox/WebKit; manifest tracking.
3. **Setup UX**: `docdex setup` browser selection (default Chromium) with `DOCDEX_BROWSER_INSTALL=chromium,firefox,webkit`.
4. **Profile continuity**: never overwrite `user_data_dir`; default stays under `browser_profiles/chrome`.
5. **Diagnostics + docs**: `docdexd check` reports Playwright availability and manifest details.
6. **Optional engine**: future `web.scraper.engine = "playwright"` to drive Firefox/WebKit scraping.

## Controls
- `DOCDEX_BROWSER_AUTO_INSTALL=0` disables Playwright auto-install.
- `PLAYWRIGHT_BROWSERS_PATH=/path` overrides the Playwright install cache.
- `DOCDEX_BROWSER_INSTALL=chromium,firefox,webkit` preselects browsers during setup.

## CLI Helpers
- `docdexd browser list` — show candidates and selected binary.
- `docdexd browser setup` — run discovery + auto-install and persist config.
- `docdexd browser install` — force Playwright install.

## Tests
- Detection ordering + env precedence.
- Config persistence without overwriting `user_data_dir`.
- Playwright manifest parsing + diagnostics.
