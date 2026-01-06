# Browser Auto-Install (Playwright)

Docdex can auto-install a Playwright-managed Chromium build on macOS, Windows, and Linux when no browser is detected. This replaces the Linux-only Chrome-for-Testing download.

## How It Works
- On config load, Docdex runs browser discovery (env → config → Playwright manifest → system).
- If no browser is found and auto-install is enabled, Docdex runs the Playwright installer helper to download Chromium into `~/.docdex/state/bin/playwright/`.
- The resolved path is persisted to `web.scraper.chrome_binary_path` and `web.scraper.browser_kind`.

## Controls
- Config:
  - `[web.scraper] auto_install = true|false` (default: true)
  - `[web.scraper] chrome_binary_path = "/path/to/browser"`
  - `[web.scraper] browser_kind = "chromium"` (informational)
- Env overrides:
  - `DOCDEX_BROWSER_AUTO_INSTALL=0` disables auto-install.
  - `PLAYWRIGHT_BROWSERS_PATH=/path/to/cache` overrides the Playwright install location.
  - `DOCDEX_PLAYWRIGHT_INSTALLER=/path/to/npm/lib/playwright_install.js` points to the installer script (needed for non-npm installs).

## CLI Helpers
- `docdexd browser list` — show candidates and selected binary.
- `docdexd browser setup` — run discovery + auto-install and persist config.
- `docdexd browser install` — force Playwright install (all platforms).

## Troubleshooting
- If web fetch fails with "browser not available", run `docdexd browser setup`.
- If the Playwright installer script cannot be found, set `DOCDEX_PLAYWRIGHT_INSTALLER` to `npm/lib/playwright_install.js` or install Docdex via npm.
