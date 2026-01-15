# Browser Auto-Install (Chromium)

Docdex can auto-install a Chromium build on macOS, Windows, and Linux when no browser is detected. The download is placed under `~/.docdex/state/bin/chromium/` with a `manifest.json` that records the installed version and binary path.

## How It Works
- On config load, Docdex runs browser discovery (env → config → Chromium manifest → system).
- If no browser is found and auto-install is enabled, Docdex downloads Chromium (Chrome for Testing) into `~/.docdex/state/bin/chromium/`.
- The resolved path is persisted to `web.scraper.chrome_binary_path` and `web.scraper.browser_kind`.

## Controls
- Config:
  - `[web.scraper] auto_install = true|false` (default: true)
  - `[web.scraper] chrome_binary_path = "/path/to/chromium"`
  - `[web.scraper] browser_kind = "chromium"` (informational)
- Env overrides:
  - `DOCDEX_BROWSER_AUTO_INSTALL=0` disables auto-install.
  - `DOCDEX_WEB_BROWSER=/path/to/chromium` or `DOCDEX_CHROME_PATH=/path/to/chromium` overrides discovery.

## CLI Helpers
- `docdexd browser list` — show candidates and selected binary.
- `docdexd browser setup` — run discovery + auto-install and persist config.
- `docdexd browser install` — force Chromium install (all platforms).

## Troubleshooting
- If web fetch fails with "browser not available", run `docdexd browser install`.
- If you already have Chromium installed, set `DOCDEX_WEB_BROWSER` to its binary path.
