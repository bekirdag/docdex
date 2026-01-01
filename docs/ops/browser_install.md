# Browser Auto-Install (Linux)

Docdex can auto-install a headless Chromium build on Linux when no browser is detected. macOS and Windows use whatever headless-capable browsers are already installed (Chrome/Chromium/Edge/Brave/Vivaldi).

## How It Works
- On config load, Docdex runs browser discovery.
- If no browser is found and auto-install is enabled, Docdex downloads a pinned Chromium build and stores it under `~/.docdex/state/bin/chromium/`.
- The resolved path is persisted to `web.scraper.chrome_binary_path` and `web.scraper.browser_kind` in `~/.docdex/config.toml`.

## Controls
- Config:
  - `[web.scraper] auto_install = true|false` (default: true on Linux)
  - `[web.scraper] chrome_binary_path = "/path/to/browser"`
  - `[web.scraper] browser_kind = "chromium"` (informational)
- Env overrides:
  - `DOCDEX_BROWSER_AUTO_INSTALL=0` disables auto-install.
  - `DOCDEX_BROWSER_DOWNLOAD_BASE`, `DOCDEX_BROWSER_VERSION`, `DOCDEX_BROWSER_SHA256` override the pinned download URL and checksum (air-gapped mirrors).

## CLI Helpers
- `docdexd browser list` — show candidates and selected binary.
- `docdexd browser setup` — run discovery + auto-install and persist config.
- `docdexd browser install` — force install (Linux only).

## Troubleshooting
- If web fetch fails with "browser not available", run `docdexd browser setup`.
- If you want to use a custom browser binary, set `DOCDEX_WEB_BROWSER` or `web.scraper.chrome_binary_path`.
