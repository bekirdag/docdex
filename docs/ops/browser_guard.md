# Browser Guard (Chrome watchdog + session lifecycle)

This repo’s “browser guard” is implemented by:

- `src/browser_session.rs`: spawns a browser process (new process group on Unix) and owns idempotent cleanup (SIGTERM → SIGKILL escalation) when the session is closed or dropped.
- `src/web/scraper.rs`: tracks browser processes and periodically reaps orphaned/unhealthy ones.
- `src/tier2.rs`: applies a concurrency cap (semaphore) and emits structured overload fallback logs.

## What to look for

**Logs**

- Target `docdexd_browser_guard`:
  - `event=browser_session_started` / `event=browser_session_cleanup_*` (start/stop + cleanup outcomes)
  - `event=browser_session_kill_escalation` (SIGTERM → SIGKILL escalation)
  - `event=chrome_watchdog_session_*` (tracking lifecycle)
- Target `docdexd`:
  - `event=chrome_watchdog_reap_*` (reaper actions + outcomes)
- Target `docdexd_tier2`:
  - `event=tier2_overload_fallback` (capacity exhausted → fallback path taken; includes `backoff_code`, `retry_after_ms`, `limit_key=chrome_concurrency`, `scope=tier2`)
  - Web throttling (DDG discovery, per-domain fetch pacing) should emit the same backoff fields when those components are enabled.

**Metrics**

`GET /metrics` includes:

- `docdex_browser_sessions_active` (gauge)
- `docdex_tier2_permits_in_use` (gauge)
- `docdex_tier2_overload_rejections_total` (counter)
- `docdex_browser_session_launch_failures_total` (counter)
- `docdex_chrome_watchdog_reaped_total` (counter)

## Config (Chrome watchdog)

Chrome watchdog config is environment-driven:

- `DOCDEX_CHROME_WATCHDOG_ENABLED` (boolish; default `true`)
- `DOCDEX_CHROME_WATCHDOG_SCAN_INTERVAL_MS` (default `5000`, minimum `10`)
- `DOCDEX_CHROME_WATCHDOG_ORPHAN_REAP_AFTER_MS` (default `30000`)
- `DOCDEX_CHROME_WATCHDOG_GRACEFUL_TIMEOUT_MS` (default `2000`, minimum `10`)
- `DOCDEX_CHROME_WATCHDOG_KILL_TIMEOUT_MS` (default `2000`, minimum `10`)
- `DOCDEX_CHROME_WATCHDOG_MAX_SESSION_AGE_MS` (default `604800000`, seven days)
- `DOCDEX_CHROME_WATCHDOG_UNRESPONSIVE_TIMEOUT_MS` (optional; unset by default; only enforced for sessions that send heartbeats)

If the watchdog is initialized without a Tokio runtime, it logs once and starts periodic
reaping automatically the next time the global tracker is accessed from a runtime.

## Security defaults and capture bounds

- Chromium runs with its sandbox enabled by default. `--no-sandbox` is added only when
  `DOCDEX_CHROME_ALLOW_NO_SANDBOX` is explicitly set to a true boolish value; Docdex logs
  a warning when this escape hatch is used.
- `DOCDEX_WEB_CHROME_MAX_HTML_CHARS` bounds captured DOM HTML (default `1500000`).
- `DOCDEX_WEB_CHROME_MAX_TEXT_CHARS` bounds each captured DOM text representation
  (default `500000`). Values below `1024` are raised to `1024`.
- Short-lived local `web-fetch` and `web-rag` commands explicitly stop their owned
  Chromium process tree before the CLI runtime exits. Daemons keep Chromium alive for
  reuse, then explicitly close the global manager during bounded SIGINT/SIGTERM shutdown;
  the watchdog remains a fallback for unhealthy or orphaned sessions.
- Chromium resolves and pins the requested host to a validated public address for the
  lifetime of the host-specific browser instance. Paused HTTP(S) requests are rechecked,
  and cross-host redirects/subresources are blocked so they cannot bypass that pin.
- Chromium requests an ephemeral debugging port (`--remote-debugging-port=0`) and accepts
  `DevToolsActivePort` only after strict port/token validation inside the owned profile.
- The host-pinning SOCKS5 proxy accepts only the expected host and connects it to the
  prevalidated public address, caps itself at 32 concurrent connections, and enforces a
  64 MiB aggregate transfer budget by default
  (`DOCDEX_WEB_CHROME_MAX_TRANSFER_BYTES`).
- Target interception is applied recursively to the page and out-of-process iframe
  targets. Popups, workers, service workers, and unknown auxiliary targets start paused
  and are closed. Cache use and browser downloads are denied so they cannot create an
  unguarded network path or persistent response channel.
- Persistent profiles with ambiguous or stale Chromium singleton markers fall back
  conservatively to an isolated temporary profile instead of deleting uncertain state.
- Direct HTTP web clients use a connection-time resolver that rejects local, reserved,
  private, mixed public/private, and rebound DNS answers. Blocking platform lookups hold
  one of 16 global permits until the underlying call actually ends, even if its caller
  times out, preventing abandoned DNS work from exhausting the blocking pool.

## Managed browser installation and updates

- The managed `manifest.json` is capped at 64 KiB and must describe the current
  platform's `chrome-headless-shell` artifact with a non-empty stable version, the exact
  Docdex-managed executable path, and the exact official Chrome-for-Testing storage URL.
  The executable must be a regular executable file; legacy, relocated, symlinked, or
  non-executable manifests are ignored.
- Auto-install checks the Chrome stable channel again after 24 hours by default. A valid
  install whose successful check is still fresh is used without any network request.
  `DOCDEX_BROWSER_AUTO_UPDATE=false` disables periodic checks while preserving the valid
  managed install. `DOCDEX_BROWSER_UPDATE_CHECK_INTERVAL_SECS` overrides the interval
  (`0` checks every time; values above 30 days are capped). An explicit browser install
  still checks the stable channel immediately.
- If an automatic due update check or download fails, Docdex logs the failure and
  continues with the previously validated executable. A successful no-change check
  atomically refreshes the manifest's `last_checked_at` timestamp. An explicit install
  reports refresh failures while leaving the validated existing executable available.
- Only one installer runs per process. Concurrent callers immediately reuse a valid
  existing install, or receive a retryable in-progress error when no install exists, so
  they do not occupy the blocking worker pool waiting behind the same download.
- Cross-process installation uses a timed file lock rather than an unbounded wait.
  `DOCDEX_BROWSER_INSTALL_LOCK_TIMEOUT_MS` defaults to 30000 and is capped at 300000.
- Browser promotion keeps the last validated install in a rollback directory until the
  new manifest is durably written. A later installer run restores that backup after an
  interrupted promotion, or removes it only after the new install validates.

## Tuning notes

- **Overload** (`event=tier2_overload_fallback`, `docdex_tier2_permits_in_use` pinned): increase Tier 2 concurrency where the limiter is configured, or reduce concurrent Tier 2 callers.
- **Orphans/Zombies** (rising `docdex_chrome_watchdog_reaped_total`): increase `DOCDEX_CHROME_WATCHDOG_ORPHAN_REAP_AFTER_MS` if legitimate sessions are long-running, or reduce timeouts if cleanup is too slow.
- **Frequent SIGKILL escalation** (`event=browser_session_kill_escalation`): increase graceful timeouts, or investigate browser subprocesses that ignore SIGTERM.
