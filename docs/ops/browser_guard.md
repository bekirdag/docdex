# Browser Guard (Chrome watchdog + session lifecycle)

This repo’s “browser guard” is implemented by:

- `src/browser_session.rs`: spawns a browser process (new process group on Unix) and guarantees cleanup (SIGTERM → SIGKILL escalation).
- `src/chrome_watchdog.rs`: tracks browser processes and periodically reaps orphaned/unhealthy ones.
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
- `DOCDEX_CHROME_WATCHDOG_MAX_SESSION_AGE_MS` (optional; unset by default)
- `DOCDEX_CHROME_WATCHDOG_UNRESPONSIVE_TIMEOUT_MS` (optional; unset by default; only enforced for sessions that send heartbeats)

If the watchdog is initialized without a Tokio runtime, periodic reaping is disabled and a warning is logged (target `docdexd`).

## Tuning notes

- **Overload** (`event=tier2_overload_fallback`, `docdex_tier2_permits_in_use` pinned): increase Tier 2 concurrency where the limiter is configured, or reduce concurrent Tier 2 callers.
- **Orphans/Zombies** (rising `docdex_chrome_watchdog_reaped_total`): increase `DOCDEX_CHROME_WATCHDOG_ORPHAN_REAP_AFTER_MS` if legitimate sessions are long-running, or reduce timeouts if cleanup is too slow.
- **Frequent SIGKILL escalation** (`event=browser_session_kill_escalation`): increase graceful timeouts, or investigate browser subprocesses that ignore SIGTERM.
