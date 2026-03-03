# FD Exhaustion Playbook

This runbook is for intermittent Docdex instability caused by low file descriptor (FD) limits, usually visible as `EMFILE` and lock/open failures.

## Symptoms
- `daemon.err.log` contains repeated `Too many open files` / `EMFILE` / `ENFILE`.
- Profile memory writes fail intermittently around lock-file open/lock operations (`profiles.lock`).
- Indexing or state updates intermittently fall back to read-only behavior.
- Startup warning includes: `low open-file soft limit detected`.

## Detection

### 1) Check daemon health
```bash
curl -sS http://127.0.0.1:28491/healthz
```
Expected: `ok`

### 2) Check daemon error log for FD pressure
```bash
rg -n "EMFILE|ENFILE|Too many open files|profile lock transient error|failed after .* attempts" ~/.docdex/logs/daemon.err.log
```
Expected during incident: one or more matches.

### 3) Inspect current process FD limits
macOS/Linux shell limit:
```bash
ulimit -n
```
launchd-managed process limits (macOS):
```bash
launchctl limit maxfiles
```
Expected healthy baseline for launchd-managed daemon: soft limit well above `4096`.

### 4) Validate startup warning threshold
```bash
echo "${DOCDEX_MIN_NOFILE_SOFT:-4096}"
```
If threshold is intentionally customized, confirm it matches fleet policy.

## Immediate Mitigation

### macOS LaunchAgent
1. Re-run installer/setup registration to refresh plist defaults.
2. Verify LaunchAgent plist includes:
- `SoftResourceLimits -> NumberOfFiles = 65536`
- `HardResourceLimits -> NumberOfFiles = 200000`

Check quickly:
```bash
PLIST="$HOME/Library/LaunchAgents/com.docdex.daemon.plist"
plutil -p "$PLIST" | rg "SoftResourceLimits|HardResourceLimits|NumberOfFiles"
```

3. Restart service:
```bash
launchctl bootout "gui/$(id -u)" com.docdex.daemon || true
launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/com.docdex.daemon.plist"
launchctl kickstart -k "gui/$(id -u)/com.docdex.daemon"
```

### Linux systemd user service
Set/increase unit-level FD limit (`LimitNOFILE`) and restart:
```bash
systemctl --user daemon-reload
systemctl --user restart docdexd.service
```

## Pressure-Reduction Knobs
These defaults are applied by installer startup registration and can be tuned if needed:
- `DOCDEX_REPO_IDLE_SECONDS=300`
- `DOCDEX_REPO_HIBERNATE_SECONDS=1800`
- `DOCDEX_REPO_CLEANUP_INTERVAL_SECONDS=60`
- `DOCDEX_WEB_MAX_CONCURRENT_BROWSER_FETCHES=1`
- `DOCDEX_WEB_MAX_CONCURRENT_LLM=1`

Profile lock retry knobs:
- `DOCDEX_PROFILE_LOCK_MAX_ATTEMPTS` (default `5`)
- `DOCDEX_PROFILE_LOCK_RETRY_BASE_MS` (default `25` ms)

Startup warning threshold:
- `DOCDEX_MIN_NOFILE_SOFT` (default `4096`)

## Verification Checklist
1. `GET /healthz` returns `ok`.
2. Startup warning for low nofile is absent (unless intentionally configured low).
3. No fresh `EMFILE`/`ENFILE` log lines during normal traffic.
4. Profile writes succeed repeatedly (no lock retry exhaustion messages).
5. `cargo test --lib daemon::fd_limits` and `cargo test --lib profiles::manager` pass in CI/local validation.

## Escalation Criteria
Escalate if any remains true after mitigation:
- Repeated `EMFILE` bursts within the same hour.
- Persistent lock retry exhaustion for `profiles.lock`.
- Health endpoint flaps or repeated read-only fallback behavior.

Collect and attach:
- `~/.docdex/logs/daemon.err.log` excerpt around incident window.
- LaunchAgent/systemd unit definition in effect.
- `launchctl limit maxfiles` or equivalent FD-limit evidence.
