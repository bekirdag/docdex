#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="dry"
KEEP_DAEMON=0
REPO_ROOT="${ROOT_DIR}"

usage() {
  cat <<'USAGE'
Usage: scripts/test_single_daemon.sh [--real] [--keep-daemon] [--repo <path>]

Default is a dry run (isolated HOME) that cleans up after itself.
--real runs against your actual HOME and leaves config changes in place.
--keep-daemon keeps the daemon running after the test (real mode only).
USAGE
}

log() {
  printf "[single-daemon] %s\n" "$*" >&2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --real)
      MODE="real"
      shift
      ;;
    --keep-daemon)
      KEEP_DAEMON=1
      shift
      ;;
    --repo)
      REPO_ROOT="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      log "unknown arg: $1"
      usage
      exit 2
      ;;
  esac
done

if [[ ! -d "${REPO_ROOT}" ]]; then
  log "repo path not found: ${REPO_ROOT}"
  exit 1
fi

DOCDEX_BIN="${DOCDEX_BIN:-}"
if [[ -z "${DOCDEX_BIN}" && -x "${ROOT_DIR}/target/release/docdexd" ]]; then
  DOCDEX_BIN="${ROOT_DIR}/target/release/docdexd"
elif [[ -z "${DOCDEX_BIN}" && -x "${ROOT_DIR}/target/debug/docdexd" ]]; then
  DOCDEX_BIN="${ROOT_DIR}/target/debug/docdexd"
else
  DOCDEX_BIN="${DOCDEX_BIN:-docdexd}"
fi

pick_free_port() {
  python3 - <<'PY'
import socket
import sys
try:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        print(s.getsockname()[1])
except PermissionError:
    sys.exit(2)
PY
}

wait_for_health() {
  local base_url="$1"
  local deadline=$((SECONDS + 20))
  while (( SECONDS < deadline )); do
    if curl -fsS "${base_url}/healthz" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.2
  done
  return 1
}

TEMP_HOME=""
if [[ "${MODE}" == "dry" ]]; then
  TEMP_HOME="$(mktemp -d)"
  export HOME="${TEMP_HOME}"
  log "dry-run HOME=${HOME}"
else
  log "real mode; HOME=${HOME}"
fi

PORT="${DOCDEX_DAEMON_PORT:-}"
if [[ -z "${PORT}" ]]; then
  set +e
  PORT="$(pick_free_port)"
  status=$?
  set -e
  if [[ "${status}" == "2" ]]; then
    log "skipping single-daemon test: TCP bind not permitted in this environment"
    exit 0
  fi
  if [[ "${status}" != "0" ]]; then
    log "failed to pick a free port"
    exit 1
  fi
fi

BASE_URL="http://127.0.0.1:${PORT}"
LOCK_PATH="${HOME}/.docdex/daemon.lock"
export DOCDEX_DAEMON_PORT="${PORT}"

if [[ "${MODE}" == "dry" ]]; then
  export DOCDEX_DAEMON_LOCK_PATH="${LOCK_PATH}"
fi

cleanup() {
  if [[ "${KEEP_DAEMON}" == "1" && "${MODE}" == "real" ]]; then
    return
  fi
  if [[ -f "${LOCK_PATH}" ]]; then
    local pid
    pid="$(python3 - <<PY
import json
try:
    with open("${LOCK_PATH}", "r", encoding="utf-8") as f:
        data=json.load(f)
    print(data.get("pid",""))
except Exception:
    print("")
PY
)"
    if [[ -n "${pid}" ]]; then
      kill "${pid}" >/dev/null 2>&1 || true
    fi
  fi
  if [[ -n "${TEMP_HOME}" ]]; then
    rm -rf "${TEMP_HOME}"
  fi
}
trap cleanup EXIT

log "running postinstall setup (port ${PORT})"
node -e "require('./npm/lib/postinstall_setup').runPostInstallSetup({binaryPath:'${DOCDEX_BIN}'})"

log "waiting for daemon healthz"
if ! wait_for_health "${BASE_URL}"; then
  log "daemon did not respond at ${BASE_URL}"
  exit 1
fi

log "checking lockfile"
if [[ ! -f "${LOCK_PATH}" ]]; then
  log "missing lockfile at ${LOCK_PATH}"
  exit 1
fi

log "checking config injection"
if ! rg "http_bind_addr\\s*=\\s*\"127\\.0\\.0\\.1:${PORT}\"" "${HOME}/.docdex/config.toml" >/dev/null 2>&1; then
  log "config.toml missing http_bind_addr"
  exit 1
fi
if ! rg "enable_mcp\\s*=\\s*true" "${HOME}/.docdex/config.toml" >/dev/null 2>&1; then
  log "config.toml missing enable_mcp"
  exit 1
fi
if ! rg "docdex" "${HOME}/.cursor/mcp.json" >/dev/null 2>&1; then
  log "cursor config missing docdex"
  exit 1
fi
if ! rg "docdex" "${HOME}/.codex/config.toml" >/dev/null 2>&1; then
  log "codex config missing docdex"
  exit 1
fi
if ! rg "docdex" "${HOME}/Library/Application Support/Claude/claude_desktop_config.json" >/dev/null 2>&1; then
  log "claude config missing docdex (ok if claude not used)"
fi

log "checking single-daemon lock rejection"
SECOND_OUTPUT="$("${DOCDEX_BIN}" daemon --repo "${REPO_ROOT}" --host 127.0.0.1 --port "${PORT}" --log warn --secure-mode=false 2>&1)"
if ! printf "%s" "${SECOND_OUTPUT}" | grep -q "already running"; then
  log "expected already-running message but got: ${SECOND_OUTPUT}"
  exit 1
fi
if ! printf "%s" "${SECOND_OUTPUT}" | grep -q "pid="; then
  log "expected pid in already-running message but got: ${SECOND_OUTPUT}"
  exit 1
fi
if ! printf "%s" "${SECOND_OUTPUT}" | grep -q "port=${PORT}"; then
  log "expected port in already-running message but got: ${SECOND_OUTPUT}"
  exit 1
fi

log "checking stale lock recovery"
if [[ -f "${LOCK_PATH}" ]]; then
  pid="$(python3 - <<PY
import json
try:
    with open("${LOCK_PATH}", "r", encoding="utf-8") as f:
        data=json.load(f)
    print(data.get("pid",""))
except Exception:
    print("")
PY
)"
  if [[ -n "${pid}" ]]; then
    kill "${pid}" >/dev/null 2>&1 || true
  fi
fi
sleep 0.3

log "starting daemon after stale lock"
"${DOCDEX_BIN}" daemon --repo "${REPO_ROOT}" --host 127.0.0.1 --port "${PORT}" --log warn --secure-mode=false >/dev/null 2>&1 &
if ! wait_for_health "${BASE_URL}"; then
  log "daemon did not restart after stale lock"
  exit 1
fi

log "checking initialize triggers mount"
curl -fsS -H "content-type: application/json" \
  -X POST "${BASE_URL}/v1/initialize" \
  -d "{\"rootUri\":\"${REPO_ROOT}\"}" >/dev/null

log "single-daemon test passed"
