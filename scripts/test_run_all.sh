#!/usr/bin/env bash
set -u -o pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="${ROOT_DIR}/target/test_logs"
DOCDEX_HTTP_BASE_URL="${DOCDEX_HTTP_BASE_URL:-http://127.0.0.1:3210}"

if [[ -z "${DOCDEX_BIN:-}" && -x "${ROOT_DIR}/target/debug/docdexd" ]]; then
  DOCDEX_BIN="${ROOT_DIR}/target/debug/docdexd"
else
  DOCDEX_BIN="${DOCDEX_BIN:-docdexd}"
fi

mkdir -p "${LOG_DIR}"

log() {
  printf "[run-all] %s\n" "$*" >&2
}

run_step() {
  local name="$1"
  shift
  local safe_name
  safe_name="${name//[^a-zA-Z0-9._-]/_}"
  local log_file="${LOG_DIR}/${safe_name}.log"
  log "start: ${name}"
  if "$@" >"${log_file}" 2>&1; then
    RESULTS+=("${name}|ok|${log_file}")
    log "ok: ${name}"
  else
    RESULTS+=("${name}|fail|${log_file}")
    FAILURES=$((FAILURES + 1))
    log "fail: ${name} (see ${log_file})"
    log "---- tail ${name} ----"
    tail -n 200 "${log_file}" >&2 || true
    log "---- end ${name} ----"
  fi
}

check_server() {
  curl -fsS "${DOCDEX_HTTP_BASE_URL}/healthz" >/dev/null 2>&1
}

FAILURES=0
RESULTS=()

run_step "unit_component" cargo test --lib
run_step "integration" cargo test --tests

if check_server; then
  run_step "api_http" "${ROOT_DIR}/scripts/test_api_http.sh"
  run_step "api_profile_evolution" "${ROOT_DIR}/scripts/test_profile_evolution.sh"
  run_step "api_hooks" "${ROOT_DIR}/scripts/test_hooks_end_to_end.sh" "${ROOT_DIR}"
  run_step "api_mcp" env DOCDEX_BIN="${DOCDEX_BIN}" "${ROOT_DIR}/scripts/test_mcp_http.sh" "${ROOT_DIR}"
else
  log "docdexd server not reachable at ${DOCDEX_HTTP_BASE_URL}; skipping API scripts"
  RESULTS+=("api_http|fail|missing_server")
  RESULTS+=("api_profile_evolution|fail|missing_server")
  RESULTS+=("api_hooks|fail|missing_server")
  RESULTS+=("api_mcp|fail|missing_server")
  FAILURES=$((FAILURES + 4))
fi

log "summary:"
for entry in "${RESULTS[@]}"; do
  IFS='|' read -r name status location <<<"${entry}"
  log "${status}: ${name} (${location})"
  unset IFS
  done

if [[ "${FAILURES}" -ne 0 ]]; then
  log "run-all failed: ${FAILURES} step(s) failed"
  exit 1
fi

log "run-all passed"
