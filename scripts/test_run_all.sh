#!/usr/bin/env bash
set -u -o pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="${ROOT_DIR}/target/test_logs"
DOCDEX_HTTP_BASE_URL="${DOCDEX_HTTP_BASE_URL:-http://127.0.0.1:3210}"
USE_EXISTING_SERVER="${DOCDEX_USE_EXISTING_SERVER:-0}"
API_BASE_URL=""
API_SERVER_PID=""
API_SERVER_STATE_DIR=""
API_SERVER_LOCK_PATH=""

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
  curl -fsS "${API_BASE_URL}/healthz" >/dev/null 2>&1
}

pick_free_port() {
  python3 - <<'PY'
import socket
with socket.socket() as s:
    s.bind(("127.0.0.1", 0))
    print(s.getsockname()[1])
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

start_api_server() {
  if [[ "${USE_EXISTING_SERVER}" == "1" ]]; then
    API_BASE_URL="${DOCDEX_HTTP_BASE_URL}"
    if ! check_server; then
      log "docdexd server not reachable at ${API_BASE_URL}"
      return 1
    fi
    return 0
  fi

  local port
  port="$(pick_free_port)"
  API_BASE_URL="http://127.0.0.1:${port}"
  API_SERVER_STATE_DIR="$(mktemp -d "${LOG_DIR}/run_all_state.XXXX")"
  API_SERVER_LOCK_PATH="$(mktemp "${LOG_DIR}/run_all_lock.XXXX")"
  rm -f "${API_SERVER_LOCK_PATH}"
  DOCDEX_STATE_DIR="${API_SERVER_STATE_DIR}" \
    DOCDEX_DAEMON_LOCK_PATH="${API_SERVER_LOCK_PATH}" \
    DOCDEX_ENABLE_MCP=0 \
    "${DOCDEX_BIN}" daemon \
    --repo "${ROOT_DIR}" \
    --host 127.0.0.1 \
    --port "${port}" \
    --log warn \
    --secure-mode=false \
    --disable-mcp \
    >/dev/null 2>&1 &
  API_SERVER_PID=$!
  if ! wait_for_health "${API_BASE_URL}"; then
    log "docdexd server not reachable at ${API_BASE_URL}"
    return 1
  fi
  return 0
}

stop_api_server() {
  if [[ -n "${API_SERVER_PID}" ]]; then
    kill "${API_SERVER_PID}" >/dev/null 2>&1 || true
    wait "${API_SERVER_PID}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${API_SERVER_LOCK_PATH}" && -f "${API_SERVER_LOCK_PATH}" ]]; then
    rm -f "${API_SERVER_LOCK_PATH}"
  fi
  if [[ -n "${API_SERVER_STATE_DIR}" && -d "${API_SERVER_STATE_DIR}" ]]; then
    rm -rf "${API_SERVER_STATE_DIR}"
  fi
}

trap stop_api_server EXIT

FAILURES=0
RESULTS=()

run_step "unit_component" cargo test --lib
if command -v node >/dev/null 2>&1 && [[ -f "${ROOT_DIR}/npm/test/postinstall_setup.test.js" ]]; then
  run_step "unit_node_postinstall" node --test "${ROOT_DIR}/npm/test/postinstall_setup.test.js"
fi
if command -v node >/dev/null 2>&1 && [[ -f "${ROOT_DIR}/npm/test/installer_local_fallback.test.js" ]]; then
  run_step "unit_node_installer_local" node --test "${ROOT_DIR}/npm/test/installer_local_fallback.test.js"
fi
if command -v node >/dev/null 2>&1 && [[ -f "${ROOT_DIR}/npm/test/uninstall.test.js" ]]; then
  run_step "unit_node_uninstall" node --test "${ROOT_DIR}/npm/test/uninstall.test.js"
fi
run_step "unit_ignore_rules" cargo test --lib file_decision_tests
run_step "unit_repo_manager_lru" cargo test --lib repo_manager_
run_step "integration" cargo test --tests

if start_api_server; then
  run_step "api_http" env DOCDEX_HTTP_BASE_URL="${API_BASE_URL}" "${ROOT_DIR}/scripts/test_api_http.sh"
  run_step "api_profile_evolution" env DOCDEX_HTTP_BASE_URL="${API_BASE_URL}" "${ROOT_DIR}/scripts/test_profile_evolution.sh"
  run_step "api_hooks" env DOCDEX_HTTP_BASE_URL="${API_BASE_URL}" "${ROOT_DIR}/scripts/test_hooks_end_to_end.sh" "${ROOT_DIR}"
  run_step "api_mcp" env DOCDEX_BIN="${DOCDEX_BIN}" DOCDEX_HTTP_BASE_URL="${API_BASE_URL}" "${ROOT_DIR}/scripts/test_mcp_http.sh" "${ROOT_DIR}"
else
  log "docdexd server not reachable; skipping API scripts"
  RESULTS+=("api_http|fail|missing_server")
  RESULTS+=("api_profile_evolution|fail|missing_server")
  RESULTS+=("api_hooks|fail|missing_server")
  RESULTS+=("api_mcp|fail|missing_server")
  FAILURES=$((FAILURES + 4))
fi

if [[ "${DOCDEX_RUN_EXTENDED_TESTS:-0}" == "1" ]]; then
  if [[ -x "${ROOT_DIR}/scripts/test_v2_1.sh" ]]; then
    run_step "extended_v2_1" env DOCDEX_BIN="${DOCDEX_BIN}" "${ROOT_DIR}/scripts/test_v2_1.sh"
  fi
  if [[ -x "${ROOT_DIR}/scripts/test_e2e.sh" ]]; then
    run_step "extended_e2e" env DOCDEXD_BIN="${DOCDEX_BIN}" "${ROOT_DIR}/scripts/test_e2e.sh"
  fi
  if [[ -x "${ROOT_DIR}/scripts/test_ast.sh" ]]; then
    run_step "extended_ast" env DOCDEX_BIN="${DOCDEX_BIN}" "${ROOT_DIR}/scripts/test_ast.sh"
  fi
  if [[ "${DOCDEX_RUN_MEMORY_DAG:-0}" == "1" && -x "${ROOT_DIR}/scripts/test_memory_dag.sh" ]]; then
    run_step "extended_memory_dag" env DOCDEXD_BIN="${DOCDEX_BIN}" "${ROOT_DIR}/scripts/test_memory_dag.sh"
  fi
  if command -v npm >/dev/null 2>&1 && [[ -f "${ROOT_DIR}/npm/package.json" ]]; then
    run_step "extended_node" bash -c "cd \"${ROOT_DIR}/npm\" && npm test"
  fi
  if [[ -f "${ROOT_DIR}/scripts/test_playwright_install.sh" ]]; then
    run_step "extended_playwright_install" bash "${ROOT_DIR}/scripts/test_playwright_install.sh"
  fi
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
