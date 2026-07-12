#!/usr/bin/env bash
set -u -o pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="${ROOT_DIR}/target/test_logs"
DOCDEX_HTTP_BASE_URL="${DOCDEX_HTTP_BASE_URL:-http://127.0.0.1:28491}"
USE_EXISTING_SERVER="${DOCDEX_USE_EXISTING_SERVER:-0}"
ALLOW_EXISTING_SERVER_MUTATION="${DOCDEX_ALLOW_EXISTING_SERVER_MUTATION:-0}"
API_BASE_URL=""
API_SERVER_PID=""
API_SERVER_WORK_DIR=""
API_SERVER_STATE_DIR=""
API_SERVER_HOME_DIR=""
API_SERVER_GLOBAL_STATE_DIR=""
API_SERVER_LOCK_PATH=""
MEMORY_DAG_WORKDIR=""
export DOCDEX_TEST_ALLOW_MULTI_DAEMON="${DOCDEX_TEST_ALLOW_MULTI_DAEMON:-1}"

log() {
  printf "[run-all] %s\n" "$*" >&2
}

usage() {
  cat <<'USAGE'
Usage: scripts/test_run_all.sh [--help]

Runs the default unit, integration, and isolated API suites.

Environment-controlled extended semantics are unchanged:
  DOCDEX_RUN_EXTENDED_TESTS=1  Run the existing extended suite.
  DOCDEX_RUN_MEMORY_DAG=1      Include memory-DAG when prerequisites are set.
  DOCDEX_RUN_RELEASE_GATE=1    Use the fail-closed external release gate.

Options:
  -h, --help                   Show this help without running tests.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    *)
      log "unknown argument: $1"
      usage >&2
      exit 2
      ;;
  esac
done

if [[ -z "${DOCDEX_BIN:-}" && -x "${ROOT_DIR}/target/debug/docdexd" ]]; then
  DOCDEX_BIN="${ROOT_DIR}/target/debug/docdexd"
else
  DOCDEX_BIN="${DOCDEX_BIN:-docdexd}"
fi

mkdir -p "${LOG_DIR}"

if [[ "$USE_EXISTING_SERVER" == "1" && "$ALLOW_EXISTING_SERVER_MUTATION" != "1" ]]; then
  log "refusing stateful tests against an existing daemon; also set DOCDEX_ALLOW_EXISTING_SERVER_MUTATION=1 to acknowledge profile/hook/MCP writes"
  exit 2
fi

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

terminate_pid() {
  local pid="$1"
  local attempts=0
  kill "$pid" >/dev/null 2>&1 || true
  while kill -0 "$pid" >/dev/null 2>&1 && (( attempts < 20 )); do
    sleep 0.1
    attempts=$((attempts + 1))
  done
  if kill -0 "$pid" >/dev/null 2>&1; then
    kill -KILL "$pid" >/dev/null 2>&1 || true
  fi
  wait "$pid" >/dev/null 2>&1 || true
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
  API_SERVER_WORK_DIR="$(mktemp -d "${LOG_DIR}/run_all_server.XXXX")"
  API_SERVER_STATE_DIR="${API_SERVER_WORK_DIR}/state"
  API_SERVER_HOME_DIR="${API_SERVER_WORK_DIR}/home"
  API_SERVER_GLOBAL_STATE_DIR="${API_SERVER_WORK_DIR}/global"
  API_SERVER_LOCK_PATH="${API_SERVER_WORK_DIR}/daemon.lock"
  mkdir -p "${API_SERVER_STATE_DIR}" "${API_SERVER_HOME_DIR}/.docdex" \
    "${API_SERVER_GLOBAL_STATE_DIR}"
  cat >"${API_SERVER_HOME_DIR}/.docdex/config.toml" <<EOF
[core]
global_state_dir = "${API_SERVER_GLOBAL_STATE_DIR}"
EOF
  HOME="${API_SERVER_HOME_DIR}" \
    DOCDEX_STATE_DIR="${API_SERVER_STATE_DIR}" \
    DOCDEX_GLOBAL_STATE_DIR="${API_SERVER_GLOBAL_STATE_DIR}" \
    DOCDEX_DAEMON_LOCK_PATH="${API_SERVER_LOCK_PATH}" \
    DOCDEX_ENABLE_MCP=1 \
    "${DOCDEX_BIN}" daemon \
    --repo "${ROOT_DIR}" \
    --host 127.0.0.1 \
    --port "${port}" \
    --log warn \
    --secure-mode=false \
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
    terminate_pid "${API_SERVER_PID}"
  fi
  if [[ -n "${API_SERVER_WORK_DIR}" && -d "${API_SERVER_WORK_DIR}" ]]; then
    rm -rf "${API_SERVER_WORK_DIR}"
  fi
  if [[ -n "${MEMORY_DAG_WORKDIR}" && -d "${MEMORY_DAG_WORKDIR}" ]]; then
    rm -rf "${MEMORY_DAG_WORKDIR}"
  fi
  API_SERVER_PID=""
  API_SERVER_WORK_DIR=""
  API_SERVER_LOCK_PATH=""
  API_SERVER_STATE_DIR=""
  API_SERVER_HOME_DIR=""
  API_SERVER_GLOBAL_STATE_DIR=""
  MEMORY_DAG_WORKDIR=""
}

run_memory_dag() {
  if [[ -z "${OLLAMA_BASE_URL:-}" ]]; then
    log "memory DAG requires OLLAMA_BASE_URL"
    return 1
  fi
  if [[ -z "${EMBEDDING_MODEL:-}" ]]; then
    log "memory DAG requires EMBEDDING_MODEL"
    return 1
  fi
  if (( BASH_VERSINFO[0] < 4 )); then
    log "memory DAG START_SERVER mode requires Bash 4+"
    return 1
  fi

  local port status home_dir state_dir global_state_dir repo_a repo_b log_file
  port="$(pick_free_port)"
  MEMORY_DAG_WORKDIR="$(mktemp -d "${LOG_DIR}/memory_dag.XXXX")"
  home_dir="${MEMORY_DAG_WORKDIR}/home"
  state_dir="${MEMORY_DAG_WORKDIR}/state"
  global_state_dir="${MEMORY_DAG_WORKDIR}/global"
  repo_a="${MEMORY_DAG_WORKDIR}/repo-a"
  repo_b="${MEMORY_DAG_WORKDIR}/repo-b"
  log_file="${MEMORY_DAG_WORKDIR}/daemon.log"
  mkdir -p "$home_dir/.docdex" "$state_dir" "$global_state_dir" \
    "$repo_a/.git" "$repo_b/.git"
  printf '# Memory DAG repo A\n' >"${repo_a}/README.md"
  printf '# Memory DAG repo B\n' >"${repo_b}/README.md"
  cat >"${home_dir}/.docdex/config.toml" <<EOF
[core]
global_state_dir = "${global_state_dir}"
EOF
  status=0
  env \
    HOME="${home_dir}" \
    DOCDEX_STATE_DIR="${state_dir}" \
    DOCDEX_GLOBAL_STATE_DIR="${global_state_dir}" \
    DOCDEX_DAEMON_LOCK_PATH="${MEMORY_DAG_WORKDIR}/daemon.lock" \
    DOCDEXD_BIN="${DOCDEX_BIN}" \
    REPO_ROOT="${repo_a}" \
    REPO_B="${repo_b}" \
    START_SERVER=1 \
    SERVER_URL="http://127.0.0.1:${port}" \
    LOG_FILE="${log_file}" \
    OLLAMA_BASE_URL="${OLLAMA_BASE_URL}" \
    EMBEDDING_MODEL="${EMBEDDING_MODEL}" \
    "${ROOT_DIR}/scripts/test_memory_dag.sh" || status=$?
  rm -rf "$MEMORY_DAG_WORKDIR"
  MEMORY_DAG_WORKDIR=""
  return "$status"
}

trap stop_api_server EXIT

FAILURES=0
RESULTS=()

cd "$ROOT_DIR" || exit 1

run_step "unit_component" cargo test --locked --lib
# The complete integration suite already includes the formerly repeated targeted
# HTTP, daemon, stdio, and platform IPC test binaries.
run_step "integration_all" cargo test --locked -j1 --test '*' -- --test-threads=1

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

stop_api_server

if [[ "${DOCDEX_RUN_EXTENDED_TESTS:-0}" == "1" ]]; then
  if [[ -x "${ROOT_DIR}/scripts/test_v2_1.sh" ]]; then
    run_step "extended_v2_1" env DOCDEX_BIN="${DOCDEX_BIN}" FAST=1 "${ROOT_DIR}/scripts/test_v2_1.sh"
  fi
  if [[ -x "${ROOT_DIR}/scripts/test_e2e.sh" ]]; then
    run_step "extended_e2e" env DOCDEXD_BIN="${DOCDEX_BIN}" "${ROOT_DIR}/scripts/test_e2e.sh"
  fi
  if [[ -x "${ROOT_DIR}/scripts/test_ast.sh" ]]; then
    run_step "extended_ast" env DOCDEX_BIN="${DOCDEX_BIN}" "${ROOT_DIR}/scripts/test_ast.sh"
  fi
  if [[ "${DOCDEX_RUN_MEMORY_DAG:-0}" == "1" && -x "${ROOT_DIR}/scripts/test_memory_dag.sh" ]]; then
    run_step "extended_memory_dag" run_memory_dag
  else
    RESULTS+=("extended_memory_dag|skip|set DOCDEX_RUN_MEMORY_DAG=1 with OLLAMA_BASE_URL and EMBEDDING_MODEL")
  fi
  if [[ -x "${ROOT_DIR}/scripts/test_single_daemon.sh" ]]; then
    run_step "extended_single_daemon" env DOCDEX_BIN="${DOCDEX_BIN}" "${ROOT_DIR}/scripts/test_single_daemon.sh" --repo "${ROOT_DIR}"
  fi
  if command -v npm >/dev/null 2>&1 && [[ -x "${ROOT_DIR}/scripts/test_npm_install_matrix.sh" ]]; then
    run_step "extended_npm_install_matrix" env DOCDEX_NPM_MATRIX_DIR="${LOG_DIR}/npm_install_matrix" "${ROOT_DIR}/scripts/test_npm_install_matrix.sh"
  fi
  if [[ -x "${ROOT_DIR}/scripts/test_release_feature_matrix.sh" ]]; then
    matrix_gate="--strict-external"
    if [[ "${DOCDEX_RUN_RELEASE_GATE:-0}" == "1" ]]; then
      matrix_gate="--release-gate"
    fi
    run_step "extended_release_feature_matrix" env DOCDEX_BIN="${DOCDEX_BIN}" "${ROOT_DIR}/scripts/test_release_feature_matrix.sh" "${matrix_gate}"
  fi
  if [[ "${DOCDEX_RUN_REAL_WEB:-0}" == "1" && -x "${ROOT_DIR}/scripts/test_mcp_web_search.sh" ]]; then
    run_step "extended_real_web" env DOCDEXD_BIN="${DOCDEX_BIN}" "${ROOT_DIR}/scripts/test_mcp_web_search.sh" "${ROOT_DIR}"
  else
    RESULTS+=("extended_real_web|skip|set DOCDEX_RUN_REAL_WEB=1 to allow real network discovery")
  fi
  if command -v npm >/dev/null 2>&1 && [[ -f "${ROOT_DIR}/npm/package.json" ]]; then
    run_step "extended_node" npm --prefix "${ROOT_DIR}/npm" test
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
