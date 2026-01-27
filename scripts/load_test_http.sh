#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE_URL="${DOCDEX_HTTP_BASE_URL:-http://127.0.0.1:28491}"
DURATION_SECS="${DOCDEX_LOAD_DURATION_SECS:-60}"
CONCURRENCY="${DOCDEX_LOAD_CONCURRENCY:-4}"
TIMEOUT_SECS="${DOCDEX_LOAD_TIMEOUT_SECS:-5}"
REQUEST_PATH="${DOCDEX_LOAD_PATH:-/search?q=docdex&limit=5}"
MAX_ERROR_RATE="${DOCDEX_LOAD_MAX_ERROR_RATE:-0}"
AUTH_TOKEN="${DOCDEX_AUTH_TOKEN:-}"
REPO_ROOT="${DOCDEX_LOAD_REPO_ROOT:-${DOCDEX_REPO_ROOT:-}}"
REPO_ID="${DOCDEX_LOAD_REPO_ID:-}"
DOCDEX_BIN="${DOCDEX_BIN:-}"

CURL_AUTH_ARGS=()
if [[ -n "${AUTH_TOKEN//[[:space:]]/}" ]]; then
  CURL_AUTH_ARGS=(-H "Authorization: Bearer ${AUTH_TOKEN}")
fi

log() {
  printf "[load-http] %s\n" "$*" >&2
}

resolve_default_repo_root() {
  local candidate=""
  if [[ -d "${ROOT_DIR}" && ( -f "${ROOT_DIR}/Cargo.toml" || -d "${ROOT_DIR}/.git" ) ]]; then
    printf "%s" "${ROOT_DIR}"
    return 0
  fi
  if command -v git >/dev/null 2>&1; then
    candidate="$(git rev-parse --show-toplevel 2>/dev/null || true)"
  fi
  if [[ -z "${candidate//[[:space:]]/}" ]]; then
    candidate="$(pwd)"
  fi
  if [[ -d "${candidate}" && ( -f "${candidate}/Cargo.toml" || -d "${candidate}/.git" ) ]]; then
    printf "%s" "${candidate}"
  fi
}

if [[ -z "${REPO_ROOT//[[:space:]]/}" ]]; then
  REPO_ROOT="$(resolve_default_repo_root || true)"
fi

append_query_param() {
  local path="$1"
  local key="$2"
  local value="$3"
  if [[ "${path}" == *"?"* ]]; then
    printf "%s&%s=%s" "${path}" "${key}" "${value}"
  else
    printf "%s?%s=%s" "${path}" "${key}" "${value}"
  fi
}

resolve_repo_id() {
  if [[ -n "${REPO_ID}" ]]; then
    return 0
  fi
  if [[ -z "${REPO_ROOT//[[:space:]]/}" ]]; then
    return 0
  fi
  local abs_root
  abs_root=$(python3 - "${REPO_ROOT}" <<'PY'
import os
import sys

print(os.path.abspath(os.path.expanduser(sys.argv[1])))
PY
)
  if [[ -n "${DOCDEX_BIN//[[:space:]]/}" ]]; then
    if command -v "${DOCDEX_BIN}" >/dev/null 2>&1; then
      local id_payload
      if id_payload=$(DOCDEX_CLI_LOCAL=1 "${DOCDEX_BIN}" repo id --repo "${abs_root}" 2>/dev/null); then
        REPO_ID=$(python3 - <<'PY' <<<"${id_payload}"
import json
import sys

try:
    data = json.loads(sys.stdin.read())
    value = data.get("repo_id", "")
    if isinstance(value, str):
        print(value)
except Exception:
    pass
PY
)
        if [[ -n "${REPO_ID}" ]]; then
          log "resolved repo_id=${REPO_ID} (local)"
          return 0
        fi
      fi
    fi
  fi
  local payload
  payload=$(python3 - "${abs_root}" <<'PY'
import json
import sys

print(json.dumps({"root_uri": sys.argv[1]}))
PY
)
  local response
  if ! response=$(curl -fsS "${CURL_AUTH_ARGS[@]}" \
    -H "Content-Type: application/json" \
    -d "${payload}" \
    "${BASE_URL}/v1/initialize"); then
    log "initialize failed for repo_root=${abs_root}"
    return 1
  fi
  REPO_ID=$(python3 - <<'PY' <<<"${response}"
import json
import sys

try:
    data = json.loads(sys.stdin.read())
    value = data.get("repo_id", "")
    if isinstance(value, str):
        print(value)
except Exception:
    pass
PY
)
  if [[ -n "${REPO_ID}" ]]; then
    log "resolved repo_id=${REPO_ID}"
    return 0
  fi
  log "initialize response missing repo_id"
  return 1
}

apply_repo_id() {
  if [[ "${REQUEST_PATH}" == *"repo_id="* ]]; then
    return 0
  fi
  if ! resolve_repo_id; then
    if [[ -n "${REPO_ROOT//[[:space:]]/}" ]]; then
      log "repo initialization failed; set DOCDEX_LOAD_REPO_ID to override"
      exit 1
    fi
    return 0
  fi
  if [[ -n "${REPO_ID}" ]]; then
    REQUEST_PATH=$(append_query_param "${REQUEST_PATH}" "repo_id" "${REPO_ID}")
  fi
}

require_server() {
  if ! curl -fsS "${BASE_URL}/healthz" >/dev/null 2>&1; then
    log "docdexd server not reachable at ${BASE_URL}"
    log "start it with: docdexd serve --repo <path> --secure-mode=false"
    exit 1
  fi
}

worker() {
  local end_epoch="$1"
  local out_file="$2"
  local ok=0
  local fail=0
  while [[ "$(date +%s)" -lt "${end_epoch}" ]]; do
    if curl -fsS --max-time "${TIMEOUT_SECS}" "${CURL_AUTH_ARGS[@]}" "${BASE_URL}${REQUEST_PATH}" >/dev/null 2>&1; then
      ok=$((ok + 1))
    else
      fail=$((fail + 1))
    fi
  done
  printf "%s %s\n" "${ok}" "${fail}" >"${out_file}"
}

log "using BASE_URL=${BASE_URL}"
require_server
apply_repo_id
log "duration=${DURATION_SECS}s concurrency=${CONCURRENCY} path=${REQUEST_PATH}"

end_epoch="$(( $(date +%s) + DURATION_SECS ))"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

for idx in $(seq 1 "${CONCURRENCY}"); do
  worker "${end_epoch}" "${tmp_dir}/${idx}" &
done

wait

total_ok=0
total_fail=0
for result in "${tmp_dir}"/*; do
  read -r ok fail <"${result}"
  total_ok=$((total_ok + ok))
  total_fail=$((total_fail + fail))
done

total=$((total_ok + total_fail))
error_rate=$(awk -v f="${total_fail}" -v t="${total}" 'BEGIN { if (t > 0) printf "%.2f", (f / t) * 100; else print "0.00"; }')
qps=$(awk -v t="${total}" -v d="${DURATION_SECS}" 'BEGIN { if (d > 0) printf "%.2f", t / d; else print "0.00"; }')

log "requests=${total} ok=${total_ok} fail=${total_fail} error_rate=${error_rate}% qps=${qps}"

if [[ "${total}" -eq 0 ]]; then
  log "no requests completed"
  exit 1
fi

if awk -v err="${total_fail}" -v total="${total}" -v max="${MAX_ERROR_RATE}" 'BEGIN { exit (err / total > max) ? 0 : 1 }'; then
  log "error rate exceeded max (${MAX_ERROR_RATE})"
  exit 1
fi

log "load http test passed"
