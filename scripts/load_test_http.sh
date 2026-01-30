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
INDEX_WAIT_SECS="${DOCDEX_LOAD_INDEX_WAIT_SECS:-30}"
INDEX_REBUILD_ON_MISSING="${DOCDEX_LOAD_REBUILD_ON_MISSING:-1}"
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
    if [[ -x "${DOCDEX_BIN}" ]]; then
      local id_payload
      if id_payload=$(DOCDEX_CLI_LOCAL=1 "${DOCDEX_BIN}" repo id --repo "${abs_root}" 2>/dev/null); then
        REPO_ID=$(python3 - "${id_payload}" <<'PY'
import json
import sys

raw = sys.argv[1]
try:
    data = json.loads(raw)
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
  REPO_ID=$(python3 - "${response}" <<'PY'
import json
import sys

raw = sys.argv[1]
try:
    data = json.loads(raw)
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
  if curl -fsS "${CURL_AUTH_ARGS[@]}" "${BASE_URL}/v1/index/status" >/dev/null 2>&1; then
    log "index status reachable without repo_id; continuing"
    return 0
  fi
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

index_status_path() {
  local path="/v1/index/status"
  if [[ -n "${REPO_ID}" && "${path}" != *"repo_id="* ]]; then
    path=$(append_query_param "${path}" "repo_id" "${REPO_ID}")
  fi
  printf "%s" "${path}"
}

index_rebuild_path() {
  local path="/v1/index/rebuild"
  if [[ -n "${REPO_ID}" && "${path}" != *"repo_id="* ]]; then
    path=$(append_query_param "${path}" "repo_id" "${REPO_ID}")
  fi
  printf "%s" "${path}"
}

parse_index_status() {
  python3 -c 'import json, sys
ready = "false"
status = ""
try:
    data = json.loads(sys.argv[1])
    if isinstance(data, dict):
        ready = "true" if data.get("ready") else "false"
        status = str(data.get("status") or "")
except Exception:
    pass
print(f"{ready} {status}")' "$1"
}

wait_for_index_ready() {
  local deadline=$(( $(date +%s) + INDEX_WAIT_SECS ))
  local status_url
  status_url="$(index_status_path)"
  local rebuild_attempted=0
  local last_status=""
  local last_ready="false"

  while [[ "$(date +%s)" -lt "${deadline}" ]]; do
    local response
    if ! response=$(curl -fsS "${CURL_AUTH_ARGS[@]}" "${BASE_URL}${status_url}" 2>/dev/null); then
      log "index status check failed; retrying"
      sleep 1
      continue
    fi
    local parsed
    if ! parsed=$(parse_index_status "${response}" 2>/dev/null); then
      log "index status parse failed; retrying"
      sleep 1
      continue
    fi
    read -r last_ready last_status <<<"${parsed}"
    if [[ -z "${last_ready}" ]]; then
      last_ready="false"
    fi
    if [[ -z "${last_status}" ]]; then
      last_status="unknown"
    fi
    if [[ "${last_ready}" == "true" ]]; then
      log "index status: ready"
      return 0
    fi
    if [[ "${last_status}" == "missing" && "${INDEX_REBUILD_ON_MISSING}" != "0" && "${rebuild_attempted}" -eq 0 ]]; then
      log "index status: missing; triggering rebuild"
      local rebuild_path
      rebuild_path="$(index_rebuild_path)"
      curl -fsS -X POST "${CURL_AUTH_ARGS[@]}" "${BASE_URL}${rebuild_path}" >/dev/null 2>&1 || true
      rebuild_attempted=1
    fi
    log "index status: ${last_status:-unknown} (ready=${last_ready})"
    sleep 1
  done

  log "index not ready after ${INDEX_WAIT_SECS}s (status=${last_status:-unknown})"
  return 1
}

strip_repo_id_param() {
  python3 - "${REQUEST_PATH}" <<'PY'
import sys
from urllib.parse import urlsplit, parse_qsl, urlencode, urlunsplit

path = sys.argv[1]
parts = urlsplit(path)
query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != "repo_id"]
new_query = urlencode(query, doseq=True)
print(urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment)))
PY
}

unknown_repo_response() {
  python3 - "$1" <<'PY'
import json
import sys

raw = sys.argv[1]
try:
    data = json.loads(raw)
except Exception:
    sys.exit(1)

err = data.get("error") or {}
code = str(err.get("code") or "")
message = str(err.get("message") or "")
if code == "unknown_repo" or "unknown repo" in message.lower():
    sys.exit(0)
sys.exit(1)
PY
}

repo_id_optional() {
  curl -fsS "${CURL_AUTH_ARGS[@]}" "${BASE_URL}/v1/index/status" >/dev/null 2>&1
}

preflight_search() {
  local attempted_drop="${1:-0}"
  local url="${BASE_URL}${REQUEST_PATH}"
  local resp_file
  resp_file="$(mktemp)"
  local status
  status=$(curl -sS -o "${resp_file}" -w "%{http_code}" --max-time "${TIMEOUT_SECS}" \
    "${CURL_AUTH_ARGS[@]}" "${url}" || echo "000")
  if [[ "${status}" == "000" ]]; then
    log "preflight /search failed to connect"
    cat "${resp_file}" >&2 || true
    rm -f "${resp_file}"
    return 1
  fi
  if [[ "${status}" -ge 400 ]]; then
    local body
    body="$(cat "${resp_file}")"
    if [[ "${status}" -eq 404 && "${attempted_drop}" -eq 0 ]]; then
      if unknown_repo_response "${body}" && repo_id_optional; then
        log "search rejected repo_id; retrying without repo_id"
        REQUEST_PATH="$(strip_repo_id_param)"
        rm -f "${resp_file}"
        preflight_search 1
        return $?
      fi
    fi
    log "preflight /search failed status=${status}"
    printf "%s\n" "${body}" | head -c 2000 >&2
    rm -f "${resp_file}"
    return 1
  fi
  rm -f "${resp_file}"
  return 0
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
wait_for_index_ready
preflight_search
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
