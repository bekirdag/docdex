#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${DOCDEX_HTTP_BASE_URL:-http://127.0.0.1:28491}"
DURATION_SECS="${DOCDEX_LOAD_DURATION_SECS:-60}"
CONCURRENCY="${DOCDEX_LOAD_CONCURRENCY:-4}"
TIMEOUT_SECS="${DOCDEX_LOAD_TIMEOUT_SECS:-5}"
REQUEST_PATH="${DOCDEX_LOAD_PATH:-/search?q=docdex&limit=5&skip_local_search=true}"
MAX_ERROR_RATE="${DOCDEX_LOAD_MAX_ERROR_RATE:-0}"
AUTH_TOKEN="${DOCDEX_AUTH_TOKEN:-}"

CURL_AUTH_ARGS=()
if [[ -n "${AUTH_TOKEN//[[:space:]]/}" ]]; then
  CURL_AUTH_ARGS=(-H "Authorization: Bearer ${AUTH_TOKEN}")
fi

log() {
  printf "[load-http] %s\n" "$*" >&2
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
log "duration=${DURATION_SECS}s concurrency=${CONCURRENCY} path=${REQUEST_PATH}"
require_server

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
