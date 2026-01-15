#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${DOCDEX_HTTP_BASE_URL:-http://127.0.0.1:28491}"
AGENT_ID="${DOCDEX_TEST_AGENT_ID:-agent-evolution}"

log() {
  printf "[profile-evolution] %s\n" "$*" >&2
}

require_server() {
  if ! curl -fsS "${BASE_URL}/healthz" >/dev/null 2>&1; then
    log "docdexd server not reachable at ${BASE_URL}"
    log "start it with: docdexd serve --repo <path> --secure-mode=false"
    exit 1
  fi
}

request_json() {
  local method="$1"
  local path="$2"
  local body="${3:-}"
  local tmp
  tmp="$(mktemp)"
  local code
  if [[ -n "$body" ]]; then
    code=$(curl -sS -o "$tmp" -w "%{http_code}" -H "content-type: application/json" -X "$method" "${BASE_URL}${path}" -d "$body")
  else
    code=$(curl -sS -o "$tmp" -w "%{http_code}" -X "$method" "${BASE_URL}${path}")
  fi
  if [[ "$code" -ge 400 ]]; then
    log "${method} ${path} failed with HTTP ${code}"
    cat "$tmp" >&2
    rm -f "$tmp"
    return 1
  fi
  cat "$tmp"
  rm -f "$tmp"
}

log "using BASE_URL=${BASE_URL}"
require_server

log "queue profile evolution"
response=$(request_json POST "/v1/profile/save" "{\"agent_id\":\"${AGENT_ID}\",\"category\":\"tooling\",\"content\":\"Prefer incremental builds\"}")
request_id=$(python3 - <<PY
import json
print(json.loads('''$response''').get('request_id',''))
PY
)
if [[ -z "$request_id" ]]; then
  log "missing request_id in profile save response"
  exit 1
fi
log "queued request_id=${request_id}"

log "profile list (may not show new preference immediately)"
if ! request_json GET "/v1/profile/list?agent_id=${AGENT_ID}" >/dev/null; then
  log "profile list unavailable (profile memory may be disabled)"
fi

log "profile evolution request queued"
