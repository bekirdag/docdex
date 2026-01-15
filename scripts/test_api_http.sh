#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${DOCDEX_HTTP_BASE_URL:-http://127.0.0.1:28491}"

log() {
  printf "[api-http] %s\n" "$*" >&2
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

log "healthz"
request_json GET "/healthz" >/dev/null

log "search (skip local index)"
request_json GET "/search?q=docdex&limit=2&skip_local_search=true" >/dev/null

log "profile list"
if ! request_json GET "/v1/profile/list" >/dev/null; then
  log "profile list unavailable (profile memory may be disabled)"
fi

log "chat completions (compressed)"
request_json POST "/v1/chat/completions" '{"model":"docdex","messages":[{"role":"user","content":"status"}],"docdex":{"compress_results":true,"skip_local_search":true,"limit":2}}' >/dev/null

log "metrics"
request_json GET "/metrics" >/dev/null

log "api http checks passed"
