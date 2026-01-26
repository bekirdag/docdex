#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${DOCDEX_HTTP_BASE_URL:-http://127.0.0.1:28491}"
REPO_ROOT="${DOCDEX_TEST_REPO:-$(pwd)}"
REPO_ID=""

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

file_uri() {
  python3 - <<'PY' "$1"
import pathlib
import sys
print(pathlib.Path(sys.argv[1]).resolve().as_uri())
PY
}

init_repo() {
  local root_uri
  root_uri="$(file_uri "${REPO_ROOT}")"
  local init_payload
  init_payload="{\"rootUri\":\"${root_uri}\"}"
  local resp
  if ! resp="$(curl -sS -H "content-type: application/json" -X POST "${BASE_URL}/v1/initialize" -d "${init_payload}")"; then
    log "repo initialize failed; continuing without repo_id"
    return 0
  fi
  REPO_ID="$(python3 - <<'PY' "${resp}"
import json
import sys
try:
    print(json.loads(sys.argv[1]).get("repo_id", ""))
except Exception:
    print("")
PY
)"
}

with_repo() {
  local path="$1"
  if [[ -z "${REPO_ID}" ]]; then
    echo "${path}"
    return 0
  fi
  if [[ "${path}" == *\?* ]]; then
    echo "${path}&repo_id=${REPO_ID}"
  else
    echo "${path}?repo_id=${REPO_ID}"
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

expect_status() {
  local method="$1"
  local path="$2"
  local expected="$3"
  local tmp
  tmp="$(mktemp)"
  local code
  code=$(curl -sS -o "$tmp" -w "%{http_code}" -X "$method" "${BASE_URL}${path}")
  if [[ "$code" != "$expected" ]]; then
    log "${method} ${path} expected HTTP ${expected}, got ${code}"
    cat "$tmp" >&2
    rm -f "$tmp"
    return 1
  fi
  cat "$tmp"
  rm -f "$tmp"
}

log "using BASE_URL=${BASE_URL}"
require_server
init_repo

log "healthz"
request_json GET "/healthz" >/dev/null

log "search (skip local index)"
request_json GET "$(with_repo "/search?q=docdex&limit=2&skip_local_search=true")" >/dev/null

log "profile list"
if ! request_json GET "/v1/profile/list" >/dev/null; then
  log "profile list unavailable (profile memory may be disabled)"
fi

log "chat completions (compressed)"
request_json POST "$(with_repo "/v1/chat/completions")" '{"model":"docdex","messages":[{"role":"user","content":"status"}],"docdex":{"compress_results":true,"skip_local_search":true,"limit":2}}' >/dev/null

log "multi-repo missing repo_id"
temp_repo="$(mktemp -d)"
mkdir -p "${temp_repo}/.git"
printf "# temp repo\n" >"${temp_repo}/README.md"
root_uri="$(file_uri "${temp_repo}")"
if request_json POST "/v1/initialize" "{\"rootUri\":\"${root_uri}\"}" >/dev/null; then
  expect_status GET "/search?q=docdex&limit=1&skip_local_search=true" 400 >/dev/null
else
  log "skipping multi-repo missing repo_id check (single-repo daemon)"
fi
rm -rf "${temp_repo}"

log "metrics"
request_json GET "/metrics" >/dev/null

log "delegation telemetry"
request_json GET "/v1/telemetry/delegation" >/dev/null

log "api http checks passed"
