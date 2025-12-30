#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${DOCDEX_HTTP_BASE_URL:-http://127.0.0.1:3210}"
REPO_ROOT="${1:-$(pwd)}"
DOCDEX_BIN="${DOCDEX_BIN:-docdexd}"

log() {
  printf "[hooks] %s\n" "$*" >&2
}

require_server() {
  if ! curl -fsS "${BASE_URL}/healthz" >/dev/null 2>&1; then
    log "docdexd server not reachable at ${BASE_URL}"
    log "start it with: docdexd serve --repo ${REPO_ROOT} --secure-mode=false"
    exit 1
  fi
}

require_repo() {
  if [[ ! -d "${REPO_ROOT}/.git" ]]; then
    log "${REPO_ROOT} is not a git repo; hooks need staged files"
    exit 1
  fi
}

repo_id_from_inspect() {
  local repo="$1"
  local output
  output=$("$DOCDEX_BIN" repo inspect --repo "$repo")
  python3 - <<PY
import json
print(json.loads('''$output''').get('computedFingerprint',''))
PY
}

log "using BASE_URL=${BASE_URL}"
require_server
require_repo

log "running hook pre-commit (HTTP fallback allowed)"
DOCDEX_HTTP_BASE_URL="${BASE_URL}" "$DOCDEX_BIN" hook pre-commit --repo "${REPO_ROOT}"

repo_id=$(repo_id_from_inspect "${REPO_ROOT}")
if [[ -z "$repo_id" ]]; then
  log "failed to resolve repo id"
  exit 1
fi

log "calling hook validate endpoint"
curl -fsS -H "content-type: application/json" -H "x-docdex-repo-id: ${repo_id}" \
  -X POST "${BASE_URL}/v1/hooks/validate" \
  -d '{"files":[]}' >/dev/null

log "hook checks passed"
