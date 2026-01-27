#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="${1:-$(pwd)}"
BASE_URL="${DOCDEX_HTTP_BASE_URL:-}"
DURATION_SECS="${DOCDEX_LOAD_DURATION_SECS:-60}"
CONCURRENCY="${DOCDEX_LOAD_CONCURRENCY:-2}"
MAX_ERROR_RATE="${DOCDEX_LOAD_MAX_ERROR_RATE:-0}"

log() {
  printf "[load-mcp] %s\n" "$*" >&2
}

resolve_repo_root() {
  local root="$1"
  python3 - "$root" <<'PY'
import os
import sys

print(os.path.abspath(os.path.expanduser(sys.argv[1])))
PY
}

REPO_ROOT="$(resolve_repo_root "${REPO_ROOT}")"

if [[ ! -d "${REPO_ROOT}" ]]; then
  log "repo path not found: ${REPO_ROOT}"
  exit 1
fi

if [[ -z "$BASE_URL" ]]; then
  lock_path="${DOCDEX_DAEMON_LOCK_PATH:-$HOME/.docdex/daemon.lock}"
  if [[ -f "$lock_path" ]]; then
    port="$(python3 - <<'PY'
import json
import sys

try:
    with open(sys.argv[1], "r", encoding="utf-8") as handle:
        data = json.load(handle)
    port = data.get("port")
    if isinstance(port, int) and port > 0:
        print(port)
except Exception:
    pass
PY
"$lock_path")"
    if [[ -n "${port:-}" ]]; then
      BASE_URL="http://127.0.0.1:${port}"
    fi
  fi
fi

if [[ -z "$BASE_URL" ]]; then
  log "DOCDEX_HTTP_BASE_URL not set and daemon lock not found"
  exit 1
fi

worker() {
  local out_file="$1"
  REPO_ROOT="${REPO_ROOT}" BASE_URL="${BASE_URL}" DOCDEX_LOAD_DURATION_SECS="${DURATION_SECS}" \
    python3 - <<'PY' >"${out_file}"
import json
import os
import sys
import time
import select
import urllib.error
import urllib.request

repo = os.environ["REPO_ROOT"]
duration = float(os.environ.get("DOCDEX_LOAD_DURATION_SECS", "60"))
timeout_secs = float(os.environ.get("DOCDEX_MCP_TIMEOUT_SECS", "10"))
base_url = os.environ.get("BASE_URL")

if not base_url:
    raise RuntimeError("missing BASE_URL for MCP load test")

def open_sse_session(api_base):
    req = urllib.request.Request(f"{api_base}/v1/mcp/sse", method="GET")
    resp = urllib.request.urlopen(req, timeout=timeout_secs)
    session_id = resp.headers.get("x-docdex-mcp-session")
    if not session_id:
        resp.close()
        raise RuntimeError("missing mcp session header")
    return resp, session_id

def post_message(api_base, session_id, payload):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(f"{api_base}/v1/mcp/message", data=data, method="POST")
    req.add_header("content-type", "application/json")
    req.add_header("x-docdex-mcp-session", session_id)
    try:
        resp = urllib.request.urlopen(req, timeout=timeout_secs)
        resp.read()
        resp.close()
        return True
    except urllib.error.HTTPError:
        return False

def read_sse(resp):
    end = time.time() + timeout_secs
    while time.time() < end:
        remaining = max(0.0, end - time.time())
        ready, _, _ = select.select([resp.fp], [], [], remaining)
        if not ready:
            return None
        line = resp.readline()
        if not line:
            return None
        text = line.decode("utf-8", errors="replace").strip()
        if text.startswith("data:"):
            payload = text[5:].strip()
            try:
                return json.loads(payload)
            except json.JSONDecodeError:
                continue
    return None

ok = 0
fail = 0
resp = None
try:
    resp, session_id = open_sse_session(base_url)
    if not post_message(base_url, session_id, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"workspace_root": repo}}):
        fail += 1
        raise RuntimeError("initialize request failed")
    init_resp = read_sse(resp)
    if not init_resp or "result" not in init_resp:
        fail += 1
        raise RuntimeError("initialize response missing")

    if not post_message(base_url, session_id, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}):
        fail += 1
        raise RuntimeError("tools/list request failed")
    tools_resp = read_sse(resp)
    if not tools_resp or "result" not in tools_resp:
        fail += 1
        raise RuntimeError("tools/list response missing")

    end = time.time() + duration
    counter = 3
    while time.time() < end:
        if not post_message(base_url, session_id, {"jsonrpc": "2.0", "id": counter, "method": "tools/list", "params": {}}):
            fail += 1
            counter += 1
            continue
        counter += 1
        resp_value = read_sse(resp)
        if resp_value and "result" in resp_value:
            ok += 1
        else:
            fail += 1
except Exception:
    fail += 1
finally:
    try:
        if resp is not None:
            resp.close()
    except Exception:
        pass

print(f"{ok} {fail}")
PY
}

log "repo=${REPO_ROOT} duration=${DURATION_SECS}s concurrency=${CONCURRENCY}"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "${tmp_dir}"' EXIT

for idx in $(seq 1 "${CONCURRENCY}"); do
  worker "${tmp_dir}/${idx}" &
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

log "load mcp test passed"
