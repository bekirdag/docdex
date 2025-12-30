#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="${1:-$(pwd)}"
MCP_BIN="${DOCDEX_MCP_SERVER_BIN:-}"
BASE_URL="${DOCDEX_HTTP_BASE_URL:-}"
DURATION_SECS="${DOCDEX_LOAD_DURATION_SECS:-60}"
CONCURRENCY="${DOCDEX_LOAD_CONCURRENCY:-2}"
MAX_ERROR_RATE="${DOCDEX_LOAD_MAX_ERROR_RATE:-0}"
if [[ -z "${DOCDEX_BIN:-}" && -x "${ROOT_DIR}/target/debug/docdexd" ]]; then
  DOCDEX_BIN="${ROOT_DIR}/target/debug/docdexd"
else
  DOCDEX_BIN="${DOCDEX_BIN:-docdexd}"
fi

log() {
  printf "[load-mcp] %s\n" "$*" >&2
}

if [[ ! -d "${REPO_ROOT}" ]]; then
  log "repo path not found: ${REPO_ROOT}"
  exit 1
fi

worker() {
  local out_file="$1"
  REPO_ROOT="${REPO_ROOT}" MCP_BIN="${MCP_BIN}" BASE_URL="${BASE_URL}" DOCDEX_BIN="${DOCDEX_BIN}" DOCDEX_LOAD_DURATION_SECS="${DURATION_SECS}" \
    python3 - <<'PY' >"${out_file}"
import json
import os
import subprocess
import sys
import time

repo = os.environ["REPO_ROOT"]
duration = float(os.environ.get("DOCDEX_LOAD_DURATION_SECS", "60"))
docdex_bin = os.environ.get("DOCDEX_BIN") or "docdexd"
mcp_bin = os.environ.get("MCP_BIN")
base_url = os.environ.get("BASE_URL")

env = os.environ.copy()
if mcp_bin:
    env["DOCDEX_MCP_SERVER_BIN"] = mcp_bin
if base_url:
    env["DOCDEX_HTTP_BASE_URL"] = base_url

proc = subprocess.Popen(
    [docdex_bin, "mcp", "--repo", repo, "--log", "warn"],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True,
    env=env,
)

def send(payload):
    proc.stdin.write(json.dumps(payload) + "\n")
    proc.stdin.flush()

def recv():
    line = proc.stdout.readline()
    if not line:
        raise RuntimeError(proc.stderr.read())
    return json.loads(line)

ok = 0
fail = 0
try:
    send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"workspace_root": repo}})
    init_resp = recv()
    if "result" not in init_resp:
        fail += 1
    else:
        send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        tools_resp = recv()
        if "result" not in tools_resp:
            fail += 1
        else:
            end = time.time() + duration
            counter = 3
            while time.time() < end:
                send({"jsonrpc": "2.0", "id": counter, "method": "tools/list", "params": {}})
                counter += 1
                resp = recv()
                if "result" in resp:
                    ok += 1
                else:
                    fail += 1
except Exception:
    fail += 1
finally:
    proc.kill()
    proc.wait()

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
