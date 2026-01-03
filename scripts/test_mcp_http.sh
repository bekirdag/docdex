#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="${1:-$(pwd)}"
MCP_BIN="${DOCDEX_MCP_SERVER_BIN:-}"
BASE_URL="${DOCDEX_HTTP_BASE_URL:-}"
if [[ -z "${DOCDEX_BIN:-}" && -x "${ROOT_DIR}/target/debug/docdexd" ]]; then
  DOCDEX_BIN="${ROOT_DIR}/target/debug/docdexd"
else
  DOCDEX_BIN="${DOCDEX_BIN:-docdexd}"
fi
export REPO_ROOT MCP_BIN BASE_URL DOCDEX_BIN

log() {
  printf "[mcp] %s\n" "$*" >&2
}

if [[ ! -d "$REPO_ROOT" ]]; then
  log "repo path not found: $REPO_ROOT"
  exit 1
fi

python3 - <<PY
import json
import os
import subprocess
import sys

repo = os.environ.get("REPO_ROOT")
base_url = os.environ.get("BASE_URL")
mcp_bin = os.environ.get("MCP_BIN")

docdex_bin = os.environ.get("DOCDEX_BIN") or "docdexd"
cmd = [docdex_bin, "mcp", "--repo", repo, "--log", "warn"]

env = os.environ.copy()
if mcp_bin:
    env["DOCDEX_MCP_SERVER_BIN"] = mcp_bin
if base_url:
    env["DOCDEX_HTTP_BASE_URL"] = base_url

proc = subprocess.Popen(
    cmd,
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
        err = proc.stderr.read()
        raise SystemExit(f"mcp server closed: {err}")
    return json.loads(line)

try:
    send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"workspace_root": repo}})
    init_resp = recv()
    if "result" not in init_resp:
        raise SystemExit(f"initialize failed: {init_resp}")

    send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    tools_resp = recv()
    if "result" not in tools_resp:
        raise SystemExit(f"tools/list failed: {tools_resp}")

    if base_url:
        env["DOCDEX_HTTP_BASE_URL"] = base_url
        send({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "docdex_save_preference",
                "arguments": {
                    "agent_id": "agent-mcp-script",
                    "category": "style",
                    "content": "Use tabs"
                }
            }
        })
        save_resp = recv()
        if "result" not in save_resp:
            raise SystemExit(f"docdex_save_preference failed: {save_resp}")
finally:
    proc.kill()
    proc.wait()

print("mcp checks passed")
PY
