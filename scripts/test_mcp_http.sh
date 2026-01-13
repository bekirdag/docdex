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

if ! python3 - <<PY
import socket
import sys

try:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.close()
except PermissionError:
    print("[mcp] skipping: TCP bind not permitted", file=sys.stderr)
    sys.exit(1)
PY
then
  exit 0
fi

python3 - <<PY
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request

repo = os.environ.get("REPO_ROOT")
base_url = os.environ.get("BASE_URL") or ""
mcp_bin = os.environ.get("MCP_BIN")

docdex_bin = os.environ.get("DOCDEX_BIN") or "docdexd"
cmd = [docdex_bin, "mcp", "--repo", repo, "--log", "warn"]
if not base_url:
    cmd.append("--start-daemon")

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


def resolve_base_url():
    if base_url:
        return base_url
    lock_path = os.environ.get("DOCDEX_DAEMON_LOCK_PATH")
    if not lock_path:
        lock_path = os.path.expanduser("~/.docdex/daemon.lock")
    try:
        with open(lock_path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
        port = data.get("port")
        if isinstance(port, int) and port > 0:
            return f"http://127.0.0.1:{port}"
    except Exception:
        return ""
    return ""


def open_sse_session(api_base):
    req = urllib.request.Request(f"{api_base}/v1/mcp/sse", method="GET")
    resp = urllib.request.urlopen(req, timeout=10)
    session_id = resp.headers.get("x-docdex-mcp-session")
    resp.close()
    return session_id


def post_json(url, payload, headers=None):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("content-type", "application/json")
    if headers:
        for key, value in headers.items():
            req.add_header(key, value)
    try:
        resp = urllib.request.urlopen(req, timeout=10)
        body = resp.read()
        status = resp.getcode()
        resp.close()
        return status, json.loads(body)
    except urllib.error.HTTPError as err:
        body = err.read()
        try:
            payload = json.loads(body)
        except Exception:
            payload = None
        return err.code, payload


base_url = resolve_base_url()

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
        session_id = open_sse_session(base_url)
        if not session_id:
            raise SystemExit("missing mcp session header")
        status, payload = post_json(
            f"{base_url}/v1/mcp/message",
            {"jsonrpc": "2.0", "id": 99, "method": "tools/list", "params": {}},
            {"x-docdex-mcp-session": session_id},
        )
        if status == 200:
            raise SystemExit(f"expected uninitialized session error, got: {payload}")
        message = ""
        if isinstance(payload, dict):
            message = payload.get("error", {}).get("message", "")
        if "initialize" not in message:
            raise SystemExit(f"expected initialize error, got: {payload}")

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
