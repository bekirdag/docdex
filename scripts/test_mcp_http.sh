#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="${1:-$(pwd)}"
BASE_URL="${DOCDEX_HTTP_BASE_URL:-}"
export REPO_ROOT BASE_URL

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
      export BASE_URL
    fi
  fi
fi

if [[ -z "$BASE_URL" ]]; then
  log "DOCDEX_HTTP_BASE_URL not set and daemon lock not found"
  exit 1
fi

python3 - <<PY
import json
import os
import sys
import urllib.error
import urllib.request

repo = os.environ.get("REPO_ROOT")
base_url = os.environ.get("BASE_URL") or ""
if not base_url:
    raise SystemExit("missing BASE_URL for MCP test")

def open_sse_session(api_base):
    req = urllib.request.Request(f"{api_base}/v1/mcp/sse", method="GET")
    resp = urllib.request.urlopen(req, timeout=10)
    session_id = resp.headers.get("x-docdex-mcp-session")
    if not session_id:
        resp.close()
        raise SystemExit("missing mcp session header")
    return resp, session_id


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


def read_sse(resp):
    while True:
        line = resp.readline()
        if not line:
            raise SystemExit("mcp sse stream closed")
        text = line.decode("utf-8", errors="replace").strip()
        if text.startswith("data:"):
            payload = text[5:].strip()
            try:
                return json.loads(payload)
            except json.JSONDecodeError:
                continue


resp, session_id = open_sse_session(base_url)
try:
    status, payload = post_json(
        f"{base_url}/v1/mcp/message",
        {"jsonrpc": "2.0", "id": 0, "method": "tools/list", "params": {}},
        {"x-docdex-mcp-session": session_id},
    )
    if status == 200:
        raise SystemExit(f"expected uninitialized session error, got: {payload}")
    message = ""
    if isinstance(payload, dict):
        message = payload.get("error", {}).get("message", "")
    if "initialize" not in message:
        raise SystemExit(f"expected initialize error, got: {payload}")

    status, payload = post_json(
        f"{base_url}/v1/mcp/message",
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"workspace_root": repo}},
        {"x-docdex-mcp-session": session_id},
    )
    if status != 200:
        raise SystemExit(f"initialize request failed: {payload}")
    init_resp = read_sse(resp)
    if "result" not in init_resp:
        raise SystemExit(f"initialize failed: {init_resp}")

    status, payload = post_json(
        f"{base_url}/v1/mcp/message",
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {"x-docdex-mcp-session": session_id},
    )
    if status != 200:
        raise SystemExit(f"tools/list request failed: {payload}")
    tools_resp = read_sse(resp)
    if "result" not in tools_resp:
        raise SystemExit(f"tools/list failed: {tools_resp}")

    status, payload = post_json(
        f"{base_url}/v1/mcp/message",
        {
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
        },
        {"x-docdex-mcp-session": session_id},
    )
    if status != 200:
        raise SystemExit(f"docdex_save_preference request failed: {payload}")
    save_resp = read_sse(resp)
    if "result" not in save_resp:
        raise SystemExit(f"docdex_save_preference failed: {save_resp}")
finally:
    resp.close()

print("mcp checks passed")
PY
