#!/usr/bin/env bash
set -euo pipefail

ROOT_ARG="${1:-.}"
REPO_ROOT="$(cd "$ROOT_ARG" && pwd -P)"
DOCDEXD_BIN="${DOCDEXD_BIN:-}"
PORT="${PORT:-}"
LOG_FILE="${LOG_FILE:-/tmp/docdexd-mcp-web.log}"
STATE_DIR="$(mktemp -d 2>/dev/null || mktemp -d -t docdex-state)"

cleanup() {
  if [[ -n "${SERVER_PID:-}" ]]; then
    kill "${SERVER_PID}" >/dev/null 2>&1 || true
  fi
  rm -rf "$STATE_DIR" >/dev/null 2>&1 || true
}
trap cleanup EXIT

if [[ -z "$DOCDEXD_BIN" ]]; then
  if [[ -x "${REPO_ROOT}/target/release/docdexd" ]]; then
    DOCDEXD_BIN="${REPO_ROOT}/target/release/docdexd"
  elif [[ -x "${REPO_ROOT}/target/debug/docdexd" ]]; then
    DOCDEXD_BIN="${REPO_ROOT}/target/debug/docdexd"
  else
    DOCDEXD_BIN="docdexd"
  fi
fi

if [[ -z "${DOCDEX_MCP_SERVER_BIN:-}" ]]; then
  if [[ -x "${REPO_ROOT}/target/release/docdex-mcp-server" ]]; then
    export DOCDEX_MCP_SERVER_BIN="${REPO_ROOT}/target/release/docdex-mcp-server"
  elif [[ -x "${REPO_ROOT}/target/debug/docdex-mcp-server" ]]; then
    export DOCDEX_MCP_SERVER_BIN="${REPO_ROOT}/target/debug/docdex-mcp-server"
  else
    candidate="$(ls -1 "${REPO_ROOT}"/npm/dist/*/docdex-mcp-server 2>/dev/null | head -n 1 || true)"
    if [[ -n "$candidate" ]]; then
      export DOCDEX_MCP_SERVER_BIN="$candidate"
    fi
  fi
fi

if [[ -z "$PORT" ]]; then
  PORT="$(
    node -e "const net=require('net');const s=net.createServer();s.listen(0,'127.0.0.1',()=>{console.log(s.address().port);s.close();});"
  )"
fi

export DOCDEX_WEB_ENABLED=1
export DOCDEX_MCP_MAX_RESULTS=8
export DOCDEX_DAEMON_LOCK_PATH="${STATE_DIR}/daemon.lock"

"$DOCDEXD_BIN" daemon \
  --repo "$REPO_ROOT" \
  --state-dir "$STATE_DIR" \
  --host 127.0.0.1 \
  --port "$PORT" \
  --log warn \
  --enable-mcp \
  >"$LOG_FILE" 2>&1 &
SERVER_PID=$!

for _ in {1..50}; do
  if curl -sS "http://127.0.0.1:${PORT}/healthz" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done

init_payload=$(printf '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"rootUri":"file://%s"}}' "$REPO_ROOT")
curl -sS --max-time 10 "http://127.0.0.1:${PORT}/v1/mcp" \
  -H 'content-type: application/json' \
  -d "$init_payload" >/dev/null

curl -sS --max-time 10 "http://127.0.0.1:${PORT}/v1/mcp" \
  -H 'content-type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{\"project_root\":\"${REPO_ROOT}\"}}" >/dev/null

call_payload=$(cat <<EOF
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"docdex_web_research","arguments":{"query":"PHP array reverse code sample","limit":5,"web_limit":5,"skip_local_search":true,"force_web":true,"project_root":"$REPO_ROOT"}}}
EOF
)

response="$(curl -sS --max-time 55 "http://127.0.0.1:${PORT}/v1/mcp" \
  -H 'content-type: application/json' \
  -d "$call_payload")"

node -e '
const raw = process.argv[1];
let parsed;
try { parsed = JSON.parse(raw); } catch (err) {
  console.error("invalid JSON response:", raw);
  process.exit(1);
}
if (parsed.error) {
  console.error("mcp error:", JSON.stringify(parsed.error));
  process.exit(1);
}
const text = parsed?.result?.content?.[0]?.text;
if (!text) {
  console.error("missing tool content text:", JSON.stringify(parsed.result));
  process.exit(1);
}
let payload;
try { payload = JSON.parse(text); } catch (err) {
  console.error("invalid tool payload JSON:", text);
  process.exit(1);
}
const discoveryResults = payload?.webDiscovery?.discovery?.results;
const fetches = payload?.webDiscovery?.fetches;
const hasDiscovery = Array.isArray(discoveryResults) && discoveryResults.length > 0;
const hasFetches = Array.isArray(fetches) && fetches.length > 0;
if (!hasDiscovery && !hasFetches) {
  console.error("web search returned no results:", JSON.stringify(payload.webDiscovery || {}));
  process.exit(1);
}
console.log(JSON.stringify(payload, null, 2));
' "$response"
