#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOCDEX_BIN="${DOCDEX_BIN:-$ROOT_DIR/target/debug/docdexd}"
REAL_HOME="${HOME:-}"
export RUSTUP_HOME="${RUSTUP_HOME:-${REAL_HOME}/.rustup}"
export CARGO_HOME="${CARGO_HOME:-${REAL_HOME}/.cargo}"
export DOCDEX_ENABLE_MEMORY="${DOCDEX_ENABLE_MEMORY:-0}"
export DOCDEX_WEB_ENABLED="${DOCDEX_WEB_ENABLED:-0}"
export RUST_TEST_THREADS="${RUST_TEST_THREADS:-1}"
STRICT_SKIPS="${DOCDEX_V2_STRICT_SKIPS:-0}"
WORKDIR=""
HOOK_SOCKET=""
CLEANUP_DONE=0
PROFILE_SAVED=0

cd "$ROOT_DIR" || exit 1

log() {
  printf "[v2.1] %s\n" "$*" >&2
}

skip_or_fail() {
  local lane="$1"
  local reason="$2"
  log "SKIP ${lane}: ${reason}"
  if [[ "$STRICT_SKIPS" == "1" ]]; then
    log "strict skip policy rejected ${lane}"
    return 1
  fi
  return 0
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    log "missing required command: $1"
    exit 1
  fi
}

pick_free_port() {
  python3 - <<'PY'
import socket
import sys
s = socket.socket()
try:
    s.bind(("127.0.0.1", 0))
except PermissionError:
    print("0")
    sys.exit(0)
print(s.getsockname()[1])
s.close()
PY
}

wait_for_health() {
  local host="$1"
  local port="$2"
  local url="http://${host}:${port}/healthz"
  local deadline=$((SECONDS + 15))
  while (( SECONDS < deadline )); do
    if curl -fsS "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.2
  done
  log "health check timed out for $url"
  return 1
}

ensure_binary() {
  if [[ ! -x "$DOCDEX_BIN" ]]; then
    log "building docdexd (debug)"
    cargo build -q --locked
  fi
}

setup_repo() {
  local repo_root="$1"
  mkdir -p "$repo_root/src" "$repo_root/docs"
  git -C "$repo_root" init -q
  printf "# Docdex v2.1 Test Repo\n" >"$repo_root/README.md"
  printf "export const value = 42;\n" >"$repo_root/src/value.ts"
  printf "# Guide\n\nUse TypeScript.\n" >"$repo_root/docs/guide.md"
  git -C "$repo_root" add README.md src/value.ts docs/guide.md
}

write_config() {
  local home_dir="$1"
  local global_state_dir="$2"
  local hook_socket="$3"
  local agent_id="$4"
  local embed_dim="${DOCDEX_PROFILE_EMBED_DIM:-768}"
  local llm_model="${DOCDEX_LLM_MODEL:-${DOCDEX_LLM_DEFAULT_MODEL:-fake-model}}"
  local llm_base_url="${DOCDEX_LLM_BASE_URL:-${DOCDEX_OLLAMA_BASE_URL:-http://127.0.0.1:11434}}"
  mkdir -p "$home_dir/.docdex"
  cat >"$home_dir/.docdex/config.toml" <<EOF
[core]
global_state_dir = "${global_state_dir}"

[llm]
base_url = "${llm_base_url}"
default_model = "${llm_model}"

[memory.profile]
embedding_model = "nomic-embed-text"
embedding_dim = ${embed_dim}

[server]
http_bind_addr = "127.0.0.1:0"
default_agent_id = "${agent_id}"
hook_socket_path = "${hook_socket}"
enable_mcp = true

[features]
hooks = true
project_map = true
tui_overlay = false
workflow_prompt = true
EOF
}

start_daemon() {
  local repo_root="$1"
  local host="$2"
  local port="$3"
  local log_level="$4"
  local log_file
  log_file="$(mktemp)"
  log "starting docdexd serve on ${host}:${port}"
  export DOCDEX_HTTP_BASE_URL="http://${host}:${port}"
  DAEMON_LOG="$log_file"
  "$DOCDEX_BIN" serve \
    --repo "$repo_root" \
    --host "$host" \
    --port "$port" \
    --log "$log_level" \
    --preflight-check=false \
    --secure-mode=false \
    --enable-mcp \
    >"$log_file" 2>&1 &
  DAEMON_PID=$!
  if ! wait_for_health "$host" "$port"; then
    log "daemon logs:"
    cat "$log_file" >&2 || true
    return 1
  fi
}

stop_daemon() {
  if [[ -n "${DAEMON_PID:-}" ]]; then
    kill "$DAEMON_PID" >/dev/null 2>&1 || true
    local attempts=0
    while kill -0 "$DAEMON_PID" >/dev/null 2>&1 && (( attempts < 20 )); do
      sleep 0.1
      attempts=$((attempts + 1))
    done
    if kill -0 "$DAEMON_PID" >/dev/null 2>&1; then
      kill -KILL "$DAEMON_PID" >/dev/null 2>&1 || true
    fi
    wait "$DAEMON_PID" >/dev/null 2>&1 || true
    DAEMON_PID=""
  fi
  if [[ -n "${DAEMON_LOG:-}" ]]; then
    rm -f "$DAEMON_LOG" >/dev/null 2>&1 || true
    DAEMON_LOG=""
  fi
}

cleanup() {
  if [[ "$CLEANUP_DONE" == "1" ]]; then
    return
  fi
  CLEANUP_DONE=1
  stop_daemon
  if [[ -n "$HOOK_SOCKET" ]]; then
    rm -f "$HOOK_SOCKET" >/dev/null 2>&1 || true
  fi
  if [[ -n "$WORKDIR" && -d "$WORKDIR" ]]; then
    rm -rf "$WORKDIR"
  fi
}

handle_signal() {
  local exit_code="$1"
  trap - EXIT INT TERM
  cleanup
  exit "$exit_code"
}

run_cli_smoke() {
  local repo_root="$1"
  log "CLI smoke"
  "$DOCDEX_BIN" --help >/dev/null
  "$DOCDEX_BIN" serve --help >/dev/null
  "$DOCDEX_BIN" profile --help >/dev/null
  "$DOCDEX_BIN" hook --help >/dev/null
  if ! "$DOCDEX_BIN" check >/dev/null; then
    skip_or_fail "cli_check" "docdexd check failed (likely missing Ollama)" || return 1
  fi
  "$DOCDEX_BIN" index --repo "$repo_root" >/dev/null
  "$DOCDEX_BIN" query --repo "$repo_root" --limit 3 --skip-local-search >/dev/null
  "$DOCDEX_BIN" query --repo "$repo_root" --agent-id "mcoda_frontend" --limit 2 >/dev/null
  "$DOCDEX_BIN" profile list >/dev/null
  "$DOCDEX_BIN" profile list --agent-id "mcoda_frontend" >/dev/null
}

run_http_smoke() {
  local host="$1"
  local port="$2"
  log "HTTP smoke"
  local tmp
  tmp="$(mktemp)"
  local code
  code=$(curl -sS -o "$tmp" -w "%{http_code}" "http://${host}:${port}/healthz")
  if [[ "$code" -ge 400 ]]; then
    log "healthz failed with HTTP ${code}"
    cat "$tmp" >&2
    rm -f "$tmp"
    return 1
  fi
  code=$(curl -sS -o "$tmp" -w "%{http_code}" "http://${host}:${port}/search?q=TypeScript&limit=2")
  if [[ "$code" -ge 400 ]]; then
    log "search failed with HTTP ${code}"
    cat "$tmp" >&2
    rm -f "$tmp"
    return 1
  fi
  code=$(curl -sS -o "$tmp" -w "%{http_code}" "http://${host}:${port}/v1/profile/list")
  if [[ "$code" -ge 400 ]]; then
    log "profile list failed with HTTP ${code}"
    cat "$tmp" >&2
    rm -f "$tmp"
    return 1
  fi
  code=$(curl -sS -o "$tmp" -w "%{http_code}" -X POST "http://${host}:${port}/v1/chat/completions" \
    -H "content-type: application/json" \
    -d '{"model":"docdex","messages":[{"role":"user","content":"Find the guide"}],"docdex":{"compress_results":true,"limit":3}}')
  if [[ "$code" -ge 400 ]]; then
    log "chat completions failed with HTTP ${code}"
    cat "$tmp" >&2
    rm -f "$tmp"
    return 1
  fi
  rm -f "$tmp"
}

run_hook_http() {
  local repo_root="$1"
  log "hook pre-commit (HTTP)"
  "$DOCDEX_BIN" hook pre-commit --repo "$repo_root"
}

run_profile_save_http() {
  local host="$1"
  local port="$2"
  log "profile save evolution (HTTP)"
  local tmp
  tmp="$(mktemp)"
  local code
  code=$(curl -sS -o "$tmp" -w "%{http_code}" -X POST "http://${host}:${port}/v1/profile/save" \
    -H "content-type: application/json" \
    -d '{"agent_id":"mcoda_frontend","category":"tooling","content":"Use Vitest"}')
  if [[ "$code" -ge 400 ]]; then
    log "profile save failed with HTTP ${code}"
    cat "$tmp" >&2
    rm -f "$tmp"
    return 1
  fi
  python3 - "$tmp" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    payload = json.load(handle)
if not payload.get("request_id") or payload.get("status") != "queued":
    raise SystemExit(f"profile save response missing queued request: {payload}")
PY
  code=$(curl -sS -o "$tmp" -w "%{http_code}" \
    "http://${host}:${port}/v1/profile/list?agent_id=mcoda_frontend")
  if [[ "$code" -ge 400 ]]; then
    log "profile persistence postcondition failed with HTTP ${code}"
    cat "$tmp" >&2
    rm -f "$tmp"
    return 1
  fi
  python3 - "$tmp" "${RUN_LLM:-0}" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    payload = json.load(handle)
matches = [
    item for item in payload.get("preferences", [])
    if item.get("agent_id") == "mcoda_frontend"
    and item.get("content") == "Use Vitest"
]
if not matches:
    raise SystemExit(f"profile seed preference was not persisted: {payload}")
if sys.argv[2] != "1" and not any(
    item.get("embedding_provider") == "fallback"
    and item.get("embedding_model") == "hash-embed-v1"
    for item in matches
):
    raise SystemExit(f"profile fallback metadata missing: {matches}")
PY
  rm -f "$tmp"
}

run_hook_unix() {
  local repo_root="$1"
  local hook_socket="$2"
  local deadline=$((SECONDS + 5))
  while (( SECONDS < deadline )) && [[ ! -S "$hook_socket" ]]; do
    sleep 0.1
  done
  if [[ ! -S "$hook_socket" ]]; then
    log "unix hook socket was not created: ${hook_socket}"
    return 1
  fi
  log "hook pre-commit (unix socket)"
  local output status
  status=0
  output="$(DOCDEX_HTTP_BASE_URL="http://127.0.0.1:1" \
    "$DOCDEX_BIN" hook pre-commit --repo "$repo_root" 2>&1)" || status=$?
  if [[ "$status" -ne 0 ]]; then
    log "unix hook request failed: ${output}"
    return "$status"
  fi
  if [[ "$output" == *"daemon not found; skipping semantic checks"* \
    || "$output" == *"falling back to HTTP"* ]]; then
    log "unix hook silently fell back instead of using ${hook_socket}: ${output}"
    return 1
  fi
}

run_profile_embedder_tests() {
  local repo_root="$1"
  if [[ "${RUN_EMBEDDING:-0}" != "1" ]]; then
    skip_or_fail "profile_embedding" "set RUN_EMBEDDING=1 to enable" || return 1
    return
  fi
  log "profile add/search/save (embedding required)"
  "$DOCDEX_BIN" profile add --agent-id "mcoda_frontend" --category style --content "Prefer concise answers" >/dev/null
  "$DOCDEX_BIN" profile search --agent-id "mcoda_frontend" --query "concise" >/dev/null
}

run_profile_export() {
  local out_path="$1"
  log "profile export"
  "$DOCDEX_BIN" profile export --out "$out_path" >/dev/null
  python3 - "$out_path" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as f:
    data = json.load(f)
assert "schema_version" in data and "preferences" in data
assert any(
    item.get("agent_id") == "mcoda_frontend"
    and item.get("content") == "Use Vitest"
    for item in data["preferences"]
), "profile export omitted the persisted fallback preference"
PY
}

run_mcp_smoke() {
  local repo_root="$1"
  local base_url="$2"
  if [[ "${SKIP_MCP:-0}" == "1" ]]; then
    skip_or_fail "mcp_http_sse" "SKIP_MCP=1" || return 1
    return
  fi
  if [[ -z "${DAEMON_PID:-}" ]] || ! kill -0 "$DAEMON_PID" >/dev/null 2>&1; then
    log "refusing MCP smoke without the isolated v2.1 daemon running"
    return 1
  fi
  if ! curl -fsS "${base_url}/healthz" >/dev/null 2>&1; then
    log "refusing MCP smoke against an unhealthy isolated daemon: ${base_url}"
    return 1
  fi
  log "MCP HTTP/SSE smoke"
  python3 - "$repo_root" "$base_url" <<'PY'
import json
import sys
import urllib.request

repo_root, base_url = sys.argv[1:3]

req = urllib.request.Request(f"{base_url}/v1/mcp/sse", method="GET")
resp = urllib.request.urlopen(req, timeout=10)
session_id = resp.headers.get("x-docdex-mcp-session")
if not session_id:
    resp.close()
    raise SystemExit("missing mcp session header")

def post_message(payload):
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(f"{base_url}/v1/mcp/message", data=data, method="POST")
    req.add_header("content-type", "application/json")
    req.add_header("x-docdex-mcp-session", session_id)
    out = urllib.request.urlopen(req, timeout=10)
    out.read()
    out.close()

def read_sse():
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

post_message({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"workspace_root": repo_root}})
init_resp = read_sse()
assert init_resp.get("id") == 1 and "result" in init_resp

post_message({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
tools_resp = read_sse()
tools = tools_resp.get("result", {}).get("tools", [])
names = {t.get("name") for t in tools}
assert "docdex_save_preference" in names and "docdex_get_profile" in names

post_message({
    "jsonrpc": "2.0",
    "id": 3,
    "method": "tools/call",
    "params": {"name": "docdex_get_profile", "arguments": {"agent_id": "mcoda_frontend"}}
})
resp_payload = read_sse()
assert resp_payload.get("id") == 3
assert "error" not in resp_payload, resp_payload
result = resp_payload.get("result")
assert isinstance(result, dict), resp_payload
assert result.get("isError") is not True, result
resp.close()
PY
}

run_cargo_tests() {
  if [[ "${FAST:-0}" == "1" ]]; then
    log "FAST=1: running focused tests only"
    cargo test -q --locked \
      --test default_agent_selection \
      --test reasoning_trace \
      --test hook_unix_socket \
      --test hook_validate_pass \
      --test hook_validate_fail \
      --test profile_sync \
      --test profile_state_layout
    return 0
  fi
  log "running cargo test (workspace)"
  cargo test --locked --workspace --tests
  if [[ "${RUN_CLIPPY:-0}" == "1" ]]; then
    log "running cargo clippy"
    cargo clippy --locked --all-targets -- -D warnings
  fi
}

main() {
  require_cmd git
  require_cmd python3
  require_cmd curl
  ensure_binary

  local workdir
  workdir="$(mktemp -d)"
  WORKDIR="$workdir"
  local repo_root="${workdir}/repo"
  local state_dir="${workdir}/state"
  local home_dir="${workdir}/home"
  local global_state_dir="${workdir}/global"
  local export_path="${workdir}/profile_sync.json"
  mkdir -p "$state_dir" "$home_dir" "$global_state_dir"

  export DOCDEX_CLI_LOCAL=1
  export DOCDEX_STATE_DIR="$state_dir"
  export HOME="$home_dir"

  setup_repo "$repo_root"
  write_config "$home_dir" "$global_state_dir" "" "mcoda_frontend"

  run_cargo_tests
  run_cli_smoke "$repo_root"

  local host="127.0.0.1"
  local port
  port="$(pick_free_port)"
  if [[ -z "$port" || "$port" == "0" ]]; then
    skip_or_fail "daemon_http" "cannot bind 127.0.0.1 in this environment" || return 1
  else
    start_daemon "$repo_root" "$host" "$port" "warn"
    run_http_smoke "$host" "$port"
    run_hook_http "$repo_root"
    run_profile_save_http "$host" "$port"
    PROFILE_SAVED=1
    run_mcp_smoke "$repo_root" "http://${host}:${port}"
    stop_daemon
  fi
  if [[ "$PROFILE_SAVED" == "1" ]]; then
    run_profile_export "$export_path"
  else
    skip_or_fail "profile_export" "profile save lane did not run" || return 1
  fi
  run_profile_embedder_tests "$repo_root"

  if [[ "$(uname -s)" == "Darwin" || "$(uname -s)" == "Linux" ]]; then
    local hook_socket="/tmp/docdex_hook_${$}_${RANDOM}.sock"
    HOOK_SOCKET="$hook_socket"
    local state_dir_unix="${workdir}/state_unix"
    mkdir -p "$state_dir_unix"
    export DOCDEX_STATE_DIR="$state_dir_unix"
    rm -f "$hook_socket"
    write_config "$home_dir" "$global_state_dir" "$hook_socket" "mcoda_frontend"
    port="$(pick_free_port)"
    if [[ -z "$port" || "$port" == "0" ]]; then
      skip_or_fail "hook_unix" "cannot bind 127.0.0.1 in this environment" || return 1
    else
      start_daemon "$repo_root" "$host" "$port" "warn"
      run_hook_unix "$repo_root" "$hook_socket"
      stop_daemon
    fi
    rm -f "$hook_socket"
    HOOK_SOCKET=""
  else
    skip_or_fail "hook_unix" "unsupported operating system" || return 1
  fi

  log "v2.1 test script completed successfully"
}

trap cleanup EXIT
trap 'handle_signal 130' INT
trap 'handle_signal 143' TERM
main "$@"
