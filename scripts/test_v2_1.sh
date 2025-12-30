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

log() {
  printf "[v2.1] %s\n" "$*" >&2
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
    cargo build -q
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
  mkdir -p "$home_dir/.docdex"
  cat >"$home_dir/.docdex/config.toml" <<EOF
[core]
global_state_dir = "${global_state_dir}"

[llm]
base_url = "http://127.0.0.1:11434"
default_model = "fake-model"

[memory.profile]
embedding_model = "nomic-embed-text"
embedding_dim = ${embed_dim}

[server]
default_agent_id = "${agent_id}"
hook_socket_path = "${hook_socket}"
enable_mcp = false

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
    --secure-mode=false \
    --disable-mcp \
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
    wait "$DAEMON_PID" >/dev/null 2>&1 || true
    DAEMON_PID=""
  fi
  if [[ -n "${DAEMON_LOG:-}" ]]; then
    rm -f "$DAEMON_LOG" >/dev/null 2>&1 || true
    DAEMON_LOG=""
  fi
}

run_cli_smoke() {
  local repo_root="$1"
  log "CLI smoke"
  "$DOCDEX_BIN" --help >/dev/null
  "$DOCDEX_BIN" serve --help >/dev/null
  "$DOCDEX_BIN" profile --help >/dev/null
  "$DOCDEX_BIN" hook --help >/dev/null
  if ! "$DOCDEX_BIN" check >/dev/null; then
    log "docdexd check failed (likely missing Ollama); continuing"
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

run_hook_unix() {
  local repo_root="$1"
  log "hook pre-commit (unix socket)"
  "$DOCDEX_BIN" hook pre-commit --repo "$repo_root"
}

run_profile_embedder_tests() {
  local repo_root="$1"
  if [[ "${RUN_EMBEDDING:-0}" != "1" ]]; then
    log "skipping embedding-dependent profile tests (set RUN_EMBEDDING=1 to enable)"
    return 0
  fi
  log "profile add/search/save (embedding required)"
  "$DOCDEX_BIN" profile add --agent-id "mcoda_frontend" --category style --content "Prefer concise answers" >/dev/null
  "$DOCDEX_BIN" profile search --agent-id "mcoda_frontend" --query "concise" >/dev/null
  if [[ "${RUN_LLM:-0}" == "1" ]]; then
    "$DOCDEX_BIN" profile save --agent-id "mcoda_frontend" --category tooling --content "Use Vitest" >/dev/null
  else
    log "skipping profile save evolution (set RUN_LLM=1 to enable)"
  fi
}

run_profile_export() {
  local out_path="$1"
  log "profile export"
  "$DOCDEX_BIN" profile export --out "$out_path" >/dev/null
  python3 - <<PY
import json, sys
with open("${out_path}", "r", encoding="utf-8") as f:
    data = json.load(f)
assert "schema_version" in data and "preferences" in data
PY
}

run_mcp_smoke() {
  local repo_root="$1"
  if [[ "${SKIP_MCP:-0}" == "1" ]]; then
    log "skipping MCP smoke (SKIP_MCP=1)"
    return 0
  fi
  log "MCP stdio smoke"
  python3 - <<PY
import json, subprocess, sys, time
cmd = ["${DOCDEX_BIN}", "mcp", "--repo", "${repo_root}", "--log", "warn"]
proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
def send(payload):
    proc.stdin.write(json.dumps(payload) + "\n")
    proc.stdin.flush()
    line = proc.stdout.readline()
    if not line:
        raise SystemExit("mcp server closed stdout")
    return json.loads(line)
resp = send({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"agent_id": "mcoda_frontend"}})
assert resp.get("id") == 1 and "result" in resp
resp = send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
tools = resp.get("result", {}).get("tools", [])
names = {t.get("name") for t in tools}
assert "docdex_save_preference" in names and "docdex_get_profile" in names
resp = send({
    "jsonrpc": "2.0",
    "id": 3,
    "method": "tools/call",
    "params": {"name": "docdex_get_profile", "arguments": {"agent_id": "mcoda_frontend"}}
})
assert resp.get("id") == 3
proc.terminate()
proc.wait(timeout=5)
PY
}

run_cargo_tests() {
  if [[ "${FAST:-0}" == "1" ]]; then
    log "FAST=1: running focused tests only"
    cargo test -q \
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
  cargo test --workspace --tests
  if [[ "${RUN_CLIPPY:-0}" == "1" ]]; then
    log "running cargo clippy"
    cargo clippy --all-targets -- -D warnings
  fi
}

main() {
  require_cmd git
  require_cmd python3
  require_cmd curl
  ensure_binary

  local workdir
  workdir="$(mktemp -d)"
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
    log "skipping daemon HTTP tests (cannot bind 127.0.0.1 in this environment)"
  else
    start_daemon "$repo_root" "$host" "$port" "warn"
    run_http_smoke "$host" "$port"
    run_hook_http "$repo_root"
    stop_daemon
  fi
  run_profile_export "$export_path"
  run_profile_embedder_tests "$repo_root"
  run_mcp_smoke "$repo_root"

  if [[ "$(uname -s)" == "Darwin" || "$(uname -s)" == "Linux" ]]; then
    local hook_socket="/tmp/docdex_hook_${$}_${RANDOM}.sock"
    local state_dir_unix="${workdir}/state_unix"
    mkdir -p "$state_dir_unix"
    export DOCDEX_STATE_DIR="$state_dir_unix"
    rm -f "$hook_socket"
    write_config "$home_dir" "$global_state_dir" "$hook_socket" "mcoda_frontend"
    port="$(pick_free_port)"
    if [[ -z "$port" || "$port" == "0" ]]; then
      log "skipping unix hook test (cannot bind 127.0.0.1 in this environment)"
    else
      start_daemon "$repo_root" "$host" "$port" "warn"
      run_hook_unix "$repo_root"
      stop_daemon
    fi
    rm -f "$hook_socket"
  fi

  log "v2.1 test script completed successfully"
}

trap stop_daemon EXIT
main "$@"
