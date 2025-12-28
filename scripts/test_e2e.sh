#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MOCK_OLLAMA="$SCRIPT_DIR/e2e/mock_ollama.py"

DOCDEXD_BIN="${DOCDEXD_BIN:-}"
if [[ -z "$DOCDEXD_BIN" ]]; then
  if [[ -x "$PWD/target/release/docdexd" ]]; then
    DOCDEXD_BIN="$PWD/target/release/docdexd"
  elif [[ -x "$PWD/target/debug/docdexd" ]]; then
    DOCDEXD_BIN="$PWD/target/debug/docdexd"
  elif [[ -x "$HOME/.cargo/bin/docdexd" ]]; then
    DOCDEXD_BIN="$HOME/.cargo/bin/docdexd"
  else
    echo "docdexd not found; set DOCDEXD_BIN or build the binary first" >&2
    exit 1
  fi
fi

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

require_cmd curl
require_cmd python3

if [[ ! -f "$MOCK_OLLAMA" ]]; then
  echo "mock ollama script not found at $MOCK_OLLAMA" >&2
  exit 1
fi

tmp_root="$(mktemp -d)"
repo_root="$tmp_root/repo"
state_dir="$tmp_root/state"
home_dir="$tmp_root/home"
log_root="${DOCDEX_E2E_LOG_DIR:-$tmp_root/logs}"
resp_dir="$log_root/responses"
mkdir -p "$repo_root" "$state_dir" "$home_dir" "$resp_dir"

keep_tmp="${DOCDEX_E2E_KEEP:-0}"

cleanup() {
  if [[ -n "${server_pid:-}" ]]; then
    kill "$server_pid" >/dev/null 2>&1 || true
    wait "$server_pid" >/dev/null 2>&1 || true
  fi
  if [[ -n "${ollama_pid:-}" ]]; then
    kill "$ollama_pid" >/dev/null 2>&1 || true
    wait "$ollama_pid" >/dev/null 2>&1 || true
  fi
  if [[ "$keep_tmp" != "1" ]]; then
    rm -rf "$tmp_root"
  else
    echo "kept temp dir: $tmp_root"
  fi
}
trap cleanup EXIT

fail() {
  echo "ERROR: $*" >&2
  echo "logs: $log_root" >&2
  exit 1
}

pick_free_port() {
  python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

write_repo() {
  mkdir -p "$repo_root/src" "$repo_root/docs"
  cat <<'RS' > "$repo_root/src/lib.rs"
mod foo;

pub fn hello() {
    foo::greet();
}
RS
  cat <<'RS' > "$repo_root/src/foo.rs"
pub fn greet() {
    println!("hi");
}
RS
  cat <<'MD' > "$repo_root/docs/notes.md"
# Notes

E2E_SEARCH_TOKEN
MD
}

start_mock_ollama() {
  local port_file="$tmp_root/ollama.port"
  local log_file="$log_root/mock_ollama.log"
  python3 "$MOCK_OLLAMA" --port-file "$port_file" --model "fake-model" >"$log_file" 2>&1 &
  ollama_pid=$!
  local deadline=$((SECONDS + 10))
  while [[ ! -s "$port_file" ]]; do
    if (( SECONDS >= deadline )); then
      fail "mock ollama did not start (see $log_file)"
    fi
    sleep 0.1
  done
  ollama_port="$(cat "$port_file")"
}

write_config() {
  mkdir -p "$home_dir/.docdex"
  cat <<EOF > "$home_dir/.docdex/config.toml"
[llm]
provider = "ollama"
base_url = "http://127.0.0.1:${ollama_port}"
default_model = "fake-model"
embedding_model = "fake-model"
max_answer_tokens = 64

[web.scraper]
engine = "none"

[memory]
enabled = false
EOF
}

start_server() {
  local host="127.0.0.1"
  server_port="$(pick_free_port)"
  local log_file="$log_root/docdexd.log"
  DOCDEX_ENABLE_MCP=0 \
    HOME="$home_dir" \
    "$DOCDEXD_BIN" serve \
    --repo "$repo_root" \
    --state-dir "$state_dir" \
    --host "$host" \
    --port "$server_port" \
    --log info \
    --secure-mode=false \
    --preflight-check=true \
    --disable-mcp \
    --ollama-base-url "http://127.0.0.1:${ollama_port}" \
    --embedding-model "fake-model" \
    >"$log_file" 2>&1 &
  server_pid=$!

  local health_url="http://${host}:${server_port}/healthz"
  local deadline=$((SECONDS + 20))
  while (( SECONDS < deadline )); do
    if curl -sSf "$health_url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.2
  done
  fail "docdexd healthz did not respond (see $log_file)"
}

curl_json() {
  local name="$1"
  local method="$2"
  local url="$3"
  local data="${4:-}"
  local body_file="$resp_dir/${name}.json"
  local status_file="$resp_dir/${name}.status"
  local status
  if [[ "$method" == "GET" ]]; then
    status="$(curl -sS --max-time 10 -o "$body_file" -w "%{http_code}" "$url")"
  else
    status="$(curl -sS --max-time 20 -o "$body_file" -w "%{http_code}" \
      -H "Content-Type: application/json" -X "$method" -d "$data" "$url")"
  fi
  echo "$status" > "$status_file"
  echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") $name $method $url $status" >> "$log_root/requests.log"
  if [[ "$status" -lt 200 || "$status" -ge 300 ]]; then
    echo "request $name failed with status $status" >&2
    cat "$body_file" >&2 || true
    return 1
  fi
}

assert_json() {
  local name="$1"
  shift
  python3 - "$resp_dir/${name}.json" "$@" <<'PY'
import json
import sys

path = sys.argv[1]
args = sys.argv[2:]
with open(path, "r", encoding="utf-8") as fh:
    data = json.load(fh)
for check in args:
    if check == "hits_non_empty":
        if not data.get("hits"):
            raise SystemExit("expected hits to be non-empty")
    elif check == "symbols_non_empty":
        if not data.get("symbols"):
            raise SystemExit("expected symbols to be non-empty")
    elif check == "ast_nodes_non_empty":
        if not data.get("nodes"):
            raise SystemExit("expected ast nodes to be non-empty")
    elif check == "ast_matches_non_empty":
        if not data.get("matches"):
            raise SystemExit("expected ast matches to be non-empty")
    elif check == "impact_outbound":
        outbound = data.get("outbound") or []
        if "src/foo.rs" not in outbound:
            raise SystemExit("expected impact outbound to include src/foo.rs")
    elif check == "chat_response":
        choices = data.get("choices") or []
        if not choices:
            raise SystemExit("expected chat choices to be non-empty")
        content = (
            choices[0].get("message", {}).get("content")
            if isinstance(choices[0], dict)
            else None
        )
        if not content:
            raise SystemExit("expected chat content to be non-empty")
    elif check == "index_docs":
        docs = data.get("docs_indexed")
        if docs is None or docs < 1:
            raise SystemExit("expected docs_indexed >= 1")
    else:
        raise SystemExit(f"unknown check: {check}")
PY
}

write_repo
start_mock_ollama
write_config
start_server

base_url="http://127.0.0.1:${server_port}"

curl_json "index_rebuild" "POST" "${base_url}/v1/index/rebuild" "{}"
assert_json "index_rebuild" "index_docs"

curl_json "search" "GET" "${base_url}/search?q=E2E_SEARCH_TOKEN&limit=5"
assert_json "search" "hits_non_empty"

curl_json "symbols" "GET" "${base_url}/v1/symbols?path=src/lib.rs"
assert_json "symbols" "symbols_non_empty"

curl_json "ast" "GET" "${base_url}/v1/ast?path=src/lib.rs"
assert_json "ast" "ast_nodes_non_empty"

curl_json "ast_search" "GET" "${base_url}/v1/ast/search?kinds=function_item,struct_item&limit=10"
assert_json "ast_search" "ast_matches_non_empty"

curl_json "ast_query" "POST" "${base_url}/v1/ast/query" '{"kinds":["function_item"],"limit":5}'
assert_json "ast_query" "ast_matches_non_empty"

curl_json "impact" "GET" "${base_url}/v1/graph/impact?file=src/lib.rs"
assert_json "impact" "impact_outbound"

curl_json "chat" "POST" "${base_url}/v1/chat/completions" \
  '{"model":"fake-model","messages":[{"role":"user","content":"hello from e2e"}],"docdex":{"limit":3}}'
assert_json "chat" "chat_response"

echo "e2e checks passed"
echo "logs: $log_root"
