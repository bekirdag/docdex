#!/usr/bin/env bash
set -euo pipefail

DOCDEXD_BIN="${DOCDEXD_BIN:-$HOME/.cargo/bin/docdexd}"
REPO_ROOT="${REPO_ROOT:-$(pwd)}"
REPO_B="${REPO_B:-}"
SERVER_URL="${SERVER_URL:-http://127.0.0.1:3210}"
OLLAMA_BASE_URL="${OLLAMA_BASE_URL:-}"
EMBEDDING_MODEL="${EMBEDDING_MODEL:-}"
START_SERVER="${START_SERVER:-0}"
CHECK_DROP_LOGS="${CHECK_DROP_LOGS:-1}"
LOG_FILE="${LOG_FILE:-}"

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1" >&2
    exit 1
  fi
}

require_env() {
  if [[ -z "${!1:-}" ]]; then
    echo "missing required env: $1" >&2
    exit 1
  fi
}

require_cmd curl
require_cmd jq

if [[ "$START_SERVER" == "1" ]]; then
  require_cmd python3
  require_env OLLAMA_BASE_URL
  require_env EMBEDDING_MODEL
  if [[ -z "$LOG_FILE" ]]; then
    LOG_FILE="$(mktemp -t docdexd-log.XXXXXX)"
  fi
  mapfile -t server_parts < <(
    python3 - <<'PY' "$SERVER_URL"
import sys
from urllib.parse import urlparse

url = sys.argv[1]
parsed = urlparse(url)
host = parsed.hostname or "127.0.0.1"
port = parsed.port or 3210
print(host)
print(port)
PY
  )
  SERVER_HOST="${server_parts[0]:-127.0.0.1}"
  SERVER_PORT="${server_parts[1]:-3210}"
  echo "starting docdexd server; logging to $LOG_FILE"
  "$DOCDEXD_BIN" serve \
    --repo "$REPO_ROOT" \
    --host "$SERVER_HOST" \
    --port "$SERVER_PORT" \
    --enable-memory=true \
    --ollama-base-url "$OLLAMA_BASE_URL" \
    --embedding-model "$EMBEDDING_MODEL" \
    --secure-mode=false \
    >"$LOG_FILE" 2>&1 &
  SERVER_PID=$!
  trap 'kill "$SERVER_PID" >/dev/null 2>&1 || true' EXIT
  sleep 1
fi

echo "memory store (HTTP)"
store_json="$(curl -sSf "$SERVER_URL/v1/memory/store" \
  -H 'Content-Type: application/json' \
  -d '{"text":"hello memory"}')"
memory_id="$(echo "$store_json" | jq -r '.id')"
if [[ -z "$memory_id" || "$memory_id" == "null" ]]; then
  echo "memory store failed: $store_json" >&2
  exit 1
fi
echo "  id=$memory_id"

echo "memory recall (HTTP)"
recall_json="$(curl -sSf "$SERVER_URL/v1/memory/recall" \
  -H 'Content-Type: application/json' \
  -d '{"query":"hello","top_k":5}')"
recall_count="$(echo "$recall_json" | jq -r '.results | length')"
if [[ "$recall_count" -lt 1 ]]; then
  echo "memory recall returned no results: $recall_json" >&2
  exit 1
fi
echo "  results=$recall_count"

echo "chat completion (HTTP, compress_results)"
chat_json="$(curl -sSf "$SERVER_URL/v1/chat/completions" \
  -H 'Content-Type: application/json' \
  -d '{"model":"phi3.5:3.8b","messages":[{"role":"user","content":"hello memory"}],"docdex":{"compress_results":true}}')"
chat_id="$(echo "$chat_json" | jq -r '.id')"
chat_content="$(echo "$chat_json" | jq -r '.choices[0].message.content')"
memory_len="$(echo "$chat_content" | jq -r '.results.memory | length')"
if [[ "$memory_len" -lt 1 ]]; then
  echo "chat completion missing memory context: $chat_content" >&2
  exit 1
fi
echo "  chat_id=$chat_id memory_items=$memory_len"

echo "dag export (HTTP)"
session_id="${chat_id#chatcmpl-}"
dag_json="$(curl -sSf "$SERVER_URL/v1/dag/export?session_id=$session_id&format=json&max_nodes=50")"
dag_nodes="$(echo "$dag_json" | jq -r '.nodes | length')"
if [[ "$dag_nodes" -lt 1 ]]; then
  echo "dag export returned no nodes: $dag_json" >&2
  exit 1
fi
curl -sSf "$SERVER_URL/v1/dag/export?session_id=$session_id&format=dot&max_nodes=50" \
  | head -n 1 >/dev/null
echo "  session_id=$session_id nodes=$dag_nodes"

echo "memory isolation (CLI)"
if [[ -z "$REPO_B" ]]; then
  echo "  skipped (set REPO_B to a second repo path)"
else
  require_env OLLAMA_BASE_URL
  require_env EMBEDDING_MODEL
  iso_token="isolation-$(date +%s)"
  DOCDEX_ENABLE_MEMORY=1 \
    DOCDEX_OLLAMA_BASE_URL="$OLLAMA_BASE_URL" \
    DOCDEX_EMBEDDING_MODEL="$EMBEDDING_MODEL" \
    "$DOCDEXD_BIN" memory-store --repo "$REPO_ROOT" --text "$iso_token" >/dev/null

  repo_a_recall="$(
    DOCDEX_ENABLE_MEMORY=1 \
      DOCDEX_OLLAMA_BASE_URL="$OLLAMA_BASE_URL" \
      DOCDEX_EMBEDDING_MODEL="$EMBEDDING_MODEL" \
      "$DOCDEXD_BIN" memory-recall --repo "$REPO_ROOT" --query "$iso_token" --top-k 5
  )"
  repo_b_recall="$(
    DOCDEX_ENABLE_MEMORY=1 \
      DOCDEX_OLLAMA_BASE_URL="$OLLAMA_BASE_URL" \
      DOCDEX_EMBEDDING_MODEL="$EMBEDDING_MODEL" \
      "$DOCDEXD_BIN" memory-recall --repo "$REPO_B" --query "$iso_token" --top-k 5
  )"
  repo_a_hits="$(echo "$repo_a_recall" | jq -r --arg tok "$iso_token" '[.results[]? | select(.content == $tok)] | length')"
  repo_b_hits="$(echo "$repo_b_recall" | jq -r --arg tok "$iso_token" '[.results[]? | select(.content == $tok)] | length')"
  if [[ "$repo_a_hits" -lt 1 || "$repo_b_hits" -ne 0 ]]; then
    echo "memory isolation failed: repo_a_hits=$repo_a_hits repo_b_hits=$repo_b_hits" >&2
    exit 1
  fi
  echo "  ok (repo_a_hits=$repo_a_hits repo_b_hits=$repo_b_hits)"
fi

echo "budget drop logging (best effort)"
if [[ -n "$LOG_FILE" && -f "$LOG_FILE" && "$CHECK_DROP_LOGS" == "1" ]]; then
  if grep -q "pruned to fit token budget" "$LOG_FILE"; then
    echo "  found budget drop log entry"
  else
    echo "  no budget drop log entry found; consider lowering max_answer_tokens to force pruning"
  fi
else
  echo "  skipped (set START_SERVER=1 or LOG_FILE=path/to/log)"
fi

echo "done"
