#!/usr/bin/env bash
set -euo pipefail

DOCDEX_BIN="${DOCDEX_BIN:-${DOCDEXD_BIN:-}}"
if [[ -z "$DOCDEX_BIN" ]]; then
  if [[ -x "$PWD/target/debug/docdexd" ]]; then
    DOCDEX_BIN="$PWD/target/debug/docdexd"
  elif [[ -x "$PWD/target/release/docdexd" ]]; then
    DOCDEX_BIN="$PWD/target/release/docdexd"
  elif [[ -x "$HOME/.cargo/bin/docdexd" ]]; then
    DOCDEX_BIN="$HOME/.cargo/bin/docdexd"
  fi
fi

if [[ ! -x "$DOCDEX_BIN" ]]; then
  echo "docdexd not found at $DOCDEX_BIN" >&2
  exit 1
fi

export DOCDEX_CLI_LOCAL=1

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required" >&2
  exit 1
fi

if ! command -v sqlite3 >/dev/null 2>&1; then
  echo "sqlite3 is required" >&2
  exit 1
fi

tmp_root="$(mktemp -d)"
repo_root="$tmp_root/repo"
state_dir="$tmp_root/state"

cleanup() {
  if [[ -n "${server_pid:-}" ]]; then
    kill "$server_pid" >/dev/null 2>&1 || true
    wait "$server_pid" >/dev/null 2>&1 || true
  fi
  rm -rf "$tmp_root"
}
trap cleanup EXIT

mkdir -p "$repo_root/src"
mkdir -p "$repo_root/docs"
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

## Overview

Just a small document so the index isn't empty.
MD

"$DOCDEX_BIN" index --repo "$repo_root" --state-dir "$state_dir" >/dev/null 2>&1

symbols_db="$(find "$state_dir" -name symbols.db -print -quit)"
if [[ -z "$symbols_db" ]]; then
  echo "symbols.db not found under $state_dir" >&2
  exit 1
fi

symbols_count="$(sqlite3 "$symbols_db" "SELECT COUNT(*) FROM symbols WHERE file_path = 'src/lib.rs';")"
notes_symbols_count="$(sqlite3 "$symbols_db" "SELECT COUNT(*) FROM symbols_files WHERE file_path = 'docs/notes.md';")"
if [[ "$notes_symbols_count" -eq 0 ]]; then
  echo "index check failed: docs/notes.md did not produce a symbols_files entry" >&2
  exit 1
fi

notes_ast_status="$(sqlite3 "$symbols_db" "SELECT outcome_status FROM ast_files WHERE file_path = 'docs/notes.md';")"
if [[ -z "$notes_ast_status" ]]; then
  echo "ast check failed: docs/notes.md did not produce an ast_files entry" >&2
  exit 1
fi

if [[ "$symbols_count" -eq 0 ]]; then
  echo "symbols check failed: no symbols for src/lib.rs (likely not indexed; default extensions are .md/.markdown/.mdx/.txt)" >&2
  exit 1
fi

ast_count="$(sqlite3 "$symbols_db" "SELECT COUNT(*) FROM ast_nodes WHERE file_path = 'src/lib.rs';")"
if [[ "$ast_count" -eq 0 ]]; then
  echo "ast check failed: no ast_nodes for src/lib.rs (file may not be indexed due to extension filtering)" >&2
  exit 1
fi

fn_count="$(sqlite3 "$symbols_db" "SELECT COUNT(*) FROM ast_nodes WHERE file_path = 'src/lib.rs' AND kind = 'function_item';")"
if [[ "$fn_count" -eq 0 ]]; then
  echo "ast check failed: function_item not found for src/lib.rs" >&2
  exit 1
fi

impact_path="$(find "$state_dir" -name impact_graph.json -print -quit)"
if [[ -z "$impact_path" ]]; then
  echo "impact_graph.json not found under $state_dir" >&2
  exit 1
fi

python3 - <<'PY' "$impact_path"
import json, sys
path = sys.argv[1]
with open(path, "r", encoding="utf-8") as fh:
    payload = json.load(fh)

edges = []
if isinstance(payload, list):
    for entry in payload:
        if isinstance(entry, dict):
            edges.extend(entry.get("edges", []))
elif isinstance(payload, dict):
    if isinstance(payload.get("edges"), list):
        edges = payload.get("edges", [])
    elif isinstance(payload.get("graphs"), list):
        for entry in payload.get("graphs", []):
            if isinstance(entry, dict):
                edges.extend(entry.get("edges", []))

expected_source = "src/lib.rs"
expected_target = "src/foo.rs"
found = any(
    isinstance(edge, dict)
    and edge.get("source") == expected_source
    and edge.get("target") == expected_target
    for edge in edges
)
if not found:
    print("impact check failed: missing edge src/lib.rs -> src/foo.rs")
    sys.exit(1)
PY

echo "AST checks passed (symbols, ast nodes, impact graph)"
