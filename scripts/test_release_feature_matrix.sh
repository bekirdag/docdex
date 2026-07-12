#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONTRACT_HELPER="${ROOT_DIR}/scripts/release_feature_matrix_contract.py"
STRICT_EXTERNAL="${DOCDEX_FEATURE_MATRIX_STRICT_EXTERNAL:-0}"
RELEASE_GATE="${DOCDEX_FEATURE_MATRIX_RELEASE_GATE:-0}"
EXTERNAL_TIMEOUT_SECONDS="${DOCDEX_FEATURE_MATRIX_EXTERNAL_TIMEOUT_SECONDS:-120}"
EVIDENCE_PATH="${DOCDEX_FEATURE_MATRIX_EVIDENCE:-${ROOT_DIR}/target/release_feature_matrix/evidence.json}"
DOCDEX_BIN="${DOCDEX_BIN:-}"
EXPECTED_LOCAL_LANES=$'daemon_health\ninitialize\ncapabilities\nindex_rebuild\nindex_status\nsearch\nbatch_search\nrerank\nfiles\nstats\ntree\nopen\nrepo_inspect\nwatcher_create\nwatcher_update\nwatcher_delete\nconversation_import\nconversation_list_read_export\ndiary_lifecycle\nwakeup\nkg_lifecycle\nconversation_redact_delete\nmcp_stateless\nmcp_sse'
EXPECTED_EXTERNAL_LANES=$'external_user_memory\nexternal_admin\nexternal_introspection\nexternal_web\nexternal_delegation'

usage() {
  cat <<'USAGE'
Usage: scripts/test_release_feature_matrix.sh [options]

Options:
  --binary PATH       Use this already-built debug or release docdexd binary.
  --evidence PATH     Write the JSON evidence ledger to PATH.
  --strict-external   Fail when an external lane is blocked as well as failed.
  --release-gate      Fail on blocked, mock-verified, or failed lanes.
  -h, --help          Show this help.

External lanes are disabled unless their executable script variable is set:
  DOCDEX_FEATURE_MATRIX_USER_MEMORY_SCRIPT
  DOCDEX_FEATURE_MATRIX_ADMIN_SCRIPT
  DOCDEX_FEATURE_MATRIX_INTROSPECTION_SCRIPT
  DOCDEX_FEATURE_MATRIX_WEB_SCRIPT
  DOCDEX_FEATURE_MATRIX_DELEGATION_SCRIPT

Each configured lane must explicitly set its matching *_MODE to "real"
(verified) or "mock" (mock_verified), plus an optional comma-separated
*_ENV_ALLOWLIST naming only the credential/config variables that adapter needs.
The adapter path must resolve inside this repository. It receives an isolated,
allowlisted environment and must write schema-v1 JSON to its unique
DOCDEX_FEATURE_MATRIX_LANE_EVIDENCE path. The top-level fields are exactly
schema_version, lane, base_url, repo_id, mode, script_sha256, adapter, and
checks; adapter contains exactly name/version/provider, and each check contains
exactly name/passed/evidence. Exact lane-specific check names are printed by:
  python3 scripts/release_feature_matrix_contract.py describe
The harness records the canonical adapter path, adapter/evidence SHA-256,
forwarded environment variable names, and measured duration. No command strings
are evaluated and no ambient environment is inherited.
USAGE
}

log() {
  printf '[release-matrix] %s\n' "$*" >&2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --binary)
      DOCDEX_BIN="$2"
      shift 2
      ;;
    --evidence)
      EVIDENCE_PATH="$2"
      shift 2
      ;;
    --strict-external)
      STRICT_EXTERNAL=1
      shift
      ;;
    --release-gate)
      RELEASE_GATE=1
      STRICT_EXTERNAL=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      log "unknown option: $1"
      usage
      exit 2
      ;;
  esac
done

if [[ ! "$EXTERNAL_TIMEOUT_SECONDS" =~ ^[0-9]+$ ]] \
  || (( EXTERNAL_TIMEOUT_SECONDS < 1 || EXTERNAL_TIMEOUT_SECONDS > 900 )); then
  log "DOCDEX_FEATURE_MATRIX_EXTERNAL_TIMEOUT_SECONDS must be between 1 and 900"
  exit 2
fi

if [[ -z "$DOCDEX_BIN" ]]; then
  if [[ -x "${ROOT_DIR}/target/release/docdexd" ]]; then
    DOCDEX_BIN="${ROOT_DIR}/target/release/docdexd"
  elif [[ -x "${ROOT_DIR}/target/debug/docdexd" ]]; then
    DOCDEX_BIN="${ROOT_DIR}/target/debug/docdexd"
  else
    log "set DOCDEX_BIN or build target/debug/docdexd or target/release/docdexd first"
    exit 1
  fi
fi

if [[ "$DOCDEX_BIN" == */* ]]; then
  DOCDEX_BIN="$(cd "$(dirname "$DOCDEX_BIN")" && pwd)/$(basename "$DOCDEX_BIN")"
else
  DOCDEX_BIN="$(command -v "$DOCDEX_BIN" || true)"
fi
if [[ -z "$DOCDEX_BIN" || ! -x "$DOCDEX_BIN" ]]; then
  log "docdexd binary is not executable: ${DOCDEX_BIN:-<missing>}"
  exit 1
fi

for command_name in python3 curl git env; do
  if ! command -v "$command_name" >/dev/null 2>&1; then
    log "missing required command: $command_name"
    exit 1
  fi
done
if [[ ! -f "$CONTRACT_HELPER" ]]; then
  log "missing release feature-matrix contract helper: ${CONTRACT_HELPER}"
  exit 1
fi

file_sha256() {
  python3 - "$1" <<'PY'
import hashlib
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
digest = hashlib.sha256()
with path.open("rb") as handle:
    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
        digest.update(chunk)
print(digest.hexdigest())
PY
}

HARNESS_SHA256="$(file_sha256 "${BASH_SOURCE[0]}")"
CONTRACT_HELPER_SHA256="$(file_sha256 "$CONTRACT_HELPER")"
BINARY_SHA256="$(file_sha256 "$DOCDEX_BIN")"
EXTERNAL_CONTRACTS_JSON="$(python3 "$CONTRACT_HELPER" describe)"
SAFE_PATH="/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin"

pick_free_port() {
  python3 - <<'PY'
import socket
with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
}

TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/docdex-release-matrix.XXXXXX")"
HOME_DIR="${TMP_ROOT}/home"
STATE_DIR="${TMP_ROOT}/state"
GLOBAL_STATE_DIR="${TMP_ROOT}/global"
REPO_DIR="${TMP_ROOT}/repo"
RESULTS_JSONL="${TMP_ROOT}/results.jsonl"
REPO_ID_FILE="${TMP_ROOT}/repo_id"
DAEMON_PID=""
EXTERNAL_DAEMON_PID=""
CLEANUP_DONE=0
PORT="$(pick_free_port)"
BASE_URL="http://127.0.0.1:${PORT}"
EVIDENCE_DIR="$(dirname "$EVIDENCE_PATH")"
DAEMON_LOG="${EVIDENCE_DIR}/daemon.log"
LOCAL_TMPDIR="${TMP_ROOT}/tmp"

mkdir -p "$HOME_DIR/.docdex" "$STATE_DIR" "$GLOBAL_STATE_DIR" \
  "$REPO_DIR/src" "$EVIDENCE_DIR/logs" "$LOCAL_TMPDIR"
env -i PATH="$SAFE_PATH" HOME="$HOME_DIR" LANG=C LC_ALL=C TZ=UTC \
  GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
  git -C "$REPO_DIR" -c init.defaultBranch=main init -q
printf '# Release feature matrix\n\nFEATURE_MATRIX_INITIAL\n' >"${REPO_DIR}/README.md"
printf 'pub fn release_matrix() -> bool { true }\n' >"${REPO_DIR}/src/lib.rs"

cat >"${HOME_DIR}/.docdex/config.toml" <<EOF
[core]
global_state_dir = "${GLOBAL_STATE_DIR}"

[memory.conversations]
enabled = true

[server]
enable_mcp = true
default_agent_id = "release-feature-matrix"
EOF

terminate_pid() {
  local pid="$1"
  local attempts=0
  kill "$pid" >/dev/null 2>&1 || true
  while kill -0 "$pid" >/dev/null 2>&1 && (( attempts < 20 )); do
    sleep 0.1
    attempts=$((attempts + 1))
  done
  if kill -0 "$pid" >/dev/null 2>&1; then
    kill -KILL "$pid" >/dev/null 2>&1 || true
  fi
  wait "$pid" >/dev/null 2>&1 || true
}

monotonic_ms() {
  python3 - <<'PY'
import time
print(time.monotonic_ns() // 1_000_000)
PY
}

elapsed_ms() {
  local started_ms="$1"
  local finished_ms
  finished_ms="$(monotonic_ms)"
  if (( finished_ms <= started_ms )); then
    printf '1\n'
  else
    printf '%s\n' "$((finished_ms - started_ms))"
  fi
}

cleanup() {
  if [[ "$CLEANUP_DONE" == "1" ]]; then
    return
  fi
  CLEANUP_DONE=1
  if [[ -n "$EXTERNAL_DAEMON_PID" ]]; then
    terminate_pid "$EXTERNAL_DAEMON_PID"
    EXTERNAL_DAEMON_PID=""
  fi
  if [[ -n "$DAEMON_PID" ]]; then
    terminate_pid "$DAEMON_PID"
    DAEMON_PID=""
  fi
  rm -rf "$TMP_ROOT"
}

handle_signal() {
  local exit_code="$1"
  trap - EXIT INT TERM
  cleanup
  exit "$exit_code"
}

trap cleanup EXIT
trap 'handle_signal 130' INT
trap 'handle_signal 143' TERM

record_shell_result() {
  local lane="$1"
  local status="$2"
  local detail="$3"
  local duration_ms="${4:-1}"
  local provenance_json="${5:-}"
  if [[ -z "$provenance_json" ]]; then
    provenance_json='{}'
  fi
  python3 - "$RESULTS_JSONL" "$lane" "$status" "$detail" \
    "$duration_ms" "$provenance_json" <<'PY'
import json
import sys

path, lane, status, detail, duration_raw, provenance_raw = sys.argv[1:7]
try:
    duration_ms = max(1, int(duration_raw))
except ValueError:
    raise SystemExit("duration_ms must be an integer")
try:
    provenance = json.loads(provenance_raw)
except json.JSONDecodeError as exc:
    raise SystemExit(f"invalid provenance JSON: {exc}")
if not isinstance(provenance, dict):
    raise SystemExit("provenance must be a JSON object")
item = {
    "lane": lane,
    "status": status,
    "detail": detail.replace("\n", " ")[:700],
    "duration_ms": duration_ms,
}
if provenance:
    item["provenance"] = provenance
with open(path, "a", encoding="utf-8") as handle:
    handle.write(json.dumps(item, sort_keys=True) + "\n")
PY
}

finalize_ledger() {
  local binary_version
  binary_version="$("$DOCDEX_BIN" --version 2>/dev/null | head -n 1 || true)"
  set +e
  python3 - "$RESULTS_JSONL" "$EVIDENCE_PATH" "$DOCDEX_BIN" \
    "$binary_version" "$STRICT_EXTERNAL" "$RELEASE_GATE" "$ROOT_DIR" \
    "$EXPECTED_LOCAL_LANES" "$EXPECTED_EXTERNAL_LANES" \
    "$HARNESS_SHA256" "$CONTRACT_HELPER_SHA256" "$BINARY_SHA256" \
    "$EXTERNAL_CONTRACTS_JSON" <<'PY'
import json
import os
import pathlib
import re
import sys
import tomllib
from collections import Counter
from datetime import datetime, timezone

(
    results_path,
    evidence_path,
    binary,
    version,
    strict_raw,
    release_gate_raw,
    root_raw,
    expected_local_raw,
    expected_external_raw,
    harness_sha256,
    contract_helper_sha256,
    binary_sha256,
    external_contracts_raw,
) = sys.argv[1:14]
allowed_statuses = {"verified", "mock_verified", "blocked_external", "failed"}
expected_local = expected_local_raw.splitlines()
expected_external = expected_external_raw.splitlines()
expected_lanes = expected_local + expected_external
validation_errors = []
sha256_pattern = re.compile(r"[0-9a-f]{64}\Z")
try:
    external_contracts = json.loads(external_contracts_raw)
except json.JSONDecodeError as exc:
    external_contracts = {}
    validation_errors.append(f"external evidence contract JSON is invalid: {exc}")
if set(external_contracts) != set(expected_external):
    validation_errors.append("external evidence contract lane inventory mismatch")
for label, digest in (
    ("harness", harness_sha256),
    ("contract helper", contract_helper_sha256),
    ("binary", binary_sha256),
):
    if sha256_pattern.fullmatch(digest) is None:
        validation_errors.append(f"{label} SHA-256 is invalid")

if not expected_lanes or len(expected_lanes) != len(set(expected_lanes)):
    validation_errors.append("expected lane inventory is empty or contains duplicates")

results = []
if os.path.exists(results_path):
    with open(results_path, "r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if line.strip():
                try:
                    item = json.loads(line)
                except json.JSONDecodeError as exc:
                    validation_errors.append(f"result line {line_number} is invalid JSON: {exc}")
                    continue
                if not isinstance(item, dict):
                    validation_errors.append(f"result line {line_number} is not an object")
                    continue
                lane = item.get("lane")
                status = item.get("status")
                duration = item.get("duration_ms")
                if not isinstance(lane, str) or not lane:
                    validation_errors.append(f"result line {line_number} has an invalid lane")
                if status not in allowed_statuses:
                    validation_errors.append(f"lane {lane!r} has invalid status {status!r}")
                if not isinstance(duration, int) or duration <= 0:
                    validation_errors.append(f"lane {lane!r} has invalid duration_ms")
                provenance = item.get("provenance")
                if provenance is not None and not isinstance(provenance, dict):
                    validation_errors.append(f"lane {lane!r} has invalid provenance")
                results.append(item)

observed_lanes = [item.get("lane") for item in results if isinstance(item.get("lane"), str)]
duplicates = sorted(lane for lane, count in Counter(observed_lanes).items() if count > 1)
if duplicates:
    validation_errors.append("duplicate result lanes: " + ", ".join(duplicates))
missing = sorted(set(expected_lanes) - set(observed_lanes))
unexpected = sorted(set(observed_lanes) - set(expected_lanes))
if missing:
    validation_errors.append("missing expected lanes: " + ", ".join(missing))
if unexpected:
    validation_errors.append("unexpected lanes: " + ", ".join(unexpected))
for item in results:
    if item.get("lane") in expected_local and item.get("status") != "verified":
        validation_errors.append(
            f"deterministic local lane {item.get('lane')!r} must be verified, got {item.get('status')!r}"
        )
    if item.get("lane") in expected_external and item.get("status") in {
        "verified", "mock_verified"
    }:
        provenance = item.get("provenance")
        required = external_contracts.get(item.get("lane"), [])
        if not isinstance(provenance, dict):
            validation_errors.append(
                f"external lane {item.get('lane')!r} is missing provenance"
            )
            continue
        if provenance.get("checks") != required:
            validation_errors.append(
                f"external lane {item.get('lane')!r} provenance check contract mismatch"
            )
        for digest_key in ("script_sha256", "evidence_sha256"):
            if sha256_pattern.fullmatch(str(provenance.get(digest_key, ""))) is None:
                validation_errors.append(
                    f"external lane {item.get('lane')!r} has invalid {digest_key}"
                )
        script_path = provenance.get("script_path")
        if not isinstance(script_path, str) or not script_path or script_path.startswith("/"):
            validation_errors.append(
                f"external lane {item.get('lane')!r} has invalid script provenance path"
            )
        environment_names = provenance.get("environment_names")
        if not isinstance(environment_names, list) or not all(
            isinstance(name, str) and name for name in environment_names
        ):
            validation_errors.append(
                f"external lane {item.get('lane')!r} has invalid environment provenance"
            )

root = pathlib.Path(root_raw)
source_version = ""
try:
    source_version = str(tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))["package"]["version"])
except Exception as exc:
    validation_errors.append(f"unable to read source version: {exc}")
binary_match = re.fullmatch(r"docdexd\s+(\S+)", version.strip())
if not version.strip() or binary_match is None:
    validation_errors.append(f"binary version output is empty or unrecognized: {version!r}")
elif not source_version or binary_match.group(1) != source_version:
    validation_errors.append(
        f"binary/source version mismatch: binary={binary_match.group(1)!r} source={source_version!r}"
    )

counts = Counter(item.get("status") for item in results)
ledger = {
    "schema_version": 1,
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "binary": binary,
    "binary_sha256": binary_sha256,
    "binary_version": version,
    "source_version": source_version,
    "harness": {
        "path": "scripts/test_release_feature_matrix.sh",
        "sha256": harness_sha256,
        "contract_helper_path": "scripts/release_feature_matrix_contract.py",
        "contract_helper_sha256": contract_helper_sha256,
    },
    "isolated": {
        "home": True,
        "state": True,
        "repo": True,
        "random_port": True,
        "allowlisted_environment": True,
        "local_web_disabled": True,
    },
    "strict_external": strict_raw == "1",
    "release_gate": release_gate_raw == "1",
    "allowed_statuses": sorted(allowed_statuses),
    "expected_lanes": {
        "local": expected_local,
        "external": expected_external,
    },
    "validation_errors": validation_errors,
    "summary": {key: counts.get(key, 0) for key in (
        "verified", "mock_verified", "blocked_external", "failed"
    )},
    "results": results,
}
tmp_path = evidence_path + ".tmp"
with open(tmp_path, "w", encoding="utf-8") as handle:
    json.dump(ledger, handle, indent=2, sort_keys=True)
    handle.write("\n")
os.replace(tmp_path, evidence_path)
print(json.dumps(ledger["summary"], sort_keys=True))
failed = counts.get("failed", 0) > 0
blocked = counts.get("blocked_external", 0) > 0
mocked = counts.get("mock_verified", 0) > 0
strict_failure = strict_raw == "1" and blocked
release_failure = release_gate_raw == "1" and (blocked or mocked)
raise SystemExit(1 if validation_errors or failed or strict_failure or release_failure else 0)
PY
  local status=$?
  set -e
  log "evidence: ${EVIDENCE_PATH}"
  return "$status"
}

wait_for_endpoint_health() {
  local base_url="$1"
  local pid="$2"
  local deadline=$((SECONDS + 30))
  while (( SECONDS < deadline )); do
    if env -i PATH="$SAFE_PATH" HOME="$HOME_DIR" LANG=C LC_ALL=C TZ=UTC \
      curl -fsS "${base_url}/healthz" >/dev/null 2>&1; then
      return 0
    fi
    if ! kill -0 "$pid" >/dev/null 2>&1; then
      return 1
    fi
    sleep 0.2
  done
  return 1
}

log "starting isolated daemon: ${DOCDEX_BIN}"
LOCAL_DAEMON_STARTED_MS="$(monotonic_ms)"
env -i \
PATH="$SAFE_PATH" \
HOME="$HOME_DIR" \
TMPDIR="$LOCAL_TMPDIR" \
LANG=C \
LC_ALL=C \
TZ=UTC \
DOCDEX_STATE_DIR="$STATE_DIR" \
DOCDEX_GLOBAL_STATE_DIR="$GLOBAL_STATE_DIR" \
DOCDEX_DAEMON_LOCK_PATH="${TMP_ROOT}/daemon.lock" \
DOCDEX_WEB_ENABLED=0 \
DOCDEX_ENABLE_MEMORY=0 \
DOCDEX_ENABLE_MCP=1 \
"$DOCDEX_BIN" serve \
  --repo "$REPO_DIR" \
  --state-dir "$STATE_DIR" \
  --host 127.0.0.1 \
  --port "$PORT" \
  --log warn \
  --secure-mode=false \
  --preflight-check=false \
  --enable-mcp \
  >"$DAEMON_LOG" 2>&1 &
DAEMON_PID=$!

if ! wait_for_endpoint_health "$BASE_URL" "$DAEMON_PID"; then
  record_shell_result "daemon_start" "failed" \
    "isolated web-disabled daemon did not become healthy; see daemon.log" \
    "$(elapsed_ms "$LOCAL_DAEMON_STARTED_MS")"
  finalize_ledger || true
  tail -n 100 "$DAEMON_LOG" >&2 || true
  exit 1
fi

LOCAL_CLIENT_STARTED_MS="$(monotonic_ms)"
if ! env -i \
  PATH="$SAFE_PATH" \
  HOME="$HOME_DIR" \
  TMPDIR="$LOCAL_TMPDIR" \
  LANG=C \
  LC_ALL=C \
  TZ=UTC \
  PYTHONDONTWRITEBYTECODE=1 \
  python3 - "$BASE_URL" "$REPO_DIR" "$RESULTS_JSONL" "$REPO_ID_FILE" <<'PY'
import json
import pathlib
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

BASE_URL, repo_raw, RESULTS_PATH, REPO_ID_PATH = sys.argv[1:5]
REPO = pathlib.Path(repo_raw).resolve()
repo_id = None
state = {}


def record(lane, status, detail, started):
    item = {
        "lane": lane,
        "status": status,
        "detail": str(detail).replace("\n", " ")[:700],
        "duration_ms": max(1, round((time.monotonic() - started) * 1000)),
    }
    with open(RESULTS_PATH, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(item, sort_keys=True) + "\n")
    print(f"[release-matrix] {status}: {lane} - {item['detail']}", file=sys.stderr)


def run_lane(lane, callback, success_status="verified"):
    started = time.monotonic()
    try:
        detail = callback()
        record(lane, success_status, detail or "contract verified", started)
    except Exception as exc:  # Keep running to produce a complete ledger.
        record(lane, "failed", f"{type(exc).__name__}: {exc}", started)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def require_mcp_tool_result(payload, label):
    result = payload.get("result") if isinstance(payload, dict) else None
    require(isinstance(result, dict), f"{label} missing MCP result")
    require(result.get("isError") is not True, f"{label} returned isError=true: {result}")
    return result


def api(method, path, payload=None, timeout=30, repo_header=True):
    url = path if path.startswith("http") else BASE_URL + path
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header("accept", "application/json")
    if payload is not None:
        request.add_header("content-type", "application/json")
    if repo_header and repo_id:
        request.add_header("x-docdex-repo-id", repo_id)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read()
            if not body:
                return {}
            return json.loads(body)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")[:500]
        raise RuntimeError(f"{method} {path} returned HTTP {exc.code}: {body}") from exc


def query_path(path, params):
    return path + "?" + urllib.parse.urlencode(params)


def search_hits(query):
    body = api("GET", query_path("/search", {
        "q": query,
        "limit": 10,
        "repo_id": repo_id,
        "async_web": "false",
    }))
    return body.get("hits", []) if isinstance(body, dict) else []


def hit_path(hit):
    return hit.get("rel_path") or hit.get("path") or ""


def wait_for_hits(query, predicate, timeout=25):
    deadline = time.monotonic() + timeout
    last = []
    while time.monotonic() < deadline:
        last = search_hits(query)
        if predicate(last):
            return last
        time.sleep(0.25)
    raise RuntimeError(f"watcher/search condition timed out; last paths={[hit_path(h) for h in last]}")


def initialize():
    global repo_id
    body = api("POST", "/v1/initialize", {"rootUri": REPO.as_uri()}, repo_header=False)
    repo_id = body.get("repo_id")
    require(isinstance(repo_id, str) and repo_id, "initialize response missing repo_id")
    pathlib.Path(REPO_ID_PATH).write_text(repo_id, encoding="utf-8")
    return f"repo_id={repo_id}"


def capabilities():
    body = api("GET", "/v1/capabilities", repo_header=False)
    require(body.get("contract_version"), "missing contract_version")
    require(isinstance(body.get("limits"), dict), "missing capability limits")
    return f"contract={body['contract_version']}"


def index_rebuild():
    body = api("POST", "/v1/index/rebuild", {"repo_id": repo_id}, timeout=60)
    require(isinstance(body, dict) and body.get("repo_root"), "invalid rebuild response")
    return f"docs_indexed={body.get('docs_indexed')}"


def index_status():
    body = api("GET", query_path("/v1/index/status", {"repo_id": repo_id}))
    require(body.get("ready") is True, f"index not ready: {body.get('status')}")
    return f"status={body.get('status')} docs={body.get('docs_indexed')}"


def initial_search():
    hits = wait_for_hits("FEATURE_MATRIX_INITIAL", lambda values: bool(values), timeout=10)
    state["search_hits"] = hits
    return f"hits={len(hits)}"


def batch_search():
    body = api("POST", "/v1/search/batch", {
        "queries": ["FEATURE_MATRIX_INITIAL", "release_matrix"],
        "limit": 5,
        "repo_id": repo_id,
    })
    require(body.get("effective_query_count") == 2, "batch query count mismatch")
    require(len(body.get("results", [])) == 2, "batch results missing")
    return "queries=2"


def rerank():
    hits = state.get("search_hits") or []
    require(hits, "initial search did not provide a candidate")
    candidate = hits[0]
    body = api("POST", "/v1/search/rerank", {
        "query": "release feature matrix",
        # Feed the live search hit back unchanged. The current wire contract
        # deserializes the complete hit (including rel_path and kind), even
        # though older documentation showed only doc_id + snippet.
        "candidates": [candidate],
        "limit": 1,
        "repo_id": repo_id,
    })
    require(body.get("returned_count") == 1, "rerank did not return the candidate")
    return "returned_count=1"


def files():
    body = api("GET", query_path("/v1/files", {"repo_id": repo_id, "limit": 20}))
    require(body.get("total", 0) >= 2, "indexed file listing is incomplete")
    return f"total={body.get('total')}"


def stats():
    body = api("GET", query_path("/v1/stats", {"repo_id": repo_id}))
    require(body.get("ready") is True, "stats reports index not ready")
    return f"num_docs={body.get('num_docs')}"


def tree():
    body = api("GET", query_path("/v1/tree", {"repo_id": repo_id, "max_depth": 3}))
    require("README.md" in body.get("tree", ""), "tree omitted README.md")
    return "README.md present"


def open_file():
    body = api("POST", "/v1/open", {
        "repo_id": repo_id,
        "path": "README.md",
        "head": 20,
    })
    require("FEATURE_MATRIX_INITIAL" in body.get("content", ""), "open content mismatch")
    return f"lines={body.get('total_lines')}"


def repo_inspect():
    body = api("GET", query_path("/v1/repo/inspect", {"repo_id": repo_id}))
    require(body.get("repo_id") == repo_id, "repo inspect resolved the wrong repo")
    require(body.get("ready") is True, "repo inspect reports not ready")
    return f"status={body.get('status')}"


def watcher_create():
    path = REPO / "watcher.md"
    path.write_text("WATCHER_CREATE_MATRIX\n", encoding="utf-8")
    hits = wait_for_hits(
        "WATCHER_CREATE_MATRIX",
        lambda values: any(hit_path(hit) == "watcher.md" for hit in values),
    )
    return f"hits={len(hits)}"


def watcher_update():
    path = REPO / "watcher.md"
    path.write_text("WATCHER_UPDATE_MATRIX\n", encoding="utf-8")
    hits = wait_for_hits(
        "WATCHER_UPDATE_MATRIX",
        lambda values: any(
            hit_path(hit) == "watcher.md"
            and "WATCHER_UPDATE_MATRIX" in (
                str(hit.get("snippet", "")) + str(hit.get("summary", ""))
            )
            for hit in values
        ),
    )
    stale = search_hits("WATCHER_CREATE_MATRIX")
    require(all(hit_path(hit) != "watcher.md" for hit in stale),
            "updated file still matches its stale indexed content")
    return f"hits={len(hits)}"


def watcher_delete():
    (REPO / "watcher.md").unlink()
    wait_for_hits(
        "WATCHER_UPDATE_MATRIX",
        lambda values: all(hit_path(hit) != "watcher.md" for hit in values),
    )
    return "deleted file absent from search"


def conversation_import():
    body = api("POST", "/v1/conversations/import", {
        "repo_id": repo_id,
        "source": "manual",
        "title": "graph maintenance",
        "agent_id": "release-feature-matrix",
        "transcript_text": (
            "user: Repo fact: wake-up endpoint lives in src/api/v1/wakeup.rs\n"
            "assistant: Repo fact: timeline_index lives in src/knowledge/db.rs\n"
            "assistant: Decision: keep graph maintenance local only"
        ),
    })
    session_id = body.get("session_id")
    require(session_id, "conversation import missing session_id")
    state["session_id"] = session_id
    require(body.get("message_count", 0) >= 3, "conversation messages were not imported")
    return f"session_id={session_id} facts={len(body.get('knowledge_facts', []))}"


def conversation_read_export():
    session_id = state.get("session_id")
    require(session_id, "conversation import failed")
    list_body = api("GET", query_path("/v1/conversations", {
        "repo_id": repo_id,
        "agent_id": "release-feature-matrix",
        "limit": 10,
    }))
    require(any(item.get("session_id") == session_id for item in list_body.get("sessions", [])),
            "conversation missing from list")
    encoded = urllib.parse.quote(session_id, safe="")
    read_body = api("GET", query_path(f"/v1/conversations/{encoded}", {"repo_id": repo_id}))
    require(read_body.get("session", {}).get("message_count", 0) >= 3, "conversation read mismatch")
    export_body = api("GET", query_path(
        f"/v1/conversations/{encoded}/export", {"repo_id": repo_id}
    ))
    require(export_body.get("export"), "conversation export missing payload")
    return "list/read/export verified"


def diary_lifecycle():
    written = api("POST", "/v1/diary/write", {
        "repo_id": repo_id,
        "agent_id": "release-feature-matrix",
        "entry_type": "note",
        "content": "Release feature matrix diary entry.",
    })
    entry_id = written.get("entry_id")
    require(entry_id, "diary write missing entry_id")
    read = api("GET", query_path("/v1/diary/read", {
        "repo_id": repo_id,
        "agent_id": "release-feature-matrix",
        "limit": 10,
    }))
    require(any(item.get("entry_id") == entry_id for item in read.get("entries", [])),
            "diary entry missing from read")
    deleted = api("POST", "/v1/diary/delete", {"repo_id": repo_id, "entry_id": entry_id})
    require(deleted.get("deleted") is True, "diary delete failed")
    return f"entry_id={entry_id} deleted=true"


def wakeup():
    body = api("POST", "/v1/wakeup", {
        "repo_id": repo_id,
        "agent_id": "release-feature-matrix",
        "query": "wake-up endpoint",
        "max_tokens": 256,
    })
    require(isinstance(body.get("trace"), dict), "wakeup trace missing")
    require(body.get("knowledge_edges"), "wakeup omitted imported knowledge edges")
    return f"selected_items={body['trace'].get('selected_items')}"


def kg_lifecycle():
    edges = api("GET", query_path("/v1/kg/search/edges", {
        "repo_id": repo_id,
        "q": "wake-up endpoint",
        "limit": 10,
    }))
    edge_items = edges.get("edges", [])
    require(edge_items, "KG edge search returned no imported edge")
    edge_id = edge_items[0].get("edge_id")
    episode_id = edge_items[0].get("episode_id")
    require(edge_id and episode_id, "KG edge is missing lifecycle identifiers")
    queried = api("GET", query_path("/v1/kg/query", {
        "repo_id": repo_id,
        "q": "graph maintenance",
        "limit": 10,
    }))
    require(isinstance(queried, dict), "KG query response invalid")
    deleted_edge = api("POST", "/v1/kg/edge/delete", {
        "repo_id": repo_id,
        "edge_id": edge_id,
    })
    require(deleted_edge.get("deleted") is True, "KG edge delete failed")
    after_edge_delete = api("GET", query_path("/v1/kg/search/edges", {
        "repo_id": repo_id,
        "q": "wake-up endpoint",
        "limit": 10,
    }))
    require(all(item.get("edge_id") != edge_id for item in after_edge_delete.get("edges", [])),
            "deleted KG edge remains queryable")
    rebuilt = api("POST", "/v1/kg/rebuild", {"repo_id": repo_id})
    require(rebuilt.get("rebuilt") is True, "KG rebuild failed")
    require(rebuilt.get("relation_links_projected", 0) >= 1,
            "KG rebuild did not project the remaining relation link")
    after_rebuild = api("GET", query_path("/v1/kg/search/edges", {
        "repo_id": repo_id,
        "q": "timeline_index",
        "limit": 10,
    }))
    require(after_rebuild.get("edges"), "KG rebuild lost the remaining sibling edge")
    deleted_episode = api("POST", "/v1/kg/episode/delete", {
        "repo_id": repo_id,
        "episode_id": episode_id,
    })
    require(deleted_episode.get("deleted") is True, "KG episode delete failed")
    after_episode_delete = api("GET", query_path("/v1/kg/search/episodes", {
        "repo_id": repo_id,
        "q": "graph maintenance",
        "limit": 10,
    }))
    require(all(item.get("episode_id") != episode_id
                for item in after_episode_delete.get("episodes", [])),
            "deleted KG episode remains queryable")
    cleared = api("POST", "/v1/kg/clear", {"repo_id": repo_id})
    require(cleared.get("cleared") is True, "KG clear failed")
    after_clear = api("GET", query_path("/v1/kg/search/edges", {
        "repo_id": repo_id,
        "q": "wake-up endpoint",
        "limit": 10,
    }))
    require(after_clear.get("total") == 0 and not after_clear.get("edges"),
            "KG clear left edges queryable")
    return "query/search/delete/rebuild/delete-episode/clear verified"


def conversation_redact_delete():
    session_id = state.get("session_id")
    require(session_id, "conversation import failed")
    encoded = urllib.parse.quote(session_id, safe="")
    redacted = api("POST", query_path(
        f"/v1/conversations/{encoded}/redact", {"repo_id": repo_id}
    ), {})
    require(redacted.get("result"), "conversation redact missing result")
    read_redacted = api("GET", query_path(
        f"/v1/conversations/{encoded}", {"repo_id": repo_id}
    ))
    messages = read_redacted.get("session", {}).get("messages", [])
    require(len(messages) >= 3, "redaction dropped original message slots")
    require(all(item.get("content") == "[redacted]" for item in messages),
            "redacted conversation exposed non-placeholder content")
    deleted = api("DELETE", query_path(f"/v1/conversations/{encoded}", {"repo_id": repo_id}))
    require(deleted.get("deleted") is True, "conversation delete failed")
    listed = api("GET", query_path("/v1/conversations", {
        "repo_id": repo_id,
        "agent_id": "release-feature-matrix",
        "limit": 10,
    }))
    require(all(item.get("session_id") != session_id for item in listed.get("sessions", [])),
            "deleted conversation remains listed")
    return "redact/delete verified"


def mcp_stateless():
    initialized = api("POST", "/v1/mcp", {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"rootUri": REPO.as_uri()},
    }, repo_header=False)
    require(initialized.get("result"), "stateless initialize failed")
    listed = api("POST", "/v1/mcp", {
        "jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}
    }, repo_header=False)
    names = {item.get("name") for item in listed.get("result", {}).get("tools", [])}
    require("docdex_capabilities" in names, "stateless tools/list omitted docdex_capabilities")
    called = api("POST", "/v1/mcp", {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "docdex_capabilities",
            "arguments": {"project_root": str(REPO)},
        },
    }, repo_header=False)
    require(not called.get("error"), "stateless tools/call returned JSON-RPC error")
    require_mcp_tool_result(called, "stateless tools/call")
    return f"tools={len(names)}"


def read_sse(response, expected_id):
    while True:
        line = response.readline()
        if not line:
            raise RuntimeError("SSE stream closed")
        text = line.decode("utf-8", errors="replace").strip()
        if not text.startswith("data:"):
            continue
        try:
            payload = json.loads(text[5:].strip())
        except json.JSONDecodeError:
            continue
        if payload.get("id") == expected_id:
            return payload


def mcp_sse():
    request = urllib.request.Request(BASE_URL + "/v1/mcp/sse", method="GET")
    response = urllib.request.urlopen(request, timeout=15)
    session = response.headers.get("x-docdex-mcp-session")
    require(session, "SSE session header missing")

    def post_message(payload):
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(BASE_URL + "/v1/mcp/message", data=data, method="POST")
        req.add_header("content-type", "application/json")
        req.add_header("x-docdex-mcp-session", session)
        with urllib.request.urlopen(req, timeout=15) as ack:
            ack.read()

    try:
        post_message({
            "jsonrpc": "2.0", "id": 10, "method": "initialize",
            "params": {"workspace_root": str(REPO)},
        })
        require(read_sse(response, 10).get("result"), "SSE initialize failed")
        post_message({"jsonrpc": "2.0", "id": 11, "method": "tools/list", "params": {}})
        listed = read_sse(response, 11)
        names = {item.get("name") for item in listed.get("result", {}).get("tools", [])}
        require("docdex_capabilities" in names, "SSE tools/list omitted docdex_capabilities")
        post_message({
            "jsonrpc": "2.0",
            "id": 12,
            "method": "tools/call",
            "params": {"name": "docdex_capabilities", "arguments": {}},
        })
        called = read_sse(response, 12)
        require(not called.get("error"), "SSE tools/call returned JSON-RPC error")
        require_mcp_tool_result(called, "SSE tools/call")
    finally:
        response.close()
    return f"session tools={len(names)}"


run_lane("daemon_health", lambda: "healthz=ok")
run_lane("initialize", initialize)
run_lane("capabilities", capabilities)
run_lane("index_rebuild", index_rebuild)
run_lane("index_status", index_status)
run_lane("search", initial_search)
run_lane("batch_search", batch_search)
run_lane("rerank", rerank)
run_lane("files", files)
run_lane("stats", stats)
run_lane("tree", tree)
run_lane("open", open_file)
run_lane("repo_inspect", repo_inspect)
run_lane("watcher_create", watcher_create)
run_lane("watcher_update", watcher_update)
run_lane("watcher_delete", watcher_delete)
run_lane("conversation_import", conversation_import)
run_lane("conversation_list_read_export", conversation_read_export)
run_lane("diary_lifecycle", diary_lifecycle)
run_lane("wakeup", wakeup)
run_lane("kg_lifecycle", kg_lifecycle)
run_lane("conversation_redact_delete", conversation_redact_delete)
run_lane("mcp_stateless", mcp_stateless)
run_lane("mcp_sse", mcp_sse)
PY
then
  record_shell_result "matrix_client" "failed" \
    "feature-matrix Python client terminated unexpectedly" \
    "$(elapsed_ms "$LOCAL_CLIENT_STARTED_MS")"
fi

REPO_ID=""
if [[ -f "$REPO_ID_FILE" ]]; then
  REPO_ID="$(<"$REPO_ID_FILE")"
fi

ALLOWLISTED_ENV_ASSIGNMENTS=()
ALLOWLIST_ERROR=""
prepare_allowlisted_environment() {
  local raw="$1"
  local normalized name value
  ALLOWLISTED_ENV_ASSIGNMENTS=()
  ALLOWLIST_ERROR=""
  normalized="${raw//,/ }"
  for name in $normalized; do
    if [[ ! "$name" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]]; then
      ALLOWLIST_ERROR="invalid environment allowlist name: ${name}"
      return 1
    fi
    case "$name" in
      HOME|PATH|LANG|LC_ALL|TZ|DOCDEX_STATE_DIR|DOCDEX_GLOBAL_STATE_DIR|\
      DOCDEX_DAEMON_LOCK_PATH|DOCDEX_HTTP_BASE_URL|DOCDEX_BIN|\
      DOCDEX_FEATURE_MATRIX_*|BASH_ENV|ENV|SHELLOPTS|CDPATH|GLOBIGNORE|\
      LD_PRELOAD|DYLD_*|PYTHONHOME|PYTHONPATH|RUBYOPT|NODE_OPTIONS|IFS|PS4|\
      PROMPT_COMMAND|PERL5OPT|PERL5LIB|RUSTC_WRAPPER|RUSTFLAGS|\
      GIT_CONFIG_NOSYSTEM|GIT_CONFIG_GLOBAL|GIT_CONFIG_SYSTEM|\
      GIT_CONFIG_KEY_*|GIT_CONFIG_VALUE_*)
        ALLOWLIST_ERROR="unsafe or harness-owned environment variable: ${name}"
        return 1
        ;;
    esac
    set +u
    value="${!name}"
    set -u
    if [[ -z "${value//[[:space:]]/}" ]]; then
      ALLOWLIST_ERROR="allowlisted environment prerequisite is missing: ${name}"
      return 1
    fi
    ALLOWLISTED_ENV_ASSIGNMENTS+=("${name}=${value}")
  done
}

json_field() {
  local path="$1"
  local key="$2"
  python3 -I - "$path" "$key" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as handle:
    data = json.load(handle)
value = data.get(sys.argv[2])
if value is None:
    print("")
elif value is True:
    print("1")
elif value is False:
    print("0")
elif isinstance(value, (dict, list)):
    print(json.dumps(value, separators=(",", ":"), sort_keys=True))
else:
    print(value)
PY
}

stop_external_web_daemon() {
  if [[ -n "$EXTERNAL_DAEMON_PID" ]]; then
    terminate_pid "$EXTERNAL_DAEMON_PID"
    EXTERNAL_DAEMON_PID=""
  fi
}

WEB_BASE_URL=""
WEB_REPO_DIR=""
WEB_REPO_ID=""
start_external_web_daemon() {
  local lane_root="$1"
  local lane_home="$2"
  local lane_state="$3"
  local lane_global="$4"
  local lane_tmp="$5"
  local port init_payload init_response web_uri
  WEB_REPO_DIR="${lane_root}/repo"
  mkdir -p "$WEB_REPO_DIR" "$lane_tmp"
  printf '# External web release lane\n\nFEATURE_MATRIX_EXTERNAL_WEB\n' \
    >"${WEB_REPO_DIR}/README.md"
  env -i PATH="$SAFE_PATH" HOME="$lane_home" LANG=C LC_ALL=C TZ=UTC \
    GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
    git -C "$WEB_REPO_DIR" -c init.defaultBranch=main init -q
  port="$(pick_free_port)"
  WEB_BASE_URL="http://127.0.0.1:${port}"
  env -i \
    PATH="$SAFE_PATH" \
    HOME="$lane_home" \
    TMPDIR="$lane_tmp" \
    LANG=C \
    LC_ALL=C \
    TZ=UTC \
    DOCDEX_STATE_DIR="$lane_state" \
    DOCDEX_GLOBAL_STATE_DIR="$lane_global" \
    DOCDEX_DAEMON_LOCK_PATH="${lane_state}/daemon.lock" \
    DOCDEX_WEB_ENABLED=1 \
    DOCDEX_ENABLE_MEMORY=0 \
    DOCDEX_ENABLE_MCP=1 \
    "${ALLOWLISTED_ENV_ASSIGNMENTS[@]}" \
    "$DOCDEX_BIN" serve \
      --repo "$WEB_REPO_DIR" \
      --state-dir "$lane_state" \
      --host 127.0.0.1 \
      --port "$port" \
      --log warn \
      --secure-mode=false \
      --preflight-check=false \
      --enable-mcp \
      >"${EVIDENCE_DIR}/logs/external_web.daemon.log" 2>&1 &
  EXTERNAL_DAEMON_PID=$!
  if ! wait_for_endpoint_health "$WEB_BASE_URL" "$EXTERNAL_DAEMON_PID"; then
    stop_external_web_daemon
    return 1
  fi
  web_uri="$(python3 -I - "$WEB_REPO_DIR" <<'PY'
import pathlib
import sys
print(pathlib.Path(sys.argv[1]).resolve().as_uri())
PY
)"
  init_payload="$(python3 -I - "$web_uri" <<'PY'
import json
import sys
print(json.dumps({"rootUri": sys.argv[1]}))
PY
)"
  if ! init_response="$(env -i PATH="$SAFE_PATH" HOME="$lane_home" \
    LANG=C LC_ALL=C TZ=UTC curl -fsS -X POST \
    -H 'content-type: application/json' --data-binary "$init_payload" \
    "${WEB_BASE_URL}/v1/initialize")"; then
    stop_external_web_daemon
    return 1
  fi
  if ! WEB_REPO_ID="$(python3 -I - "$init_response" <<'PY'
import json
import sys
value = json.loads(sys.argv[1]).get("repo_id")
if not isinstance(value, str) or not value:
    raise SystemExit(1)
print(value)
PY
)"; then
    stop_external_web_daemon
    return 1
  fi
}

run_external_lane() {
  local lane="$1"
  local script_var="$2"
  local mode_var="$3"
  local allowlist_var="$4"
  local script_path="${!script_var:-}"
  local mode="${!mode_var:-}"
  local env_allowlist="${!allowlist_var:-}"
  local status lane_root lane_home lane_state lane_global lane_tmp
  local lane_evidence lane_log lane_control_log evidence_copy runner_json
  local lane_started_ms runner_error runner_return_code runner_timed_out
  local runner_duration script_relative script_sha environment_names_json
  local provenance_json checks_json lane_base_url lane_repo lane_repo_id
  lane_started_ms="$(monotonic_ms)"

  if [[ -z "$script_path" ]]; then
    record_shell_result "$lane" "blocked_external" \
      "set ${script_var} to an executable in-repo integration adapter" \
      "$(elapsed_ms "$lane_started_ms")"
    return 0
  fi
  if [[ -z "$mode" ]]; then
    record_shell_result "$lane" "failed" \
      "${mode_var} must be explicitly set to real or mock" \
      "$(elapsed_ms "$lane_started_ms")"
    return 0
  fi
  if [[ -z "$REPO_ID" ]]; then
    record_shell_result "$lane" "failed" "local initialize did not provide a repo_id" \
      "$(elapsed_ms "$lane_started_ms")"
    return 0
  fi
  case "$mode" in
    real)
      status="verified"
      ;;
    mock)
      status="mock_verified"
      ;;
    *)
      record_shell_result "$lane" "failed" "${mode_var} must be real or mock" \
        "$(elapsed_ms "$lane_started_ms")"
      return 0
      ;;
  esac
  if ! prepare_allowlisted_environment "$env_allowlist"; then
    record_shell_result "$lane" "failed" \
      "${allowlist_var}: ${ALLOWLIST_ERROR}" \
      "$(elapsed_ms "$lane_started_ms")"
      return 0
  fi

  lane_root="${TMP_ROOT}/external/${lane}"
  lane_home="${lane_root}/home"
  lane_state="${lane_root}/state"
  lane_global="${lane_root}/global"
  lane_tmp="${lane_root}/tmp"
  lane_evidence="${lane_root}/evidence.json"
  lane_log="${EVIDENCE_DIR}/logs/${lane}.log"
  lane_control_log="${EVIDENCE_DIR}/logs/${lane}.runner.log"
  evidence_copy="${EVIDENCE_DIR}/logs/${lane}.evidence.json"
  runner_json="${lane_root}/runner.json"
  mkdir -p "$lane_home/.docdex" "$lane_state" "$lane_global" "$lane_tmp"
  cat >"${lane_home}/.docdex/config.toml" <<EOF
[core]
global_state_dir = "${lane_global}"
EOF
  rm -f "$lane_evidence" "$evidence_copy" "$runner_json" "$lane_control_log"

  lane_base_url="$BASE_URL"
  lane_repo="$REPO_DIR"
  lane_repo_id="$REPO_ID"
  if [[ "$lane" == "external_web" ]]; then
    if ! start_external_web_daemon "$lane_root" "$lane_home" "$lane_state" \
      "$lane_global" "$lane_tmp"; then
      record_shell_result "$lane" "failed" \
        "isolated web-enabled external daemon failed to initialize; log=${EVIDENCE_DIR}/logs/external_web.daemon.log" \
        "$(elapsed_ms "$lane_started_ms")"
      return 0
    fi
    lane_base_url="$WEB_BASE_URL"
    lane_repo="$WEB_REPO_DIR"
    lane_repo_id="$WEB_REPO_ID"
  fi

  if ! env -i PATH="$SAFE_PATH" HOME="$lane_home" TMPDIR="$lane_tmp" \
    LANG=C LC_ALL=C TZ=UTC PYTHONDONTWRITEBYTECODE=1 \
    "${ALLOWLISTED_ENV_ASSIGNMENTS[@]}" \
    python3 -I "$CONTRACT_HELPER" run-adapter \
      --script "$script_path" \
      --root-dir "$ROOT_DIR" \
      --log "$lane_log" \
      --home "$lane_home" \
      --state "$lane_state" \
      --global-state "$lane_global" \
      --evidence "$lane_evidence" \
      --lane "$lane" \
      --base-url "$lane_base_url" \
      --repo-path "$lane_repo" \
      --repo-id "$lane_repo_id" \
      --mode "$mode" \
      --docdex-bin "$DOCDEX_BIN" \
      --timeout "$EXTERNAL_TIMEOUT_SECONDS" \
      --env-allowlist "$env_allowlist" \
      >"$runner_json" 2>>"$lane_control_log"; then
    stop_external_web_daemon
    record_shell_result "$lane" "failed" \
      "external adapter runner failed; log=${lane_log}" \
      "$(elapsed_ms "$lane_started_ms")"
    return 0
  fi
  if [[ ! -s "$runner_json" ]]; then
    stop_external_web_daemon
    record_shell_result "$lane" "failed" \
      "external adapter runner returned no result; log=${lane_log}" \
      "$(elapsed_ms "$lane_started_ms")"
    return 0
  fi
  runner_error="$(json_field "$runner_json" runner_error)"
  runner_return_code="$(json_field "$runner_json" return_code)"
  runner_timed_out="$(json_field "$runner_json" timed_out)"
  runner_duration="$(json_field "$runner_json" duration_ms)"
  script_relative="$(json_field "$runner_json" script_path)"
  script_sha="$(json_field "$runner_json" script_sha256)"
  environment_names_json="$(json_field "$runner_json" environment_names)"
  stop_external_web_daemon

  if [[ -n "$runner_error" ]]; then
    record_shell_result "$lane" "failed" \
      "external adapter rejected: ${runner_error}; log=${lane_log}" \
      "$(elapsed_ms "$lane_started_ms")"
    return 0
  fi
  if [[ "$runner_timed_out" == "1" ]]; then
    record_shell_result "$lane" "failed" \
      "external adapter timed out after ${EXTERNAL_TIMEOUT_SECONDS}s; log=${lane_log}" \
      "$(elapsed_ms "$lane_started_ms")"
    return 0
  fi
  if [[ -z "$runner_return_code" || "$runner_return_code" != "0" ]]; then
    record_shell_result "$lane" "failed" \
      "external adapter exited ${runner_return_code:-without a code}; log=${lane_log}" \
      "$(elapsed_ms "$lane_started_ms")"
    return 0
  fi

  if provenance_json="$(env -i PATH="$SAFE_PATH" HOME="$lane_home" \
    TMPDIR="$lane_tmp" LANG=C LC_ALL=C TZ=UTC PYTHONDONTWRITEBYTECODE=1 \
    python3 -I "$CONTRACT_HELPER" validate-evidence \
      --evidence "$lane_evidence" \
      --copy "$evidence_copy" \
      --lane "$lane" \
      --base-url "$lane_base_url" \
      --repo-id "$lane_repo_id" \
      --mode "$mode" \
      --script-path "$script_relative" \
      --script-sha256 "$script_sha" \
      --environment-names-json "$environment_names_json" \
      2>>"$lane_log")"; then
    provenance_json="$(python3 -I - "$provenance_json" "$runner_duration" <<'PY'
import json
import sys
data = json.loads(sys.argv[1])
data["adapter_duration_ms"] = max(1, int(sys.argv[2]))
print(json.dumps(data, separators=(",", ":"), sort_keys=True))
PY
)"
    checks_json="$(python3 -I - "$provenance_json" <<'PY'
import json
import sys
print(",".join(json.loads(sys.argv[1])["checks"]))
PY
)"
    record_shell_result "$lane" "$status" \
      "attested exact checks=${checks_json}; evidence=${evidence_copy}; log=${lane_log}" \
      "$(elapsed_ms "$lane_started_ms")" "$provenance_json"
  else
    record_shell_result "$lane" "failed" \
      "external adapter returned malformed or contract-mismatched evidence; log=${lane_log}" \
      "$(elapsed_ms "$lane_started_ms")"
  fi
}

run_external_lane "external_user_memory" \
  "DOCDEX_FEATURE_MATRIX_USER_MEMORY_SCRIPT" "DOCDEX_FEATURE_MATRIX_USER_MEMORY_MODE" \
  "DOCDEX_FEATURE_MATRIX_USER_MEMORY_ENV_ALLOWLIST"
run_external_lane "external_admin" \
  "DOCDEX_FEATURE_MATRIX_ADMIN_SCRIPT" "DOCDEX_FEATURE_MATRIX_ADMIN_MODE" \
  "DOCDEX_FEATURE_MATRIX_ADMIN_ENV_ALLOWLIST"
run_external_lane "external_introspection" \
  "DOCDEX_FEATURE_MATRIX_INTROSPECTION_SCRIPT" "DOCDEX_FEATURE_MATRIX_INTROSPECTION_MODE" \
  "DOCDEX_FEATURE_MATRIX_INTROSPECTION_ENV_ALLOWLIST"
run_external_lane "external_web" \
  "DOCDEX_FEATURE_MATRIX_WEB_SCRIPT" "DOCDEX_FEATURE_MATRIX_WEB_MODE" \
  "DOCDEX_FEATURE_MATRIX_WEB_ENV_ALLOWLIST"
run_external_lane "external_delegation" \
  "DOCDEX_FEATURE_MATRIX_DELEGATION_SCRIPT" "DOCDEX_FEATURE_MATRIX_DELEGATION_MODE" \
  "DOCDEX_FEATURE_MATRIX_DELEGATION_ENV_ALLOWLIST"

finalize_ledger
