#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'EOF'
Usage: scripts/ci_local.sh [--ci] [--nightly] [--release-dry-run] [--all]

Defaults to --ci when no flags are provided.

Flags:
  --ci             Run CI workflow steps (fmt + cargo tests + npm tests).
  --nightly        Run nightly workflow steps (security, bench, release builds, short soak).
  --release-dry-run Run release dry-run steps (tests + npm dry-run publish).
  --all            Run all of the above (dedupes repeated tests).
  -h, --help       Show this help text.
EOF
}

RUN_CI=0
RUN_NIGHTLY=0
RUN_RELEASE_DRY_RUN=0

if [[ "$#" -eq 0 ]]; then
  RUN_CI=1
fi

for arg in "$@"; do
  case "${arg}" in
    --ci)
      RUN_CI=1
      ;;
    --nightly)
      RUN_NIGHTLY=1
      ;;
    --release-dry-run)
      RUN_RELEASE_DRY_RUN=1
      ;;
    --all)
      RUN_CI=1
      RUN_NIGHTLY=1
      RUN_RELEASE_DRY_RUN=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: ${arg}" >&2
      usage >&2
      exit 1
      ;;
  esac
done

log() {
  printf "[ci-local] %s\n" "$*" >&2
}

run_cmd() {
  log "$*"
  "$@"
}

RAN_TESTS=0

run_ci() {
  log "== CI workflow (ci.yml) =="
  run_cmd cargo fmt --all -- --check
  if [[ "${RAN_TESTS}" -eq 0 ]]; then
    run_cmd cargo test --locked --all
    RAN_TESTS=1
  fi
  (
    cd "${ROOT_DIR}/npm"
    run_cmd node --test
  )
}

install_audit_tools() {
  if [[ "${DOCDEX_SKIP_INSTALL_TOOLS:-0}" == "1" ]]; then
    log "Skipping audit tool installation (DOCDEX_SKIP_INSTALL_TOOLS=1)"
    return
  fi
  if ! cargo audit -V >/dev/null 2>&1; then
    run_cmd cargo install cargo-audit --locked
  fi
  if ! cargo sbom -h >/dev/null 2>&1; then
    run_cmd cargo install cargo-sbom --locked
  fi
}

run_nightly() {
  log "== Nightly workflow (nightly.yml) =="
  install_audit_tools
  run_cmd "${ROOT_DIR}/scripts/security_audit.sh"
  run_cmd "${ROOT_DIR}/scripts/bench_indexing.sh"
  run_cmd cargo build --release --locked
  run_cmd cargo build --release --locked -p docdex-mcp-server

  if [[ "${DOCDEX_SKIP_SOAK:-0}" == "1" ]]; then
    log "Skipping short soak (DOCDEX_SKIP_SOAK=1)"
    return
  fi

  local port="${DOCDEX_CI_PORT:-3210}"
  export DOCDEX_LOAD_DURATION_SECS="${DOCDEX_LOAD_DURATION_SECS:-60}"
  export DOCDEX_LOAD_CONCURRENCY="${DOCDEX_LOAD_CONCURRENCY:-2}"
  export DOCDEX_LOAD_MAX_ERROR_RATE="${DOCDEX_LOAD_MAX_ERROR_RATE:-0.005}"
  export DOCDEX_BIN="${DOCDEX_BIN:-${ROOT_DIR}/target/release/docdexd}"
  export DOCDEX_MCP_SERVER_BIN="${DOCDEX_MCP_SERVER_BIN:-${ROOT_DIR}/target/release/docdex-mcp-server}"
  export DOCDEX_OFFLINE="${DOCDEX_OFFLINE:-1}"
  export DOCDEX_HTTP_BASE_URL="http://127.0.0.1:${port}"

  log "Starting docdexd for short soak on ${DOCDEX_HTTP_BASE_URL}"
  "${DOCDEX_BIN}" serve \
    --repo "${DOCDEX_REPO_ROOT:-${ROOT_DIR}}" \
    --secure-mode=false \
    --enable-memory=false \
    --disable-mcp \
    --access-log=false \
    --log warn \
    --host 127.0.0.1 \
    --port "${port}" &
  local pid=$!
  trap 'kill ${pid} >/dev/null 2>&1 || true' EXIT

  for _ in $(seq 1 20); do
    if curl -fsS "${DOCDEX_HTTP_BASE_URL}/healthz" >/dev/null 2>&1; then
      break
    fi
    sleep 0.5
  done

  run_cmd "${ROOT_DIR}/scripts/load_test_http.sh"
  run_cmd "${ROOT_DIR}/scripts/load_test_mcp.sh" "${DOCDEX_REPO_ROOT:-${ROOT_DIR}}"
}

run_release_dry_run() {
  log "== Release dry run workflow (release-dry-run.yml) =="
  if [[ "${RAN_TESTS}" -eq 0 ]]; then
    run_cmd cargo test --locked --all
    RAN_TESTS=1
  fi
  (
    cd "${ROOT_DIR}/npm"
    run_cmd npm install --ignore-scripts
    run_cmd npm publish --dry-run --provenance --access public
  )
}

if [[ "${RUN_CI}" -eq 1 ]]; then
  run_ci
fi
if [[ "${RUN_NIGHTLY}" -eq 1 ]]; then
  run_nightly
fi
if [[ "${RUN_RELEASE_DRY_RUN}" -eq 1 ]]; then
  run_release_dry_run
fi

log "ci-local completed"
