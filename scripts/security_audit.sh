#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="${ROOT_DIR}/target/audit"
STRICT="${DOCDEX_AUDIT_STRICT:-1}"

mkdir -p "${LOG_DIR}"

log() {
  printf "[security-audit] %s\n" "$*" >&2
}

require_tool() {
  local name="$1"
  local check_cmd="$2"
  if ! eval "${check_cmd}" >/dev/null 2>&1; then
    if [[ "${STRICT}" == "1" ]]; then
      log "${name} not available (set DOCDEX_AUDIT_STRICT=0 to skip)"
      exit 1
    fi
    log "skipping ${name} (missing)"
    return 1
  fi
  return 0
}

log "running cargo audit"
if require_tool "cargo-audit" "cargo audit --version"; then
  cargo audit --json >"${LOG_DIR}/cargo_audit.json"
  log "cargo audit written to ${LOG_DIR}/cargo_audit.json"
fi

if command -v npm >/dev/null 2>&1 && [[ -f "${ROOT_DIR}/npm/package.json" ]]; then
  log "running npm audit"
  (cd "${ROOT_DIR}/npm" && npm audit --json >"${LOG_DIR}/npm_audit.json")
  log "npm audit written to ${LOG_DIR}/npm_audit.json"

  if npm sbom --version >/dev/null 2>&1; then
    log "generating npm sbom"
    (cd "${ROOT_DIR}/npm" && npm sbom --json >"${LOG_DIR}/npm_sbom.json")
    log "npm sbom written to ${LOG_DIR}/npm_sbom.json"
  elif [[ "${STRICT}" == "1" ]]; then
    log "npm sbom not available (upgrade npm or set DOCDEX_AUDIT_STRICT=0)"
    exit 1
  else
    log "skipping npm sbom (missing)"
  fi
else
  log "npm package not found; skipping npm audit/sbom"
fi

log "generating Rust SBOM"
if require_tool "cargo-sbom" "cargo sbom --version"; then
  cargo sbom --output-format cyclonedx-json >"${LOG_DIR}/cargo_sbom.json"
  log "cargo sbom written to ${LOG_DIR}/cargo_sbom.json"
fi

log "security audit complete"
