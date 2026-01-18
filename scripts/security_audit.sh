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
  audit_ignore_args=()
  if [[ -f "${ROOT_DIR}/audit.toml" ]]; then
    ignores="$(python3 - <<'PY' 2>/dev/null || true
import tomllib
with open('audit.toml', 'rb') as f:
    data = tomllib.load(f)
for advisory_id in data.get('advisories', {}).get('ignore', []):
    print(advisory_id)
PY
)"
    if [[ -n "${ignores}" ]]; then
      while read -r advisory_id; do
        [[ -n "${advisory_id}" ]] && audit_ignore_args+=(--ignore "${advisory_id}")
      done <<< "${ignores}"
    fi
  fi
  cargo audit --json "${audit_ignore_args[@]}" >"${LOG_DIR}/cargo_audit.json"
  log "cargo audit written to ${LOG_DIR}/cargo_audit.json"
fi

if command -v npm >/dev/null 2>&1 && [[ -f "${ROOT_DIR}/npm/package.json" ]]; then
  log "running npm audit"
  npm_audit_status=0
  set +e
  (cd "${ROOT_DIR}/npm" && npm audit --json >"${LOG_DIR}/npm_audit.json")
  npm_audit_status=$?
  set -e

  if [[ "${npm_audit_status}" -eq 0 ]]; then
    log "npm audit written to ${LOG_DIR}/npm_audit.json"
  elif [[ "${npm_audit_status}" -eq 1 ]]; then
    log "npm audit reported vulnerabilities (exit 1); report at ${LOG_DIR}/npm_audit.json"
  else
    if [[ "${STRICT}" == "1" ]]; then
      log "npm audit failed (exit ${npm_audit_status}); set DOCDEX_AUDIT_STRICT=0 to skip"
      exit 1
    fi
    log "npm audit failed (exit ${npm_audit_status}); continuing"
  fi

  if npm sbom --version >/dev/null 2>&1; then
    log "generating npm sbom"
    (cd "${ROOT_DIR}/npm" && npm sbom --package-lock-only --sbom-format cyclonedx >"${LOG_DIR}/npm_sbom.json")
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
  cargo sbom --output-format cyclone_dx_json_1_6 >"${LOG_DIR}/cargo_sbom.json"
  log "cargo sbom written to ${LOG_DIR}/cargo_sbom.json"
fi

log "security audit complete"
