#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="${DOCDEX_AUDIT_LOG_DIR:-${ROOT_DIR}/target/audit}"
STRICT="${DOCDEX_AUDIT_STRICT:-1}"
NPM_AUDIT_FAILURE=0

mkdir -p "${LOG_DIR}"

log() {
  printf "[security-audit] %s\n" "$*" >&2
}

summarize_cargo_audit_json() {
  local json_path="$1"
  python3 - "${json_path}" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
if not path.exists() or path.stat().st_size == 0:
    raise SystemExit(0)

try:
    data = json.loads(path.read_text(encoding="utf-8"))
except Exception as exc:
    print(f"[security-audit] unable to parse cargo audit JSON report: {exc}", file=sys.stderr)
    raise SystemExit(0)

vuln_entries = (data.get("vulnerabilities") or {}).get("list") or []
if vuln_entries:
    print(
        f"[security-audit] cargo audit found {len(vuln_entries)} vulnerability advisory hit(s):",
        file=sys.stderr,
    )
    for item in vuln_entries:
        advisory = item.get("advisory") or {}
        package = item.get("package") or {}
        advisory_id = advisory.get("id") or "unknown"
        pkg_name = package.get("name") or "unknown"
        pkg_version = package.get("version") or "unknown"
        title = (advisory.get("title") or "").strip()
        if title:
            print(
                f"[security-audit] - {advisory_id} {pkg_name} {pkg_version}: {title}",
                file=sys.stderr,
            )
        else:
            print(
                f"[security-audit] - {advisory_id} {pkg_name} {pkg_version}",
                file=sys.stderr,
            )

warning_hits = []
for kind, entries in (data.get("warnings") or {}).items():
    if isinstance(entries, list):
        for entry in entries:
            warning_hits.append((kind, entry))

if warning_hits:
    print(
        f"[security-audit] cargo audit reported {len(warning_hits)} warning advisory hit(s):",
        file=sys.stderr,
    )
    for kind, entry in warning_hits[:20]:
        advisory = entry.get("advisory") or {}
        package = entry.get("package") or {}
        advisory_id = advisory.get("id") or "unknown"
        pkg_name = package.get("name") or "unknown"
        pkg_version = package.get("version") or "unknown"
        title = (advisory.get("title") or "").strip()
        suffix = f": {title}" if title else ""
        print(
            f"[security-audit] - [{kind}] {advisory_id} {pkg_name} {pkg_version}{suffix}",
            file=sys.stderr,
        )
    if len(warning_hits) > 20:
        print(
            f"[security-audit] ... {len(warning_hits) - 20} additional warning hit(s) omitted",
            file=sys.stderr,
        )

if not vuln_entries and not warning_hits:
    print(
        "[security-audit] cargo audit returned non-zero but no advisory entries were parsed from JSON",
        file=sys.stderr,
    )
PY
}

npm_audit_severity_counts() {
  local json_path="$1"
  python3 - "${json_path}" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
data = json.loads(path.read_text(encoding="utf-8"))
if not isinstance(data, dict):
    raise SystemExit("npm audit JSON must be an object")
if data.get("error") not in (None, {}, []):
    print(f"npm audit returned a top-level error: {data.get('error')!r}", file=sys.stderr)
    raise SystemExit(2)

metadata_container = data.get("metadata")
metadata = (
    metadata_container.get("vulnerabilities")
    if isinstance(metadata_container, dict)
    else None
)
legacy = data.get("vulnerabilities")
has_current_schema = isinstance(metadata, dict)
has_legacy_schema = isinstance(legacy, dict)
if not has_current_schema and not has_legacy_schema:
    raise SystemExit("unrecognized npm audit JSON schema")

counts = {}
severities = ("low", "moderate", "high", "critical")
if has_current_schema:
    missing = [severity for severity in severities if severity not in metadata]
    if missing:
        raise SystemExit(
            "unrecognized npm audit metadata.vulnerabilities schema; missing "
            + ", ".join(missing)
        )
    for severity in severities:
        try:
            counts[severity] = int(metadata[severity])
        except (TypeError, ValueError) as exc:
            raise SystemExit(f"invalid npm audit count for {severity}") from exc
        if counts[severity] < 0:
            raise SystemExit(f"invalid negative npm audit count for {severity}")
else:
    counts = {severity: 0 for severity in severities}

# npm's current JSON format includes metadata.vulnerabilities. Keep a
# compatibility fallback for older reports that only list advisory objects.
if not has_current_schema:
    for item in legacy.values():
        if not isinstance(item, dict):
            raise SystemExit("invalid legacy npm audit vulnerability entry")
        severity = str(item.get("severity") or "").lower()
        if severity in counts:
            counts[severity] += 1

print(counts["low"], counts["moderate"], counts["high"], counts["critical"])
PY
}

if [[ "${1:-}" == "--validate-npm-audit-json" ]]; then
  if [[ "$#" -ne 2 ]]; then
    log "usage: security_audit.sh --validate-npm-audit-json PATH"
    exit 2
  fi
  npm_audit_severity_counts "$2"
  exit $?
elif [[ "$#" -ne 0 ]]; then
  log "unknown argument: $1"
  exit 2
fi

should_retry_cargo_audit_fetch() {
  local stderr_path="$1"
  [[ -s "${stderr_path}" ]] || return 1
  grep -Eqi \
    "couldn't fetch advisory database|failed to obtain lock file|exclusive lock on a read-only path|could not resolve host|timed out" \
    "${stderr_path}"
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
  cargo_audit_json="${LOG_DIR}/cargo_audit.json"
  cargo_audit_stderr="${LOG_DIR}/cargo_audit.stderr.log"
  audit_ignore_args=()
  if [[ -f "${ROOT_DIR}/audit.toml" ]]; then
    ignores="$(python3 - "${ROOT_DIR}" <<'PY' 2>/dev/null || true
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1])
path = root / 'audit.toml'
text = path.read_text(encoding='utf-8')

toml = None
try:
    import tomllib as toml  # py311+
except Exception:
    try:
        import tomli as toml  # optional backport
    except Exception:
        toml = None

if toml is not None:
    data = toml.loads(text)
    for advisory_id in data.get('advisories', {}).get('ignore', []):
        print(advisory_id)
    raise SystemExit(0)

match = re.search(r'ignore\\s*=\\s*\\[(.*?)\\]', text, re.S)
if not match:
    raise SystemExit(0)
for raw in match.group(1).split(','):
    val = raw.strip().strip('\"').strip(\"'\")
    if val:
        print(val)
PY
)"
    if [[ -z "${ignores}" ]]; then
      ignores="$(grep -oE 'RUSTSEC-[0-9]{4}-[0-9]+' "${ROOT_DIR}/audit.toml" 2>/dev/null | sort -u || true)"
    fi
    if [[ -n "${ignores}" ]]; then
      while read -r advisory_id; do
        [[ -n "${advisory_id}" ]] && audit_ignore_args+=(--ignore "${advisory_id}")
      done <<< "${ignores}"
      log "cargo audit ignores: $(printf "%s\n" "${ignores}" | tr '\n' ' ' | sed 's/[[:space:]]\+/ /g' | sed 's/^ //; s/ $//')"
    else
      log "audit.toml found, but no advisory ignore IDs were detected"
    fi
  fi

  set +e
  cargo audit --json "${audit_ignore_args[@]}" >"${cargo_audit_json}" 2>"${cargo_audit_stderr}"
  cargo_audit_status=$?
  set -e

  if [[ "${cargo_audit_status}" -ne 0 ]] && should_retry_cargo_audit_fetch "${cargo_audit_stderr}"; then
    log "cargo audit failed to refresh advisory DB; retrying with --stale --no-fetch"
    set +e
    cargo audit --json --stale --no-fetch "${audit_ignore_args[@]}" >"${cargo_audit_json}" 2>"${cargo_audit_stderr}"
    cargo_audit_status=$?
    set -e
  fi

  if [[ "${cargo_audit_status}" -ne 0 ]]; then
    if [[ -s "${cargo_audit_json}" ]]; then
      summarize_cargo_audit_json "${cargo_audit_json}" || true
      log "cargo audit JSON report written to ${cargo_audit_json}"
    else
      log "cargo audit failed before producing JSON output"
    fi

    if [[ -s "${cargo_audit_stderr}" ]]; then
      log "cargo audit stderr:"
      sed 's/^/[security-audit]   /' "${cargo_audit_stderr}" >&2
    fi
    exit "${cargo_audit_status}"
  fi

  log "cargo audit written to ${cargo_audit_json}"
fi

if command -v npm >/dev/null 2>&1 && [[ -f "${ROOT_DIR}/npm/package.json" ]]; then
  log "running npm audit"
  npm_audit_status=0
  set +e
  (cd "${ROOT_DIR}/npm" && npm audit --json >"${LOG_DIR}/npm_audit.json")
  npm_audit_status=$?
  set -e

  npm_audit_counts=""
  npm_audit_counts_status=0
  set +e
  npm_audit_counts="$(npm_audit_severity_counts "${LOG_DIR}/npm_audit.json")"
  npm_audit_counts_status=$?
  set -e

  npm_low=0
  npm_moderate=0
  npm_high=0
  npm_critical=0
  if [[ "${npm_audit_counts_status}" -eq 0 ]]; then
    read -r npm_low npm_moderate npm_high npm_critical <<<"${npm_audit_counts}"
    log "npm audit severities: low=${npm_low} moderate=${npm_moderate} high=${npm_high} critical=${npm_critical}"
    if (( npm_high > 0 || npm_critical > 0 )); then
      NPM_AUDIT_FAILURE=1
      log "npm audit release gate failed: high/critical vulnerabilities found"
    fi
  else
    log "unable to parse npm audit JSON report at ${LOG_DIR}/npm_audit.json"
    if [[ "${STRICT}" == "1" ]]; then
      NPM_AUDIT_FAILURE=1
    fi
  fi

  if [[ "${npm_audit_status}" -eq 0 ]]; then
    log "npm audit written to ${LOG_DIR}/npm_audit.json"
  elif [[ "${npm_audit_status}" -eq 1 ]]; then
    log "npm audit reported vulnerabilities (exit 1); report at ${LOG_DIR}/npm_audit.json"
  else
    if [[ "${STRICT}" == "1" ]]; then
      NPM_AUDIT_FAILURE=1
      log "npm audit failed (exit ${npm_audit_status}); deferring failure until SBOM artifacts are generated"
    else
      log "npm audit failed (exit ${npm_audit_status}); continuing"
    fi
  fi

  if npm sbom --version >/dev/null 2>&1; then
    log "generating npm sbom"
    npm_sbom_status=0
    set +e
    (cd "${ROOT_DIR}/npm" && npm sbom --package-lock-only --sbom-format cyclonedx >"${LOG_DIR}/npm_sbom.json")
    npm_sbom_status=$?
    set -e
    if [[ "${npm_sbom_status}" -eq 0 ]]; then
      log "npm sbom written to ${LOG_DIR}/npm_sbom.json"
    elif [[ "${STRICT}" == "1" ]]; then
      NPM_AUDIT_FAILURE=1
      log "npm sbom failed (exit ${npm_sbom_status}); deferring failure until remaining artifacts are generated"
    else
      log "npm sbom failed (exit ${npm_sbom_status}); continuing"
    fi
  elif [[ "${STRICT}" == "1" ]]; then
    NPM_AUDIT_FAILURE=1
    log "npm sbom not available; deferring failure until remaining artifacts are generated"
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

if [[ "${NPM_AUDIT_FAILURE}" -ne 0 ]]; then
  log "security audit failed after preserving available audit and SBOM artifacts in ${LOG_DIR}"
  exit 1
fi

log "security audit complete"
