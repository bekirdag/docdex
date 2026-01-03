#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_DIR="${ROOT_DIR}/target/bench_logs"
RUN_TAG="${DOCDEX_BENCH_TAG:-indexing}"

mkdir -p "${LOG_DIR}"

log() {
  printf "[bench-indexing] %s\n" "$*" >&2
}

log "starting indexing benchmark (criterion)"
log "results stored under target/criterion (compare to docs/quality_gates.md)"

log_file="${LOG_DIR}/indexing_${RUN_TAG}_$(date +%Y%m%d%H%M%S).log"
if cargo bench --bench indexing_bench -- --noplot 2>&1 | tee "${log_file}"; then
  log "benchmark completed (log: ${log_file})"
else
  log "benchmark failed (log: ${log_file})"
  exit 1
fi
