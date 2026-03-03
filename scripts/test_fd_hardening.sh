#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

log() {
  printf "[fd-hardening] %s\n" "$*" >&2
}

if ! command -v node >/dev/null 2>&1; then
  log "node is required for npm postinstall tests"
  exit 1
fi

log "running npm postinstall tests"
node --test "${ROOT_DIR}/npm/test/postinstall_setup.test.js"

log "running daemon FD limit unit tests"
cargo test --lib daemon::fd_limits

log "running profile lock retry unit tests"
cargo test --lib profiles::manager

log "fd hardening validation passed"
