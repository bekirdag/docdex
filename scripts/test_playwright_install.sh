#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NPM_DIR="${ROOT_DIR}/npm"
BROWSERS_PATH="${PLAYWRIGHT_BROWSERS_PATH:-${HOME}/.docdex/state/bin/playwright}"
BROWSERS="chromium,firefox,webkit"

log() {
  printf "[playwright-install] %s\n" "$*"
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    log "missing dependency: $1"
    exit 1
  fi
}

require_cmd node
require_cmd npm

if [[ ! -d "${NPM_DIR}/node_modules/playwright" ]]; then
  log "playwright dependency missing; installing npm deps..."
  (cd "${NPM_DIR}" && npm install)
fi

export PLAYWRIGHT_BROWSERS_PATH="${BROWSERS_PATH}"
export PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=0

log "installing playwright browsers: ${BROWSERS}"
node "${NPM_DIR}/lib/playwright_install.js" --browsers "${BROWSERS}" --path "${BROWSERS_PATH}"

manifest="${BROWSERS_PATH}/manifest.json"
if [[ ! -f "${manifest}" ]]; then
  log "manifest missing at ${manifest}"
  exit 1
fi

log "verifying manifest entries..."
node - <<'NODE'
const fs = require("node:fs");
const path = require("node:path");

const manifestPath = process.env.PLAYWRIGHT_BROWSERS_PATH
  ? path.join(process.env.PLAYWRIGHT_BROWSERS_PATH, "manifest.json")
  : null;
if (!manifestPath || !fs.existsSync(manifestPath)) {
  console.error(`[playwright-install] missing manifest at ${manifestPath || "<unknown>"}`);
  process.exit(1);
}
const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
const expected = ["chromium", "firefox", "webkit"];
const seen = new Set((manifest.browsers || []).map((entry) => entry.name));
for (const name of expected) {
  if (!seen.has(name)) {
    console.error(`[playwright-install] missing browser ${name} in manifest`);
    process.exit(1);
  }
}
for (const entry of manifest.browsers || []) {
  if (!entry.path || !fs.existsSync(entry.path)) {
    console.error(`[playwright-install] browser path missing: ${entry.name} -> ${entry.path || "<none>"}`);
    process.exit(1);
  }
}
console.log("[playwright-install] manifest ok");
NODE

log "playwright browsers installed successfully"
