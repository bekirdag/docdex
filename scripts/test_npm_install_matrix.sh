#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NPM_DIR="$ROOT/npm"
WORK_ROOT="${DOCDEX_NPM_MATRIX_DIR:-$ROOT/target/npm_install_matrix}"
RUN_DIR="$WORK_ROOT/$(date +%Y%m%d%H%M%S)"

mkdir -p "$RUN_DIR"

pushd "$NPM_DIR" >/dev/null
PKG_TGZ="$(npm pack --silent)"
popd >/dev/null

TARBALL="$NPM_DIR/$PKG_TGZ"
if [[ ! -f "$TARBALL" ]]; then
  echo "[npm-matrix] failed to produce npm tarball" >&2
  exit 1
fi

install_local() {
  local dest="$1"
  mkdir -p "$dest"
  pushd "$dest" >/dev/null
  npm init -y >/dev/null
  npm install --ignore-scripts "$TARBALL" >/dev/null
  popd >/dev/null
  echo "[npm-matrix] ok: local install (ignore-scripts) in $dest"
}

install_with_installer() {
  local dest="$1"
  local repo="${DOCDEX_DOWNLOAD_REPO:-bekirdag/docdex}"
  local version="${DOCDEX_VERSION:-$(node -p "require('./npm/package.json').version" 2>/dev/null || echo "0.0.0")}"
  pushd "$dest" >/dev/null
  DOCDEX_DOWNLOAD_REPO="$repo" DOCDEX_VERSION="$version" node ./node_modules/docdex/lib/install.js
  popd >/dev/null
  echo "[npm-matrix] ok: installer ran in $dest"
}

install_local "$RUN_DIR/local"

if [[ "${DOCDEX_NPM_RUN_INSTALLER:-0}" == "1" ]]; then
  install_with_installer "$RUN_DIR/local"
else
  echo "[npm-matrix] skipped installer (set DOCDEX_NPM_RUN_INSTALLER=1 to run)"
fi

if [[ "${DOCDEX_NPM_DOCKER_MATRIX:-0}" == "1" ]]; then
  if ! command -v docker >/dev/null 2>&1; then
    echo "[npm-matrix] docker not available; skipping container matrix" >&2
    exit 0
  fi
  if ! docker info >/dev/null 2>&1; then
    echo "[npm-matrix] docker daemon not running; skipping container matrix" >&2
    exit 0
  fi
  IMAGE="${DOCDEX_NPM_DOCKER_IMAGE:-node:20-bullseye}"
  docker run --rm -v "$ROOT":/work -w /work "$IMAGE" \
    bash -lc "cd /work && scripts/test_npm_install_matrix.sh"
fi
