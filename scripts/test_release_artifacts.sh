#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ASSETS_DIR="${DOCDEX_RELEASE_DIR:-}"
CHECK_ROOT="${DOCDEX_RELEASE_CHECK_DIR:-$ROOT/target/release_checks}"

if [[ -z "$ASSETS_DIR" ]]; then
  echo "[release-check] DOCDEX_RELEASE_DIR must point to a release assets directory" >&2
  exit 2
fi

if [[ ! -d "$ASSETS_DIR" ]]; then
  echo "[release-check] assets dir not found: $ASSETS_DIR" >&2
  exit 2
fi

TAG="${DOCDEX_RELEASE_TAG:-}"
if [[ -z "$TAG" ]]; then
  VERSION="$(node -p "require('./npm/package.json').version" 2>/dev/null || echo "")"
  if [[ -n "$VERSION" ]]; then
    TAG="v$VERSION"
  else
    TAG="v0.0.0"
  fi
fi

REPO="${DOCDEX_RELEASE_REPO:-bekirdag/docdex}"
RUN_DIR="$CHECK_ROOT/$(date +%Y%m%d%H%M%S)"
ASSET_COPY="$RUN_DIR/assets"
mkdir -p "$ASSET_COPY"

cp -R "$ASSETS_DIR"/. "$ASSET_COPY"

node "$ROOT/scripts/generate_release_manifest.cjs" \
  --dir "$ASSET_COPY" \
  --out "$ASSET_COPY/docdexd-manifest.json" \
  --tag "$TAG" \
  --repo "$REPO"

if [[ ! -f "$ASSET_COPY/SHA256SUMS" ]]; then
  echo "[release-check] missing SHA256SUMS in generated assets" >&2
  exit 1
fi

grep -q "docdexd-manifest.json" "$ASSET_COPY/SHA256SUMS"
grep -q "docdexd-manifest.json.sha256" "$ASSET_COPY/SHA256SUMS"

shopt -s nullglob
for archive in "$ASSET_COPY"/docdexd-*.tar.gz; do
  if ! tar -tzf "$archive" | grep -q "docdexd"; then
    echo "[release-check] missing docdexd in $archive" >&2
    exit 1
  fi
done

echo "[release-check] ok: manifest + checksums validated in $ASSET_COPY"
