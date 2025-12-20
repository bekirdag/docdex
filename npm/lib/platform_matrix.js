"use strict";

/**
 * Single source of truth for:
 *   detected runtime (platform/arch/libc) -> platformKey -> Rust target triple -> release asset naming.
 * Contract: docs/contracts/installer_platform_mapping_v1.md
 *
 * Notes:
 * - `platformKey` is the suffix used in release assets: `docdexd-<platformKey>.tar.gz`.
 * - Some mappings are defined but marked `published: false` when the release workflow does not
 *   currently publish a matching binary artifact; these MUST be treated as unsupported at install/runtime.
 */

/** @type {{platform: string, arch: string, libc: (null|"gnu"|"musl"), platformKey: string, targetTriple: string, published: boolean}[]} */
const PLATFORM_MATRIX = Object.freeze([
  {
    platform: "darwin",
    arch: "arm64",
    libc: null,
    platformKey: "darwin-arm64",
    targetTriple: "aarch64-apple-darwin",
    published: true
  },
  {
    platform: "darwin",
    arch: "x64",
    libc: null,
    platformKey: "darwin-x64",
    targetTriple: "x86_64-apple-darwin",
    published: true
  },
  {
    platform: "linux",
    arch: "x64",
    libc: "gnu",
    platformKey: "linux-x64-gnu",
    targetTriple: "x86_64-unknown-linux-gnu",
    published: true
  },
  {
    platform: "linux",
    arch: "x64",
    libc: "musl",
    platformKey: "linux-x64-musl",
    targetTriple: "x86_64-unknown-linux-musl",
    published: true
  },
  {
    platform: "linux",
    arch: "arm64",
    libc: "gnu",
    platformKey: "linux-arm64-gnu",
    targetTriple: "aarch64-unknown-linux-gnu",
    published: true
  },
  {
    platform: "linux",
    arch: "arm64",
    libc: "musl",
    platformKey: "linux-arm64-musl",
    targetTriple: "aarch64-unknown-linux-musl",
    published: false
  },
  {
    platform: "win32",
    arch: "x64",
    libc: null,
    platformKey: "win32-x64",
    targetTriple: "x86_64-pc-windows-msvc",
    published: true
  },
  {
    platform: "win32",
    arch: "arm64",
    libc: null,
    platformKey: "win32-arm64",
    targetTriple: "aarch64-pc-windows-msvc",
    published: false
  }
]);

const PLATFORM_ENTRY_BY_KEY = Object.freeze(
  PLATFORM_MATRIX.reduce((acc, entry) => {
    acc[entry.platformKey] = entry;
    return acc;
  }, {})
);

const PUBLISHED_PLATFORM_KEYS = Object.freeze(
  PLATFORM_MATRIX.filter((e) => e.published)
    .map((e) => e.platformKey)
    .slice()
    .sort()
);

const PUBLISHED_TARGET_TRIPLES = Object.freeze(
  [...new Set(PLATFORM_MATRIX.filter((e) => e.published).map((e) => e.targetTriple))].sort()
);

function archiveBaseForPlatformKey(platformKey) {
  return `docdexd-${platformKey}`;
}

function assetNameForPlatformKey(platformKey) {
  return `${archiveBaseForPlatformKey(platformKey)}.tar.gz`;
}

/**
 * Default target list for release-manifest generation (published targets only).
 * Shape matches scripts/generate_release_manifest.cjs `targets` input.
 */
const PUBLISHED_RELEASE_TARGETS = Object.freeze(
  PLATFORM_MATRIX.filter((e) => e.published)
    .map((e) => ({ targetTriple: e.targetTriple, archiveBase: archiveBaseForPlatformKey(e.platformKey) }))
    .slice()
    .sort((a, b) => a.targetTriple.localeCompare(b.targetTriple))
);

module.exports = {
  PLATFORM_MATRIX,
  PLATFORM_ENTRY_BY_KEY,
  PUBLISHED_PLATFORM_KEYS,
  PUBLISHED_TARGET_TRIPLES,
  PUBLISHED_RELEASE_TARGETS,
  archiveBaseForPlatformKey,
  assetNameForPlatformKey
};
