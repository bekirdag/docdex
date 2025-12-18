"use strict";

const fs = require("node:fs");

const {
  PLATFORM_ENTRY_BY_KEY,
  PUBLISHED_PLATFORM_KEYS,
  PUBLISHED_TARGET_TRIPLES,
  assetNameForPlatformKey
} = require("./platform_matrix");

class UnsupportedPlatformError extends Error {
  /**
   * @param {{
   *   platform: string,
   *   arch: string,
   *   libc?: (null|"gnu"|"musl"),
   *   candidatePlatformKey?: (string|null),
   *   candidateTargetTriple?: (string|null),
   *   reason?: (string|null),
   *   supportedPlatformKeys: string[],
   *   supportedTargetTriples: string[]
   * }} options
   */
  constructor({
    platform,
    arch,
    libc = null,
    candidatePlatformKey = null,
    candidateTargetTriple = null,
    reason = null,
    supportedPlatformKeys,
    supportedTargetTriples
  }) {
    super(`Unsupported platform: ${platform}/${arch}`);
    this.name = "UnsupportedPlatformError";
    this.code = "DOCDEX_UNSUPPORTED_PLATFORM";
    this.exitCode = 3;
    this.details = {
      targetTriple: null,
      manifestVersion: null,
      assetName: null,
      platform,
      arch,
      libc,
      candidatePlatformKey,
      candidateTargetTriple,
      reason,
      supportedPlatformKeys: supportedPlatformKeys || [],
      supportedTargetTriples: supportedTargetTriples || []
    };
  }
}

const SUPPORTED_PLATFORM_KEYS = PUBLISHED_PLATFORM_KEYS;
const SUPPORTED_TARGET_TRIPLES = PUBLISHED_TARGET_TRIPLES;

function libcForPlatformKey(platformKey) {
  if (!platformKey || typeof platformKey !== "string") return null;
  if (!platformKey.startsWith("linux-")) return null;
  if (platformKey.endsWith("-gnu")) return "gnu";
  if (platformKey.endsWith("-musl")) return "musl";
  return null;
}

function normalizeLibc(value) {
  if (value == null) return null;
  const libc = String(value).toLowerCase().trim();
  if (!libc) return null;
  if (libc === "glibc") return "gnu";
  if (libc === "musl" || libc === "gnu") return libc;
  return null;
}

function readFileSliceSync(fsModule, filePath, offset, length) {
  const fd = fsModule.openSync(filePath, "r");
  try {
    const buf = Buffer.alloc(length);
    const bytesRead = fsModule.readSync(fd, buf, 0, length, offset);
    return bytesRead === length ? buf : buf.subarray(0, bytesRead);
  } finally {
    fsModule.closeSync(fd);
  }
}

function detectLibcFromElfInterpreter(execPath, fsModule) {
  if (!execPath || typeof execPath !== "string") return null;
  try {
    const header = readFileSliceSync(fsModule, execPath, 0, 64);
    if (header.length < 64) return null;
    if (header[0] !== 0x7f || header[1] !== 0x45 || header[2] !== 0x4c || header[3] !== 0x46) return null;

    const eiClass = header[4]; // 1=32-bit, 2=64-bit
    const eiData = header[5]; // 1=little-endian
    if (eiData !== 1) return null;

    const PT_INTERP = 3;

    let phoff;
    let phentsize;
    let phnum;

    if (eiClass === 2) {
      phoff = Number(header.readBigUInt64LE(32));
      phentsize = header.readUInt16LE(54);
      phnum = header.readUInt16LE(56);
    } else if (eiClass === 1) {
      phoff = header.readUInt32LE(28);
      phentsize = header.readUInt16LE(42);
      phnum = header.readUInt16LE(44);
    } else {
      return null;
    }

    if (!phoff || !phentsize || !phnum) return null;
    if (phnum > 64) return null;
    if (phentsize < 32 || phentsize > 128) return null;

    const tableSize = phentsize * phnum;
    const phTable = readFileSliceSync(fsModule, execPath, phoff, tableSize);
    if (phTable.length < tableSize) return null;

    for (let i = 0; i < phnum; i++) {
      const base = i * phentsize;
      const pType = phTable.readUInt32LE(base);
      if (pType !== PT_INTERP) continue;

      let pOffset;
      let pFileSz;

      if (eiClass === 2) {
        pOffset = Number(phTable.readBigUInt64LE(base + 8));
        pFileSz = Number(phTable.readBigUInt64LE(base + 32));
      } else {
        pOffset = phTable.readUInt32LE(base + 4);
        pFileSz = phTable.readUInt32LE(base + 16);
      }

      if (!pOffset || !pFileSz || pFileSz > 4096) return null;
      const interpBytes = readFileSliceSync(fsModule, execPath, pOffset, pFileSz);
      const interp = interpBytes.toString("utf8").split("\0")[0];
      if (!interp) return null;
      if (interp.includes("ld-musl")) return "musl";
      if (interp.includes("ld-linux")) return "gnu";
      return null;
    }
  } catch {
    return null;
  }

  return null;
}

function detectLibc() {
  return detectLibcFromRuntime();
}

function detectLibcFromRuntime(options) {
  const env = options?.env ?? process.env;
  const fsModule = options?.fs ?? fs;

  const overrideRaw = env?.DOCDEX_LIBC;
  if (overrideRaw != null && String(overrideRaw).trim() !== "") {
    const override = normalizeLibc(overrideRaw);
    if (!override) {
      throw new Error(`Invalid DOCDEX_LIBC=${overrideRaw}; expected "gnu", "musl", or "glibc"`);
    }
    return override;
  }

  const report =
    options?.report ??
    (typeof process.report?.getReport === "function" ? process.report.getReport() : null);

  const glibcVersion = report?.header?.glibcVersionRuntime;
  if (typeof glibcVersion === "string" && glibcVersion.trim()) return "gnu";

  // Some Node builds include a `musl` field in the report header. Treat it as a positive signal.
  if (report?.header?.musl != null) return "musl";

  // Alpine is musl-based by default; use it as a strong hint.
  try {
    if (typeof fsModule.existsSync === "function" && fsModule.existsSync("/etc/alpine-release")) return "musl";
  } catch {}

  const execPath = options?.execPath ?? process.execPath;
  const fromElf = detectLibcFromElfInterpreter(execPath, fsModule);
  if (fromElf) return fromElf;

  // Deterministic fallback: musl binaries are typically more portable on glibc than the reverse.
  return "musl";
}

function detectPlatformKey(options) {
  const platform = options?.platform ?? process.platform;
  const arch = options?.arch ?? process.arch;
  let libc = null;
  let candidatePlatformKey = null;
  let candidateTargetTriple = null;

  if (platform === "darwin") {
    if (arch === "arm64") candidatePlatformKey = "darwin-arm64";
    if (arch === "x64") candidatePlatformKey = "darwin-x64";
  }

  if (platform === "linux") {
    libc = normalizeLibc(options?.libc) ?? detectLibcFromRuntime(options);
    if (arch === "arm64") candidatePlatformKey = `linux-arm64-${libc}`;
    if (arch === "x64") candidatePlatformKey = `linux-x64-${libc}`;
  }

  if (platform === "win32") {
    if (arch === "x64") candidatePlatformKey = "win32-x64";
    if (arch === "arm64") candidatePlatformKey = "win32-arm64";
  }

  if (candidatePlatformKey) {
    const entry = PLATFORM_ENTRY_BY_KEY[candidatePlatformKey];
    candidateTargetTriple = entry?.targetTriple ?? null;
    if (entry?.published) return candidatePlatformKey;
    if (entry && entry.published === false) {
      throw new UnsupportedPlatformError({
        platform,
        arch,
        libc,
        candidatePlatformKey,
        candidateTargetTriple,
        reason: "target_not_published",
        supportedPlatformKeys: SUPPORTED_PLATFORM_KEYS,
        supportedTargetTriples: SUPPORTED_TARGET_TRIPLES
      });
    }
  }

  throw new UnsupportedPlatformError({
    platform,
    arch,
    libc,
    candidatePlatformKey,
    candidateTargetTriple,
    reason: "unknown_or_unsupported_runtime",
    supportedPlatformKeys: SUPPORTED_PLATFORM_KEYS,
    supportedTargetTriples: SUPPORTED_TARGET_TRIPLES
  });
}

function artifactName(platformKey) {
  return assetNameForPlatformKey(platformKey);
}

/**
 * Human-readable release asset naming pattern for `docdexd` archives.
 * @param {string|null} [platformKey]
 * @param {{includeExample?: boolean, exampleAssetName?: string}} [options]
 */
function assetPatternForPlatformKey(platformKey, options) {
  const includeExample = options?.includeExample !== false;
  const exampleAssetName =
    typeof options?.exampleAssetName === "string" && options.exampleAssetName.trim()
      ? options.exampleAssetName.trim()
      : null;
  const base = "docdexd-<platformKey>.tar.gz";
  if (!platformKey || typeof platformKey !== "string") return base;
  if (!includeExample) return base;
  return `${base} (e.g. ${exampleAssetName || assetNameForPlatformKey(platformKey)})`;
}

function targetTripleForPlatformKey(platformKey) {
  const triple = PLATFORM_ENTRY_BY_KEY[platformKey]?.targetTriple;
  if (triple) return triple;
  throw new Error(
    `Unsupported platform key: ${platformKey}. Supported: ${Object.keys(PLATFORM_ENTRY_BY_KEY).sort().join(", ")}`
  );
}

function detectTargetTriple(options) {
  return targetTripleForPlatformKey(detectPlatformKey(options));
}

/**
 * Resolve the full platform support policy (runtime → supported? → target triple + asset naming).
 * Consumers should use this as the single source of truth for distinguishing unsupported platforms
 * from missing release artifacts (supported-but-missing).
 *
 * @param {Parameters<typeof detectPlatformKey>[0]} [options]
 */
function resolvePlatformPolicy(options) {
  const platform = options?.platform ?? process.platform;
  const arch = options?.arch ?? process.arch;
  const platformKey = detectPlatformKey(options);
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const libc = platform === "linux" ? libcForPlatformKey(platformKey) : null;
  return {
    detected: { platform, arch, ...(libc ? { libc } : {}) },
    platformKey,
    targetTriple,
    expectedAssetName: artifactName(platformKey),
    expectedAssetPattern: assetPatternForPlatformKey(platformKey)
  };
}

module.exports = {
  detectLibc,
  detectLibcFromRuntime,
  detectPlatformKey,
  UnsupportedPlatformError,
  libcForPlatformKey,
  artifactName,
  assetPatternForPlatformKey,
  targetTripleForPlatformKey,
  detectTargetTriple,
  resolvePlatformPolicy
};
