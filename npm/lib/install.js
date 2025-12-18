#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const https = require("node:https");
const os = require("node:os");
const path = require("node:path");
const { pipeline } = require("node:stream/promises");
const crypto = require("node:crypto");

const pkg = require("../package.json");
const {
  artifactName,
  assetPatternForPlatformKey,
  detectPlatformKey,
  resolvePlatformPolicy,
  targetTripleForPlatformKey,
  UnsupportedPlatformError
} = require("./platform");
const { ManifestResolutionError, resolveCanonicalAssetForTargetTriple } = require("./release_manifest");

const MAX_REDIRECTS = 5;
const USER_AGENT = "docdex-installer";
const PLACEHOLDER_REPO_TOKEN = /OWNER|REPO/i;
const MAX_MANIFEST_BYTES = 1024 * 1024; // 1 MiB cap for safety
const INVALID_JSON_ERROR = "invalid JSON";
const INSTALL_METADATA_SCHEMA_VERSION = 1;
const INSTALL_METADATA_FILENAME = "docdexd-install.json";

const EXIT_CODE_BY_ERROR_CODE = Object.freeze({
  DOCDEX_INSTALLER_CONFIG: 2,
  DOCDEX_UNSUPPORTED_PLATFORM: 3,
  DOCDEX_MANIFEST_MALFORMED: 10,
  DOCDEX_TARGET_TRIPLE_INVALID: 11,
  DOCDEX_ASSET_NO_MATCH: 12,
  DOCDEX_ASSET_MULTI_MATCH: 13,
  DOCDEX_ASSET_MALFORMED: 14,
  DOCDEX_CHECKSUM_UNUSABLE: 24,
  DOCDEX_DOWNLOAD_FAILED: 20,
  DOCDEX_ASSET_MISSING: 21,
  DOCDEX_INTEGRITY_MISMATCH: 22,
  DOCDEX_ARCHIVE_INVALID: 23
});

function withBaseDetails(details) {
  return {
    targetTriple: null,
    manifestVersion: null,
    assetName: null,
    ...(details || {})
  };
}

class InstallerConfigError extends Error {
  /**
   * @param {string} message
   * @param {object} [details]
   */
  constructor(message, details) {
    super(message);
    this.name = "InstallerConfigError";
    this.code = "DOCDEX_INSTALLER_CONFIG";
    this.exitCode = EXIT_CODE_BY_ERROR_CODE[this.code];
    this.details = withBaseDetails(details);
  }
}

class MissingArtifactError extends Error {
  /**
   * @param {object} details
   */
  constructor(details) {
    super("Missing release artifact for detected platform");
    this.name = "MissingArtifactError";
    this.code = "DOCDEX_ASSET_MISSING";
    this.exitCode = EXIT_CODE_BY_ERROR_CODE[this.code];
    this.details = withBaseDetails(details);
  }
}

class DownloadError extends Error {
  /**
   * @param {string} message
   * @param {object} details
   * @param {Error} [cause]
   */
  constructor(message, details, cause) {
    super(message, cause ? { cause } : undefined);
    this.name = "DownloadError";
    this.code = "DOCDEX_DOWNLOAD_FAILED";
    this.exitCode = EXIT_CODE_BY_ERROR_CODE[this.code];
    this.details = withBaseDetails(details);
  }
}

class IntegrityMismatchError extends Error {
  /**
   * @param {string} archiveName
   * @param {string} expectedSha256
   * @param {string} actualSha256
   * @param {object} [details]
   */
  constructor(archiveName, expectedSha256, actualSha256, details) {
    super(
      `Integrity check failed for ${archiveName}: expected sha256=${expectedSha256} got sha256=${actualSha256}`
    );
    this.name = "IntegrityMismatchError";
    this.code = "DOCDEX_INTEGRITY_MISMATCH";
    this.exitCode = EXIT_CODE_BY_ERROR_CODE[this.code];
    this.details = withBaseDetails({
      ...details,
      assetName: archiveName,
      expectedSha256,
      actualSha256
    });
  }
}

class ArchiveInvalidError extends Error {
  /**
   * @param {string} message
   * @param {object} details
   */
  constructor(message, details) {
    super(message);
    this.name = "ArchiveInvalidError";
    this.code = "DOCDEX_ARCHIVE_INVALID";
    this.exitCode = EXIT_CODE_BY_ERROR_CODE[this.code];
    this.details = withBaseDetails(details);
  }
}

class ChecksumResolutionError extends Error {
  /**
   * @param {string} message
   * @param {object} [details]
   */
  constructor(message, details) {
    super(message);
    this.name = "ChecksumResolutionError";
    this.code = "DOCDEX_CHECKSUM_UNUSABLE";
    this.exitCode = EXIT_CODE_BY_ERROR_CODE[this.code];
    this.details = withBaseDetails(details);
  }
}

function parseRepoSlug() {
  const envRepo = process.env.DOCDEX_DOWNLOAD_REPO;
  if (envRepo) return envRepo;

  const repoUrl = pkg.repository?.url || "";
  const match = repoUrl.match(/github\.com[:/](.+?)(\.git)?$/);

  if (match && match[1] && !PLACEHOLDER_REPO_TOKEN.test(match[1])) {
    return match[1];
  }

  throw new InstallerConfigError(
    "Set DOCDEX_DOWNLOAD_REPO env var or update package.json repository.url to owner/repo",
    { repoSlug: null }
  );
}

function getDownloadBase(repoSlug) {
  return process.env.DOCDEX_DOWNLOAD_BASE || `https://github.com/${repoSlug}/releases/download`;
}

function getVersion() {
  const envVersion = process.env.DOCDEX_VERSION;
  const version = (envVersion || pkg.version || "").replace(/^v/, "");

  if (!version) {
    throw new InstallerConfigError("Missing package version; set DOCDEX_VERSION or package.json version", {
      version: null
    });
  }

  return version;
}

function requestOptions() {
  const headers = { "User-Agent": USER_AGENT };
  const token = process.env.DOCDEX_GITHUB_TOKEN || process.env.GITHUB_TOKEN;
  if (token) headers.Authorization = `Bearer ${token}`;
  return { headers };
}

function downloadText(url, redirects = 0) {
  if (redirects > MAX_REDIRECTS) {
    throw new Error(`Too many redirects while fetching ${url}`);
  }

  return new Promise((resolve, reject) => {
    https
      .get(url, requestOptions(), (res) => {
        if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          res.resume();
          return downloadText(res.headers.location, redirects + 1).then(resolve, reject);
        }

        if (res.statusCode !== 200) {
          res.resume();
          const err = new Error(`Download failed (${res.statusCode}) from ${url}`);
          err.statusCode = res.statusCode;
          err.url = url;
          return reject(err);
        }

        const chunks = [];
        let total = 0;
        res.on("data", (chunk) => {
          total += chunk.length;
          if (total > MAX_MANIFEST_BYTES) {
            const err = new Error(`Response too large while fetching ${url} (>${MAX_MANIFEST_BYTES} bytes)`);
            err.code = "DOCDEX_DOWNLOAD_TOO_LARGE";
            err.url = url;
            err.maxBytes = MAX_MANIFEST_BYTES;
            err.actualBytes = total;
            res.destroy(err);
            return;
          }
          chunks.push(chunk);
        });
        res.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
        res.on("error", reject);
      })
      .on("error", reject);
  });
}

function download(url, dest, redirects = 0) {
  if (redirects > MAX_REDIRECTS) {
    throw new Error(`Too many redirects while fetching ${url}`);
  }

  return new Promise((resolve, reject) => {
    https
      .get(url, requestOptions(), (res) => {
        if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          res.resume();
          return download(res.headers.location, dest, redirects + 1).then(resolve, reject);
        }

        if (res.statusCode !== 200) {
          res.resume();
          const err = new Error(`Download failed (${res.statusCode}) from ${url}`);
          err.statusCode = res.statusCode;
          err.url = url;
          return reject(err);
        }

        const file = fs.createWriteStream(dest);
        pipeline(res, file).then(resolve).catch(reject);
      })
      .on("error", reject);
  });
}

async function extractTarball(archivePath, targetDir) {
  // Lazy import so unit tests can load this module without installing optional npm deps.
  const tar = require("tar");
  await fs.promises.mkdir(targetDir, { recursive: true });
  await tar.x({ file: archivePath, cwd: targetDir, gzip: true });
}

async function sha256File(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash("sha256");
    const stream = fs.createReadStream(filePath);
    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("error", reject);
    stream.on("end", () => resolve(hash.digest("hex")));
  });
}

function installMetadataPath(distDir, pathModule = path) {
  return pathModule.join(distDir, INSTALL_METADATA_FILENAME);
}

function nowIso() {
  return new Date().toISOString();
}

async function readJsonFileIfPossible({ fsModule, filePath }) {
  if (!fsModule?.promises?.readFile) {
    return { value: null, error: "readFile_unavailable", errorCode: "READFILE_UNAVAILABLE" };
  }
  try {
    const raw = await fsModule.promises.readFile(filePath, "utf8");
    try {
      return { value: JSON.parse(raw), error: null, errorCode: null };
    } catch (err) {
      return { value: null, error: err?.message || String(err), errorCode: "INVALID_JSON" };
    }
  } catch (err) {
    return {
      value: null,
      error: err?.message || String(err),
      errorCode: typeof err?.code === "string" && err.code ? err.code : "READ_ERROR"
    };
  }
}

async function writeJsonFileAtomic({ fsModule, pathModule, filePath, value }) {
  const dir = pathModule.dirname(filePath);
  await fsModule.promises.mkdir(dir, { recursive: true });
  const tmp = `${filePath}.${process.pid}.${Date.now()}.tmp`;
  const payload = `${JSON.stringify(value, null, 2)}\n`;
  await fsModule.promises.writeFile(tmp, payload, "utf8");
  await fsModule.promises.rename(tmp, filePath);
}

function isValidInstallMetadata(meta) {
  if (!meta || typeof meta !== "object") return false;
  if (meta.schemaVersion !== INSTALL_METADATA_SCHEMA_VERSION) return false;
  if (typeof meta.version !== "string" || !meta.version) return false;
  if (typeof meta.platformKey !== "string" || !meta.platformKey) return false;
  if (!meta.binary || typeof meta.binary !== "object") return false;
  if (typeof meta.binary.sha256 !== "string" || meta.binary.sha256.length !== 64) return false;
  return true;
}

function normalizeSha256Hex(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(trimmed)) return null;
  return trimmed;
}

function integrityUnverifiable(reason, { expectedSha256, actualSha256, expectedSource, error } = {}) {
  return {
    status: "unverifiable",
    reason,
    expectedSha256: expectedSha256 ?? null,
    actualSha256: actualSha256 ?? null,
    expectedSource: expectedSource ?? null,
    error: error ?? null
  };
}

function integrityMismatch({ expectedSha256, actualSha256, expectedSource }) {
  return {
    status: "mismatch",
    reason: "hash_mismatch",
    expectedSha256: expectedSha256 ?? null,
    actualSha256: actualSha256 ?? null,
    expectedSource: expectedSource ?? null,
    error: null
  };
}

function integrityVerified({ expectedSha256, actualSha256, expectedSource }) {
  return {
    status: "verified_ok",
    reason: "hash_match",
    expectedSha256: expectedSha256 ?? null,
    actualSha256: actualSha256 ?? null,
    expectedSource: expectedSource ?? null,
    error: null
  };
}

async function verifyInstalledDocdexdIntegrity({
  fsModule,
  sha256FileFn,
  binaryPath,
  expectedBinarySha256,
  installedMetadata,
  installedMetadataStatus,
  installedMetadataStatusReason
}) {
  const existsSync = typeof fsModule?.existsSync === "function" ? fsModule.existsSync.bind(fsModule) : null;
  if (!existsSync) {
    return integrityUnverifiable("fs_unavailable", { expectedSource: null, error: "existsSync_unavailable" });
  }

  if (!existsSync(binaryPath)) {
    return integrityUnverifiable("missing_file", { expectedSource: null });
  }

  const expectedFromRelease = expectedBinarySha256 != null ? normalizeSha256Hex(expectedBinarySha256) : null;
  if (expectedBinarySha256 != null && !expectedFromRelease) {
    return integrityUnverifiable("expected_hash_invalid", { expectedSource: "release" });
  }

  const expectedFromMetadata =
    installedMetadataStatus === "valid" ? normalizeSha256Hex(installedMetadata?.binary?.sha256) : null;

  const expectedSha256 = expectedFromRelease || expectedFromMetadata;
  const expectedSource = expectedFromRelease ? "release" : expectedFromMetadata ? "metadata" : null;

  if (!expectedSha256) {
    if (installedMetadataStatus && installedMetadataStatus !== "valid") {
      const reason =
        typeof installedMetadataStatusReason === "string" && installedMetadataStatusReason
          ? installedMetadataStatusReason
          : "metadata_missing";
      return integrityUnverifiable(reason, { expectedSource });
    }
    return integrityUnverifiable("expected_hash_unavailable", { expectedSource });
  }

  try {
    const actualSha256 = normalizeSha256Hex(await sha256FileFn(binaryPath));
    if (!actualSha256) {
      return integrityUnverifiable("hash_unreadable", { expectedSha256, expectedSource });
    }
    if (actualSha256 !== expectedSha256) {
      return integrityMismatch({ expectedSha256, actualSha256, expectedSource });
    }
    return integrityVerified({ expectedSha256, actualSha256, expectedSource });
  } catch (err) {
    return integrityUnverifiable("unreadable", {
      expectedSha256,
      expectedSource,
      error: err?.message || String(err)
    });
  }
}

/**
 * @param {object} args
 * @param {string} args.expectedVersion
 * @param {{binarySha256: (string|null)}} args.expectedIntegrityMaterial
 * @param {object} args.discoveredInstalledState
 * @param {object} args.integrityResult
 * @returns {{outcome: string, reason: string}}
 */
function decideInstallAction({
  expectedVersion,
  expectedIntegrityMaterial,
  discoveredInstalledState,
  integrityResult
}) {
  if (!discoveredInstalledState?.binaryPresent) return { outcome: "update", reason: "binary_missing" };

  if (discoveredInstalledState.metadataStatus !== "valid") {
    return {
      outcome: "reinstall_unknown",
      reason: discoveredInstalledState.metadataStatusReason || "metadata_invalid"
    };
  }

  if (discoveredInstalledState.platformMismatch) {
    return { outcome: "reinstall_unknown", reason: "platform_mismatch" };
  }

  if (discoveredInstalledState.installedVersion !== expectedVersion) {
    return { outcome: "update", reason: "version_mismatch" };
  }

  const expectedBinarySha256 = normalizeSha256Hex(expectedIntegrityMaterial?.binarySha256);
  if (!expectedBinarySha256) {
    return { outcome: "reinstall_unknown", reason: "expected_integrity_missing" };
  }

  if (integrityResult?.status === "mismatch") {
    return { outcome: "repair", reason: "binary_integrity_mismatch" };
  }

  if (integrityResult?.status === "verified_ok") {
    return { outcome: "no-op", reason: "verified" };
  }

  return { outcome: "reinstall_unknown", reason: "integrity_unverifiable" };
}

async function discoverInstalledState({ fsModule, pathModule, distDir, platformKey, isWin32 }) {
  const binaryPath = pathModule.join(distDir, isWin32 ? "docdexd.exe" : "docdexd");
  const metadataPath = installMetadataPath(distDir, pathModule);

  const existsSync = typeof fsModule?.existsSync === "function" ? fsModule.existsSync.bind(fsModule) : null;
  if (!existsSync) {
    return {
      binaryPath,
      metadataPath,
      binaryPresent: false,
      installedVersion: null,
      metadata: null,
      metadataStatus: "unavailable",
      metadataStatusReason: "existsSync_unavailable",
      platformMismatch: false
    };
  }

  if (!existsSync(binaryPath)) {
    return {
      binaryPath,
      metadataPath,
      binaryPresent: false,
      installedVersion: null,
      metadata: null,
      metadataStatus: "missing",
      metadataStatusReason: "binary_missing",
      platformMismatch: false
    };
  }

  const metaResult = await readJsonFileIfPossible({ fsModule, filePath: metadataPath });
  const meta = metaResult.value;
  if (!isValidInstallMetadata(meta)) {
    return {
      binaryPath,
      metadataPath,
      binaryPresent: true,
      installedVersion: typeof meta?.version === "string" ? meta.version : null,
      metadata: null,
      metadataStatus:
        metaResult.errorCode === "ENOENT"
          ? "missing"
          : metaResult.errorCode
            ? "unreadable"
            : "invalid",
      metadataStatusReason:
        metaResult.errorCode === "ENOENT"
          ? "metadata_missing"
          : metaResult.errorCode
            ? "metadata_unreadable"
            : "metadata_invalid",
      platformMismatch: false
    };
  }

  return {
    binaryPath,
    metadataPath,
    binaryPresent: true,
    installedVersion: meta.version,
    metadata: meta,
    metadataStatus: "valid",
    metadataStatusReason: null,
    platformMismatch: meta.platformKey !== platformKey
  };
}

async function verifyInstalledBinaryIntegrity({ sha256FileFn, binaryPath, expectedBinarySha256 }) {
  const expected = normalizeSha256Hex(expectedBinarySha256);
  if (!expected) {
    return integrityUnverifiable("expected_hash_unavailable", {
      expectedSha256: null,
      actualSha256: null,
      expectedSource: null,
      error: "expected_missing"
    });
  }

  try {
    const actual = normalizeSha256Hex(await sha256FileFn(binaryPath));
    if (!actual) {
      return integrityUnverifiable("hash_unreadable", {
        expectedSha256: expected,
        actualSha256: null,
        expectedSource: null,
        error: "actual_invalid"
      });
    }
    if (actual !== expected) {
      return integrityMismatch({ expectedSha256: expected, actualSha256: actual, expectedSource: null });
    }
    return integrityVerified({ expectedSha256: expected, actualSha256: actual, expectedSource: null });
  } catch (err) {
    return integrityUnverifiable("unreadable", {
      expectedSha256: expected,
      actualSha256: null,
      expectedSource: null,
      error: err?.message || String(err)
    });
  }
}

async function determineLocalInstallerOutcome({
  fsModule,
  pathModule,
  distDir,
  platformKey,
  expectedVersion,
  isWin32,
  sha256FileFn = sha256File,
  expectedBinarySha256 = null
}) {
  const discoveredInstalledState = await discoverInstalledState({
    fsModule,
    pathModule,
    distDir,
    platformKey,
    isWin32
  });

  const expectedIntegrityMaterial = {
    binarySha256: normalizeSha256Hex(expectedBinarySha256)
      ? expectedBinarySha256
      : discoveredInstalledState.metadataStatus === "valid"
        ? discoveredInstalledState.metadata.binary.sha256
        : null
  };

  const shouldVerifyIntegrity =
    discoveredInstalledState.binaryPresent &&
    !discoveredInstalledState.platformMismatch &&
    discoveredInstalledState.installedVersion === expectedVersion &&
    (normalizeSha256Hex(expectedBinarySha256) || discoveredInstalledState.metadataStatus === "valid");

  const integrityResult = shouldVerifyIntegrity
    ? await verifyInstalledDocdexdIntegrity({
        fsModule,
        sha256FileFn,
        binaryPath: discoveredInstalledState.binaryPath,
        expectedBinarySha256: expectedBinarySha256,
        installedMetadata: discoveredInstalledState.metadata,
        installedMetadataStatus: discoveredInstalledState.metadataStatus,
        installedMetadataStatusReason: discoveredInstalledState.metadataStatusReason
      })
    : null;

  const decision = decideInstallAction({
    expectedVersion,
    expectedIntegrityMaterial,
    discoveredInstalledState,
    integrityResult
  });

  const installedVersion =
    typeof discoveredInstalledState.installedVersion === "string" ? discoveredInstalledState.installedVersion : null;

  return {
    outcome: decision.outcome,
    reason: decision.reason,
    binaryPath: discoveredInstalledState.binaryPath,
    metadataPath: discoveredInstalledState.metadataPath,
    installedVersion,
    integrityResult
  };
}

function parseSha256File(text, expectedFilename) {
  const lines = String(text).split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  for (const line of lines) {
    // Typical format: "<hex>  <filename>"
    const match = line.match(/^([0-9a-fA-F]{64})\s+\*?(.+)$/);
    if (!match) continue;
    const hash = match[1].toLowerCase();
    const filename = match[2].trim();
    if (!expectedFilename || filename === expectedFilename) return hash;
  }
  return null;
}

function checksumCandidateNames() {
  const envNames = process.env.DOCDEX_CHECKSUMS_NAMES || process.env.DOCDEX_CHECKSUMS_NAME;
  if (envNames) {
    return envNames
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
  }

  // Documented fallback (ops-01-us-08): SHA256SUMS from the same GitHub Release.
  return ["SHA256SUMS", "SHA256SUMS.txt"];
}

function manifestCandidateNames() {
  const envNames = process.env.DOCDEX_MANIFEST_NAMES || process.env.DOCDEX_MANIFEST_NAME;
  if (envNames) {
    return envNames
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
  }

  // Assumption (documented by code): release attaches one of these filenames.
  return [
    "docdex-release-manifest.json",
    // Legacy/compat candidates:
    "docdexd-manifest.json",
    "docdex-manifest.json",
    "manifest.json"
  ];
}

async function tryResolveSha256ViaChecksumFiles({
  repoSlug,
  version,
  archive,
  downloadTextFn = downloadText,
  getDownloadBaseFn = getDownloadBase,
  checksumCandidateNamesFn = checksumCandidateNames
}) {
  const base = getDownloadBaseFn(repoSlug);
  const candidates = checksumCandidateNamesFn();
  const errors = [];
  const events = [];

  for (const name of candidates) {
    const url = `${base}/v${version}/${name}`;
    try {
      const text = await downloadTextFn(url);
      const parsed = parseSha256File(text, archive);
      if (parsed) {
        return { checksumName: name, checksumUrl: url, sha256: parsed, errors, events, attempted: true };
      }

      const message = `Checksum file (${name}) is missing an entry for ${archive}`;
      errors.push(`[DOCDEX_CHECKSUM_ENTRY_MISSING] ${message}`);
      events.push({ code: "DOCDEX_CHECKSUM_ENTRY_MISSING", message, details: { checksumName: name, url, archive } });
      continue;
    } catch (e) {
      // 404 => missing candidate; try next.
      if (e && typeof e.statusCode === "number" && e.statusCode === 404) {
        events.push({
          code: "DOCDEX_CHECKSUM_NOT_FOUND",
          message: `Checksum candidate not found (${name})`,
          details: { checksumName: name, url, archive, statusCode: 404 }
        });
        continue;
      }

      if (e && e.code === "DOCDEX_DOWNLOAD_TOO_LARGE") {
        const message = `Checksum file too large (${name}): exceeded ${e.maxBytes} bytes`;
        errors.push(`[DOCDEX_CHECKSUM_TOO_LARGE] ${message}`);
        events.push({
          code: "DOCDEX_CHECKSUM_TOO_LARGE",
          message,
          details: { checksumName: name, url, archive, maxBytes: e.maxBytes, actualBytes: e.actualBytes }
        });
        continue;
      }

      const message = `Failed to fetch checksum file (${name}): ${e.message}`;
      errors.push(`[DOCDEX_CHECKSUM_FETCH_FAILED] ${message}`);
      events.push({
        code: "DOCDEX_CHECKSUM_FETCH_FAILED",
        message,
        details: {
          checksumName: name,
          url,
          archive,
          statusCode: typeof e?.statusCode === "number" ? e.statusCode : null
        }
      });
      continue;
    }
  }

  return { checksumName: null, checksumUrl: null, sha256: null, errors, events, attempted: true, candidates };
}

async function tryResolveAssetViaManifest({
  repoSlug,
  version,
  targetTriple,
  downloadTextFn = downloadText,
  getDownloadBaseFn = getDownloadBase,
  manifestCandidateNamesFn = manifestCandidateNames
}) {
  const base = getDownloadBaseFn(repoSlug);
  const errors = [];
  const events = [];
  const candidates = manifestCandidateNamesFn();

  for (const name of candidates) {
    const url = `${base}/v${version}/${name}`;
    try {
      const text = await downloadTextFn(url);
      let manifest;
      try {
        manifest = JSON.parse(text);
      } catch (e) {
        const message = `Malformed manifest (${name}): ${INVALID_JSON_ERROR}`;
        errors.push(`[DOCDEX_MANIFEST_JSON_INVALID] ${message}`);
        events.push({
          code: "DOCDEX_MANIFEST_JSON_INVALID",
          message,
          details: { manifestName: name, url, targetTriple }
        });
        continue;
      }

      // If a manifest exists but doesn't support the current triple, fail deterministically.
      try {
        return {
          manifestName: name,
          resolved: resolveCanonicalAssetForTargetTriple(manifest, targetTriple),
          errors,
          events,
          attempted: true
        };
      } catch (e) {
        if (e instanceof ManifestResolutionError) {
          // Fail closed when the manifest is present but resolution is unsupported or ambiguous.
          if (e.code === "DOCDEX_ASSET_NO_MATCH" || e.code === "DOCDEX_ASSET_MULTI_MATCH") {
            e.message = `Manifest ${name}: ${e.message}`;
            e.details = {
              ...withBaseDetails(e.details),
              manifestName: name,
              manifestUrl: url,
              fallbackAttempted: false,
              fallbackReason: "manifest_present_but_unusable"
            };
            throw e;
          }

          // Missing keys / invalid shape / missing sha256: treat as malformed and deterministically fall back.
          const message = `Manifest unusable (${name}): ${e.code} ${e.message}`;
          errors.push(`[DOCDEX_MANIFEST_UNUSABLE] ${message}`);
          events.push({
            code: "DOCDEX_MANIFEST_UNUSABLE",
            message,
            details: {
              manifestName: name,
              url,
              targetTriple,
              manifestErrorCode: e.code,
              manifestErrorMessage: e.message
            }
          });
          continue;
        }
        throw e;
      }
    } catch (e) {
      if (e instanceof ManifestResolutionError) throw e;
      // 404 => "missing manifest" candidate; try next. Anything else is recorded and we still try next.
      if (e && typeof e.statusCode === "number" && e.statusCode === 404) {
        events.push({
          code: "DOCDEX_MANIFEST_NOT_FOUND",
          message: `Manifest candidate not found (${name})`,
          details: { manifestName: name, url, targetTriple, statusCode: 404 }
        });
        continue;
      }

      if (e && e.code === "DOCDEX_DOWNLOAD_TOO_LARGE") {
        const message = `Manifest too large (${name}): exceeded ${e.maxBytes} bytes`;
        errors.push(`[DOCDEX_MANIFEST_TOO_LARGE] ${message}`);
        events.push({
          code: "DOCDEX_MANIFEST_TOO_LARGE",
          message,
          details: { manifestName: name, url, targetTriple, maxBytes: e.maxBytes, actualBytes: e.actualBytes }
        });
        continue;
      }

      const message = `Failed to fetch manifest (${name}): ${e.message}`;
      errors.push(`[DOCDEX_MANIFEST_FETCH_FAILED] ${message}`);
      events.push({
        code: "DOCDEX_MANIFEST_FETCH_FAILED",
        message,
        details: {
          manifestName: name,
          url,
          targetTriple,
          statusCode: typeof e?.statusCode === "number" ? e.statusCode : null
        }
      });
      continue;
    }
  }

  if (candidates.length) {
    events.push({
      code: "DOCDEX_FALLBACK_USED",
      message: "No usable manifest candidate; falling back to deterministic asset naming",
      details: { targetTriple, manifestCandidates: candidates.slice() }
    });
  }

  return { manifestName: null, resolved: null, errors, events, attempted: true };
}

async function resolveInstallerDownloadPlan({
  repoSlug,
  version,
  platformKey,
  targetTriple,
  logger = console,
  downloadTextFn = downloadText,
  artifactNameFn = artifactName,
  getDownloadBaseFn = getDownloadBase,
  manifestCandidateNamesFn = manifestCandidateNames,
  checksumCandidateNamesFn = checksumCandidateNames
}) {
  let archive = null;
  let expectedSha256 = null;
  let source = "fallback";

  let manifestAttempt;
  try {
    manifestAttempt = await tryResolveAssetViaManifest({
      repoSlug,
      version,
      targetTriple,
      downloadTextFn,
      getDownloadBaseFn,
      manifestCandidateNamesFn
    });
  } catch (err) {
    if (err instanceof ManifestResolutionError) {
      const expectedAsset = artifactNameFn(platformKey);
      err.details = {
        ...withBaseDetails(err.details),
        platformKey,
        expectedAsset,
        expectedAssetPattern: assetPatternForPlatformKey(platformKey, { exampleAssetName: expectedAsset })
      };
    }
    throw err;
  }

  if (manifestAttempt.resolved) {
    archive = manifestAttempt.resolved.asset.name;
    expectedSha256 = manifestAttempt.resolved.integrity.sha256;
    source = `manifest:${manifestAttempt.manifestName}`;
  } else if (manifestAttempt.errors && manifestAttempt.errors.length) {
    logger.warn(`[docdex] Manifest unavailable; falling back. Details: ${manifestAttempt.errors.join(" | ")}`);
  } else {
    logger.log("[docdex] No manifest found; falling back to deterministic asset naming.");
  }

  if (!archive) {
    archive = artifactNameFn(platformKey);

    const checksumAttempt = await tryResolveSha256ViaChecksumFiles({
      repoSlug,
      version,
      archive,
      downloadTextFn,
      getDownloadBaseFn,
      checksumCandidateNamesFn
    });

    if (checksumAttempt.sha256) {
      expectedSha256 = checksumAttempt.sha256;
    } else {
      // Legacy fallback: per-asset .sha256 sidecar.
      const shaUrl = `${getDownloadBaseFn(repoSlug)}/v${version}/${archive}.sha256`;
      try {
        const shaText = await downloadTextFn(shaUrl);
        expectedSha256 = parseSha256File(shaText, archive);
      } catch {
        expectedSha256 = null;
      }
    }

    if (!expectedSha256) {
      const manifestCandidates = manifestCandidateNamesFn();
      const checksumCandidates = checksumCandidateNamesFn();
      throw new ChecksumResolutionError(
        `Missing SHA-256 integrity metadata for ${archive} (tried manifest ${manifestCandidates.join(
          ", "
        )} and checksums ${checksumCandidates.join(", ")})`,
        {
          platformKey,
          targetTriple,
          version,
          repoSlug,
          assetName: archive,
          source: "fallback",
          manifestName: manifestAttempt?.manifestName ?? null,
          manifestVersion: manifestAttempt?.resolved?.manifestVersion ?? null,
          fallbackAttempted: true,
          fallbackReason: manifestAttempt?.errors?.length ? "manifest_unavailable" : "manifest_not_found",
          checksumCandidates,
          checksumErrors: checksumAttempt?.errors ?? null,
          checksumEvents: checksumAttempt?.events ?? null
        }
      );
    }
  }

  return {
    archive,
    expectedSha256,
    source,
    manifestAttempt: { ...manifestAttempt, fallbackAttempted: !manifestAttempt.resolved }
  };
}

async function verifyDownloadedFileIntegrity({
  filePath,
  expectedSha256,
  archiveName,
  sha256FileFn = sha256File,
  details
}) {
  if (!expectedSha256) return null;
  const actual = await sha256FileFn(filePath);
  if (actual.toLowerCase() !== expectedSha256.toLowerCase()) {
    throw new IntegrityMismatchError(archiveName, expectedSha256, actual, details);
  }
  return actual;
}

async function runInstaller(options) {
  const opts = options || {};
  const logger = opts.logger || console;

  const detectPlatformKeyFn = opts.detectPlatformKeyFn || detectPlatformKey;
  const targetTripleForPlatformKeyFn = opts.targetTripleForPlatformKeyFn || targetTripleForPlatformKey;
  const getVersionFn = opts.getVersionFn || getVersion;
  const parseRepoSlugFn = opts.parseRepoSlugFn || parseRepoSlug;
  const resolveInstallerDownloadPlanFn = opts.resolveInstallerDownloadPlanFn || resolveInstallerDownloadPlan;
  const getDownloadBaseFn = opts.getDownloadBaseFn || getDownloadBase;
  const downloadFn = opts.downloadFn || download;
  const verifyDownloadedFileIntegrityFn = opts.verifyDownloadedFileIntegrityFn || verifyDownloadedFileIntegrity;
  const extractTarballFn = opts.extractTarballFn || extractTarball;
  const fsModule = opts.fsModule || fs;
  const pathModule = opts.pathModule || path;
  const osModule = opts.osModule || os;
  const artifactNameFn = opts.artifactNameFn || artifactName;
  const assetPatternForPlatformKeyFn = opts.assetPatternForPlatformKeyFn || assetPatternForPlatformKey;
  const sha256FileFn = opts.sha256FileFn || sha256File;

  const detectedPlatform = opts.platform || process.platform;
  const detectedArch = opts.arch || process.arch;

  const resolvePlatformPolicyFn =
    opts.resolvePlatformPolicyFn ||
    (opts.detectPlatformKeyFn || opts.targetTripleForPlatformKeyFn
      ? () => {
          const platformKey = detectPlatformKeyFn();
          const targetTriple = targetTripleForPlatformKeyFn(platformKey);
          const expectedAssetName = artifactNameFn(platformKey);
          const expectedAssetPattern = assetPatternForPlatformKeyFn(platformKey, {
            exampleAssetName: expectedAssetName
          });
          return {
            detected: { platform: detectedPlatform, arch: detectedArch },
            platformKey,
            targetTriple,
            expectedAssetName,
            expectedAssetPattern
          };
        }
      : resolvePlatformPolicy);

  const platformPolicy = resolvePlatformPolicyFn({
    platform: detectedPlatform,
    arch: detectedArch,
    env: opts.env,
    report: opts.report,
    execPath: opts.execPath
  });

  const platformKey = platformPolicy.platformKey;
  const targetTriple = platformPolicy.targetTriple;
  const version = getVersionFn();
  const distBaseDir = opts.distBaseDir || pathModule.join(__dirname, "..", "dist");
  const distDir = pathModule.join(distBaseDir, platformKey);
  const isWin32 = detectedPlatform === "win32";

  const local = await determineLocalInstallerOutcome({
    fsModule,
    pathModule,
    distDir,
    platformKey,
    expectedVersion: version,
    isWin32,
    sha256FileFn
  });

  if (local.outcome === "no-op") {
    logger.log("[docdex] Install outcome: no-op");
    return { binaryPath: local.binaryPath, outcome: local.outcome, integrityResult: local.integrityResult };
  }

  const repoSlug = parseRepoSlugFn();

  const { archive, expectedSha256, source, manifestAttempt } = await resolveInstallerDownloadPlanFn({
    repoSlug,
    version,
    platformKey,
    targetTriple,
    logger
  });

  const downloadUrl = `${getDownloadBaseFn(repoSlug)}/v${version}/${archive}`;
  const tmpDir = opts.tmpDir || osModule.tmpdir();
  const tmpFile = pathModule.join(tmpDir, `${archive}.${process.pid}.tgz`);
  const stagingDir = pathModule.join(distBaseDir, `${platformKey}.staging.${process.pid}`);

  logger.log(`[docdex] Fetching ${archive} for ${platformKey} (${targetTriple}) via ${source}...`);
  try {
    try {
      await downloadFn(downloadUrl, tmpFile);
    } catch (err) {
      if (err && typeof err.statusCode === "number" && err.statusCode === 404) {
        const fallbackReason = manifestAttempt?.errors?.length ? "manifest_unavailable" : "manifest_not_found";
        throw new MissingArtifactError({
          detected: { os: detectedPlatform, arch: detectedArch },
          platformKey,
          targetTriple,
          assetName: archive,
          source,
          manifestName: manifestAttempt?.manifestName ?? null,
          manifestVersion: manifestAttempt?.resolved?.manifestVersion ?? null,
          fallbackAttempted: source === "fallback",
          fallbackReason,
          version,
          repoSlug,
          downloadUrl,
          expectedAsset: archive,
          expectedAssetPattern: assetPatternForPlatformKeyFn(platformKey, { exampleAssetName: archive }),
          note: "This usually means the GitHub release assets are missing or the npm version is out of sync with the release."
        });
      }
      throw new DownloadError(
        `Download failed for ${archive}`,
        {
          platformKey,
          targetTriple,
          version,
          repoSlug,
          assetName: archive,
          downloadUrl,
          source,
          manifestName: manifestAttempt?.manifestName ?? null,
          manifestVersion: manifestAttempt?.resolved?.manifestVersion ?? null,
          fallbackAttempted: source === "fallback",
          statusCode: typeof err?.statusCode === "number" ? err.statusCode : null
        },
        err
      );
    }

    await verifyDownloadedFileIntegrityFn({
      filePath: tmpFile,
      expectedSha256,
      archiveName: archive,
      details: {
        platformKey,
        targetTriple,
        version,
        repoSlug,
        downloadUrl,
        source,
        manifestName: manifestAttempt?.manifestName ?? null,
        manifestVersion: manifestAttempt?.resolved?.manifestVersion ?? null,
        fallbackAttempted: source === "fallback"
      }
    });

    // Only replace an existing installation after we have successfully fetched + verified the archive.
    // Extract into a staging directory first so failures never clobber a working install.
    await fsModule.promises.rm(stagingDir, { recursive: true, force: true });
    await extractTarballFn(tmpFile, stagingDir);

    const stagingBinaryPath = pathModule.join(stagingDir, isWin32 ? "docdexd.exe" : "docdexd");
    if (!fsModule.existsSync(stagingBinaryPath)) {
      throw new ArchiveInvalidError(`Downloaded archive missing binary at ${stagingBinaryPath}`, {
        platformKey,
        targetTriple,
        version,
        repoSlug,
        assetName: archive,
        downloadUrl,
        source,
        manifestName: manifestAttempt?.manifestName ?? null,
        manifestVersion: manifestAttempt?.resolved?.manifestVersion ?? null,
        fallbackAttempted: source === "fallback",
        binaryPath: stagingBinaryPath
      });
    }

    await fsModule.promises.chmod(stagingBinaryPath, 0o755).catch(() => {});
    const binarySha256 = await sha256FileFn(stagingBinaryPath);
    const metadata = {
      schemaVersion: INSTALL_METADATA_SCHEMA_VERSION,
      installedAt: nowIso(),
      version,
      repoSlug,
      platformKey,
      targetTriple,
      binary: {
        filename: isWin32 ? "docdexd.exe" : "docdexd",
        sha256: binarySha256
      },
      archive: {
        name: archive,
        sha256: expectedSha256 || null,
        source,
        downloadUrl
      }
    };
    await writeJsonFileAtomic({
      fsModule,
      pathModule,
      filePath: installMetadataPath(stagingDir, pathModule),
      value: metadata
    });

    await fsModule.promises.rm(distDir, { recursive: true, force: true });
    await fsModule.promises.rename(stagingDir, distDir);

    const binaryPath = pathModule.join(distDir, isWin32 ? "docdexd.exe" : "docdexd");
    logger.log(`[docdex] Installed binary to ${binaryPath}`);
    logger.log(`[docdex] Install outcome: ${local.outcome}`);
    return { binaryPath, outcome: local.outcome };
  } finally {
    await fsModule.promises.rm(tmpFile, { force: true }).catch(() => {});
    await fsModule.promises.rm(stagingDir, { recursive: true, force: true }).catch(() => {});
  }
}

async function main() {
  await runInstaller();
}

function describeFatalError(err) {
  const fallbackAttempted =
    err && typeof err.details?.fallbackAttempted === "boolean" ? err.details.fallbackAttempted : null;

  if (err instanceof UnsupportedPlatformError) {
    const detected = `${err.details.platform}/${err.details.arch}`;
    const supportedKeys = (err.details.supportedPlatformKeys || []).join(", ");
    const supportedTriples = (err.details.supportedTargetTriples || []).join(", ");
    const libc = err.details?.libc ? String(err.details.libc) : null;
    const candidatePlatformKey =
      typeof err.details?.candidatePlatformKey === "string" ? err.details.candidatePlatformKey : null;
    const candidateTargetTriple =
      typeof err.details?.candidateTargetTriple === "string" ? err.details.candidateTargetTriple : null;
    const unpublished = err.details?.reason === "target_not_published";
    const candidateAssetPattern = candidatePlatformKey ? assetPatternForPlatformKey(candidatePlatformKey) : null;

    return {
      code: err.code,
      exitCode: err.exitCode || EXIT_CODE_BY_ERROR_CODE[err.code] || 1,
      details: withBaseDetails(err.details),
      lines: [
        `[docdex] install failed: unsupported platform (${detected})`,
        `[docdex] error code: ${err.code}`,
        "[docdex] No download was attempted for this platform.",
        libc ? `[docdex] Detected libc: ${libc}` : null,
        candidatePlatformKey ? `[docdex] Platform key: ${candidatePlatformKey}` : null,
        candidateTargetTriple ? `[docdex] Target triple: ${candidateTargetTriple}` : null,
        candidateAssetPattern ? `[docdex] Asset naming pattern: ${candidateAssetPattern}` : null,
        unpublished ? "[docdex] Note: this platform is recognized but no published binary is available yet." : null,
        supportedKeys ? `[docdex] Supported platforms: ${supportedKeys}` : null,
        supportedTriples ? `[docdex] Supported target triples: ${supportedTriples}` : null,
        "[docdex] Next steps:",
        "[docdex] - Use a supported platform (see list above).",
        "[docdex] - Or build from source (requires Rust): `cargo build --release --locked`.",
        "[docdex] - If you are on Linux and unsure of libc, set `DOCDEX_LIBC=gnu` or `DOCDEX_LIBC=musl`."
      ].filter(Boolean)
    };
  }

  if (err instanceof InstallerConfigError) {
    return {
      code: err.code,
      exitCode: err.exitCode || EXIT_CODE_BY_ERROR_CODE[err.code] || 1,
      details: withBaseDetails(err.details),
      lines: [
        `[docdex] install failed: ${err.message}`,
        `[docdex] error code: ${err.code}`,
        "[docdex] Next steps:",
        "[docdex] - Ensure you are installing a published npm package version (not a local folder missing metadata).",
        "[docdex] - If installing from a fork, set `DOCDEX_DOWNLOAD_REPO=<owner/repo>` to the repo that hosts the release assets."
      ]
    };
  }

  if (err instanceof MissingArtifactError) {
    const detected = err.details?.detected ? `${err.details.detected.os}/${err.details.detected.arch}` : null;
    const platformKey = typeof err.details?.platformKey === "string" ? err.details.platformKey : null;
    const expectedAsset =
      typeof err.details?.expectedAsset === "string" && err.details.expectedAsset.trim()
        ? err.details.expectedAsset.trim()
        : typeof err.details?.assetName === "string" && err.details.assetName.trim()
          ? err.details.assetName.trim()
          : null;
    const expectedAssetPattern =
      typeof err.details?.expectedAssetPattern === "string" && err.details.expectedAssetPattern.trim()
        ? err.details.expectedAssetPattern.trim()
        : assetPatternForPlatformKey(platformKey, { exampleAssetName: expectedAsset || undefined });
    return {
      code: err.code,
      exitCode: err.exitCode || EXIT_CODE_BY_ERROR_CODE[err.code] || 1,
      details: withBaseDetails(err.details),
      lines: [
        "[docdex] install failed: missing artifact/version sync issue (release asset not found)",
        `[docdex] error code: ${err.code}`,
        detected ? `[docdex] Detected platform: ${detected}` : null,
        err.details?.platformKey ? `[docdex] Platform key: ${err.details.platformKey}` : null,
        err.details?.targetTriple ? `[docdex] Expected target triple: ${err.details.targetTriple}` : null,
        err.details?.manifestName ? `[docdex] Manifest name: ${err.details.manifestName}` : null,
        err.details?.manifestVersion != null ? `[docdex] Manifest version: ${err.details.manifestVersion}` : null,
        fallbackAttempted != null ? `[docdex] Fallback attempted: ${fallbackAttempted}` : null,
        err.details?.fallbackReason ? `[docdex] Fallback reason: ${err.details.fallbackReason}` : null,
        err.details?.version ? `[docdex] Version: v${err.details.version}` : null,
        err.details?.repoSlug ? `[docdex] Download repo: ${err.details.repoSlug}` : null,
        err.details?.expectedAsset ? `[docdex] Expected asset: ${err.details.expectedAsset}` : null,
        expectedAssetPattern ? `[docdex] Asset naming pattern: ${expectedAssetPattern}` : null,
        err.details?.downloadUrl ? `[docdex] URL tried: ${err.details.downloadUrl}` : null,
        err.details?.note ? `[docdex] Note: ${err.details.note}` : null,
        "[docdex] Next steps:",
        "[docdex] - Confirm the GitHub Release for this version contains the expected asset for your target.",
        "[docdex] - If installing from a fork, set `DOCDEX_DOWNLOAD_REPO=<owner/repo>` to the repo that hosts the assets.",
        "[docdex] - Workaround: install a version with matching assets, or build from source (`cargo build --release --locked`)."
      ].filter(Boolean)
    };
  }

  if (err instanceof ChecksumResolutionError) {
    const checksumCandidates = Array.isArray(err.details?.checksumCandidates) ? err.details.checksumCandidates : [];
    return {
      code: err.code,
      exitCode: err.exitCode || EXIT_CODE_BY_ERROR_CODE[err.code] || 1,
      details: withBaseDetails(err.details),
      lines: [
        `[docdex] install failed: ${err.message}`,
        `[docdex] error code: ${err.code}`,
        "[docdex] Verification method: SHA-256 (archive bytes)",
        err.details?.assetName ? `[docdex] Asset: ${err.details.assetName}` : null,
        err.details?.targetTriple ? `[docdex] Expected target triple: ${err.details.targetTriple}` : null,
        err.details?.manifestName ? `[docdex] Manifest name: ${err.details.manifestName}` : null,
        err.details?.manifestVersion != null ? `[docdex] Manifest version: ${err.details.manifestVersion}` : null,
        checksumCandidates.length
          ? `[docdex] Checksum candidates tried: ${checksumCandidates.join(", ")}`
          : null,
        err.details?.fallbackReason ? `[docdex] Fallback reason: ${err.details.fallbackReason}` : null,
        "[docdex] Next steps:",
        "[docdex] - Ensure the GitHub Release includes `docdex-release-manifest.json` or `SHA256SUMS` with a line for this asset.",
        "[docdex] - If installing from a fork, set `DOCDEX_DOWNLOAD_REPO=<owner/repo>` to the repo that hosts the release assets.",
        "[docdex] - If you cannot publish checksums, build from source (`cargo build --release --locked`)."
      ].filter(Boolean)
    };
  }

  if (err instanceof DownloadError) {
    return {
      code: err.code,
      exitCode: err.exitCode || EXIT_CODE_BY_ERROR_CODE[err.code] || 1,
      details: withBaseDetails(err.details),
      lines: [
        `[docdex] install failed: ${err.message}`,
        `[docdex] error code: ${err.code}`,
        err.details?.downloadUrl ? `[docdex] URL tried: ${err.details.downloadUrl}` : null,
        err.details?.statusCode != null ? `[docdex] HTTP status: ${err.details.statusCode}` : null,
        err.cause?.message ? `[docdex] Cause: ${err.cause.message}` : null
      ].filter(Boolean)
    };
  }

  if (err instanceof IntegrityMismatchError) {
    const expectedSha256 = typeof err.details?.expectedSha256 === "string" ? err.details.expectedSha256 : null;
    const actualSha256 = typeof err.details?.actualSha256 === "string" ? err.details.actualSha256 : null;
    return {
      code: err.code,
      exitCode: err.exitCode || EXIT_CODE_BY_ERROR_CODE[err.code] || 1,
      details: withBaseDetails(err.details),
      lines: [
        `[docdex] install failed: ${err.message}`,
        `[docdex] error code: ${err.code}`,
        "[docdex] Verification method: SHA-256 (archive bytes)",
        err.details?.assetName ? `[docdex] Asset: ${err.details.assetName}` : null,
        err.details?.downloadUrl ? `[docdex] URL tried: ${err.details.downloadUrl}` : null,
        expectedSha256 ? `[docdex] Expected sha256: ${expectedSha256}` : null,
        actualSha256 ? `[docdex] Actual sha256:   ${actualSha256}` : null,
        err.details?.source ? `[docdex] Source: ${err.details.source}` : null,
        err.details?.manifestName ? `[docdex] Manifest name: ${err.details.manifestName}` : null,
        err.details?.manifestVersion != null ? `[docdex] Manifest version: ${err.details.manifestVersion}` : null,
        fallbackAttempted != null ? `[docdex] Fallback attempted: ${fallbackAttempted}` : null,
        "[docdex] Next steps:",
        "[docdex] - Re-run the install; transient network/caching issues can corrupt downloads.",
        "[docdex] - Ensure you are installing from the intended repo/version (DOCDEX_DOWNLOAD_REPO, DOCDEX_VERSION).",
        "[docdex] - If behind a proxy or cache, bypass it; integrity mismatches can indicate tampering.",
        "[docdex] - If it still fails, build from source (`cargo build --release --locked`)."
      ].filter(Boolean)
    };
  }

  if (err instanceof ArchiveInvalidError) {
    return {
      code: err.code,
      exitCode: err.exitCode || EXIT_CODE_BY_ERROR_CODE[err.code] || 1,
      details: withBaseDetails(err.details),
      lines: [
        `[docdex] install failed: ${err.message}`,
        `[docdex] error code: ${err.code}`,
        err.details?.binaryPath ? `[docdex] Expected binary path: ${err.details.binaryPath}` : null
      ].filter(Boolean)
    };
  }

  if (err instanceof ManifestResolutionError) {
    const platformKey = typeof err.details?.platformKey === "string" ? err.details.platformKey : null;
    const expectedAssetPattern =
      typeof err.details?.expectedAssetPattern === "string"
        ? err.details.expectedAssetPattern
        : platformKey
          ? assetPatternForPlatformKey(platformKey)
          : assetPatternForPlatformKey(null);

    const lines =
      err.code === "DOCDEX_ASSET_NO_MATCH"
        ? [
            "[docdex] install failed: missing artifact/version sync issue (manifest has no asset for this target)",
            `[docdex] error code: ${err.code}`,
            err.details?.targetTriple ? `[docdex] Expected target triple: ${err.details.targetTriple}` : null,
            `[docdex] Asset naming pattern: ${expectedAssetPattern}`,
            `[docdex] Details: ${err.message}`
          ].filter(Boolean)
        : [`[docdex] install failed: ${err.message}`, `[docdex] error code: ${err.code}`];

    if (fallbackAttempted === false) {
      lines.push("[docdex] Fallback was not attempted because a manifest was present but unusable.");
    }
    if (Array.isArray(err.details?.supported) && err.details.supported.length) {
      lines.push(`[docdex] supported targets: ${err.details.supported.join(", ")}`);
    }
    if (Array.isArray(err.details?.matches) && err.details.matches.length) {
      lines.push(`[docdex] matched assets: ${err.details.matches.join(", ")}`);
    }
    return {
      code: err.code,
      exitCode: err.exitCode || EXIT_CODE_BY_ERROR_CODE[err.code] || 1,
      details: withBaseDetails(err.details),
      lines
    };
  }

  const code = (err && typeof err.code === "string" && err.code) || "DOCDEX_INSTALL_FAILED";
  return {
    code,
    exitCode: (err && typeof err.exitCode === "number" && err.exitCode) || EXIT_CODE_BY_ERROR_CODE[code] || 1,
    details: withBaseDetails(err && err.details),
    lines: [`[docdex] install failed: ${err?.message || "unknown error"}`, `[docdex] error code: ${code}`]
  };
}

function handleFatal(err) {
  const report = describeFatalError(err);
  for (const line of report.lines) console.error(line);
  process.exit(report.exitCode || 1);
}

if (require.main === module) {
  main().catch(handleFatal);
}

module.exports = {
  checksumCandidateNames,
  manifestCandidateNames,
  tryResolveAssetViaManifest,
  tryResolveSha256ViaChecksumFiles,
  resolveInstallerDownloadPlan,
  parseSha256File,
  sha256File,
  verifyInstalledDocdexdIntegrity,
  decideInstallAction,
  determineLocalInstallerOutcome,
  verifyDownloadedFileIntegrity,
  MissingArtifactError,
  ChecksumResolutionError,
  runInstaller,
  describeFatalError,
  handleFatal
};
