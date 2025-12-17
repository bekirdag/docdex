#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const https = require("node:https");
const os = require("node:os");
const path = require("node:path");
const { pipeline } = require("node:stream/promises");
const crypto = require("node:crypto");
<<<<<<< HEAD
<<<<<<< HEAD
const util = require("node:util");
=======
const { execFile } = require("node:child_process");
>>>>>>> mcoda/task/ops-01-us-06-t41
=======
const childProcess = require("node:child_process");
>>>>>>> mcoda/task/ops-01-us-06-t20

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
const INSTALL_METADATA_SCHEMA_VERSION = 2;
const INSTALL_METADATA_FILENAME = "docdexd-install.json";
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
const INSTALL_OUTCOME_SCHEMA_VERSION = 1;

const INSTALL_OUTCOME_CODE_BY_DECISION_OUTCOME = Object.freeze({
  "no-op": "skipped_noop",
  // Back-compat alias: some earlier design docs used `no_op`.
  no_op: "skipped_noop",
  update: "updated",
  repair: "repaired",
  reinstall_unknown: "reinstalled_unknown"
});
=======
const INSTALL_STATE_DIRNAME = "daemon";
const DEFAULT_STATE_ROOT_RELATIVE = [".docdex", "state"];
>>>>>>> mcoda/task/ops-01-us-06-t45
=======
const INSTALL_EVENT_SCHEMA_VERSION = 1;
const INSTALL_EVENT_PREFIX = "[docdex] event ";

function normalizeOutcomeCode(outcome) {
  // Stable support-facing outcome codes (ops-01-us-06-t15).
  if (outcome === "no-op") return "noop";
  if (outcome === "repair") return "repair";
  // Includes: "update", "reinstall_unknown", and any future non-noop actions.
  return "replace";
}

function emitInstallerEvent({ logger, level = "info", code, message, details }) {
  const sink =
    level === "error"
      ? logger?.error || logger?.log || console.error
      : level === "warn"
        ? logger?.warn || logger?.log || console.warn
        : logger?.log || console.log;

  const payload = {
    schemaVersion: INSTALL_EVENT_SCHEMA_VERSION,
    ts: nowIso(),
    level,
    code,
    message: message || null,
    details: details || null
  };

  // Keep the human-facing prefix stable while allowing machine parsing via JSON.
  try {
    sink(`${INSTALL_EVENT_PREFIX}${JSON.stringify(payload)}`);
  } catch (_err) {
    // Never fail installs due to logging/telemetry serialization issues.
  }
}

function summarizeIntegrityResult(integrityResult) {
  if (!integrityResult || typeof integrityResult !== "object") return null;
  return {
    status: typeof integrityResult.status === "string" ? integrityResult.status : null,
    reason: typeof integrityResult.reason === "string" ? integrityResult.reason : null,
    expectedSource: typeof integrityResult.expectedSource === "string" ? integrityResult.expectedSource : null,
    expectedSha256: typeof integrityResult.expectedSha256 === "string" ? integrityResult.expectedSha256 : null,
    actualSha256: typeof integrityResult.actualSha256 === "string" ? integrityResult.actualSha256 : null,
    error: typeof integrityResult.error === "string" ? integrityResult.error : null
  };
}
>>>>>>> mcoda/task/ops-01-us-06-t15
=======
const INSTALL_ATTEMPT_SCHEMA_VERSION = 1;
>>>>>>> mcoda/task/ops-01-us-05-t39
=======
const INSTALL_STAGING_SUFFIX = ".__docdexd_install_staging";
const INSTALL_BACKUP_SUFFIX = ".__docdexd_install_backup";
>>>>>>> mcoda/task/ops-01-us-05-t05

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

function createNoopLogger() {
  return {
    log: () => {},
    warn: () => {},
    error: () => {}
  };
}

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

function requestOptionsWithExtras(extras) {
  const base = requestOptions();
  if (!extras || typeof extras !== "object") return base;
  return { ...base, ...extras };
}

function downloadText(url, redirects = 0, opts = {}) {
  if (redirects > MAX_REDIRECTS) {
    throw new Error(`Too many redirects while fetching ${url}`);
  }

  return new Promise((resolve, reject) => {
    https
      .get(url, requestOptionsWithExtras({ signal: opts.signal }), (res) => {
        if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          res.resume();
          return downloadText(res.headers.location, redirects + 1, opts).then(resolve, reject);
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

function download(url, dest, redirects = 0, opts = {}) {
  if (redirects > MAX_REDIRECTS) {
    throw new Error(`Too many redirects while fetching ${url}`);
  }

  return new Promise((resolve, reject) => {
    https
      .get(url, requestOptionsWithExtras({ signal: opts.signal }), (res) => {
        if (res.statusCode && res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          res.resume();
          return download(res.headers.location, dest, redirects + 1, opts).then(resolve, reject);
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
  // Security: do not preserve executable bits from the archive while staging.
  await tar.x({ file: archivePath, cwd: targetDir, gzip: true, noChmod: true });
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

<<<<<<< HEAD
function resolveInstallerStateRootDir({ osModule, pathModule, env }) {
  const override =
    typeof env?.DOCDEX_INSTALL_STATE_DIR === "string" && env.DOCDEX_INSTALL_STATE_DIR.trim()
      ? env.DOCDEX_INSTALL_STATE_DIR.trim()
      : null;

  const homeDir = typeof osModule?.homedir === "function" ? osModule.homedir() : null;
  const base = override || (homeDir ? pathModule.join(homeDir, ...DEFAULT_STATE_ROOT_RELATIVE) : null);
  if (!base) {
    const err = new InstallerConfigError("Unable to resolve a writable install state directory", {
      repoSlug: null
    });
    err.code = "DOCDEX_INSTALLER_CONFIG";
    throw err;
  }
  return pathModule.resolve(base);
}

function resolveInstallerInstallDir({ stateRootDir, platformKey, pathModule }) {
  return pathModule.join(stateRootDir, INSTALL_STATE_DIRNAME, platformKey);
=======
function installSwapDirs(distDir) {
  return {
    stagingDir: `${distDir}${INSTALL_STAGING_SUFFIX}`,
    backupDir: `${distDir}${INSTALL_BACKUP_SUFFIX}`
  };
}

function binaryPathInDir({ pathModule, dirPath, isWin32 }) {
  return pathModule.join(dirPath, isWin32 ? "docdexd.exe" : "docdexd");
>>>>>>> mcoda/task/ops-01-us-05-t05
}

function nowIso() {
  return new Date().toISOString();
}

<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
function normalizeInstallerOutputFormat(raw) {
  const value = String(raw || "")
    .trim()
    .toLowerCase();
  if (value === "json") return "json";
  return "text";
}

function installOutcomeCodeForDecisionOutcome(decisionOutcome) {
  if (typeof decisionOutcome !== "string") return "reinstalled_unknown";
  return INSTALL_OUTCOME_CODE_BY_DECISION_OUTCOME[decisionOutcome] || "reinstalled_unknown";
}

function isNoopDecisionOutcome(decisionOutcome) {
  return decisionOutcome === "no-op" || decisionOutcome === "no_op";
}

function buildInstallOutcomeMessage({ code, decisionReason, expectedVersion, installedVersion }) {
  const expected = expectedVersion ? `v${expectedVersion}` : "the expected version";
  const installed = installedVersion ? `v${installedVersion}` : null;

  switch (code) {
    case "skipped_noop":
      return `docdexd ${expected} is already installed and verified; skipping download.`;
    case "updated":
      if (decisionReason === "binary_missing") return `installed docdexd ${expected}.`;
      if (installed) return `updated docdexd to ${expected} (was ${installed}).`;
      return `updated docdexd to ${expected}.`;
    case "repaired":
      return `repaired docdexd ${expected} by replacing a binary that failed integrity verification.`;
    case "reinstalled_unknown":
    default: {
      const reason = decisionReason ? ` (${decisionReason})` : "";
      return `reinstalled docdexd ${expected} because the prior state could not be verified deterministically${reason}.`;
    }
  }
}

function buildInstallOutcomeReport({
  decision,
  expectedVersion,
  platformKey,
  targetTriple,
  repoSlug,
  archive,
  downloadUrl,
  source
}) {
  const legacyOutcome = decision?.outcome || null;
  const decisionReason = decision?.reason || null;
  const code = installOutcomeCodeForDecisionOutcome(legacyOutcome);
  const message = buildInstallOutcomeMessage({
    code,
    decisionReason,
    expectedVersion,
    installedVersion: decision?.installedVersion || null
  });

  return {
    schemaVersion: INSTALL_OUTCOME_SCHEMA_VERSION,
    kind: "docdex_installer_outcome",
    timestamp: nowIso(),
    code,
    message,
    legacyOutcome,
    decisionReason,
    expectedVersion: expectedVersion || null,
    installedVersion: decision?.installedVersion ?? null,
    platformKey: platformKey || null,
    targetTriple: targetTriple || null,
    repoSlug: repoSlug || null,
    binaryPath: decision?.binaryPath || null,
    metadataPath: decision?.metadataPath || null,
    downloaded: isNoopDecisionOutcome(legacyOutcome) ? false : true,
    archive: archive || null,
    downloadUrl: downloadUrl || null,
    source: source || null
  };
}

function emitInstallOutcomeReport(report, { logger, outputFormat }) {
  const format = normalizeInstallerOutputFormat(outputFormat);
  if (format === "json") {
    logger.log(JSON.stringify(report));
    return;
  }

  if (report.legacyOutcome) logger.log(`[docdex] Install outcome: ${report.legacyOutcome}`);
  logger.log(`[docdex] Install outcome code: ${report.code}`);
  logger.log(`[docdex] ${report.message}`);
=======
function computeCanonicalSourceUriForPlatform({
  repoSlug,
  expectedVersion,
  platformKey,
  getDownloadBaseFn,
  artifactNameFn
}) {
  if (typeof repoSlug !== "string" || !repoSlug.trim()) return null;
  try {
    const base = getDownloadBaseFn(repoSlug);
    if (typeof base !== "string" || !base.trim()) return null;
    const archive = artifactNameFn(platformKey);
    if (typeof archive !== "string" || !archive.trim()) return null;
    return `${base}/v${expectedVersion}/${archive}`;
=======
function uniqueSuffix() {
  return `${process.pid}.${Date.now()}`;
}

function envRestartCommand(env = process.env) {
  const value = env.DOCDEXD_RESTART_CMD || env.DOCDEX_RESTART_CMD;
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

async function restartDaemonIfConfigured({ logger, env = process.env } = {}) {
  const cmd = envRestartCommand(env);
  if (!cmd) {
    return { attempted: false, status: "skipped", reason: "no_restart_cmd" };
  }

  const child = childProcess.spawn(cmd, {
    shell: true,
    stdio: "inherit"
  });

  const exitCode = await new Promise((resolve, reject) => {
    child.on("error", reject);
    child.on("exit", (code) => resolve(typeof code === "number" ? code : 1));
  });

  if (exitCode !== 0) {
    const message = `Restart command failed (exit ${exitCode}): ${cmd}`;
    if (logger?.warn) logger.warn(`[docdex] ${message}`);
    return { attempted: true, status: "failed", reason: "restart_cmd_failed", exitCode, cmd };
  }

  if (logger?.log) logger.log(`[docdex] Restart command succeeded: ${cmd}`);
  return { attempted: true, status: "ok", reason: "restart_cmd_ok", exitCode, cmd };
}

async function tryStatMode({ fsModule, filePath }) {
  try {
    const stat = await fsModule.promises.stat(filePath);
    if (!stat || typeof stat.mode !== "number") return null;
    return stat.mode & 0o777;
>>>>>>> mcoda/task/ops-01-us-06-t20
  } catch {
    return null;
  }
}

<<<<<<< HEAD
function applyNoopInstallMetadataBackfill({
  meta,
  expectedVersion,
  platformKey,
  targetTriple,
  isWin32,
  integrityResult,
  getDownloadBaseFn,
  artifactNameFn
}) {
  let changed = false;

  const expectedBinaryFilename = isWin32 ? "docdexd.exe" : "docdexd";

  if (typeof meta.installedAt !== "string" || !meta.installedAt) {
    meta.installedAt = nowIso();
    changed = true;
  }

  if (typeof meta.expectedVersion !== "string" || !meta.expectedVersion) {
    meta.expectedVersion = expectedVersion;
    changed = true;
  }

  if (typeof meta.installedVersion !== "string" || !meta.installedVersion) {
    meta.installedVersion = typeof meta.version === "string" && meta.version ? meta.version : expectedVersion;
    changed = true;
  }

  if (typeof meta.targetTriple !== "string" || !meta.targetTriple) {
    meta.targetTriple = targetTriple;
    changed = true;
  }

  if (!meta.binary || typeof meta.binary !== "object") {
    meta.binary = {};
    changed = true;
  }

  if (typeof meta.binary.filename !== "string" || !meta.binary.filename) {
    meta.binary.filename = expectedBinaryFilename;
    changed = true;
  }

  if (integrityResult?.status === "verified_ok") {
    const actualSha256 = normalizeSha256Hex(integrityResult.actualSha256);
    if (actualSha256 && meta.binary.sha256 !== actualSha256) {
      meta.binary.sha256 = actualSha256;
      changed = true;
    }
  }

  if (typeof meta.lastOutcome !== "string" || !meta.lastOutcome) {
    meta.lastOutcome = "no-op";
    changed = true;
  }

  if (typeof meta.lastOutcomeReason !== "string" || !meta.lastOutcomeReason) {
    meta.lastOutcomeReason = "verified";
    changed = true;
  }

  if (typeof meta.lastOutcomeAt !== "string" || !meta.lastOutcomeAt) {
    meta.lastOutcomeAt = meta.installedAt;
    changed = true;
  }

  if (!meta.archive || typeof meta.archive !== "object") {
    meta.archive = {};
    changed = true;
  }

  const candidateSourceUri =
    (typeof meta.sourceUri === "string" && meta.sourceUri.trim() ? meta.sourceUri.trim() : null) ||
    (typeof meta.archive.downloadUrl === "string" && meta.archive.downloadUrl.trim()
      ? meta.archive.downloadUrl.trim()
      : null) ||
    computeCanonicalSourceUriForPlatform({
      repoSlug: meta.repoSlug,
      expectedVersion,
      platformKey,
      getDownloadBaseFn,
      artifactNameFn
    });

  if (candidateSourceUri && (typeof meta.sourceUri !== "string" || !meta.sourceUri.trim())) {
    meta.sourceUri = candidateSourceUri;
    changed = true;
  }

  const candidateArchiveName =
    (typeof meta.archive.name === "string" && meta.archive.name.trim() ? meta.archive.name.trim() : null) ||
    (typeof meta.sourceUri === "string" && meta.sourceUri.trim() ? meta.sourceUri.trim().split("/").pop() : null) ||
    (typeof meta.binary.filename === "string" && meta.binary.filename
      ? artifactNameFn(platformKey)
      : artifactNameFn(platformKey));

  if (candidateArchiveName && (typeof meta.archive.name !== "string" || !meta.archive.name.trim())) {
    meta.archive.name = candidateArchiveName;
    changed = true;
  }

  if (
    candidateSourceUri &&
    (typeof meta.archive.downloadUrl !== "string" || !meta.archive.downloadUrl.trim())
  ) {
    meta.archive.downloadUrl = candidateSourceUri;
    changed = true;
  }

  return changed;
>>>>>>> mcoda/task/ops-01-us-06-t29
=======
function applyExecuteBitsIfMissing(mode) {
  if (typeof mode !== "number") return null;
  // If no execute bits are set, fall back to a sane executable default.
  // This preserves permissions for typical installs while avoiding a non-executable daemon.
  if ((mode & 0o111) === 0) return 0o755;
  return mode;
}

async function installDocdexdBinaryAtomically({
  fsModule,
  pathModule,
  extractTarballFn,
  archivePath,
  distDir,
  isWin32,
  logger,
  errorDetails
}) {
  const filename = isWin32 ? "docdexd.exe" : "docdexd";
  const binaryPath = pathModule.join(distDir, filename);

  await fsModule.promises.mkdir(distDir, { recursive: true });

  const stageDir = pathModule.join(distDir, `.installing-${uniqueSuffix()}`);
  const incomingPath = pathModule.join(distDir, `${filename}.incoming-${uniqueSuffix()}`);
  const backupPath = pathModule.join(distDir, `${filename}.backup-${uniqueSuffix()}`);

  await fsModule.promises.rm(stageDir, { recursive: true, force: true }).catch(() => {});
  await fsModule.promises.rm(incomingPath, { force: true }).catch(() => {});
  await fsModule.promises.rm(backupPath, { force: true }).catch(() => {});

  try {
    await extractTarballFn(archivePath, stageDir);

    const extractedBinaryPath = pathModule.join(stageDir, filename);
    if (!fsModule.existsSync(extractedBinaryPath)) {
      throw new ArchiveInvalidError(`Downloaded archive missing binary at ${extractedBinaryPath}`, {
        ...(errorDetails || {}),
        binaryPath: extractedBinaryPath
      });
    }

    if (!isWin32) {
      const existingMode = await tryStatMode({ fsModule, filePath: binaryPath });
      const desiredMode = applyExecuteBitsIfMissing(existingMode ?? 0o755) ?? 0o755;
      await fsModule.promises.chmod(extractedBinaryPath, desiredMode).catch(() => {});
    }

    // Move the extracted binary into the dist dir first so subsequent renames stay within the same directory.
    await fsModule.promises.rename(extractedBinaryPath, incomingPath);

    const hadExisting = fsModule.existsSync(binaryPath);
    if (hadExisting) {
      await fsModule.promises.rename(binaryPath, backupPath);
    }

    try {
      await fsModule.promises.rename(incomingPath, binaryPath);
    } catch (err) {
      // Attempt rollback: restore previous binary if we moved it aside.
      if (hadExisting && fsModule.existsSync(backupPath) && !fsModule.existsSync(binaryPath)) {
        await fsModule.promises.rename(backupPath, binaryPath).catch(() => {});
      }
      throw err;
    }

    // Clean up the backup only after the new binary is in place.
    if (hadExisting) {
      await fsModule.promises.rm(backupPath, { force: true }).catch(() => {});
    }

    if (logger?.log) logger.log(`[docdex] Installed binary to ${binaryPath}`);
    return { binaryPath, replacedExisting: hadExisting };
  } finally {
    await fsModule.promises.rm(stageDir, { recursive: true, force: true }).catch(() => {});
    await fsModule.promises.rm(incomingPath, { force: true }).catch(() => {});
  }
>>>>>>> mcoda/task/ops-01-us-06-t20
=======
async function rmRf(fsModule, targetPath) {
  if (!targetPath) return;
  if (!fsModule?.promises?.rm) return;
  await fsModule.promises.rm(targetPath, { recursive: true, force: true }).catch(() => {});
}

async function rmFile(fsModule, targetPath) {
  if (!targetPath) return;
  if (!fsModule?.promises?.rm) return;
  await fsModule.promises.rm(targetPath, { force: true }).catch(() => {});
}

async function cleanupTransientInstallerArtifacts({ fsModule, pathModule, distBaseDir, platformKey, distDir }) {
  const existsSync = typeof fsModule?.existsSync === "function" ? fsModule.existsSync.bind(fsModule) : null;
  if (!existsSync || !existsSync(distBaseDir)) return;

  let entries = [];
  try {
    entries = await fsModule.promises.readdir(distBaseDir, { withFileTypes: true });
  } catch {
    return;
  }

  const stagingPrefix = `${platformKey}.staging.`;
  const backupPrefix = `${platformKey}.backup.`;
  const failedPrefix = `${platformKey}.failed.`;

  const stagingDirs = [];
  const backupDirs = [];
  const failedDirs = [];

  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    if (entry.name.startsWith(stagingPrefix)) stagingDirs.push(pathModule.join(distBaseDir, entry.name));
    if (entry.name.startsWith(failedPrefix)) failedDirs.push(pathModule.join(distBaseDir, entry.name));
    if (entry.name.startsWith(backupPrefix)) backupDirs.push(pathModule.join(distBaseDir, entry.name));
  }

  for (const dirPath of stagingDirs) await rmRf(fsModule, dirPath);
  for (const dirPath of failedDirs) await rmRf(fsModule, dirPath);

  if (!backupDirs.length) return;

  if (existsSync(distDir)) {
    for (const dirPath of backupDirs) await rmRf(fsModule, dirPath);
    return;
  }

  // If a previous install was interrupted mid-swap and the final dir is missing, restore one backup.
  backupDirs.sort().reverse();
  const candidate = backupDirs[0];
  try {
    await fsModule.promises.rename(candidate, distDir);
  } catch {
    // If restore fails, leave backups in place; a subsequent install may still succeed.
    return;
  }

  for (const dirPath of backupDirs.slice(1)) await rmRf(fsModule, dirPath);
>>>>>>> mcoda/task/ops-01-us-05-t37
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
  try {
    await fsModule.promises.rename(tmp, filePath);
  } catch (err) {
    const code = typeof err?.code === "string" ? err.code : null;
    if (code === "EEXIST" || code === "EPERM") {
      await fsModule.promises.rm(filePath, { force: true }).catch(() => {});
      await fsModule.promises.rename(tmp, filePath);
    } else {
      throw err;
    }
  } finally {
    await fsModule.promises.rm(tmp, { force: true }).catch(() => {});
  }
}

<<<<<<< HEAD
function isValidInstallMetadataV2(meta) {
=======
function isExecutableMode(mode) {
  if (typeof mode !== "number") return false;
  return (mode & 0o111) !== 0;
}

async function ensureExecutableBinary({ fsModule, binaryPath, isWin32 }) {
  if (isWin32) return;

  try {
    await fsModule.promises.chmod(binaryPath, 0o755);
  } catch {
    // Best-effort: fall through to stat-based verification.
  }

  const stat = await fsModule.promises.stat(binaryPath);
  if (!isExecutableMode(stat.mode)) {
    const err = new Error(`Installed binary is not executable: ${binaryPath}`);
    err.code = "DOCDEX_BINARY_NOT_EXECUTABLE";
    throw err;
  }
}

function createArchiveDetails({ platformKey, targetTriple, version, repoSlug, archiveName, downloadUrl, source, binaryPath }) {
  return {
    platformKey,
    targetTriple,
    version,
    repoSlug,
    assetName: archiveName,
    downloadUrl,
    source,
    fallbackAttempted: source === "fallback",
    binaryPath
  };
}

async function installVerifiedArchiveAtomically({
  fsModule,
  pathModule,
  logger,
  archivePath,
  distDir,
  platformKey,
  targetTriple,
  version,
  repoSlug,
  archiveName,
  expectedSha256,
  source,
  downloadUrl,
  manifestAttempt,
  isWin32,
  extractTarballFn,
  sha256FileFn
}) {
  const parentDir = pathModule.dirname(distDir);
  await fsModule.promises.mkdir(parentDir, { recursive: true });

  const stagingDir = await fsModule.promises.mkdtemp(`${distDir}.staging-`);
  const stagedBinaryPath = pathModule.join(stagingDir, isWin32 ? "docdexd.exe" : "docdexd");

  try {
    await extractTarballFn(archivePath, stagingDir);

    if (!fsModule.existsSync(stagedBinaryPath)) {
      throw new ArchiveInvalidError(`Downloaded archive missing binary at ${stagedBinaryPath}`, {
        ...createArchiveDetails({
          platformKey,
          targetTriple,
          version,
          repoSlug,
          archiveName,
          downloadUrl,
          source,
          binaryPath: stagedBinaryPath
        }),
        manifestName: manifestAttempt?.manifestName ?? null,
        manifestVersion: manifestAttempt?.resolved?.manifestVersion ?? null
      });
    }

    await ensureExecutableBinary({ fsModule, binaryPath: stagedBinaryPath, isWin32 });

    const binarySha256 = await sha256FileFn(stagedBinaryPath);
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
        name: archiveName,
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

    const backupDir = `${distDir}.backup.${process.pid}.${Date.now()}`;
    let movedExisting = false;

    try {
      if (fsModule.existsSync(distDir)) {
        await fsModule.promises.rename(distDir, backupDir);
        movedExisting = true;
      }

      await fsModule.promises.rename(stagingDir, distDir);

      if (movedExisting) {
        await fsModule.promises.rm(backupDir, { recursive: true, force: true }).catch((err) => {
          const msg = err?.message || String(err);
          if (logger && typeof logger.warn === "function") {
            logger.warn(`[docdex] Warning: failed to remove backup dir ${backupDir}: ${msg}`);
          }
        });
      }
    } catch (err) {
      if (movedExisting && fsModule.existsSync(backupDir) && !fsModule.existsSync(distDir)) {
        await fsModule.promises.rename(backupDir, distDir).catch(() => {});
      }
      await fsModule.promises.rm(stagingDir, { recursive: true, force: true }).catch(() => {});
      throw err;
    }

    const binaryPath = pathModule.join(distDir, isWin32 ? "docdexd.exe" : "docdexd");
    logger.log(`[docdex] Installed binary to ${binaryPath}`);
    return { binaryPath };
  } catch (err) {
    if (err && err.code === "DOCDEX_BINARY_NOT_EXECUTABLE") {
      await fsModule.promises.rm(stagingDir, { recursive: true, force: true }).catch(() => {});
      throw new ArchiveInvalidError(err.message, {
        ...createArchiveDetails({
          platformKey,
          targetTriple,
          version,
          repoSlug,
          archiveName,
          downloadUrl,
          source,
          binaryPath: stagedBinaryPath
        }),
        manifestName: manifestAttempt?.manifestName ?? null,
        manifestVersion: manifestAttempt?.resolved?.manifestVersion ?? null
      });
    }

    await fsModule.promises.rm(stagingDir, { recursive: true, force: true }).catch(() => {});
    throw err;
  }
}

async function cleanupInterruptedInstallArtifacts({ fsModule, pathModule, distBaseDir, distDir, platformKey, isWin32 }) {
  // Best-effort cleanup for artifacts from interrupted installs. This is intentionally narrow and only
  // removes files/dirs that match the installer’s own naming patterns within `dist/`.
  const cutoffMs = Date.now() - 10 * 60 * 1000;
  try {
    const entries = await fsModule.promises.readdir(distBaseDir, { withFileTypes: true });
    for (const ent of entries) {
      if (!ent.isDirectory()) continue;
      if (!ent.name.startsWith(`${platformKey}.staging.`)) continue;
      const fullPath = pathModule.join(distBaseDir, ent.name);
      const stat = await fsModule.promises.stat(fullPath).catch(() => null);
      if (stat && typeof stat.mtimeMs === "number" && stat.mtimeMs > cutoffMs) continue;
      await fsModule.promises.rm(fullPath, { recursive: true, force: true }).catch(() => {});
    }
  } catch (err) {
    if (err && err.code === "ENOENT") return;
  }

  try {
    const entries = await fsModule.promises.readdir(distDir, { withFileTypes: true });
    const expectedPrefix = `${isWin32 ? "docdexd.exe" : "docdexd"}.`;
    for (const ent of entries) {
      if (!ent.isFile()) continue;
      if (!ent.name.startsWith(expectedPrefix)) continue;
      if (!ent.name.endsWith(".new")) continue;
      const fullPath = pathModule.join(distDir, ent.name);
      const stat = await fsModule.promises.stat(fullPath).catch(() => null);
      if (stat && typeof stat.mtimeMs === "number" && stat.mtimeMs > cutoffMs) continue;
      await fsModule.promises.rm(fullPath, { force: true }).catch(() => {});
    }
  } catch (err) {
    if (err && err.code === "ENOENT") return;
  }
}

async function cleanupStaleInstallerStagingDirs({ fsModule, pathModule, distBaseDir, platformKey, maxAgeMs }) {
  const readdir = fsModule?.promises?.readdir ? fsModule.promises.readdir.bind(fsModule.promises) : null;
  const stat = fsModule?.promises?.stat ? fsModule.promises.stat.bind(fsModule.promises) : null;
  const rm = fsModule?.promises?.rm ? fsModule.promises.rm.bind(fsModule.promises) : null;
  if (!readdir || !stat || !rm) return;

  const prefix = `.docdex-install-staging-${platformKey}-`;
  let entries;
  try {
    entries = await readdir(distBaseDir, { withFileTypes: true });
  } catch {
    return;
  }

  const now = Date.now();
  await Promise.all(
    entries
      .filter((e) => e.isDirectory() && typeof e.name === "string" && e.name.startsWith(prefix))
      .map(async (e) => {
        const fullPath = pathModule.join(distBaseDir, e.name);
        try {
          const info = await stat(fullPath);
          const ageMs = now - info.mtimeMs;
          if (ageMs < maxAgeMs) return;
          await rm(fullPath, { recursive: true, force: true });
        } catch {
          // best-effort cleanup only
        }
      })
  );
}

function yesNoUnknown(value) {
  if (value === true) return "yes";
  if (value === false) return "no";
  return "unknown";
}

function describeBinaryRunnability({ fsModule, binaryPath, isWin32 }) {
  const existsSync = typeof fsModule?.existsSync === "function" ? fsModule.existsSync.bind(fsModule) : null;
  const accessSync = typeof fsModule?.accessSync === "function" ? fsModule.accessSync.bind(fsModule) : null;

  if (!existsSync) return { exists: null, runnable: null, reason: "existsSync_unavailable" };
  const exists = existsSync(binaryPath);
  if (!exists) return { exists: false, runnable: false, reason: "missing" };
  if (isWin32) return { exists: true, runnable: true, reason: "present_win32" };

  if (!accessSync) return { exists: true, runnable: null, reason: "accessSync_unavailable" };
  try {
    accessSync(binaryPath, fs.constants.X_OK);
    return { exists: true, runnable: true, reason: "executable" };
  } catch (err) {
    return { exists: true, runnable: false, reason: `access:${err?.code || err?.message || "denied"}` };
  }
}

async function safeRm({ fsModule, targetPath, options }) {
  if (!targetPath) return { attempted: false, removed: null, error: null };
  try {
    await fsModule.promises.rm(targetPath, options);
    return { attempted: true, removed: true, error: null };
  } catch (err) {
    return {
      attempted: true,
      removed: false,
      error: err?.message || String(err),
      errorCode: typeof err?.code === "string" ? err.code : null
    };
  }
}

async function safeRename({ fsModule, from, to }) {
  try {
    await fsModule.promises.rename(from, to);
    return { attempted: true, ok: true, error: null };
  } catch (err) {
    return {
      attempted: true,
      ok: false,
      error: err?.message || String(err),
      errorCode: typeof err?.code === "string" ? err.code : null
    };
  }
}

async function recoverInterruptedInstallIfNeeded({ fsModule, pathModule, distBaseDir, distDir, platformKey, logger }) {
  const existsSync = typeof fsModule?.existsSync === "function" ? fsModule.existsSync.bind(fsModule) : null;
  const readdir = typeof fsModule?.promises?.readdir === "function" ? fsModule.promises.readdir.bind(fsModule.promises) : null;

  if (!existsSync || !readdir) {
    return { attempted: false, restored: false, reason: "fs_unavailable", from: null, error: null, errorCode: null };
  }

  if (existsSync(distDir)) {
    return { attempted: true, restored: false, reason: "dist_present", from: null, error: null, errorCode: null };
  }

  let entries;
  try {
    entries = await readdir(distBaseDir, { withFileTypes: true });
  } catch (err) {
    return {
      attempted: true,
      restored: false,
      reason: "readdir_failed",
      from: null,
      error: err?.message || String(err),
      errorCode: typeof err?.code === "string" ? err.code : null
    };
  }

  const prefix = `.${platformKey}.backup.`;
  const candidates = entries
    .filter((entry) => entry?.isDirectory?.() && typeof entry.name === "string" && entry.name.startsWith(prefix))
    .map((entry) => entry.name);

  if (!candidates.length) {
    return { attempted: true, restored: false, reason: "no_backup_candidates", from: null, error: null, errorCode: null };
  }

  const pickNewest = candidates
    .map((name) => {
      const parts = name.split(".");
      const last = parts[parts.length - 1];
      const timestamp = Number.isFinite(Number(last)) ? Number(last) : 0;
      return { name, timestamp };
    })
    .sort((a, b) => b.timestamp - a.timestamp)[0]?.name;

  const from = pathModule.join(distBaseDir, pickNewest || candidates[0]);
  const restore = await safeRename({ fsModule, from, to: distDir });
  if (restore.ok) {
    logger?.warn?.(`[docdex] Restored previous installation from ${from}`);
    return { attempted: true, restored: true, reason: "restored", from, error: null, errorCode: null };
  }

  return {
    attempted: true,
    restored: false,
    reason: "restore_failed",
    from,
    error: restore.error,
    errorCode: restore.errorCode
  };
}

function isValidInstallMetadata(meta) {
>>>>>>> mcoda/task/ops-01-us-06-t35
  if (!meta || typeof meta !== "object") return false;
  if (meta.schemaVersion !== INSTALL_METADATA_SCHEMA_VERSION) return false;
  if (typeof meta.installedVersion !== "string" || !meta.installedVersion) return false;
  if (typeof meta.expectedVersion !== "string" || !meta.expectedVersion) return false;
  if (typeof meta.platformKey !== "string" || !meta.platformKey) return false;
  if (typeof meta.binaryPath !== "string" || !meta.binaryPath) return false;
  if (typeof meta.binaryHash !== "string" || meta.binaryHash.length !== 64) return false;
  if (typeof meta.provenance !== "object" || !meta.provenance) return false;
  if (typeof meta.installedAt !== "string" || !meta.installedAt) return false;
  if (typeof meta.lastVerifiedAt !== "string" || !meta.lastVerifiedAt) return false;
  return true;
}

<<<<<<< HEAD
<<<<<<< HEAD
function normalizeInstallMetadata(meta, { binaryPath }) {
  if (!meta || typeof meta !== "object") return null;

  if (meta.schemaVersion === INSTALL_METADATA_SCHEMA_VERSION) {
    return isValidInstallMetadataV2(meta) ? meta : null;
  }

  // Legacy schema (v1) lived in the package dist folder; normalize it for decision-making and migration.
  if (meta.schemaVersion === 1) {
    const version = typeof meta.version === "string" ? meta.version : null;
    const platformKey = typeof meta.platformKey === "string" ? meta.platformKey : null;
    const binarySha256 = normalizeSha256Hex(meta.binary?.sha256);
    const installedAt = typeof meta.installedAt === "string" ? meta.installedAt : null;
    if (!version || !platformKey || !binarySha256 || !installedAt) return null;

    const targetTriple = typeof meta.targetTriple === "string" ? meta.targetTriple : null;
    const repoSlug = typeof meta.repoSlug === "string" ? meta.repoSlug : null;
    const assetName = typeof meta.archive?.name === "string" ? meta.archive.name : null;
    const assetUrl = typeof meta.archive?.downloadUrl === "string" ? meta.archive.downloadUrl : null;
    const source = typeof meta.archive?.source === "string" ? meta.archive.source : null;
    const assetSha256 = normalizeSha256Hex(meta.archive?.sha256);

    return {
      schemaVersion: INSTALL_METADATA_SCHEMA_VERSION,
      installedVersion: version,
      expectedVersion: version,
      platformKey,
      targetTriple,
      binaryPath,
      binaryHash: binarySha256,
      provenance: {
        repoSlug,
        releaseTag: `v${version}`,
        releaseId: null,
        assetName,
        assetUrl,
        assetSha256,
        source
      },
      installedAt,
      lastVerifiedAt: installedAt
    };
  }

  return null;
=======
async function maybeBackfillInstallMetadataForNoop({
  fsModule,
  pathModule,
  metadataPath,
  expectedVersion,
  platformKey,
  targetTriple,
  isWin32,
  integrityResult,
  getDownloadBaseFn,
  artifactNameFn,
  logger
}) {
  const metaResult = await readJsonFileIfPossible({ fsModule, filePath: metadataPath });
  const meta = metaResult.value;
  if (!isValidInstallMetadata(meta)) return false;
  if (meta.platformKey !== platformKey) return false;

  const before = JSON.parse(JSON.stringify(meta));
  const changed = applyNoopInstallMetadataBackfill({
    meta,
    expectedVersion,
    platformKey,
    targetTriple,
    isWin32,
    integrityResult,
    getDownloadBaseFn,
    artifactNameFn
  });
  if (!changed) return false;
  if (util.isDeepStrictEqual(before, meta)) return false;

  try {
    await writeJsonFileAtomic({ fsModule, pathModule, filePath: metadataPath, value: meta });
    return true;
  } catch (err) {
    logger?.warn?.(`[docdex] Install metadata backfill failed: ${err?.message || String(err)}`);
    return false;
  }
>>>>>>> mcoda/task/ops-01-us-06-t29
=======
async function recoverInterruptedInstall({ fsModule, pathModule, distDir, isWin32, logger }) {
  const existsSync = typeof fsModule?.existsSync === "function" ? fsModule.existsSync.bind(fsModule) : null;
  const rm = fsModule?.promises?.rm;
  const rename = fsModule?.promises?.rename;

  if (!existsSync || typeof rm !== "function" || typeof rename !== "function") {
    return { recovered: false, actions: [] };
  }

  const { stagingDir, backupDir } = installSwapDirs(distDir);
  const actions = [];

  const distExists = existsSync(distDir);
  const stagingExists = existsSync(stagingDir);
  const backupExists = existsSync(backupDir);

  const distBinaryPath = binaryPathInDir({ pathModule, dirPath: distDir, isWin32 });
  const backupBinaryPath = binaryPathInDir({ pathModule, dirPath: backupDir, isWin32 });
  const stagingBinaryPath = binaryPathInDir({ pathModule, dirPath: stagingDir, isWin32 });

  const distBinaryExists = distExists && existsSync(distBinaryPath);
  const backupBinaryExists = backupExists && existsSync(backupBinaryPath);
  const stagingBinaryExists = stagingExists && existsSync(stagingBinaryPath);

  async function rmDir(dirPath) {
    await rm(dirPath, { recursive: true, force: true }).catch(() => {});
  }

  // If a previous install renamed the old directory aside but never swapped the new one in, restore the backup.
  if (!distExists && backupExists) {
    if (stagingExists) {
      await rmDir(stagingDir);
      actions.push("removed_staging");
    }
    await rename(backupDir, distDir);
    actions.push("restored_backup");
    if (logger?.log) logger.log("[docdex] Recovered interrupted install (restored backup).");
    return { recovered: true, actions };
  }

  // If the current directory exists but is missing the binary while a backup exists, prefer the known-good backup.
  if (distExists && !distBinaryExists && backupBinaryExists) {
    await rmDir(distDir);
    actions.push("removed_incomplete_dist");
    if (stagingExists) {
      await rmDir(stagingDir);
      actions.push("removed_staging");
    }
    await rename(backupDir, distDir);
    actions.push("restored_backup");
    if (logger?.log) logger.log("[docdex] Recovered interrupted install (rolled back to backup).");
    return { recovered: true, actions };
  }

  // If we extracted into staging but never swapped, discard the staging candidate and keep the existing install.
  if (stagingExists && distExists) {
    await rmDir(stagingDir);
    actions.push("removed_staging");
  }

  // If the swap succeeded but cleanup did not, remove the backup once the current install has a runnable binary.
  if (backupExists && distBinaryExists) {
    await rmDir(backupDir);
    actions.push("removed_backup");
  }

  // If there's no current install but a staging directory exists, only promote it if it looks complete.
  if (!distExists && !backupExists && stagingExists) {
    const metaPath = installMetadataPath(stagingDir, pathModule);
    const metaResult = await readJsonFileIfPossible({ fsModule, filePath: metaPath });
    if (stagingBinaryExists && isValidInstallMetadata(metaResult.value)) {
      await rename(stagingDir, distDir);
      actions.push("promoted_staging");
      if (logger?.log) logger.log("[docdex] Recovered interrupted install (promoted staged install).");
      return { recovered: true, actions };
    }
    await rmDir(stagingDir);
    actions.push("removed_staging");
  }

  return { recovered: actions.length > 0, actions };
}

function recoverInterruptedInstallSync({ fsModule, pathModule, distDir, isWin32 }) {
  const existsSync = typeof fsModule?.existsSync === "function" ? fsModule.existsSync.bind(fsModule) : null;
  const rmSync = typeof fsModule?.rmSync === "function" ? fsModule.rmSync.bind(fsModule) : null;
  const renameSync = typeof fsModule?.renameSync === "function" ? fsModule.renameSync.bind(fsModule) : null;

  if (!existsSync || !rmSync || !renameSync) return { recovered: false, actions: [] };

  const { stagingDir, backupDir } = installSwapDirs(distDir);
  const actions = [];

  const distExists = existsSync(distDir);
  const stagingExists = existsSync(stagingDir);
  const backupExists = existsSync(backupDir);

  const distBinaryPath = binaryPathInDir({ pathModule, dirPath: distDir, isWin32 });
  const backupBinaryPath = binaryPathInDir({ pathModule, dirPath: backupDir, isWin32 });
  const stagingBinaryPath = binaryPathInDir({ pathModule, dirPath: stagingDir, isWin32 });

  const distBinaryExists = distExists && existsSync(distBinaryPath);
  const backupBinaryExists = backupExists && existsSync(backupBinaryPath);
  const stagingBinaryExists = stagingExists && existsSync(stagingBinaryPath);

  function rmDirSync(dirPath) {
    try {
      rmSync(dirPath, { recursive: true, force: true });
    } catch {}
  }

  // Restore backup when swap was interrupted.
  if (!distExists && backupExists) {
    if (stagingExists) {
      rmDirSync(stagingDir);
      actions.push("removed_staging");
    }
    try {
      renameSync(backupDir, distDir);
      actions.push("restored_backup");
      return { recovered: true, actions };
    } catch {
      return { recovered: actions.length > 0, actions };
    }
  }

  // Prefer backup when current install looks incomplete.
  if (distExists && !distBinaryExists && backupBinaryExists) {
    rmDirSync(distDir);
    actions.push("removed_incomplete_dist");
    if (stagingExists) {
      rmDirSync(stagingDir);
      actions.push("removed_staging");
    }
    try {
      renameSync(backupDir, distDir);
      actions.push("restored_backup");
      return { recovered: true, actions };
    } catch {
      return { recovered: actions.length > 0, actions };
    }
  }

  // Discard abandoned staging dir when current install is present.
  if (stagingExists && distExists) {
    rmDirSync(stagingDir);
    actions.push("removed_staging");
  }

  // Remove leftover backup after successful swap.
  if (backupExists && distBinaryExists) {
    rmDirSync(backupDir);
    actions.push("removed_backup");
  }

  // Promote staging only if it looks complete enough (binary + metadata file present).
  if (!distExists && !backupExists && stagingExists) {
    const metaPath = installMetadataPath(stagingDir, pathModule);
    if (stagingBinaryExists && existsSync(metaPath)) {
      try {
        renameSync(stagingDir, distDir);
        actions.push("promoted_staging");
        return { recovered: true, actions };
      } catch {}
    }
    rmDirSync(stagingDir);
    actions.push("removed_staging");
  }

  return { recovered: actions.length > 0, actions };
>>>>>>> mcoda/task/ops-01-us-05-t05
}

function normalizeSha256Hex(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(trimmed)) return null;
  return trimmed;
}

<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
function parseSemverLike(version) {
  if (typeof version !== "string") return null;
  const trimmed = version.trim().replace(/^v/i, "");
  if (!trimmed) return null;
  const core = trimmed.split("+")[0].split("-")[0];
  const parts = core.split(".").map((p) => Number.parseInt(p, 10));
  if (!parts.length || parts.some((n) => !Number.isFinite(n))) return null;
  while (parts.length < 3) parts.push(0);
  return parts.slice(0, 3);
}

function compareSemverLike(a, b) {
  const av = parseSemverLike(a);
  const bv = parseSemverLike(b);
  if (!av || !bv) return null;
  for (let i = 0; i < 3; i += 1) {
    if (av[i] < bv[i]) return -1;
    if (av[i] > bv[i]) return 1;
  }
  return 0;
}

function planFromOutcome({ outcome, installedVersion, expectedVersion, binaryPresent }) {
  if (outcome === "no-op") return "no-op";
  if (outcome === "repair") return "repair";

  const cmp = compareSemverLike(installedVersion, expectedVersion);

  if (outcome === "update") {
    if (cmp === 1) return "downgrade";
    return "upgrade";
  }

  // Any other reinstall path is treated as a repair-like convergence step.
  if (cmp === 1) return "downgrade";
  if (cmp === -1) return "upgrade";
  return binaryPresent ? "repair" : "upgrade";
}

=======
function parseSemverLoose(version) {
  if (typeof version !== "string") return null;
  const cleaned = version.trim().replace(/^v/, "");
  if (!cleaned) return null;

  const withoutBuild = cleaned.split("+", 1)[0];
  const [core, prereleaseRaw] = withoutBuild.split("-", 2);
  const parts = core.split(".");
  if (parts.length !== 3) return null;

  const major = Number(parts[0]);
  const minor = Number(parts[1]);
  const patch = Number(parts[2]);
  if (!Number.isInteger(major) || !Number.isInteger(minor) || !Number.isInteger(patch)) return null;
  if (major < 0 || minor < 0 || patch < 0) return null;

  const prerelease = prereleaseRaw
    ? prereleaseRaw
        .split(".")
        .map((id) => (id === "" ? null : id))
        .filter((id) => id != null)
    : [];

  return { major, minor, patch, prerelease };
}

function compareSemverLoose(a, b) {
  const av = parseSemverLoose(a);
  const bv = parseSemverLoose(b);
  if (!av || !bv) return null;

  if (av.major !== bv.major) return av.major < bv.major ? -1 : 1;
  if (av.minor !== bv.minor) return av.minor < bv.minor ? -1 : 1;
  if (av.patch !== bv.patch) return av.patch < bv.patch ? -1 : 1;

  const aPre = av.prerelease;
  const bPre = bv.prerelease;
  const aHas = aPre.length > 0;
  const bHas = bPre.length > 0;
  if (!aHas && !bHas) return 0;
  if (!aHas && bHas) return 1;
  if (aHas && !bHas) return -1;

  const len = Math.max(aPre.length, bPre.length);
  for (let i = 0; i < len; i += 1) {
    const ai = aPre[i];
    const bi = bPre[i];
    if (ai == null && bi == null) return 0;
    if (ai == null) return -1;
    if (bi == null) return 1;

    const aNum = /^[0-9]+$/.test(ai) ? Number(ai) : null;
    const bNum = /^[0-9]+$/.test(bi) ? Number(bi) : null;
    if (aNum != null && bNum != null) {
      if (aNum !== bNum) return aNum < bNum ? -1 : 1;
      continue;
    }
    if (aNum != null && bNum == null) return -1;
    if (aNum == null && bNum != null) return 1;

    if (ai !== bi) return ai < bi ? -1 : 1;
  }

  return 0;
}

>>>>>>> mcoda/task/ops-01-us-06-t40
=======
function parseDocdexdVersionOutput(text) {
  const match = String(text || "").match(/\bv?(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)\b/);
  return match ? match[1] : null;
}

function execFileText(execFileFn, file, args, opts) {
  return new Promise((resolve, reject) => {
    execFileFn(file, args, opts, (err, stdout, stderr) => {
      if (err) {
        err.stdout = stdout;
        err.stderr = stderr;
        return reject(err);
      }
      resolve({ stdout, stderr });
    });
  });
}

async function readInstalledDocdexdVersion({ binaryPath, timeoutMs = 1500, execFileFn = execFile } = {}) {
  const attempts = [["--version"], ["-V"]];
  const opts = { timeout: timeoutMs, windowsHide: true, maxBuffer: 64 * 1024 };
  const errors = [];

  for (const args of attempts) {
    try {
      const { stdout, stderr } = await execFileText(execFileFn, binaryPath, args, opts);
      const parsed = parseDocdexdVersionOutput(`${stdout || ""}\n${stderr || ""}`);
      if (parsed) return { version: parsed, error: null, attemptedArgs: args };
      errors.push(`no_version_in_output(${args.join(" ")})`);
    } catch (err) {
      const parsed = parseDocdexdVersionOutput(`${err?.stdout || ""}\n${err?.stderr || ""}`);
      if (parsed) return { version: parsed, error: null, attemptedArgs: args };
      errors.push(err?.code ? `${err.code}(${args.join(" ")})` : `exec_failed(${args.join(" ")})`);
    }
  }

  return { version: null, error: errors.length ? errors.join(";") : "unavailable", attemptedArgs: null };
}

>>>>>>> mcoda/task/ops-01-us-06-t41
=======
function parseVersionTriplet(version) {
  if (typeof version !== "string") return null;
  const trimmed = version.trim().replace(/^v/i, "");
  if (!trimmed) return null;

  const core = trimmed.split(/[+-]/)[0];
  const parts = core.split(".");
  if (parts.length < 2 || parts.length > 3) return null;

  const major = Number(parts[0]);
  const minor = Number(parts[1]);
  const patch = parts.length === 3 ? Number(parts[2]) : 0;
  if (![major, minor, patch].every((n) => Number.isInteger(n) && n >= 0)) return null;

  return { major, minor, patch };
}

function compareVersionTriplets(a, b) {
  if (!a || !b) return null;
  if (a.major !== b.major) return a.major < b.major ? -1 : 1;
  if (a.minor !== b.minor) return a.minor < b.minor ? -1 : 1;
  if (a.patch !== b.patch) return a.patch < b.patch ? -1 : 1;
  return 0;
}

>>>>>>> mcoda/task/ops-01-us-06-t02
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

function integrityMismatch({ expectedSha256, actualSha256, expectedSource, ...extra }) {
  return {
    status: "mismatch",
    reason: "hash_mismatch",
    expectedSha256: expectedSha256 ?? null,
    actualSha256: actualSha256 ?? null,
    expectedSource: expectedSource ?? null,
    error: null,
    ...extra
  };
}

function integrityVerified({ expectedSha256, actualSha256, expectedSource, ...extra }) {
  return {
    status: "verified_ok",
    reason: "hash_match",
    expectedSha256: expectedSha256 ?? null,
    actualSha256: actualSha256 ?? null,
    expectedSource: expectedSource ?? null,
    error: null,
    ...extra
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
    installedMetadataStatus === "valid" ? normalizeSha256Hex(installedMetadata?.binaryHash) : null;

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

function verifyInstalledArchiveRecordIntegrity({
  installedMetadata,
  installedMetadataStatus,
  installedMetadataStatusReason,
  expectedArchiveName,
  expectedArchiveSha256,
  expectedArchiveSource
}) {
  if (installedMetadataStatus !== "valid") {
    const reason =
      typeof installedMetadataStatusReason === "string" && installedMetadataStatusReason
        ? installedMetadataStatusReason
        : "metadata_invalid";
    return integrityUnverifiable(reason, { expectedSource: expectedArchiveSource ?? null });
  }

  const expectedSha256 = normalizeSha256Hex(expectedArchiveSha256);
  if (!expectedSha256) {
    return integrityUnverifiable("expected_hash_unavailable", {
      expectedSource: expectedArchiveSource ?? null,
      error: expectedArchiveSha256 == null ? "expected_missing" : "expected_invalid"
    });
  }

  const recordedName =
    typeof installedMetadata?.archive?.name === "string" && installedMetadata.archive.name.trim()
      ? installedMetadata.archive.name.trim()
      : null;
  const recordedSha256 = normalizeSha256Hex(installedMetadata?.archive?.sha256);

  if (!recordedName) {
    return integrityUnverifiable("metadata_missing_archive_name", {
      expectedSha256,
      expectedSource: expectedArchiveSource ?? null
    });
  }

  if (!recordedSha256) {
    return integrityUnverifiable("metadata_missing_archive_sha256", {
      expectedSha256,
      expectedSource: expectedArchiveSource ?? null
    });
  }

  if (typeof expectedArchiveName === "string" && expectedArchiveName.trim() && recordedName !== expectedArchiveName) {
    return integrityMismatch({
      expectedSha256,
      actualSha256: recordedSha256,
      expectedSource: expectedArchiveSource ?? null,
      reason: "archive_name_mismatch",
      expectedArchiveName: expectedArchiveName,
      actualArchiveName: recordedName
    });
  }

  if (recordedSha256 !== expectedSha256) {
    return integrityMismatch({
      expectedSha256,
      actualSha256: recordedSha256,
      expectedSource: expectedArchiveSource ?? null,
      reason: "archive_sha256_mismatch",
      expectedArchiveName: expectedArchiveName ?? null,
      actualArchiveName: recordedName
    });
  }

  return integrityVerified({
    expectedSha256,
    actualSha256: recordedSha256,
    expectedSource: expectedArchiveSource ?? null,
    expectedArchiveName: expectedArchiveName ?? null,
    actualArchiveName: recordedName
  });
}

/**
 * @param {object} args
 * @param {string} args.expectedVersion
 * @param {{binarySha256: (string|null), archiveSha256: (string|null)}} args.expectedIntegrityMaterial
 * @param {object} args.discoveredInstalledState
 * @param {object} args.integrityResult
<<<<<<< HEAD
 * @returns {{
 *   outcome: string,
 *   reason: string,
 *   action: string,
 *   versionComparison: { expected: object|null, installed: object|null, cmp: (number|null) }
 * }}
=======
 * @param {object} args.archiveRecordResult
 * @returns {{outcome: string, reason: string}}
>>>>>>> mcoda/task/ops-01-us-06-t03
 */
function decideInstallDecision({
  expectedVersion,
  expectedIntegrityMaterial,
  discoveredInstalledState,
  integrityResult,
  archiveRecordResult
}) {
<<<<<<< HEAD
  if (!discoveredInstalledState?.binaryPresent) return { outcome: "install", reason: "binary_missing" };
=======
  let outcome;
  let reason;
>>>>>>> mcoda/task/ops-01-us-06-t02

  if (!discoveredInstalledState?.binaryPresent) {
    outcome = "update";
    reason = "binary_missing";
  } else if (discoveredInstalledState.metadataStatus !== "valid") {
    outcome = "reinstall_unknown";
    reason = discoveredInstalledState.metadataStatusReason || "metadata_invalid";
  } else if (discoveredInstalledState.platformMismatch) {
    outcome = "reinstall_unknown";
    reason = "platform_mismatch";
  } else if (discoveredInstalledState.installedVersion !== expectedVersion) {
    outcome = "update";
    reason = "version_mismatch";
  } else {
    const expectedBinarySha256 = normalizeSha256Hex(expectedIntegrityMaterial?.binarySha256);
    if (!expectedBinarySha256) {
      outcome = "reinstall_unknown";
      reason = "expected_integrity_missing";
    } else if (integrityResult?.status === "mismatch") {
      outcome = "repair";
      reason = "binary_integrity_mismatch";
    } else if (integrityResult?.status === "verified_ok") {
      outcome = "no-op";
      reason = "verified";
    } else {
      outcome = "reinstall_unknown";
      reason = "integrity_unverifiable";
    }
  }

  const installedVersion =
    discoveredInstalledState && typeof discoveredInstalledState.installedVersion === "string"
      ? discoveredInstalledState.installedVersion
      : null;
  const expectedParsed = parseVersionTriplet(expectedVersion);
  const installedParsed = parseVersionTriplet(installedVersion);
  const cmp = compareVersionTriplets(expectedParsed, installedParsed);
  const versionComparison = { expected: expectedParsed, installed: installedParsed, cmp };

<<<<<<< HEAD
  if (discoveredInstalledState.installedVersion !== expectedVersion) {
    const comparison = compareSemverLoose(discoveredInstalledState.installedVersion, expectedVersion);
    if (comparison === -1) return { outcome: "upgrade", reason: "version_mismatch" };
    if (comparison === 1) return { outcome: "downgrade", reason: "version_mismatch" };
    return { outcome: "replace", reason: "version_mismatch" };
  }
=======
  const direction = cmp === -1 ? "downgrade" : "upgrade";
  let action;
  if (outcome === "no-op") action = "no-op";
  else if (outcome === "repair") action = "repair";
  else if (outcome === "update") action = direction;
  else if (outcome === "reinstall_unknown") {
    action = installedVersion && installedVersion !== expectedVersion ? direction : "repair";
  } else action = "repair";
>>>>>>> mcoda/task/ops-01-us-06-t02

<<<<<<< HEAD
  return { outcome, reason, action, versionComparison };
}
=======
  const expectedArchiveSha256 = normalizeSha256Hex(expectedIntegrityMaterial?.archiveSha256);
  if (!expectedArchiveSha256) {
    return { outcome: "reinstall_unknown", reason: "expected_archive_integrity_missing" };
  }

  if (archiveRecordResult?.status === "mismatch") {
    return { outcome: "repair", reason: archiveRecordResult.reason || "archive_integrity_mismatch" };
  }

  if (archiveRecordResult?.status !== "verified_ok") {
    return { outcome: "reinstall_unknown", reason: "archive_integrity_unverifiable" };
  }

  const expectedBinarySha256 = normalizeSha256Hex(expectedIntegrityMaterial?.binarySha256);
  if (!expectedBinarySha256) {
    return { outcome: "reinstall_unknown", reason: "expected_integrity_missing" };
  }
>>>>>>> mcoda/task/ops-01-us-06-t03

function decideInstallAction(args) {
  const decision = decideInstallDecision(args);
  return { outcome: decision.outcome, reason: decision.reason };
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
  const normalized = normalizeInstallMetadata(meta, { binaryPath });
  if (!normalized) {
    return {
      binaryPath,
      metadataPath,
      binaryPresent: true,
      installedVersion:
        typeof meta?.installedVersion === "string"
          ? meta.installedVersion
          : typeof meta?.version === "string"
            ? meta.version
            : null,
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
    installedVersion: normalized.installedVersion,
    metadata: normalized,
    metadataStatus: "valid",
    metadataStatusReason: null,
    platformMismatch: normalized.platformKey !== platformKey
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
  expectedBinarySha256 = null,
<<<<<<< HEAD
  readInstalledBinaryVersionFn = null
=======
  expectedArchiveName = null,
  expectedArchiveSha256 = null,
  expectedArchiveSource = null,
  discoveredInstalledState = null
>>>>>>> mcoda/task/ops-01-us-06-t03
}) {
  const state =
    discoveredInstalledState ||
    (await discoverInstalledState({
      fsModule,
      pathModule,
      distDir,
      platformKey,
      isWin32
    }));

  const binaryPresent = Boolean(discoveredInstalledState.binaryPresent);
  const metadataStatus = discoveredInstalledState.metadataStatus;
  const metadataStatusReason = discoveredInstalledState.metadataStatusReason;
  const platformMismatch = Boolean(discoveredInstalledState.platformMismatch);

  const expectedIntegrityMaterial = {
    archiveSha256: normalizeSha256Hex(expectedArchiveSha256) ? expectedArchiveSha256 : null,
    binarySha256: normalizeSha256Hex(expectedBinarySha256)
      ? expectedBinarySha256
<<<<<<< HEAD
      : discoveredInstalledState.metadataStatus === "valid"
        ? discoveredInstalledState.metadata.binaryHash
=======
      : state.metadataStatus === "valid"
        ? state.metadata.binary.sha256
>>>>>>> mcoda/task/ops-01-us-06-t03
        : null
  };

  const shouldVerifyIntegrity =
<<<<<<< HEAD
    binaryPresent &&
    !platformMismatch &&
    discoveredInstalledState.installedVersion === expectedVersion &&
    (normalizeSha256Hex(expectedBinarySha256) || discoveredInstalledState.metadataStatus === "valid");
=======
    state.binaryPresent &&
    !state.platformMismatch &&
    state.installedVersion === expectedVersion &&
    (normalizeSha256Hex(expectedBinarySha256) || state.metadataStatus === "valid");
>>>>>>> mcoda/task/ops-01-us-06-t03

  const integrityResult = shouldVerifyIntegrity
    ? await verifyInstalledDocdexdIntegrity({
        fsModule,
        sha256FileFn,
        binaryPath: state.binaryPath,
        expectedBinarySha256: expectedBinarySha256,
        installedMetadata: state.metadata,
        installedMetadataStatus: state.metadataStatus,
        installedMetadataStatusReason: state.metadataStatusReason
      })
    : null;

  const shouldVerifyArchiveRecord =
    state.binaryPresent &&
    !state.platformMismatch &&
    state.installedVersion === expectedVersion &&
    state.metadataStatus === "valid";

  const archiveRecordResult = shouldVerifyArchiveRecord
    ? verifyInstalledArchiveRecordIntegrity({
        installedMetadata: state.metadata,
        installedMetadataStatus: state.metadataStatus,
        installedMetadataStatusReason: state.metadataStatusReason,
        expectedArchiveName,
        expectedArchiveSha256,
        expectedArchiveSource
      })
    : null;

<<<<<<< HEAD
  let decision = decideInstallAction({
=======
  const decision = decideInstallDecision({
>>>>>>> mcoda/task/ops-01-us-06-t02
    expectedVersion,
    expectedIntegrityMaterial,
    discoveredInstalledState: state,
    integrityResult,
    archiveRecordResult
  });

<<<<<<< HEAD
  let installedVersion =
    typeof discoveredInstalledState.installedVersion === "string" ? discoveredInstalledState.installedVersion : null;
=======
  const installedVersion =
    typeof state.installedVersion === "string" ? state.installedVersion : null;
>>>>>>> mcoda/task/ops-01-us-06-t03

  let binaryVersion = null;
  let binaryVersionError = null;
  if (
    decision.outcome === "no-op" &&
    integrityResult?.status === "verified_ok" &&
    typeof readInstalledBinaryVersionFn === "function"
  ) {
    try {
      const maybe = await readInstalledBinaryVersionFn({ binaryPath: discoveredInstalledState.binaryPath });
      if (typeof maybe === "string" && maybe) binaryVersion = maybe;
    } catch (err) {
      binaryVersionError = err?.message || String(err);
    }
  }

  if (binaryVersion && binaryVersion !== expectedVersion) {
    decision = { outcome: "update", reason: "version_mismatch" };
    installedVersion = binaryVersion;
  }

  return {
    plan: planFromOutcome({
      outcome: decision.outcome,
      installedVersion,
      expectedVersion,
      binaryPresent: Boolean(discoveredInstalledState.binaryPresent)
    }),
    outcome: decision.outcome,
    reason: decision.reason,
<<<<<<< HEAD
    action: decision.action,
    decision: {
      schemaVersion: 1,
      outcome: decision.outcome,
      action: decision.action,
      reason: decision.reason,
      expectedVersion,
      installedVersion,
      platformKey,
      versionComparison: decision.versionComparison
    },
    binaryPath: discoveredInstalledState.binaryPath,
    metadataPath: discoveredInstalledState.metadataPath,
    installedVersion,
    integrityResult,
<<<<<<< HEAD
    binaryVersion,
    binaryVersionError
=======
    integrityChecked: shouldVerifyIntegrity,
    binaryPresent,
    metadataStatus,
    metadataStatusReason,
    platformMismatch
>>>>>>> mcoda/task/ops-01-us-06-t15
=======
    binaryPath: state.binaryPath,
    metadataPath: state.metadataPath,
    installedVersion,
    integrityResult,
    verification: {
      installedBinary: integrityResult,
      installedArchiveRecord: archiveRecordResult
    }
>>>>>>> mcoda/task/ops-01-us-06-t03
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
          manifestUrl: url,
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

  return { manifestName: null, manifestUrl: null, resolved: null, errors, events, attempted: true };
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
  let assetId = null;
  let integritySourceType = null;
  let integritySourceName = null;
  let integritySourceUrl = null;

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
    assetId = manifestAttempt.resolved.asset.id ?? null;
    source = `manifest:${manifestAttempt.manifestName}`;
    integritySourceType = "manifest";
    integritySourceName = manifestAttempt.manifestName;
    integritySourceUrl = manifestAttempt.manifestUrl;
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
      integritySourceType = "sha256sums";
      integritySourceName = checksumAttempt.checksumName;
      integritySourceUrl = checksumAttempt.checksumUrl;
    } else {
      // Legacy fallback: per-asset .sha256 sidecar.
      const shaUrl = `${getDownloadBaseFn(repoSlug)}/v${version}/${archive}.sha256`;
      try {
        const shaText = await downloadTextFn(shaUrl);
        expectedSha256 = parseSha256File(shaText, archive);
        if (expectedSha256) {
          integritySourceType = "sidecar";
          integritySourceName = `${archive}.sha256`;
          integritySourceUrl = shaUrl;
        }
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
    assetId,
    integrity: {
      method: expectedSha256 ? "sha256" : null,
      expectedSha256: expectedSha256 || null,
      sourceType: integritySourceType,
      sourceName: integritySourceName,
      sourceUrl: integritySourceUrl
    },
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
  const expected = normalizeSha256Hex(expectedSha256);
  if (!expected) {
    throw new ChecksumResolutionError(`Missing SHA-256 integrity metadata for ${archiveName}`, {
      ...(details || {}),
      assetName: archiveName,
      expectedSha256: null,
      actualSha256: null
    });
  }

  const rawActual = await sha256FileFn(filePath);
  const actual = normalizeSha256Hex(rawActual);
  if (!actual) {
    throw new IntegrityMismatchError(archiveName, expected, String(rawActual), {
      ...(details || {}),
      error: typeof rawActual === "string" ? `invalid_sha256:${rawActual}` : "invalid_sha256"
    });
  }

  if (actual !== expected) {
    throw new IntegrityMismatchError(archiveName, expected, actual, details);
  }

  return integrityVerified({
    expectedSha256: expected,
    actualSha256: actual,
    expectedSource: typeof details?.source === "string" ? details.source : null,
    filePath,
    assetName: archiveName
  });
}

function incomingInstallDir(distDir) {
  return `${distDir}.incoming`;
}

function backupInstallDir(distDir) {
  return `${distDir}.backup`;
}

async function rmTreeQuiet(fsModule, targetPath) {
  if (!targetPath) return;
  await fsModule.promises.rm(targetPath, { recursive: true, force: true }).catch(() => {});
}

async function recoverInterruptedInstall({ fsModule, distDir, incomingDir, backupDir }) {
  const rmFn = fsModule?.promises?.rm;
  const renameFn = fsModule?.promises?.rename;
  if (typeof rmFn !== "function" || typeof renameFn !== "function") return;

  const existsSync = typeof fsModule?.existsSync === "function" ? fsModule.existsSync.bind(fsModule) : null;
  if (!existsSync) return;

  const distExists = existsSync(distDir);
  const backupExists = existsSync(backupDir);
  const incomingExists = existsSync(incomingDir);

  if (!distExists && backupExists) {
    try {
      await fsModule.promises.rename(backupDir, distDir);
    } catch {
      // Best-effort only.
    }
  }

  if (incomingExists) {
    await rmTreeQuiet(fsModule, incomingDir);
  }

  if (existsSync(distDir) && existsSync(backupDir)) {
    await rmTreeQuiet(fsModule, backupDir);
  }
}

async function runInstaller(options) {
  const opts = options || {};
<<<<<<< HEAD
  const noisyLogger = opts.logger || console;
  const outputFormat = normalizeInstallerOutputFormat(opts.outputFormat || process.env.DOCDEX_INSTALLER_OUTPUT);
  const logger = outputFormat === "json" ? createNoopLogger() : noisyLogger;
=======
  const logger = opts.logger || console;
  const attemptId = `${process.pid}-${Date.now()}`;
>>>>>>> mcoda/task/ops-01-us-06-t15

  const detectPlatformKeyFn = opts.detectPlatformKeyFn || detectPlatformKey;
  const targetTripleForPlatformKeyFn = opts.targetTripleForPlatformKeyFn || targetTripleForPlatformKey;
  const getVersionFn = opts.getVersionFn || getVersion;
  const parseRepoSlugFn = opts.parseRepoSlugFn || parseRepoSlug;
  const resolveInstallerDownloadPlanFn = opts.resolveInstallerDownloadPlanFn || resolveInstallerDownloadPlan;
  const getDownloadBaseFn = opts.getDownloadBaseFn || getDownloadBase;
  const downloadFn = opts.downloadFn || download;
  const verifyDownloadedFileIntegrityFn = opts.verifyDownloadedFileIntegrityFn || verifyDownloadedFileIntegrity;
  const extractTarballFn = opts.extractTarballFn || extractTarball;
  const writeJsonFileAtomicFn = opts.writeJsonFileAtomicFn || writeJsonFileAtomic;
  const fsModule = opts.fsModule || fs;
  const pathModule = opts.pathModule || path;
  const osModule = opts.osModule || os;
  const artifactNameFn = opts.artifactNameFn || artifactName;
  const assetPatternForPlatformKeyFn = opts.assetPatternForPlatformKeyFn || assetPatternForPlatformKey;
  const sha256FileFn = opts.sha256FileFn || sha256File;
  const execFileFn = opts.execFileFn || execFile;
  const readInstalledBinaryVersionFn =
    opts.readInstalledBinaryVersionFn ||
    (async ({ binaryPath }) => {
      const result = await readInstalledDocdexdVersion({ binaryPath, execFileFn });
      return result.version;
    });

  const detectedPlatform = opts.platform || process.platform;
  const detectedArch = opts.arch || process.arch;
  const env = opts.env || process.env;

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
<<<<<<< HEAD
  const stateRootDir = opts.stateRootDir || resolveInstallerStateRootDir({ osModule, pathModule, env });
  const distDir = resolveInstallerInstallDir({ stateRootDir, platformKey, pathModule });
  const legacyDistBaseDir = opts.distBaseDir || pathModule.join(__dirname, "..", "dist");
  const legacyDistDir = pathModule.join(legacyDistBaseDir, platformKey);
  const isWin32 = detectedPlatform === "win32";

<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
  emitInstallerEvent({
    logger,
    code: "DOCDEX_INSTALL_START",
    message: "Installer started",
    details: { attemptId, expectedVersion: version, platformKey, targetTriple, distDir }
  });

=======
  const discoveredInstalledState = await discoverInstalledState({
    fsModule,
    pathModule,
    distDir,
    platformKey,
    isWin32
  });

  const needsReleaseIntegrityForLocal =
    discoveredInstalledState.binaryPresent &&
    discoveredInstalledState.metadataStatus === "valid" &&
    !discoveredInstalledState.platformMismatch &&
    discoveredInstalledState.installedVersion === version;

  let preflightRepoSlug = null;
  let preflightPlan = null;
  if (needsReleaseIntegrityForLocal) {
    preflightRepoSlug = parseRepoSlugFn();
    preflightPlan = await resolveInstallerDownloadPlanFn({
      repoSlug: preflightRepoSlug,
      version,
      platformKey,
      targetTriple,
      logger
    });
  }

>>>>>>> mcoda/task/ops-01-us-06-t03
=======
  // Best-effort cleanup of stale staging artifacts from prior interrupted installs.
  await cleanupTransientInstallerArtifacts({ fsModule, pathModule, distBaseDir, platformKey, distDir });

>>>>>>> mcoda/task/ops-01-us-05-t37
=======
  const distBaseDir = opts.distBaseDir || pathModule.join(__dirname, "..", "dist");
  const distDir = pathModule.join(distBaseDir, platformKey);
  const incomingDir = incomingInstallDir(distDir);
  const backupDir = backupInstallDir(distDir);
  const isWin32 = detectedPlatform === "win32";

  await recoverInterruptedInstall({ fsModule, distDir, incomingDir, backupDir });

>>>>>>> mcoda/task/ops-01-us-05-t40
=======
  const preflightRecovery = await recoverInterruptedInstallIfNeeded({
    fsModule,
    pathModule,
    distBaseDir,
    distDir,
    platformKey,
    logger
  });

>>>>>>> mcoda/task/ops-01-us-05-t39
=======
  await recoverInterruptedInstall({ fsModule, pathModule, distDir, isWin32, logger }).catch(() => {});

>>>>>>> mcoda/task/ops-01-us-05-t05
  const local = await determineLocalInstallerOutcome({
    fsModule,
    pathModule,
    distDir,
    platformKey,
    expectedVersion: version,
    isWin32,
    sha256FileFn,
<<<<<<< HEAD
    readInstalledBinaryVersionFn
  });

  const localOutcomeCode = normalizeOutcomeCode(local.outcome);
  emitInstallerEvent({
    logger,
    code: "DOCDEX_INSTALL_DECISION",
    message: "Local state evaluated",
    details: {
      attemptId,
      expectedVersion: version,
      platformKey,
      targetTriple,
      distDir,
      installedVersion: local.installedVersion,
      binaryPresent: local.binaryPresent,
      metadataStatus: local.metadataStatus,
      metadataStatusReason: local.metadataStatusReason,
      platformMismatch: local.platformMismatch,
      integrityChecked: Boolean(local.integrityChecked),
      integrity: summarizeIntegrityResult(local.integrityResult),
      // Stable support-facing fields (in addition to the nested `decision` object).
      outcome: local.outcome,
      outcomeCode: localOutcomeCode,
      outcomeReason: local.reason,
      decision: { outcome: local.outcome, outcomeCode: localOutcomeCode, reason: local.reason }
    }
  });

  if (local.integrityChecked) {
    emitInstallerEvent({
      logger,
      code: "DOCDEX_INSTALL_INTEGRITY_LOCAL",
      message: "Local binary integrity verification result",
      details: {
        attemptId,
        binaryPath: local.binaryPath,
        metadataPath: local.metadataPath,
        integrity: summarizeIntegrityResult(local.integrityResult)
      }
    });
  }

  if (local.outcome === "no-op") {
<<<<<<< HEAD
<<<<<<< HEAD
=======
    if (local.metadataPath) {
      await maybeBackfillInstallMetadataForNoop({
        fsModule,
        pathModule,
        metadataPath: local.metadataPath,
        expectedVersion: version,
        platformKey,
        targetTriple,
        isWin32,
        integrityResult: local.integrityResult,
        getDownloadBaseFn,
        artifactNameFn,
        logger
      });
    }
>>>>>>> mcoda/task/ops-01-us-06-t29
    logger.log("[docdex] Install outcome: no-op");
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
    return { binaryPath: local.binaryPath, outcome: local.outcome, integrityResult: local.integrityResult };
=======
    const report = buildInstallOutcomeReport({
      decision: local,
      expectedVersion: version,
      platformKey,
      targetTriple,
      repoSlug: null,
      archive: null,
      downloadUrl: null,
      source: null
    });
    emitInstallOutcomeReport(report, { logger: noisyLogger, outputFormat });
    return {
      binaryPath: local.binaryPath,
      outcome: local.outcome,
      outcomeCode: report.code,
      outcomeMessage: report.message,
      decisionReason: local.reason
    };
>>>>>>> mcoda/task/ops-01-us-06-t47
=======
    emitInstallerEvent({
      logger,
      code: "DOCDEX_INSTALL_OUTCOME",
      message: "Install completed",
      details: {
        attemptId,
        outcome: local.outcome,
        outcomeCode: localOutcomeCode,
        reason: local.reason,
        binaryPath: local.binaryPath,
        metadataPath: local.metadataPath,
        downloadAttempted: false,
        integrity: summarizeIntegrityResult(local.integrityResult)
      }
    });
    return {
      binaryPath: local.binaryPath,
      outcome: local.outcome,
      outcomeCode: localOutcomeCode,
      integrityResult: local.integrityResult
    };
>>>>>>> mcoda/task/ops-01-us-06-t15
  }

  // Backward-compatible migration path: older installers stored the verified binary + metadata under package dist/.
  // If the state-root install dir is missing but the legacy one is verified, migrate without redownloading.
  if (local.reason === "binary_missing" || local.reason === "metadata_missing") {
    const legacy = await determineLocalInstallerOutcome({
      fsModule,
      pathModule,
      distDir: legacyDistDir,
      platformKey,
      expectedVersion: version,
      isWin32,
      sha256FileFn
    });

    if (legacy.outcome === "no-op") {
      const legacyMetadataPath = installMetadataPath(legacyDistDir, pathModule);
      const legacyMetaResult = await readJsonFileIfPossible({ fsModule, filePath: legacyMetadataPath });
      const legacyNormalized = normalizeInstallMetadata(legacyMetaResult.value, { binaryPath: legacy.binaryPath });

      const binaryPath = pathModule.join(distDir, isWin32 ? "docdexd.exe" : "docdexd");
      await fsModule.promises.mkdir(distDir, { recursive: true });
      await fsModule.promises.copyFile(legacy.binaryPath, binaryPath);
      await fsModule.promises.chmod(binaryPath, 0o755).catch(() => {});

      const binarySha256 = await sha256FileFn(binaryPath);
      const installedAt = legacyNormalized?.installedAt || nowIso();
      const lastVerifiedAt = legacyNormalized?.lastVerifiedAt || installedAt;
      const metadata = {
        schemaVersion: INSTALL_METADATA_SCHEMA_VERSION,
        installedVersion: legacyNormalized?.installedVersion || version,
        expectedVersion: version,
        platformKey,
        targetTriple,
        binaryPath,
        binaryHash: binarySha256,
        provenance: legacyNormalized?.provenance || {
          repoSlug: null,
          releaseTag: `v${version}`,
          releaseId: null,
          assetName: null,
          assetUrl: null,
          assetSha256: null,
          source: "legacy-dist"
        },
        installedAt,
        lastVerifiedAt
      };

      await writeJsonFileAtomic({
        fsModule,
        pathModule,
        filePath: installMetadataPath(distDir, pathModule),
        value: metadata
      });

      logger.log("[docdex] Install outcome: no-op");
      return { binaryPath, outcome: "no-op", integrityResult: legacy.integrityResult };
    }
=======
    return {
      binaryPath: local.binaryPath,
      outcome: local.outcome,
      plan: local.plan,
      integrityResult: local.integrityResult
    };
>>>>>>> mcoda/task/ops-01-us-06-t37
=======
    return {
      binaryPath: local.binaryPath,
      outcome: local.outcome,
      reason: local.reason,
      previousVersion: local.installedVersion,
      expectedVersion: version,
      finalVersion: version,
      integrityResult: local.integrityResult
    };
>>>>>>> mcoda/task/ops-01-us-06-t40
=======
    logger.log(`[docdex] Install decision: ${JSON.stringify(local.decision)}`);
    return {
      binaryPath: local.binaryPath,
      outcome: local.outcome,
      action: local.action,
      decision: local.decision,
      integrityResult: local.integrityResult
    };
>>>>>>> mcoda/task/ops-01-us-06-t02
  }

  await cleanupInterruptedInstallArtifacts({ fsModule, pathModule, distBaseDir, distDir, platformKey, isWin32 });

  const repoSlug = parseRepoSlugFn();

  const {
    archive,
    expectedSha256,
    source,
    assetId = null,
    integrity: resolvedIntegrityPlan = null,
    manifestAttempt
  } = await resolveInstallerDownloadPlanFn({
    repoSlug,
    version,
    platformKey,
    targetTriple,
    logger
  });
=======
    expectedArchiveName: preflightPlan?.archive ?? null,
    expectedArchiveSha256: preflightPlan?.expectedSha256 ?? null,
    expectedArchiveSource: preflightPlan?.source ?? null,
    discoveredInstalledState
  });

  if (local.outcome === "no-op") {
    logger.log("[docdex] Install outcome: no-op");
    return {
      binaryPath: local.binaryPath,
      outcome: local.outcome,
      integrityResult: local.integrityResult,
      verification: local.verification
    };
  }

  const repoSlug = preflightRepoSlug || parseRepoSlugFn();

  const { archive, expectedSha256, source, manifestAttempt } =
    preflightPlan ||
    (await resolveInstallerDownloadPlanFn({
      repoSlug,
      version,
      platformKey,
      targetTriple,
      logger
    }));
>>>>>>> mcoda/task/ops-01-us-06-t03

  const downloadUrl = `${getDownloadBaseFn(repoSlug)}/v${version}/${archive}`;
  const tmpDir = opts.tmpDir || osModule.tmpdir();
<<<<<<< HEAD
  const tmpFile = pathModule.join(tmpDir, `${archive}.${process.pid}.tgz`);
<<<<<<< HEAD
<<<<<<< HEAD
  const stageDir = pathModule.join(distBaseDir, `${platformKey}.staging.${process.pid}.${Date.now()}`);
  let tmpBinaryPath = null;
=======
  const installStagingPrefix = pathModule.join(distBaseDir, `.docdex-install-staging-${platformKey}-`);
  const downloadStagingPrefix = pathModule.join(tmpDir, `.docdex-download-staging-`);
  const extractDirName = "extract";
  const binaryFilename = isWin32 ? "docdexd.exe" : "docdexd";

  let downloadStagingDir = null;
  let downloadFilePath = null;
  let installStagingDir = null;
  let installExtractDir = null;
>>>>>>> mcoda/task/ops-01-us-05-t36

  emitInstallerEvent({
    logger,
    code: "DOCDEX_INSTALL_PLAN",
    message: "Resolved download plan",
    details: {
      attemptId,
      expectedVersion: version,
      platformKey,
      targetTriple,
      repoSlug,
      archive,
      source,
      downloadUrl,
      expectedSha256Present: Boolean(normalizeSha256Hex(expectedSha256)),
      manifestName: manifestAttempt?.manifestName ?? null,
      manifestVersion: manifestAttempt?.resolved?.manifestVersion ?? null,
      fallbackAttempted: Boolean(manifestAttempt?.fallbackAttempted)
    }
  });

  const resolutionEvents = Array.isArray(manifestAttempt?.events) ? manifestAttempt.events : [];
  for (const ev of resolutionEvents) {
    emitInstallerEvent({
      logger,
      level: typeof ev?.code === "string" && /(_FAILED|_UNUSABLE|_TOO_LARGE)$/.test(ev.code) ? "warn" : "info",
      code: typeof ev?.code === "string" ? ev.code : "DOCDEX_INSTALL_EVENT",
      message: typeof ev?.message === "string" ? ev.message : null,
      details: { attemptId, ...(ev?.details || {}) }
    });
  }
=======
  const { stagingDir, backupDir } = installSwapDirs(distDir);
  let stagingPrepared = false;
  let backupRenamed = false;
>>>>>>> mcoda/task/ops-01-us-05-t05

  logger.log(`[docdex] Fetching ${archive} for ${platformKey} (${targetTriple}) via ${source}...`);
  const abortController = new AbortController();
  let stageDir = null;
  let backupDir = null;
  let installCommitted = false;
  let cleanupOnce = null;

  const binaryFilename = isWin32 ? "docdexd.exe" : "docdexd";
  const finalBinaryPath = pathModule.join(distDir, binaryFilename);

  async function rollbackIfNeeded() {
    const existsSync = typeof fsModule?.existsSync === "function" ? fsModule.existsSync.bind(fsModule) : null;
    if (!existsSync) return;
    if (!backupDir || !existsSync(backupDir)) return;

    // If a new install dir exists, move it out of the way so we can restore the backup.
    if (existsSync(distDir)) {
      const failedDir = pathModule.join(distBaseDir, `${platformKey}.failed.${process.pid}.${Date.now()}`);
      try {
        await fsModule.promises.rename(distDir, failedDir);
      } catch {
        await rmRf(fsModule, distDir);
      }
      await rmRf(fsModule, failedDir);
    }

=======
  const binaryFilename = isWin32 ? "docdexd.exe" : "docdexd";
  const installAttemptId = `${process.pid}.${Date.now()}`;
  const stagingDir = pathModule.join(distBaseDir, `.${platformKey}.staging.${installAttemptId}`);
  const backupDir = pathModule.join(distBaseDir, `.${platformKey}.backup.${installAttemptId}`);

  const installAttempt = {
    schemaVersion: INSTALL_ATTEMPT_SCHEMA_VERSION,
    platformKey,
    targetTriple,
    distDir,
    binaryPath: pathModule.join(distDir, binaryFilename),
    tmpFile,
    stagingDir,
    backupDir,
    preflightRecovery,
    priorBinaryPath: local.binaryPath,
    priorBinaryAtStart: describeBinaryRunnability({ fsModule, binaryPath: local.binaryPath, isWin32 }),
    swap: { attempted: false, backupCreated: false, promoted: false },
    rollback: { attempted: false, restored: false, error: null, errorCode: null },
    cleanup: { tmpFile: null, stagingDir: null, backupDir: null },
    priorBinaryAfter: null,
    backupBinaryAfter: null
  };

  logger.log(`[docdex] Fetching ${archive} for ${platformKey} (${targetTriple}) via ${source}...`);
  let thrownError = null;
  try {
>>>>>>> mcoda/task/ops-01-us-05-t39
    try {
      await fsModule.promises.rename(backupDir, distDir);
    } catch {
      // If rollback fails, keep backupDir in place for a subsequent run to attempt recovery.
    }
  }

  async function cleanupArtifacts() {
    if (cleanupOnce) return cleanupOnce;
    cleanupOnce = (async () => {
      abortController.abort();
      if (!installCommitted) await rollbackIfNeeded();
      await rmRf(fsModule, stageDir);
      await rmFile(fsModule, tmpFile);
    })();
    return cleanupOnce;
  }

  const signalHandlers = [];
  const enableSignalHandlers = opts.enableSignalHandlers === true;
  if (enableSignalHandlers) {
    const register = (signal, exitCode) => {
      const handler = () => {
        logger.error(`[docdex] install interrupted (${signal}); cleaning up...`);
        cleanupArtifacts()
          .catch(() => {})
          .finally(() => process.exit(exitCode));
      };
      signalHandlers.push([signal, handler]);
      process.once(signal, handler);
    };
    register("SIGINT", 130);
    register("SIGTERM", 143);
    register("SIGHUP", 129);
  }

  try {
    if (typeof fsModule?.promises?.mkdtemp === "function") {
      try {
        downloadStagingDir = await fsModule.promises.mkdtemp(downloadStagingPrefix);
      } catch {
        downloadStagingDir = null;
      }
    }
    downloadFilePath = downloadStagingDir
      ? pathModule.join(downloadStagingDir, archive)
      : pathModule.join(tmpDir, `${archive}.${process.pid}.${Date.now()}.tgz`);

    try {
<<<<<<< HEAD
<<<<<<< HEAD
      await downloadFn(downloadUrl, downloadFilePath);
=======
      emitInstallerEvent({
        logger,
        code: "DOCDEX_INSTALL_DOWNLOAD_START",
        message: "Downloading release archive",
        details: { attemptId, downloadUrl, tmpFile, archive, source }
      });
      await downloadFn(downloadUrl, tmpFile);
      emitInstallerEvent({
        logger,
        code: "DOCDEX_INSTALL_DOWNLOAD_OK",
        message: "Downloaded release archive",
        details: { attemptId, downloadUrl, tmpFile, archive, source }
      });
>>>>>>> mcoda/task/ops-01-us-06-t15
=======
      await downloadFn(downloadUrl, tmpFile, { signal: abortController.signal });
>>>>>>> mcoda/task/ops-01-us-05-t37
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

<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
    const verifiedArchiveSha256 = await verifyDownloadedFileIntegrityFn({
=======
    const verifiedArchiveSha256 =
      (await verifyDownloadedFileIntegrityFn({
>>>>>>> mcoda/task/ops-01-us-06-t21
=======
    const candidateArchiveVerification = await verifyDownloadedFileIntegrityFn({
>>>>>>> mcoda/task/ops-01-us-06-t03
      filePath: tmpFile,
=======
    await verifyDownloadedFileIntegrityFn({
      filePath: downloadFilePath,
>>>>>>> mcoda/task/ops-01-us-05-t36
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
    })) || null;
=======
    let verifiedArchiveSha256 = null;
    try {
      verifiedArchiveSha256 = await verifyDownloadedFileIntegrityFn({
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

<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
      emitInstallerEvent({
        logger,
        code: "DOCDEX_INSTALL_INTEGRITY_ARCHIVE",
        message: "Downloaded archive integrity verification result",
        details: {
          attemptId,
          archive,
          downloadUrl,
          source,
          status: normalizeSha256Hex(expectedSha256) ? "verified_ok" : "skipped",
          expectedSha256: normalizeSha256Hex(expectedSha256) ? expectedSha256 : null,
          actualSha256: typeof verifiedArchiveSha256 === "string" ? verifiedArchiveSha256 : null,
          error: null
        }
      });
    } catch (err) {
      const isMismatch = err && err.code === "DOCDEX_INTEGRITY_MISMATCH";
      const expectedFromErr = normalizeSha256Hex(err?.details?.expectedSha256);
      const expectedFromInput = normalizeSha256Hex(expectedSha256);
      const actualFromErr = normalizeSha256Hex(err?.details?.actualSha256);
      emitInstallerEvent({
        logger,
        level: isMismatch ? "error" : "warn",
        code: "DOCDEX_INSTALL_INTEGRITY_ARCHIVE",
        message: "Downloaded archive integrity verification result",
        details: {
          attemptId,
          archive,
          downloadUrl,
          source,
          status: isMismatch ? "mismatch" : "unverifiable",
          expectedSha256: expectedFromErr ? err.details.expectedSha256 : expectedFromInput ? expectedSha256 : null,
          actualSha256: actualFromErr ? err.details.actualSha256 : null,
          error: err?.message || String(err)
        }
      });
      throw err;
    }
>>>>>>> mcoda/task/ops-01-us-06-t15

<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
    // Only replace an existing installation after we have successfully fetched + verified the archive.
    emitInstallerEvent({
      logger,
      code: "DOCDEX_INSTALL_REPLACE_START",
      message: "Replacing existing installation",
      details: { attemptId, distDir }
    });
    await fsModule.promises.rm(distDir, { recursive: true, force: true });
    await extractTarballFn(tmpFile, distDir);
<<<<<<< HEAD
=======
    const filename = isWin32 ? "docdexd.exe" : "docdexd";
    const finalBinaryPath = pathModule.join(distDir, filename);
    const previousBinarySha256 = fsModule.existsSync(finalBinaryPath)
      ? await sha256FileFn(finalBinaryPath).catch(() => null)
      : null;
>>>>>>> mcoda/task/ops-01-us-06-t20
=======
    emitInstallerEvent({
      logger,
      code: "DOCDEX_INSTALL_REPLACE_OK",
      message: "Extracted archive into dist directory",
      details: { attemptId, distDir }
    });
>>>>>>> mcoda/task/ops-01-us-06-t15

    // Only replace an existing installation after we have successfully fetched + verified the archive.
    const installResult = await installDocdexdBinaryAtomically({
      fsModule,
      pathModule,
      extractTarballFn,
      archivePath: tmpFile,
      distDir,
      isWin32,
      logger,
      errorDetails: {
=======
    // Staged/atomic install:
    // - Extract into a staging directory (not runnable via the wrapper)
    // - Validate expected binary exists
    // - Atomically rename into final location
    const stagedBinaryPath = pathModule.join(stageDir, isWin32 ? "docdexd.exe" : "docdexd");
    const binaryPath = pathModule.join(distDir, isWin32 ? "docdexd.exe" : "docdexd");
    tmpBinaryPath = pathModule.join(
      distDir,
      `${pathModule.basename(binaryPath)}.${process.pid}.${Date.now()}.new`
    );

    await extractTarballFn(tmpFile, stageDir);

    if (!fsModule.existsSync(stagedBinaryPath)) {
      throw new ArchiveInvalidError(`Downloaded archive missing binary at ${stagedBinaryPath}`, {
>>>>>>> mcoda/task/ops-01-us-05-t41
=======
    await fsModule.promises.mkdir(distBaseDir, { recursive: true });
    // Best-effort cleanup of stale staging dirs from interrupted installs.
    await cleanupStaleInstallerStagingDirs({
      fsModule,
      pathModule,
      distBaseDir,
      platformKey,
      maxAgeMs: 60 * 60 * 1000
    });

    installStagingDir = await fsModule.promises.mkdtemp(installStagingPrefix);
    installExtractDir = pathModule.join(installStagingDir, extractDirName);

    // Extract into a per-run staging directory; do not touch the final install location yet.
    await extractTarballFn(downloadFilePath, installExtractDir);

    const stagedBinaryPath = pathModule.join(installExtractDir, binaryFilename);
    if (!fsModule.existsSync(stagedBinaryPath)) {
      throw new ArchiveInvalidError(`Downloaded archive missing binary at ${stagedBinaryPath}`, {
>>>>>>> mcoda/task/ops-01-us-05-t36
=======
    // Stage the install under a side directory. A verified binary is only moved into place after staging succeeds.
    stageDir = pathModule.join(distBaseDir, `${platformKey}.staging.${process.pid}.${Date.now()}`);
    await fsModule.promises.rm(stageDir, { recursive: true, force: true }).catch(() => {});
    await fsModule.promises.mkdir(stageDir, { recursive: true, mode: 0o700 }).catch(async () => {
      await fsModule.promises.mkdir(stageDir, { recursive: true });
    });
    await extractTarballFn(tmpFile, stageDir);

    const stagedBinaryPath = pathModule.join(stageDir, binaryFilename);
    if (!fsModule.existsSync(stagedBinaryPath)) {
      throw new ArchiveInvalidError(`Downloaded archive missing binary at ${stagedBinaryPath}`, {
>>>>>>> mcoda/task/ops-01-us-05-t37
=======
    // Extract into a sibling staging directory first, then atomically swap into place.
    // This ensures a failed install does not remove a previously-working `docdexd`.
    await fsModule.promises.mkdir(distBaseDir, { recursive: true });
    await fsModule.promises.rm(stagingDir, { recursive: true, force: true }).catch(() => {});
    await extractTarballFn(tmpFile, stagingDir);

    const stagedBinaryPath = pathModule.join(stagingDir, binaryFilename);
    if (!fsModule.existsSync(stagedBinaryPath)) {
      throw new ArchiveInvalidError(`Downloaded archive missing binary at ${stagedBinaryPath}`, {
>>>>>>> mcoda/task/ops-01-us-05-t39
=======
    // Stage into a sentinel directory and only swap into place once the staged install is verified.
    await fsModule.promises.rm(stagingDir, { recursive: true, force: true }).catch(() => {});
    await fsModule.promises.mkdir(stagingDir, { recursive: true });
    stagingPrepared = true;
    await extractTarballFn(tmpFile, stagingDir);

    const stagedBinaryPath = binaryPathInDir({ pathModule, dirPath: stagingDir, isWin32 });
    if (!fsModule.existsSync(stagedBinaryPath)) {
      throw new ArchiveInvalidError(`Downloaded archive missing binary at ${stagedBinaryPath}`, {
>>>>>>> mcoda/task/ops-01-us-05-t05
        platformKey,
        targetTriple,
        version,
        repoSlug,
        assetName: archive,
        downloadUrl,
        source,
        manifestName: manifestAttempt?.manifestName ?? null,
        manifestVersion: manifestAttempt?.resolved?.manifestVersion ?? null,
<<<<<<< HEAD
<<<<<<< HEAD
        fallbackAttempted: source === "fallback"
      }
    });

    const binaryPath = installResult.binaryPath;
    const binarySha256 = await sha256FileFn(binaryPath);
<<<<<<< HEAD
<<<<<<< HEAD
    const installedAt = nowIso();
=======
    const binaryChanged = previousBinarySha256 ? previousBinarySha256 !== binarySha256 : true;
>>>>>>> mcoda/task/ops-01-us-06-t20
=======
    const resolvedIntegrity = typeof expectedSha256 === "string" ? expectedSha256 : null;
>>>>>>> mcoda/task/ops-01-us-06-t21
=======
        fallbackAttempted: source === "fallback",
        binaryPath: stagedBinaryPath
<<<<<<< HEAD
=======
    let swappedIntoPlace = false;
    try {
      await rmTreeQuiet(fsModule, incomingDir);
      await rmTreeQuiet(fsModule, backupDir);

      await extractTarballFn(tmpFile, incomingDir);

      const incomingBinaryPath = pathModule.join(incomingDir, isWin32 ? "docdexd.exe" : "docdexd");
      if (!fsModule.existsSync(incomingBinaryPath)) {
        throw new ArchiveInvalidError(`Downloaded archive missing binary at ${incomingBinaryPath}`, {
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
          binaryPath: incomingBinaryPath
        });
      }

      await fsModule.promises.chmod(incomingBinaryPath, 0o755).catch(() => {});

      const binarySha256 = await sha256FileFn(incomingBinaryPath);
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
      await writeJsonFileAtomicFn({
        fsModule,
        pathModule,
        filePath: installMetadataPath(incomingDir, pathModule),
        value: metadata
>>>>>>> mcoda/task/ops-01-us-05-t40
      });

<<<<<<< HEAD
<<<<<<< HEAD
    await fsModule.promises.chmod(stagedBinaryPath, 0o755).catch(() => {});
    const binarySha256 = await sha256FileFn(stagedBinaryPath);
<<<<<<< HEAD

    await fsModule.promises.mkdir(distDir, { recursive: true });
    await fsModule.promises.rename(stagedBinaryPath, tmpBinaryPath);
    await fsModule.promises.rename(tmpBinaryPath, binaryPath);
    await fsModule.promises.chmod(binaryPath, 0o755).catch(() => {});
    tmpBinaryPath = null;
    logger.log(`[docdex] Installed binary to ${binaryPath}`);

>>>>>>> mcoda/task/ops-01-us-05-t41
=======
>>>>>>> mcoda/task/ops-01-us-05-t36
=======
    // Ensure staged binaries are not runnable; add exec bits only after an atomic swap into the final location.
    if (!isWin32) {
      await fsModule.promises.chmod(stagedBinaryPath, 0o644).catch(() => {});
    }

    const binarySha256 = await sha256FileFn(stagedBinaryPath);
>>>>>>> mcoda/task/ops-01-us-05-t37
=======
        fallbackAttempted: source === "fallback",
        binaryPath: stagedBinaryPath
=======
>>>>>>> mcoda/task/ops-01-us-05-t05
      });
    }

    await fsModule.promises.chmod(stagedBinaryPath, 0o755).catch(() => {});

    const binarySha256 = await sha256FileFn(stagedBinaryPath);
<<<<<<< HEAD
>>>>>>> mcoda/task/ops-01-us-05-t39
=======
>>>>>>> mcoda/task/ops-01-us-05-t05
    const metadata = {
      schemaVersion: INSTALL_METADATA_SCHEMA_VERSION,
<<<<<<< HEAD
      installedVersion: version,
      expectedVersion: version,
      platformKey,
      targetTriple,
      binaryPath,
      binaryHash: binarySha256,
      provenance: {
        repoSlug,
        releaseTag: `v${version}`,
        releaseId: null,
        assetName: archive,
        assetUrl: downloadUrl,
        assetSha256: normalizeSha256Hex(expectedSha256),
=======
      installedAt,
      expectedVersion: version,
      installedVersion: version,
      version,
      lastOutcome: local.outcome,
      lastOutcomeReason: local.reason,
      lastOutcomeAt: installedAt,
      repoSlug,
      platformKey,
      targetTriple,
      sourceUri: downloadUrl,
      binary: {
        filename: binaryFilename,
        sha256: binarySha256
      },
      archive: {
        assetId,
        name: archive,
<<<<<<< HEAD
        sha256: expectedSha256 || null,
<<<<<<< HEAD
        verifiedSha256: typeof verifiedArchiveSha256 === "string" ? verifiedArchiveSha256 : null,
>>>>>>> mcoda/task/ops-01-us-06-t29
=======
        verifiedSha256:
          candidateArchiveVerification && typeof candidateArchiveVerification.actualSha256 === "string"
            ? candidateArchiveVerification.actualSha256
            : null,
>>>>>>> mcoda/task/ops-01-us-06-t03
        source,
        manifestName: manifestAttempt?.manifestName ?? null,
        manifestVersion: manifestAttempt?.resolved?.manifestVersion ?? null
      },
      installedAt,
      lastVerifiedAt: installedAt
=======
        sha256: resolvedIntegrity,
        source,
        downloadUrl,
        integrity: {
          method: resolvedIntegrity ? "sha256" : null,
          expectedSha256: resolvedIntegrity,
          actualSha256: verifiedArchiveSha256,
          verifiedAt: resolvedIntegrity ? nowIso() : null,
          sourceType: resolvedIntegrityPlan?.sourceType ?? null,
          sourceName: resolvedIntegrityPlan?.sourceName ?? null,
          sourceUrl: resolvedIntegrityPlan?.sourceUrl ?? null
        }
      }
>>>>>>> mcoda/task/ops-01-us-06-t21
    };
    const stagedMetadataPath = installMetadataPath(installExtractDir, pathModule);
    await writeJsonFileAtomic({
=======
    // Do not touch the existing install until we have a fully-extracted, verified, ready-to-swap staging directory.
    const { binaryPath } = await installVerifiedArchiveAtomically({
>>>>>>> mcoda/task/ops-01-us-06-t35
      fsModule,
      pathModule,
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
      logger,
      archivePath: tmpFile,
      distDir,
      platformKey,
      targetTriple,
      version,
      repoSlug,
      archiveName: archive,
      expectedSha256,
      source,
      downloadUrl,
      manifestAttempt,
      isWin32,
      extractTarballFn,
      sha256FileFn
    });

<<<<<<< HEAD
<<<<<<< HEAD
    const report = buildInstallOutcomeReport({
      decision: local,
      expectedVersion: version,
      platformKey,
      targetTriple,
      repoSlug,
      archive,
      downloadUrl,
      source
    });
    emitInstallOutcomeReport(report, { logger: noisyLogger, outputFormat });
    return {
      binaryPath,
      outcome: local.outcome,
      outcomeCode: report.code,
      outcomeMessage: report.message,
      decisionReason: local.reason
    };
=======
    logger.log(`[docdex] Install outcome: ${local.outcome}`);
<<<<<<< HEAD
<<<<<<< HEAD
    return { binaryPath, outcome: local.outcome, plan: local.plan };
>>>>>>> mcoda/task/ops-01-us-06-t37
=======
    return {
      binaryPath,
      outcome: local.outcome,
      reason: local.reason,
      previousVersion: local.installedVersion,
      expectedVersion: version,
      finalVersion: version
    };
>>>>>>> mcoda/task/ops-01-us-06-t40
=======
    const restartDaemonFn = opts.restartDaemonFn;
    const restartResult =
      binaryChanged && typeof restartDaemonFn === "function"
        ? await restartDaemonFn({
            logger,
            binaryPath,
            platformKey,
            targetTriple,
            version,
            repoSlug,
            outcome: local.outcome
          })
        : binaryChanged
          ? await restartDaemonIfConfigured({ logger, env: opts.env || process.env })
          : { attempted: false, status: "skipped", reason: "binary_unchanged" };

    logger.log(`[docdex] Install outcome: ${local.outcome}`);
    return { binaryPath, outcome: local.outcome, restart: restartResult };
>>>>>>> mcoda/task/ops-01-us-06-t20
=======
    logger.log(`[docdex] Install decision: ${JSON.stringify(local.decision)}`);
    return { binaryPath, outcome: local.outcome, action: local.action, decision: local.decision };
>>>>>>> mcoda/task/ops-01-us-06-t02
  } finally {
    await fsModule.promises.rm(tmpFile, { force: true }).catch(() => {});
    await fsModule.promises.rm(stageDir, { recursive: true, force: true }).catch(() => {});
    if (tmpBinaryPath) {
      await fsModule.promises.rm(tmpBinaryPath, { force: true }).catch(() => {});
=======
      filePath: stagedMetadataPath,
      value: metadata
    });

    // Atomic commit: only after verification + staged extraction succeed do we update the final install location.
    await fsModule.promises.mkdir(distDir, { recursive: true });
    const finalBinaryPath = pathModule.join(distDir, binaryFilename);
    const finalMetadataPath = installMetadataPath(distDir, pathModule);

    await fsModule.promises.rename(stagedBinaryPath, finalBinaryPath);
    await fsModule.promises.rename(stagedMetadataPath, finalMetadataPath);
    await fsModule.promises.chmod(finalBinaryPath, 0o755).catch(() => {});
    logger.log(`[docdex] Installed binary to ${finalBinaryPath}`);

    logger.log(`[docdex] Install outcome: ${local.outcome}`);
<<<<<<< HEAD
<<<<<<< HEAD
    return { binaryPath: finalBinaryPath, outcome: local.outcome };
=======
    emitInstallerEvent({
      logger,
      code: "DOCDEX_INSTALL_METADATA_WRITTEN",
      message: "Wrote install metadata",
      details: {
        attemptId,
        metadataPath: installMetadataPath(distDir, pathModule),
        binaryPath,
        version,
        platformKey,
        targetTriple,
        binarySha256
      }
    });

    emitInstallerEvent({
      logger,
      code: "DOCDEX_INSTALL_OUTCOME",
      message: "Install completed",
      details: {
        attemptId,
        outcome: local.outcome,
        outcomeCode: localOutcomeCode,
        reason: local.reason,
        binaryPath,
        metadataPath: installMetadataPath(distDir, pathModule),
        downloadAttempted: true
      }
    });

    return { binaryPath, outcome: local.outcome, outcomeCode: localOutcomeCode };
>>>>>>> mcoda/task/ops-01-us-06-t15
=======
    return {
      binaryPath,
      outcome: local.outcome,
      verification: {
        ...local.verification,
        candidateArchive: candidateArchiveVerification
      }
    };
>>>>>>> mcoda/task/ops-01-us-06-t03
=======
      await rmTreeQuiet(fsModule, backupDir);
      if (fsModule.existsSync(distDir)) {
        await fsModule.promises.rename(distDir, backupDir);
      }

      try {
        await fsModule.promises.rename(incomingDir, distDir);
        swappedIntoPlace = true;
      } catch (err) {
        try {
          if (fsModule.existsSync(backupDir) && !fsModule.existsSync(distDir)) {
            await fsModule.promises.rename(backupDir, distDir);
          }
        } catch {
          // Best-effort rollback only.
        }
        throw err;
      }

      await rmTreeQuiet(fsModule, backupDir);

      const binaryPath = pathModule.join(distDir, isWin32 ? "docdexd.exe" : "docdexd");
      logger.log(`[docdex] Installed binary to ${binaryPath}`);
      logger.log(`[docdex] Install outcome: ${local.outcome}`);
      return { binaryPath, outcome: local.outcome };
    } catch (err) {
      if (!swappedIntoPlace) {
        await rmTreeQuiet(fsModule, incomingDir);
      }
      throw err;
    }
>>>>>>> mcoda/task/ops-01-us-05-t40
  } finally {
    if (installStagingDir) {
      await fsModule.promises.rm(installStagingDir, { recursive: true, force: true }).catch(() => {});
    }
    if (downloadStagingDir) {
      await fsModule.promises.rm(downloadStagingDir, { recursive: true, force: true }).catch(() => {});
    } else if (downloadFilePath) {
      await fsModule.promises.rm(downloadFilePath, { force: true }).catch(() => {});
>>>>>>> mcoda/task/ops-01-us-05-t36
    }
=======
      filePath: installMetadataPath(stageDir, pathModule),
      value: metadata
    });

    // Atomic-ish directory swap: keep existing distDir intact until staging is complete.
    const existsSync = typeof fsModule?.existsSync === "function" ? fsModule.existsSync.bind(fsModule) : null;
    if (!existsSync) throw new Error("fs existsSync unavailable");
    await fsModule.promises.mkdir(distBaseDir, { recursive: true }).catch(() => {});

    if (existsSync(distDir)) {
      backupDir = pathModule.join(distBaseDir, `${platformKey}.backup.${process.pid}.${Date.now()}`);
      await fsModule.promises.rm(backupDir, { recursive: true, force: true }).catch(() => {});
      await fsModule.promises.rename(distDir, backupDir);
    }

    try {
      await fsModule.promises.rename(stageDir, distDir);
      stageDir = null;
    } catch (err) {
      await rollbackIfNeeded();
      throw err;
    }

    // Now that the verified binary is in its final location, set executable permissions.
    if (!isWin32) {
      try {
        await fsModule.promises.chmod(finalBinaryPath, 0o755);
      } catch (err) {
        await rollbackIfNeeded();
        throw err;
      }
    }

    // Commit: cleanup backup only after the final binary is runnable.
    installCommitted = true;
    await rmRf(fsModule, backupDir);
    backupDir = null;

    logger.log(`[docdex] Installed binary to ${finalBinaryPath}`);
    logger.log(`[docdex] Install outcome: ${local.outcome}`);
    return { binaryPath: finalBinaryPath, outcome: local.outcome };
  } finally {
    for (const [signal, handler] of signalHandlers) {
      process.removeListener(signal, handler);
    }
    await cleanupArtifacts().catch(() => {});
>>>>>>> mcoda/task/ops-01-us-05-t37
=======
      filePath: installMetadataPath(stagingDir, pathModule),
      value: metadata
    });

    const distDirExists = typeof fsModule?.existsSync === "function" ? fsModule.existsSync(distDir) : false;
    installAttempt.swap.attempted = true;
    if (distDirExists) {
      await fsModule.promises.rm(backupDir, { recursive: true, force: true }).catch(() => {});
      const backupMove = await safeRename({ fsModule, from: distDir, to: backupDir });
      if (!backupMove.ok) {
        const err = new Error(`Failed to move existing installation into backup: ${backupMove.error}`);
        err.code = backupMove.errorCode || "DOCDEX_INSTALL_SWAP_FAILED";
        throw err;
      }
      installAttempt.swap.backupCreated = true;
    }

    const promote = await safeRename({ fsModule, from: stagingDir, to: distDir });
    if (!promote.ok) {
      const err = new Error(`Failed to promote staged installation: ${promote.error}`);
      err.code = promote.errorCode || "DOCDEX_INSTALL_SWAP_FAILED";
      throw err;
    }
    installAttempt.swap.promoted = true;

    const binaryPath = pathModule.join(distDir, binaryFilename);
    logger.log(`[docdex] Installed binary to ${binaryPath}`);

    if (installAttempt.swap.backupCreated) {
      const removed = await safeRm({ fsModule, targetPath: backupDir, options: { recursive: true, force: true } });
      installAttempt.cleanup.backupDir = removed;
      if (!removed.removed) {
        logger.warn(
          `[docdex] Warning: could not remove installer backup dir (${backupDir}): ${removed.error || "unknown error"}`
        );
      }
    }

    logger.log(`[docdex] Install outcome: ${local.outcome}`);
    return { binaryPath, outcome: local.outcome };
  } catch (err) {
    thrownError = err;
=======
      filePath: installMetadataPath(stagingDir, pathModule),
      value: metadata
    });

    await fsModule.promises.rm(backupDir, { recursive: true, force: true }).catch(() => {});
    if (fsModule.existsSync(distDir)) {
      await fsModule.promises.rename(distDir, backupDir);
      backupRenamed = true;
    }
    try {
      await fsModule.promises.rename(stagingDir, distDir);
    } catch (err) {
      await fsModule.promises.rm(stagingDir, { recursive: true, force: true }).catch(() => {});
      if (fsModule.existsSync(backupDir) && !fsModule.existsSync(distDir)) {
        await fsModule.promises.rename(backupDir, distDir).catch(() => {});
      }
      throw err;
    }
    await fsModule.promises.rm(backupDir, { recursive: true, force: true }).catch(() => {});

    const binaryPath = binaryPathInDir({ pathModule, dirPath: distDir, isWin32 });
    logger.log(`[docdex] Installed binary to ${binaryPath}`);

    logger.log(`[docdex] Install outcome: ${local.outcome}`);
    return { binaryPath, outcome: local.outcome };
  } catch (err) {
    if (stagingPrepared) {
      await fsModule.promises.rm(stagingDir, { recursive: true, force: true }).catch(() => {});
    }
    if (backupRenamed && fsModule.existsSync(backupDir) && !fsModule.existsSync(distDir)) {
      await fsModule.promises.rename(backupDir, distDir).catch(() => {});
    }
>>>>>>> mcoda/task/ops-01-us-05-t05
    throw err;
  } finally {
    installAttempt.cleanup.tmpFile = await safeRm({ fsModule, targetPath: tmpFile, options: { force: true } });

    const backupBinaryPath = pathModule.join(backupDir, binaryFilename);

    if (thrownError && installAttempt.swap.backupCreated && !installAttempt.swap.promoted) {
      // If we moved the existing install to backup but failed to promote the staged install,
      // try to restore the previous installation back to its original location.
      installAttempt.rollback.attempted = true;
      const distMissing = typeof fsModule?.existsSync === "function" ? !fsModule.existsSync(distDir) : true;
      const backupExists = typeof fsModule?.existsSync === "function" ? fsModule.existsSync(backupDir) : false;
      if (distMissing && backupExists) {
        const rollback = await safeRename({ fsModule, from: backupDir, to: distDir });
        installAttempt.rollback.restored = rollback.ok;
        installAttempt.rollback.error = rollback.ok ? null : rollback.error;
        installAttempt.rollback.errorCode = rollback.ok ? null : rollback.errorCode;
      } else {
        installAttempt.rollback.restored = false;
        if (!distMissing) {
          installAttempt.rollback.error = "rollback_skipped_dist_present";
        } else if (!backupExists) {
          installAttempt.rollback.error = "rollback_skipped_backup_missing";
        } else {
          installAttempt.rollback.error = "rollback_skipped_unknown";
        }
        installAttempt.rollback.errorCode = null;
      }
    }

    // Cleanup staged artifacts on failure so partially-extracted binaries are not left runnable.
    if (thrownError) {
      installAttempt.cleanup.stagingDir = await safeRm({
        fsModule,
        targetPath: stagingDir,
        options: { recursive: true, force: true }
      });
    }

    // Record final state for error reporting.
    installAttempt.priorBinaryAfter = describeBinaryRunnability({ fsModule, binaryPath: local.binaryPath, isWin32 });
    installAttempt.backupBinaryAfter = describeBinaryRunnability({ fsModule, binaryPath: backupBinaryPath, isWin32 });

    if (thrownError) {
      if (!thrownError.details || typeof thrownError.details !== "object") thrownError.details = {};
      thrownError.details.installAttempt = installAttempt;
    }
>>>>>>> mcoda/task/ops-01-us-05-t39
  }
}

async function main() {
  await runInstaller({ enableSignalHandlers: true });
}

function describeFatalError(err) {
  const fallbackAttempted =
    err && typeof err.details?.fallbackAttempted === "boolean" ? err.details.fallbackAttempted : null;

  function withInstallAttemptLines(report) {
    const attempt = err && err.details && err.details.installAttempt;
    if (!attempt || typeof attempt !== "object") return report;

    const lines = Array.isArray(report.lines) ? report.lines.slice() : [];

    const priorAtStart = attempt.priorBinaryAtStart || null;
    const priorAfter = attempt.priorBinaryAfter || null;
    const priorBinaryPath =
      typeof attempt.priorBinaryPath === "string" && attempt.priorBinaryPath ? attempt.priorBinaryPath : null;

    const backupAfter = attempt.backupBinaryAfter || null;

    function preflightLabel() {
      const r = attempt.preflightRecovery;
      if (!r || typeof r !== "object") return "unknown";
      if (r.attempted === false) return r.reason ? `not attempted (${r.reason})` : "not attempted";
      if (r.restored) return r.from ? `restored from ${r.from}` : "restored";
      if (r.reason === "dist_present") return "not needed";
      if (r.reason === "no_backup_candidates") return "no backup found";
      if (r.reason === "restore_failed") {
        const bits = [];
        bits.push("restore failed");
        if (r.errorCode) bits.push(String(r.errorCode));
        if (r.from) bits.push(`from ${r.from}`);
        return bits.join(" ");
      }
      if (typeof r.reason === "string" && r.reason) return r.reason;
      return "unknown";
    }

    function rollbackLabel() {
      const r = attempt.rollback;
      if (!r || typeof r !== "object") return "unknown";
      if (r.attempted === false) return attempt.swap?.backupCreated ? "not attempted" : "not needed";
      if (r.restored) return "restored previous installation";
      if (typeof r.error === "string" && r.error.startsWith("rollback_skipped_")) {
        if (r.error === "rollback_skipped_dist_present") return "skipped (install dir already present)";
        if (r.error === "rollback_skipped_backup_missing") return "skipped (backup dir missing)";
        return "skipped";
      }
      const bits = ["failed"];
      if (r.errorCode) bits.push(`(${r.errorCode})`);
      return bits.join(" ");
    }

    function cleanupLabel(kind, record, fallbackPath) {
      if (!record || typeof record !== "object" || record.attempted !== true) return null;
      if (record.removed) return `${kind}: cleaned`;
      const bits = [`${kind}: left at ${fallbackPath || "unknown"}`];
      if (record.errorCode) bits.push(`(${record.errorCode})`);
      return bits.join(" ");
    }

    const cleanupBits = [
      cleanupLabel("download temp", attempt.cleanup?.tmpFile, attempt.tmpFile),
      cleanupLabel("staging dir", attempt.cleanup?.stagingDir, attempt.stagingDir)
    ].filter(Boolean);

    const backupHint =
      backupAfter?.exists === true && attempt.backupDir
        ? `[docdex] - Backup dir still present: ${attempt.backupDir} (prior docdexd runnable: ${yesNoUnknown(
            backupAfter?.runnable
          )})`
        : null;

    lines.push("[docdex] Install safety status:");
    lines.push(`[docdex] - Preflight recovery: ${preflightLabel()}`);
    lines.push(`[docdex] - Rollback: ${rollbackLabel()}`);
    lines.push(`[docdex] - Prior docdexd runnable at start: ${yesNoUnknown(priorAtStart?.runnable)}`);
    lines.push(
      priorBinaryPath
        ? `[docdex] - Prior docdexd runnable after failure: ${yesNoUnknown(priorAfter?.runnable)} (path: ${priorBinaryPath})`
        : `[docdex] - Prior docdexd runnable after failure: ${yesNoUnknown(priorAfter?.runnable)}`
    );
    if (cleanupBits.length) lines.push(`[docdex] - Cleanup: ${cleanupBits.join("; ")}`);
    if (backupHint) lines.push(backupHint);

    return { ...report, lines };
  }

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

    return withInstallAttemptLines({
      code: err.code,
      exitCode: err.exitCode || EXIT_CODE_BY_ERROR_CODE[err.code] || 1,
      details: withBaseDetails(err.details),
      lines: [
        `[docdex] install failed: unsupported platform (${detected})`,
        `[docdex] error code: ${err.code}`,
        `[docdex] Detected platform: ${detected}`,
        "[docdex] No download was attempted for this platform (and no binary was installed).",
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
    });
  }

  if (err instanceof InstallerConfigError) {
    return withInstallAttemptLines({
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
    });
  }

  if (err instanceof MissingArtifactError) {
    const detectedOs =
      err.details?.detected && typeof err.details.detected === "object"
        ? err.details.detected.os ?? err.details.detected.platform
        : null;
    const detectedArch =
      err.details?.detected && typeof err.details.detected === "object" ? err.details.detected.arch : null;
    const detected =
      typeof detectedOs === "string" && detectedOs && typeof detectedArch === "string" && detectedArch
        ? `${detectedOs}/${detectedArch}`
        : null;
    const platformKey = typeof err.details?.platformKey === "string" ? err.details.platformKey : null;
    let expectedTargetTriple =
      typeof err.details?.targetTriple === "string" && err.details.targetTriple.trim()
        ? err.details.targetTriple.trim()
        : null;
    if (!expectedTargetTriple && platformKey) {
      try {
        expectedTargetTriple = targetTripleForPlatformKey(platformKey);
      } catch {}
    }
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
    return withInstallAttemptLines({
      code: err.code,
      exitCode: err.exitCode || EXIT_CODE_BY_ERROR_CODE[err.code] || 1,
      details: withBaseDetails(err.details),
      lines: [
        "[docdex] install failed: missing artifact/version sync issue (release asset not found)",
        `[docdex] error code: ${err.code}`,
        detected ? `[docdex] Detected platform: ${detected}` : null,
        err.details?.platformKey ? `[docdex] Platform key: ${err.details.platformKey}` : null,
        expectedTargetTriple ? `[docdex] Expected target triple: ${expectedTargetTriple}` : null,
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
    });
  }

  if (err instanceof ChecksumResolutionError) {
    const checksumCandidates = Array.isArray(err.details?.checksumCandidates) ? err.details.checksumCandidates : [];
    return withInstallAttemptLines({
      code: err.code,
      exitCode: err.exitCode || EXIT_CODE_BY_ERROR_CODE[err.code] || 1,
      details: withBaseDetails(err.details),
      lines: [
        `[docdex] install failed: ${err.message}`,
        `[docdex] error code: ${err.code}`,
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
    });
  }

  if (err instanceof DownloadError) {
    return withInstallAttemptLines({
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
    });
  }

  if (err instanceof IntegrityMismatchError) {
    const expectedSha256 = typeof err.details?.expectedSha256 === "string" ? err.details.expectedSha256 : null;
    const actualSha256 = typeof err.details?.actualSha256 === "string" ? err.details.actualSha256 : null;
    return withInstallAttemptLines({
      code: err.code,
      exitCode: err.exitCode || EXIT_CODE_BY_ERROR_CODE[err.code] || 1,
      details: withBaseDetails(err.details),
      lines: [
        `[docdex] install failed: ${err.message}`,
        `[docdex] error code: ${err.code}`,
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
    });
  }

  if (err instanceof ArchiveInvalidError) {
    return withInstallAttemptLines({
      code: err.code,
      exitCode: err.exitCode || EXIT_CODE_BY_ERROR_CODE[err.code] || 1,
      details: withBaseDetails(err.details),
      lines: [
        `[docdex] install failed: ${err.message}`,
        `[docdex] error code: ${err.code}`,
        err.details?.binaryPath ? `[docdex] Expected binary path: ${err.details.binaryPath}` : null
      ].filter(Boolean)
    });
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
    return withInstallAttemptLines({
      code: err.code,
      exitCode: err.exitCode || EXIT_CODE_BY_ERROR_CODE[err.code] || 1,
      details: withBaseDetails(err.details),
      lines
    });
  }

  const code = (err && typeof err.code === "string" && err.code) || "DOCDEX_INSTALL_FAILED";
  return withInstallAttemptLines({
    code,
    exitCode: (err && typeof err.exitCode === "number" && err.exitCode) || EXIT_CODE_BY_ERROR_CODE[code] || 1,
    details: withBaseDetails(err && err.details),
    lines: [`[docdex] install failed: ${err?.message || "unknown error"}`, `[docdex] error code: ${code}`]
  });
}

function handleFatal(err) {
  const report = describeFatalError(err);
  const outputFormat = normalizeInstallerOutputFormat(process.env.DOCDEX_INSTALLER_OUTPUT);
  if (outputFormat === "json") {
    const payload = {
      schemaVersion: 1,
      kind: "docdex_installer_error",
      timestamp: nowIso(),
      code: report.code,
      exitCode: report.exitCode || 1,
      details: report.details,
      lines: report.lines
    };
    console.log(JSON.stringify(payload));
    process.exit(payload.exitCode);
  }

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
  readInstalledDocdexdVersion,
  parseDocdexdVersionOutput,
  verifyInstalledDocdexdIntegrity,
  decideInstallDecision,
  decideInstallAction,
  determineLocalInstallerOutcome,
  verifyDownloadedFileIntegrity,
  MissingArtifactError,
  ChecksumResolutionError,
<<<<<<< HEAD
  buildInstallOutcomeReport,
=======
  recoverInterruptedInstall,
  recoverInterruptedInstallSync,
>>>>>>> mcoda/task/ops-01-us-05-t05
  runInstaller,
  describeFatalError,
  handleFatal
};
