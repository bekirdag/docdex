#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const https = require("node:https");
const os = require("node:os");
const path = require("node:path");
const { pipeline } = require("node:stream/promises");
const crypto = require("node:crypto");

const pkg = require("../package.json");
const { artifactName, detectPlatformKey, targetTripleForPlatformKey, UnsupportedPlatformError } = require("./platform");
const { ManifestResolutionError, resolveCanonicalAssetForTargetTriple } = require("./release_manifest");

const MAX_REDIRECTS = 5;
const USER_AGENT = "docdex-installer";
const PLACEHOLDER_REPO_TOKEN = /OWNER|REPO/i;
const MAX_MANIFEST_BYTES = 1024 * 1024; // 1 MiB cap for safety
const INVALID_JSON_ERROR = "invalid JSON";

const EXIT_CODE_BY_ERROR_CODE = Object.freeze({
  DOCDEX_INSTALLER_CONFIG: 2,
  DOCDEX_UNSUPPORTED_PLATFORM: 3,
  DOCDEX_MANIFEST_MALFORMED: 10,
  DOCDEX_TARGET_TRIPLE_INVALID: 11,
  DOCDEX_ASSET_NO_MATCH: 12,
  DOCDEX_ASSET_MULTI_MATCH: 13,
  DOCDEX_ASSET_MALFORMED: 14,
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

function manifestCandidateNames() {
  const envNames = process.env.DOCDEX_MANIFEST_NAMES || process.env.DOCDEX_MANIFEST_NAME;
  if (envNames) {
    return envNames
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean);
  }

  // Assumption (documented by code): release attaches one of these filenames.
  return ["docdexd-manifest.json", "docdex-manifest.json", "manifest.json"];
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
  manifestCandidateNamesFn = manifestCandidateNames
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
        expectedAssetPattern: `docdexd-<platformKey>.tar.gz (e.g. ${expectedAsset})`
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
    const shaUrl = `${getDownloadBaseFn(repoSlug)}/v${version}/${archive}.sha256`;
    try {
      const shaText = await downloadTextFn(shaUrl);
      expectedSha256 = parseSha256File(shaText, archive);
      if (!expectedSha256) {
        logger.warn(
          `[docdex] [DOCDEX_CHECKSUM_PARSE_FAILED] Could not parse SHA-256 from ${archive}.sha256; continuing without integrity check.`
        );
      }
    } catch (e) {
      if (e && typeof e.statusCode === "number" && e.statusCode === 404) {
        logger.warn(`[docdex] [DOCDEX_CHECKSUM_MISSING] Missing ${archive}.sha256; continuing without integrity check.`);
      } else {
        logger.warn(
          `[docdex] [DOCDEX_CHECKSUM_FETCH_FAILED] Failed to fetch ${archive}.sha256; continuing without integrity check: ${e.message}`
        );
      }
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

async function main() {
  const platformKey = detectPlatformKey();
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const version = getVersion();
  const repoSlug = parseRepoSlug();

  const { archive, expectedSha256, source, manifestAttempt } = await resolveInstallerDownloadPlan({
    repoSlug,
    version,
    platformKey,
    targetTriple,
    logger: console
  });

  const downloadUrl = `${getDownloadBase(repoSlug)}/v${version}/${archive}`;
  const distDir = path.join(__dirname, "..", "dist", platformKey);
  const tmpFile = path.join(os.tmpdir(), `${archive}.${process.pid}.tgz`);

  console.log(`[docdex] Fetching ${archive} for ${platformKey} (${targetTriple}) via ${source}...`);
  try {
    try {
      await download(downloadUrl, tmpFile);
    } catch (err) {
      if (err && typeof err.statusCode === "number" && err.statusCode === 404) {
        const fallbackReason = manifestAttempt?.errors?.length ? "manifest_unavailable" : "manifest_not_found";
        throw new MissingArtifactError({
          detected: { os: process.platform, arch: process.arch },
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
          expectedAssetPattern: `docdexd-<platformKey>.tar.gz (e.g. ${artifactName(platformKey)})`,
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

    await verifyDownloadedFileIntegrity({
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
    await fs.promises.rm(distDir, { recursive: true, force: true });
    await extractTarball(tmpFile, distDir);

    const binaryPath = path.join(distDir, process.platform === "win32" ? "docdexd.exe" : "docdexd");
    if (!fs.existsSync(binaryPath)) {
      throw new ArchiveInvalidError(`Downloaded archive missing binary at ${binaryPath}`, {
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
        binaryPath
      });
    }

    await fs.promises.chmod(binaryPath, 0o755).catch(() => {});
    console.log(`[docdex] Installed binary to ${binaryPath}`);
  } finally {
    await fs.promises.rm(tmpFile, { force: true }).catch(() => {});
  }
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
        err.details?.expectedAssetPattern ? `[docdex] Asset naming pattern: ${err.details.expectedAssetPattern}` : null,
        err.details?.downloadUrl ? `[docdex] URL tried: ${err.details.downloadUrl}` : null,
        err.details?.note ? `[docdex] Note: ${err.details.note}` : null,
        "[docdex] Next steps:",
        "[docdex] - Confirm the GitHub Release for this version contains the expected asset for your target.",
        "[docdex] - If installing from a fork, set `DOCDEX_DOWNLOAD_REPO=<owner/repo>` to the repo that hosts the assets.",
        "[docdex] - Workaround: install a version with matching assets, or build from source (`cargo build --release --locked`)."
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
          ? `docdexd-<platformKey>.tar.gz (e.g. ${artifactName(platformKey)})`
          : "docdexd-<platformKey>.tar.gz";

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
  manifestCandidateNames,
  tryResolveAssetViaManifest,
  resolveInstallerDownloadPlan,
  parseSha256File,
  sha256File,
  verifyDownloadedFileIntegrity,
  MissingArtifactError,
  describeFatalError,
  handleFatal
};
