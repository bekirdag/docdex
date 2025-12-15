#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const https = require("node:https");
const os = require("node:os");
const path = require("node:path");
const { pipeline } = require("node:stream/promises");
const crypto = require("node:crypto");
const tar = require("tar");

const pkg = require("../package.json");
const { artifactName, detectPlatformKey, detectTargetTriple } = require("./platform");
const { ManifestResolutionError, resolveCanonicalAssetForTargetTriple } = require("./release_manifest");

const MAX_REDIRECTS = 5;
const USER_AGENT = "docdex-installer";
const PLACEHOLDER_REPO_TOKEN = /OWNER|REPO/i;
const MAX_MANIFEST_BYTES = 1024 * 1024; // 1 MiB cap for safety

function parseRepoSlug() {
  const envRepo = process.env.DOCDEX_DOWNLOAD_REPO;
  if (envRepo) return envRepo;

  const repoUrl = pkg.repository?.url || "";
  const match = repoUrl.match(/github\.com[:/](.+?)(\.git)?$/);

  if (match && match[1] && !PLACEHOLDER_REPO_TOKEN.test(match[1])) {
    return match[1];
  }

  throw new Error("Set DOCDEX_DOWNLOAD_REPO env var or update package.json repository.url to owner/repo");
}

function getDownloadBase(repoSlug) {
  return process.env.DOCDEX_DOWNLOAD_BASE || `https://github.com/${repoSlug}/releases/download`;
}

function getVersion() {
  const envVersion = process.env.DOCDEX_VERSION;
  const version = (envVersion || pkg.version || "").replace(/^v/, "");

  if (!version) {
    throw new Error("Missing package version; set DOCDEX_VERSION or package.json version");
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
          return reject(err);
        }

        const chunks = [];
        let total = 0;
        res.on("data", (chunk) => {
          total += chunk.length;
          if (total > MAX_MANIFEST_BYTES) {
            res.destroy(new Error(`Response too large while fetching ${url} (>${MAX_MANIFEST_BYTES} bytes)`));
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
          return reject(new Error(`Download failed (${res.statusCode}) from ${url}`));
        }

        const file = fs.createWriteStream(dest);
        pipeline(res, file).then(resolve).catch(reject);
      })
      .on("error", reject);
  });
}

async function extractTarball(archivePath, targetDir) {
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

async function tryResolveAssetViaManifest({ repoSlug, version, targetTriple }) {
  const base = getDownloadBase(repoSlug);
  const errors = [];

  for (const name of manifestCandidateNames()) {
    const url = `${base}/v${version}/${name}`;
    try {
      const text = await downloadText(url);
      let manifest;
      try {
        manifest = JSON.parse(text);
      } catch (e) {
        errors.push(`Malformed manifest (${name}): ${e.message}`);
        continue;
      }

      // If a manifest exists but doesn't support the current triple, fail deterministically.
      try {
        return { manifestName: name, resolved: resolveCanonicalAssetForTargetTriple(manifest, targetTriple) };
      } catch (e) {
        if (e instanceof ManifestResolutionError) {
          e.message = `Manifest ${name}: ${e.message}`;
          throw e;
        }
        throw e;
      }
    } catch (e) {
      // 404 => "missing manifest" candidate; try next. Anything else is recorded and we still try next.
      if (e && typeof e.statusCode === "number" && e.statusCode === 404) continue;
      errors.push(`Failed to fetch manifest (${name}): ${e.message}`);
      continue;
    }
  }

  return { manifestName: null, resolved: null, errors };
}

async function main() {
  const platformKey = detectPlatformKey();
  const targetTriple = detectTargetTriple();
  const version = getVersion();
  const repoSlug = parseRepoSlug();

  let archive = null;
  let expectedSha256 = null;
  let source = "fallback";

  const manifestAttempt = await tryResolveAssetViaManifest({ repoSlug, version, targetTriple });
  if (manifestAttempt.resolved) {
    archive = manifestAttempt.resolved.asset.name;
    expectedSha256 = manifestAttempt.resolved.integrity.sha256;
    source = `manifest:${manifestAttempt.manifestName}`;
  } else if (manifestAttempt.errors && manifestAttempt.errors.length) {
    console.warn(`[docdex] Manifest unavailable; falling back. Details: ${manifestAttempt.errors.join(" | ")}`);
  } else {
    console.log("[docdex] No manifest found; falling back to deterministic asset naming.");
  }

  if (!archive) {
    archive = artifactName(platformKey);
    const shaUrl = `${getDownloadBase(repoSlug)}/v${version}/${archive}.sha256`;
    try {
      const shaText = await downloadText(shaUrl);
      expectedSha256 = parseSha256File(shaText, archive);
      if (!expectedSha256) {
        console.warn(`[docdex] Could not parse SHA-256 from ${archive}.sha256; continuing without integrity check.`);
      }
    } catch (e) {
      if (e && typeof e.statusCode === "number" && e.statusCode === 404) {
        console.warn(`[docdex] Missing ${archive}.sha256; continuing without integrity check.`);
      } else {
        console.warn(`[docdex] Failed to fetch ${archive}.sha256; continuing without integrity check: ${e.message}`);
      }
    }
  }

  const downloadUrl = `${getDownloadBase(repoSlug)}/v${version}/${archive}`;
  const distDir = path.join(__dirname, "..", "dist", platformKey);
  const tmpFile = path.join(os.tmpdir(), `${archive}.${process.pid}.tgz`);

  console.log(`[docdex] Fetching ${archive} for ${platformKey} (${targetTriple}) via ${source}...`);
  await fs.promises.rm(distDir, { recursive: true, force: true });
  await download(downloadUrl, tmpFile);

  if (expectedSha256) {
    const actual = await sha256File(tmpFile);
    if (actual.toLowerCase() !== expectedSha256.toLowerCase()) {
      throw new Error(
        `Integrity check failed for ${archive}: expected sha256=${expectedSha256} got sha256=${actual}`
      );
    }
  }

  await extractTarball(tmpFile, distDir);

  const binaryPath = path.join(distDir, process.platform === "win32" ? "docdexd.exe" : "docdexd");
  if (!fs.existsSync(binaryPath)) {
    throw new Error(`Downloaded archive missing binary at ${binaryPath}`);
  }

  await fs.promises.chmod(binaryPath, 0o755).catch(() => {});
  await fs.promises.rm(tmpFile, { force: true });
  console.log(`[docdex] Installed binary to ${binaryPath}`);
}

main().catch((err) => {
  if (err instanceof ManifestResolutionError) {
    console.error(`[docdex] install failed: ${err.message}`);
    console.error(`[docdex] error code: ${err.code}`);
    if (Array.isArray(err.details?.supported) && err.details.supported.length) {
      console.error(`[docdex] supported targets: ${err.details.supported.join(", ")}`);
    }
    if (Array.isArray(err.details?.matches) && err.details.matches.length) {
      console.error(`[docdex] matched assets: ${err.details.matches.join(", ")}`);
    }
    process.exit(1);
  }

  console.error(`[docdex] install failed: ${err.message}`);
  process.exit(1);
});
