#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const https = require("node:https");
const os = require("node:os");
const path = require("node:path");
const { pipeline } = require("node:stream/promises");
const tar = require("tar");

const pkg = require("../package.json");
const { artifactName, detectPlatformKey } = require("./platform");

const MAX_REDIRECTS = 5;
const USER_AGENT = "docdex-installer";
const PLACEHOLDER_REPO_TOKEN = /OWNER|REPO/i;

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

async function main() {
  const platformKey = detectPlatformKey();
  const version = getVersion();
  const repoSlug = parseRepoSlug();
  const archive = artifactName(platformKey);
  const downloadUrl = `${getDownloadBase(repoSlug)}/v${version}/${archive}`;
  const distDir = path.join(__dirname, "..", "dist", platformKey);
  const tmpFile = path.join(os.tmpdir(), `${archive}.${process.pid}.tgz`);

  console.log(`[docdex] Fetching ${archive} for ${platformKey}...`);
  await fs.promises.rm(distDir, { recursive: true, force: true });
  await download(downloadUrl, tmpFile);
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
  console.error(`[docdex] install failed: ${err.message}`);
  process.exit(1);
});
