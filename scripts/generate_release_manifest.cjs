#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

const { PUBLISHED_RELEASE_TARGETS } = require("../npm/lib/platform_matrix");

// Single source of truth: published targets come from npm/lib/platform_matrix.js
const DEFAULT_TARGETS = Object.freeze(PUBLISHED_RELEASE_TARGETS.slice());

function usage() {
  return [
    "Usage: node scripts/generate_release_manifest.cjs --dir <assets_dir> --out <manifest_path> [--tag vX.Y.Z] [--repo owner/repo] [--source-commit SHA] [--source-date-epoch SECONDS] [--allow-partial]",
    "",
    "Generates a machine-readable release manifest with per-target SHA-256 integrity metadata,",
    "writes a sibling .sha256 file for the manifest itself, and writes SHA256SUMS (+ SHA256SUMS.txt)",
    "in the assets directory for deterministic installer fallback.",
    "",
    "Optional flags:",
    "  --source-commit    Record the immutable 40-hex source commit in the manifest.",
    "  --source-date-epoch  Use the immutable source commit timestamp for generatedAt.",
    "                       SOURCE_DATE_EPOCH is used when this flag is omitted.",
    "  --allow-partial   Generate a manifest from only assets present in the dir. Missing targets",
    "                    are ignored if neither the archive nor its .sha256 exists.",
    "",
    "Optional signing:",
    "  Set DOCDEX_RELEASE_SIGNING_PRIVATE_KEY to a PEM-encoded Ed25519 private key to write",
    "  detached signature files alongside integrity metadata:",
    "    - <manifest>.sig",
    "    - SHA256SUMS.sig",
    "    - SHA256SUMS.txt.sig",
    "",
    "Exit codes:",
    "  1  generic failure",
    "  2  invalid arguments",
    "  3  missing expected assets",
    "  4  checksum mismatch"
  ].join("\n");
}

function parseArgs(argv) {
  const args = { dir: null, out: null, tag: null, repo: null, sourceCommit: null, sourceDateEpoch: null, allowPartial: false };
  const rest = [...argv];
  while (rest.length) {
    const flag = rest.shift();
    if (flag === "--help" || flag === "-h") return { ...args, help: true };
    if (flag === "--dir") args.dir = rest.shift() || null;
    else if (flag === "--out") args.out = rest.shift() || null;
    else if (flag === "--tag") args.tag = rest.shift() || null;
    else if (flag === "--repo") args.repo = rest.shift() || null;
    else if (flag === "--source-commit") args.sourceCommit = rest.shift() || null;
    else if (flag === "--source-date-epoch") args.sourceDateEpoch = rest.shift() || null;
    else if (flag === "--allow-partial") args.allowPartial = true;
    else return { ...args, error: `Unknown arg: ${flag}` };
  }
  return args;
}

function dateFromSourceEpoch(raw) {
  const value = String(raw ?? "").trim();
  if (!/^\d+$/.test(value)) {
    const err = new Error("source date epoch must be a non-negative integer");
    err.exitCode = 2;
    throw err;
  }
  const seconds = Number(value);
  if (!Number.isSafeInteger(seconds) || seconds > 253402300799) {
    const err = new Error("source date epoch is outside the supported timestamp range");
    err.exitCode = 2;
    throw err;
  }
  return new Date(seconds * 1000);
}

function sha256FileSync(filePath) {
  const hash = crypto.createHash("sha256");
  hash.update(fs.readFileSync(filePath));
  return hash.digest("hex");
}

function signFileDetachedBase64({ filePath, privateKeyPem }) {
  const key = crypto.createPrivateKey(privateKeyPem);
  const data = fs.readFileSync(filePath);
  const signature = crypto.sign(null, data, key);
  return signature.toString("base64");
}

function parseSha256File(text, expectedFilename) {
  const lines = String(text)
    .split(/\r?\n/)
    .map((l) => l.trim())
    .filter(Boolean);
  for (const line of lines) {
    const match = line.match(/^([0-9a-fA-F]{64})\s+\*?(.+)$/);
    if (!match) continue;
    const hash = match[1].toLowerCase();
    const filename = match[2].trim();
    if (!expectedFilename || filename === expectedFilename) return hash;
  }
  return null;
}

function uniqueOrThrow(values, label) {
  const seen = new Set();
  for (const v of values) {
    if (seen.has(v)) throw new Error(`Non-unique ${label}: ${v}`);
    seen.add(v);
  }
}

/**
 * @param {{
 *   assetsDir: string,
 *   outPath: string,
 *   tag?: string|null,
 *   repo?: string|null,
 *   sourceCommit?: string|null,
 *   targets?: {targetTriple: string, archiveBase: string}[],
 *   allowPartial?: boolean,
 *   now?: Date,
 *   sourceDateEpoch?: string|number|null
 * }} options
 */
function generateReleaseManifest(options) {
  const assetsDir = options?.assetsDir;
  const outPath = options?.outPath;
  const tag = options?.tag ?? null;
  const repo = options?.repo ?? null;
  const sourceCommit = options?.sourceCommit ?? null;
  const allowPartial = Boolean(options?.allowPartial);
  const targets = Array.isArray(options?.targets) && options.targets.length ? options.targets : DEFAULT_TARGETS;
  const sourceDateEpoch = options?.sourceDateEpoch ?? process.env.SOURCE_DATE_EPOCH ?? null;
  const now = options?.now instanceof Date
    ? options.now
    : sourceDateEpoch === null
      ? new Date()
      : dateFromSourceEpoch(sourceDateEpoch);

  if (!assetsDir || !outPath) {
    const err = new Error("Missing required --dir/--out");
    err.exitCode = 2;
    throw err;
  }
  if (sourceCommit !== null && !/^[0-9a-f]{40}$/.test(sourceCommit)) {
    const err = new Error("source commit must be a lowercase 40-hex Git commit");
    err.exitCode = 2;
    throw err;
  }

  uniqueOrThrow(
    targets.map((t) => t.targetTriple),
    "target triple"
  );
  uniqueOrThrow(
    targets.map((t) => t.archiveBase),
    "archive base"
  );

  const missing = [];
  const presentTargets = [];
  const targetsObj = {};
  const publishedAssets = [];

  for (const t of targets) {
    const tarName = `${t.archiveBase}.tar.gz`;
    const tarPath = path.join(assetsDir, tarName);
    const shaName = `${tarName}.sha256`;
    const shaPath = path.join(assetsDir, shaName);
    const hasTar = fs.existsSync(tarPath);
    const hasSha = fs.existsSync(shaPath);

    if (hasTar && hasSha) {
      presentTargets.push(t);
      continue;
    }

    if (hasTar || hasSha) {
      if (!hasTar) missing.push(tarName);
      if (!hasSha) missing.push(shaName);
      continue;
    }

    if (!allowPartial) {
      missing.push(tarName);
      missing.push(shaName);
    }
  }

  if (missing.length) {
    const err = new Error(`Missing expected release assets: ${missing.sort().join(", ")}`);
    err.exitCode = 3;
    throw err;
  }

  const resolvedTargets = allowPartial ? presentTargets : targets;
  if (allowPartial && resolvedTargets.length === 0) {
    const err = new Error(`No release assets found in ${assetsDir}`);
    err.exitCode = 3;
    throw err;
  }

  for (const t of resolvedTargets) {
    const tarName = `${t.archiveBase}.tar.gz`;
    const tarPath = path.join(assetsDir, tarName);
    const shaName = `${tarName}.sha256`;
    const shaPath = path.join(assetsDir, shaName);
    const tarSize = fs.statSync(tarPath).size;

    const computedTarSha = sha256FileSync(tarPath);
    const shaText = fs.readFileSync(shaPath, "utf8");
    const declared = parseSha256File(shaText, tarName);
    if (!declared) {
      const err = new Error(`Could not parse SHA-256 file: ${shaName}`);
      err.exitCode = 4;
      throw err;
    }
    if (declared !== computedTarSha) {
      const err = new Error(
        `Checksum mismatch for ${tarName}: declared sha256=${declared} computed sha256=${computedTarSha}`
      );
      err.exitCode = 4;
      throw err;
    }

    targetsObj[t.targetTriple] = {
      asset: { name: tarName },
      integrity: { sha256: computedTarSha, size: tarSize }
    };

    publishedAssets.push({ name: tarName, sha256: computedTarSha, size: tarSize });
    publishedAssets.push({ name: shaName, sha256: sha256FileSync(shaPath), size: fs.statSync(shaPath).size });
  }

  const manifest = {
    manifestVersion: 1,
    ...(repo ? { repo } : {}),
    ...(tag ? { tag, version: tag.startsWith("v") ? tag.slice(1) : tag } : {}),
    ...(sourceCommit ? { sourceCommit } : {}),
    generatedAt: now.toISOString(),
    targets: targetsObj,
    publishedAssets
  };

  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, JSON.stringify(manifest, null, 2) + "\n");

  const manifestSha = sha256FileSync(outPath);
  const shaOutPath = `${outPath}.sha256`;
  fs.writeFileSync(shaOutPath, `${manifestSha}  ${path.basename(outPath)}\n`);

  const checksumEntries = publishedAssets
    .slice()
    .concat([
      { name: path.basename(outPath), sha256: manifestSha },
      { name: path.basename(shaOutPath), sha256: sha256FileSync(shaOutPath) }
    ]);

  const checksumLines = checksumEntries
    .sort((a, b) => a.name.localeCompare(b.name))
    .map((entry) => `${entry.sha256}  ${entry.name}`)
    .join("\n");

  const checksumsPath = path.join(assetsDir, "SHA256SUMS");
  const checksumsTxtPath = path.join(assetsDir, "SHA256SUMS.txt");
  fs.writeFileSync(checksumsPath, checksumLines + "\n");
  fs.writeFileSync(checksumsTxtPath, checksumLines + "\n");

  const signingKeyPem = String(process.env.DOCDEX_RELEASE_SIGNING_PRIVATE_KEY || "").trim() || null;
  const signatures = {};
  if (signingKeyPem) {
    const toSign = [outPath, checksumsPath, checksumsTxtPath];
    for (const filePath of toSign) {
      const sigB64 = signFileDetachedBase64({ filePath, privateKeyPem: signingKeyPem });
      const sigPath = `${filePath}.sig`;
      fs.writeFileSync(sigPath, sigB64 + "\n");
      signatures[path.basename(filePath)] = path.basename(sigPath);
    }
  }

  return {
    manifestPath: outPath,
    manifestSha256: manifestSha,
    sha256Path: shaOutPath,
    checksumsPath,
    checksumsTxtPath,
    signatures,
    manifest
  };
}

if (require.main === module) {
  try {
    const args = parseArgs(process.argv.slice(2));
    if (args.help) {
      process.stdout.write(usage() + "\n");
      process.exit(0);
    }
    if (args.error) {
      process.stderr.write(args.error + "\n\n" + usage() + "\n");
      process.exit(2);
    }

    const result = generateReleaseManifest({
      assetsDir: args.dir,
      outPath: args.out,
      tag: args.tag,
      repo: args.repo,
      sourceCommit: args.sourceCommit,
      sourceDateEpoch: args.sourceDateEpoch,
      allowPartial: args.allowPartial
    });

    process.stdout.write(
      `Wrote manifest: ${result.manifestPath}\nWrote manifest checksum: ${result.sha256Path}\n`
    );
  } catch (err) {
    const exitCode = typeof err?.exitCode === "number" ? err.exitCode : 1;
    process.stderr.write(`${err?.message || String(err)}\n`);
    process.exit(exitCode);
  }
}

module.exports = { generateReleaseManifest, dateFromSourceEpoch, DEFAULT_TARGETS };
