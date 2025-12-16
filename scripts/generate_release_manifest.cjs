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
    "Usage: node scripts/generate_release_manifest.cjs --dir <assets_dir> --out <manifest_path> [--tag vX.Y.Z] [--repo owner/repo]",
    "",
    "Generates a machine-readable release manifest with per-target SHA-256 integrity metadata,",
    "and writes a sibling .sha256 file for the manifest itself.",
    "",
    "Exit codes:",
    "  1  generic failure",
    "  2  invalid arguments",
    "  3  missing expected assets",
    "  4  checksum mismatch"
  ].join("\n");
}

function parseArgs(argv) {
  const args = { dir: null, out: null, tag: null, repo: null };
  const rest = [...argv];
  while (rest.length) {
    const flag = rest.shift();
    if (flag === "--help" || flag === "-h") return { ...args, help: true };
    if (flag === "--dir") args.dir = rest.shift() || null;
    else if (flag === "--out") args.out = rest.shift() || null;
    else if (flag === "--tag") args.tag = rest.shift() || null;
    else if (flag === "--repo") args.repo = rest.shift() || null;
    else return { ...args, error: `Unknown arg: ${flag}` };
  }
  return args;
}

function sha256FileSync(filePath) {
  const hash = crypto.createHash("sha256");
  hash.update(fs.readFileSync(filePath));
  return hash.digest("hex");
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
 *   targets?: {targetTriple: string, archiveBase: string}[],
 *   now?: Date
 * }} options
 */
function generateReleaseManifest(options) {
  const assetsDir = options?.assetsDir;
  const outPath = options?.outPath;
  const tag = options?.tag ?? null;
  const repo = options?.repo ?? null;
  const targets = Array.isArray(options?.targets) && options.targets.length ? options.targets : DEFAULT_TARGETS;
  const now = options?.now instanceof Date ? options.now : new Date();

  if (!assetsDir || !outPath) {
    const err = new Error("Missing required --dir/--out");
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
  const targetsObj = {};
  const publishedAssets = [];

  for (const t of targets) {
    const tarName = `${t.archiveBase}.tar.gz`;
    const tarPath = path.join(assetsDir, tarName);
    const shaName = `${tarName}.sha256`;
    const shaPath = path.join(assetsDir, shaName);

    if (!fs.existsSync(tarPath)) missing.push(tarName);
    if (!fs.existsSync(shaPath)) missing.push(shaName);
  }

  if (missing.length) {
    const err = new Error(`Missing expected release assets: ${missing.sort().join(", ")}`);
    err.exitCode = 3;
    throw err;
  }

  for (const t of targets) {
    const tarName = `${t.archiveBase}.tar.gz`;
    const tarPath = path.join(assetsDir, tarName);
    const shaName = `${tarName}.sha256`;
    const shaPath = path.join(assetsDir, shaName);

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
      integrity: { sha256: computedTarSha }
    };

    publishedAssets.push({ name: tarName, sha256: computedTarSha });
    publishedAssets.push({ name: shaName, sha256: sha256FileSync(shaPath) });
  }

  const manifest = {
    manifestVersion: 1,
    ...(repo ? { repo } : {}),
    ...(tag ? { tag, version: tag.startsWith("v") ? tag.slice(1) : tag } : {}),
    generatedAt: now.toISOString(),
    targets: targetsObj,
    publishedAssets
  };

  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, JSON.stringify(manifest, null, 2) + "\n");

  const manifestSha = sha256FileSync(outPath);
  const shaOutPath = `${outPath}.sha256`;
  fs.writeFileSync(shaOutPath, `${manifestSha}  ${path.basename(outPath)}\n`);

  return { manifestPath: outPath, manifestSha256: manifestSha, sha256Path: shaOutPath, manifest };
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
      repo: args.repo
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

module.exports = { generateReleaseManifest, DEFAULT_TARGETS };
