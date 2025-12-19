#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");

const { PLATFORM_MATRIX, assetNameForPlatformKey } = require("../npm/lib/platform_matrix");

const ARCHIVE_RE = /^docdexd-(.+)\.tar\.gz$/;

function usage() {
  return [
    "Usage: node scripts/validate_release_assets.cjs --dir <assets_dir>",
    "",
    "Validates docdexd release archives against the canonical naming convention and",
    "ensures exactly one asset exists per published target triple.",
    "",
    "Exit codes:",
    "  1  generic failure",
    "  2  invalid arguments",
    "  3  validation failed"
  ].join("\n");
}

function parseArgs(argv) {
  const args = { dir: null };
  const rest = [...argv];
  while (rest.length) {
    const flag = rest.shift();
    if (flag === "--help" || flag === "-h") return { ...args, help: true };
    if (flag === "--dir") args.dir = rest.shift() || null;
    else return { ...args, error: `Unknown arg: ${flag}` };
  }
  return args;
}

function listFiles(dirPath) {
  const resolved = path.resolve(dirPath);
  let stat;
  try {
    stat = fs.statSync(resolved);
  } catch (err) {
    const error = new Error(`Assets directory not found: ${resolved}`);
    error.exitCode = 2;
    throw error;
  }
  if (!stat.isDirectory()) {
    const error = new Error(`Assets path is not a directory: ${resolved}`);
    error.exitCode = 2;
    throw error;
  }
  return fs
    .readdirSync(resolved, { withFileTypes: true })
    .filter((entry) => entry.isFile())
    .map((entry) => entry.name);
}

function buildEntryByKey(platformMatrix) {
  return platformMatrix.reduce((acc, entry) => {
    acc[entry.platformKey] = entry;
    return acc;
  }, {});
}

function buildExpectedByTriple(publishedEntries) {
  const expectedByTriple = new Map();
  const duplicateTriples = new Map();

  for (const entry of publishedEntries) {
    const existing = expectedByTriple.get(entry.targetTriple);
    if (existing) {
      const keys = duplicateTriples.get(entry.targetTriple) || [existing.platformKey];
      if (!keys.includes(entry.platformKey)) keys.push(entry.platformKey);
      duplicateTriples.set(entry.targetTriple, keys);
      continue;
    }
    expectedByTriple.set(entry.targetTriple, {
      platformKey: entry.platformKey,
      assetName: assetNameForPlatformKey(entry.platformKey)
    });
  }

  return { expectedByTriple, duplicateTriples };
}

function collectReleaseAssetIssues(options) {
  const assetsDir = options?.assetsDir;
  const platformMatrix = Array.isArray(options?.platformMatrix) ? options.platformMatrix : PLATFORM_MATRIX;
  if (!assetsDir) {
    const err = new Error("Missing required --dir");
    err.exitCode = 2;
    throw err;
  }

  const publishedEntries = platformMatrix.filter((entry) => entry.published);
  const entryByKey = buildEntryByKey(platformMatrix);
  const { expectedByTriple, duplicateTriples: duplicateTriplesInMatrix } = buildExpectedByTriple(publishedEntries);

  const files = listFiles(assetsDir);
  const archives = files.filter((name) => ARCHIVE_RE.test(name));

  const assetsByTriple = new Map();
  const nonCanonical = [];

  for (const name of archives) {
    const match = name.match(ARCHIVE_RE);
    const platformKey = match ? match[1] : null;
    if (!platformKey) continue;

    const entry = entryByKey[platformKey];
    if (!entry) {
      nonCanonical.push({ name, reason: `unknown platformKey: ${platformKey}` });
      continue;
    }
    if (!entry.published) {
      nonCanonical.push({ name, reason: `platformKey not published: ${platformKey}` });
      continue;
    }

    const expectedName = assetNameForPlatformKey(platformKey);
    if (name !== expectedName) {
      nonCanonical.push({ name, reason: `expected ${expectedName}` });
      continue;
    }

    const list = assetsByTriple.get(entry.targetTriple) || [];
    list.push(name);
    assetsByTriple.set(entry.targetTriple, list);
  }

  const missing = [];
  for (const [targetTriple, expected] of expectedByTriple.entries()) {
    if (!assetsByTriple.has(targetTriple)) {
      missing.push({
        targetTriple,
        platformKey: expected.platformKey,
        expectedAsset: expected.assetName
      });
    }
  }

  const duplicateTriples = [];
  for (const [targetTriple, platformKeys] of duplicateTriplesInMatrix.entries()) {
    duplicateTriples.push({
      targetTriple,
      platformKeys: platformKeys.slice().sort(),
      reason: "platform matrix contains multiple published platform keys"
    });
  }

  const duplicateAssets = [];
  for (const [targetTriple, assets] of assetsByTriple.entries()) {
    if (assets.length > 1) {
      duplicateAssets.push({
        targetTriple,
        assets: assets.slice().sort(),
        reason: "multiple assets matched the same target triple"
      });
    }
  }

  return {
    assetsDir: path.resolve(assetsDir),
    archives: archives.slice().sort(),
    missing,
    nonCanonical,
    duplicateTriples,
    duplicateAssets,
    ok: missing.length === 0 && nonCanonical.length === 0 && duplicateTriples.length === 0 && duplicateAssets.length === 0
  };
}

function formatIssues(result) {
  const lines = [`Release asset validation failed for ${result.assetsDir}.`];

  if (!result.archives.length) {
    lines.push("", "No docdexd-*.tar.gz archives found.");
  }

  if (result.missing.length) {
    lines.push("", "Missing target triples (expected docdexd-<platformKey>.tar.gz):");
    for (const entry of result.missing.sort((a, b) => a.targetTriple.localeCompare(b.targetTriple))) {
      lines.push(`- ${entry.targetTriple} -> ${entry.expectedAsset}`);
    }
  }

  const duplicates = result.duplicateTriples.concat(result.duplicateAssets);
  if (duplicates.length) {
    lines.push("", "Duplicate target triples:");
    for (const entry of duplicates) {
      if (entry.assets) {
        lines.push(`- ${entry.targetTriple} -> assets: ${entry.assets.join(", ")}`);
      } else {
        lines.push(`- ${entry.targetTriple} -> platformKeys: ${entry.platformKeys.join(", ")}`);
      }
    }
  }

  if (result.nonCanonical.length) {
    lines.push("", "Non-canonical asset names:");
    for (const entry of result.nonCanonical.sort((a, b) => a.name.localeCompare(b.name))) {
      lines.push(`- ${entry.name} (${entry.reason})`);
    }
  }

  return lines.join("\n");
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

    const result = collectReleaseAssetIssues({ assetsDir: args.dir });
    if (!result.ok) {
      process.stderr.write(formatIssues(result) + "\n");
      process.exit(3);
    }

    process.stdout.write(`Release asset validation OK (${result.archives.length} archive(s)).\n`);
  } catch (err) {
    const exitCode = typeof err?.exitCode === "number" ? err.exitCode : 1;
    process.stderr.write(`${err?.message || String(err)}\n`);
    process.exit(exitCode);
  }
}

module.exports = { collectReleaseAssetIssues, formatIssues };
