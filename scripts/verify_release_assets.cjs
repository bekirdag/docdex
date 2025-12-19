#!/usr/bin/env node
"use strict";

const { setTimeout: delay } = require("node:timers/promises");

const { PUBLISHED_RELEASE_TARGETS } = require("../npm/lib/platform_matrix");
const {
  ManifestResolutionError,
  resolveCanonicalAssetForTargetTriple,
  getManifestVersion
} = require("../npm/lib/release_manifest");
const {
  manifestCandidateNames,
  checksumCandidateNames,
  parseSha256File,
  getVersion,
  parseRepoSlug
} = require("../npm/lib/install");

const USER_AGENT = "docdex-release-guard";
const MAX_RETRIES = 2;
const RETRY_DELAY_MS = 1500;

const EXIT_CODE_BY_ERROR_CODE = Object.freeze({
  DOCDEX_INSTALLER_CONFIG: 2,
  DOCDEX_MANIFEST_MALFORMED: 10,
  DOCDEX_TARGET_TRIPLE_INVALID: 11,
  DOCDEX_ASSET_NO_MATCH: 12,
  DOCDEX_ASSET_MULTI_MATCH: 13,
  DOCDEX_ASSET_MALFORMED: 14,
  DOCDEX_DOWNLOAD_FAILED: 20,
  DOCDEX_ASSET_MISSING: 21,
  DOCDEX_CHECKSUM_UNUSABLE: 24
});

const EXPECTED_ASSETS_BY_TRIPLE = new Map(
  PUBLISHED_RELEASE_TARGETS.map((entry) => [entry.targetTriple, `${entry.archiveBase}.tar.gz`])
);
const EXPECTED_ASSETS = Array.from(EXPECTED_ASSETS_BY_TRIPLE.values()).sort();
const EXPECTED_TARGET_TRIPLES = Array.from(EXPECTED_ASSETS_BY_TRIPLE.keys()).sort();

function withAuthHeaders(headers) {
  const token = process.env.DOCDEX_GITHUB_TOKEN || process.env.GITHUB_TOKEN;
  const base = { "User-Agent": USER_AGENT };
  if (token) base.Authorization = `Bearer ${token}`;
  return { ...base, ...(headers || {}) };
}

function shouldRetry(err) {
  const code = err?.statusCode;
  if (code === 404) return true;
  return typeof code === "number" && code >= 500 && code < 600;
}

async function withRetries(fn) {
  let lastErr;
  for (let attempt = 0; attempt <= MAX_RETRIES; attempt += 1) {
    try {
      return await fn();
    } catch (err) {
      lastErr = err;
      if (attempt >= MAX_RETRIES || !shouldRetry(err)) break;
      await delay(RETRY_DELAY_MS * (attempt + 1));
    }
  }
  throw lastErr;
}

async function fetchJson(url) {
  const res = await fetch(url, {
    headers: withAuthHeaders({ Accept: "application/vnd.github+json" }),
    redirect: "follow"
  });
  if (!res.ok) {
    const err = new Error(`HTTP ${res.status} ${res.statusText}`);
    err.statusCode = res.status;
    err.body = await res.text().catch(() => "");
    throw err;
  }
  return res.json();
}

async function fetchText(url, headers) {
  const res = await fetch(url, {
    headers: withAuthHeaders(headers),
    redirect: "follow"
  });
  if (!res.ok) {
    const err = new Error(`HTTP ${res.status} ${res.statusText}`);
    err.statusCode = res.status;
    err.body = await res.text().catch(() => "");
    throw err;
  }
  return res.text();
}

function listMissing(expected, assetsByName) {
  return expected.filter((name) => !assetsByName.has(name));
}

function printFailure({ code, message, details }) {
  const exitCode = EXIT_CODE_BY_ERROR_CODE[code] || 1;
  const lines = [
    `[docdex] release guardrail failed: ${message}`,
    `[docdex] error code: ${code}`,
    details?.expectedVersion ? `[docdex] Expected version: ${details.expectedVersion}` : null,
    details?.expectedTag ? `[docdex] Expected tag: ${details.expectedTag}` : null,
    details?.detectedVersion ? `[docdex] Detected version: ${details.detectedVersion}` : null,
    details?.repoSlug ? `[docdex] Download repo: ${details.repoSlug}` : null,
    details?.releaseUrl ? `[docdex] Release URL: ${details.releaseUrl}` : null,
    details?.manifestName ? `[docdex] Manifest name: ${details.manifestName}` : null,
    details?.manifestVersion != null ? `[docdex] Manifest version: ${details.manifestVersion}` : null,
    details?.source ? `[docdex] Source: ${details.source}` : null,
    details?.expectedAssets?.length ? `[docdex] Expected assets: ${details.expectedAssets.join(", ")}` : null,
    details?.missingAssets?.length ? `[docdex] Missing assets: ${details.missingAssets.join(", ")}` : null,
    details?.missingTargets?.length ? `[docdex] Missing target triples: ${details.missingTargets.join(", ")}` : null,
    details?.missingChecksums?.length ? `[docdex] Missing checksums: ${details.missingChecksums.join(", ")}` : null,
    details?.note ? `[docdex] Note: ${details.note}` : null
  ].filter(Boolean);
  for (const line of lines) console.error(line);
  process.exit(exitCode);
}

async function resolveManifestCandidate(assetsByName, candidates) {
  const errors = [];
  for (const name of candidates) {
    const asset = assetsByName.get(name);
    if (!asset) continue;
    try {
      const text = await withRetries(() => fetchText(asset.url, { Accept: "application/octet-stream" }));
      return { manifest: JSON.parse(text), manifestName: name, errors };
    } catch (err) {
      errors.push(`${name}: ${err.message}`);
    }
  }
  return { manifest: null, manifestName: null, errors };
}

function isFatalManifestError(err) {
  return err.code === "DOCDEX_ASSET_NO_MATCH" || err.code === "DOCDEX_ASSET_MULTI_MATCH";
}

async function ensureChecksumsAvailable({ assetsByName, expectedAssets, detailsBase }) {
  const checksumCoverage = new Set();
  const checksumCandidates = checksumCandidateNames();

  for (const name of checksumCandidates) {
    const asset = assetsByName.get(name);
    if (!asset) continue;
    try {
      const text = await withRetries(() => fetchText(asset.url, { Accept: "application/octet-stream" }));
      for (const assetName of expectedAssets) {
        if (checksumCoverage.has(assetName)) continue;
        const sha = parseSha256File(text, assetName);
        if (sha) checksumCoverage.add(assetName);
      }
    } catch {
      continue;
    }
  }

  const missingChecksums = [];
  for (const assetName of expectedAssets) {
    if (checksumCoverage.has(assetName)) continue;
    const shaName = `${assetName}.sha256`;
    const asset = assetsByName.get(shaName);
    if (!asset) {
      missingChecksums.push(assetName);
      continue;
    }
    try {
      const shaText = await withRetries(() => fetchText(asset.url, { Accept: "application/octet-stream" }));
      const sha = parseSha256File(shaText, assetName);
      if (!sha) missingChecksums.push(assetName);
    } catch {
      missingChecksums.push(assetName);
    }
  }

  if (missingChecksums.length) {
    printFailure({
      code: "DOCDEX_CHECKSUM_UNUSABLE",
      message: "missing checksum metadata for release assets",
      details: {
        ...detailsBase,
        source: "fallback",
        expectedAssets,
        missingChecksums: missingChecksums.sort()
      }
    });
  }
}

async function main() {
  let repoSlug;
  let version;

  try {
    repoSlug = parseRepoSlug();
  } catch (err) {
    printFailure({
      code: "DOCDEX_INSTALLER_CONFIG",
      message: err?.message || "missing repo slug",
      details: { expectedAssets: EXPECTED_ASSETS }
    });
  }

  try {
    version = getVersion();
  } catch (err) {
    printFailure({
      code: "DOCDEX_INSTALLER_CONFIG",
      message: err?.message || "missing version",
      details: { repoSlug, expectedAssets: EXPECTED_ASSETS }
    });
  }

  const expectedTag = `v${version}`;
  const releaseApiUrl = `https://api.github.com/repos/${repoSlug}/releases/tags/${expectedTag}`;
  let release;

  try {
    release = await withRetries(() => fetchJson(releaseApiUrl));
  } catch (err) {
    if (err?.statusCode === 404) {
      printFailure({
        code: "DOCDEX_ASSET_MISSING",
        message: "release tag not found",
        details: {
          expectedVersion: version,
          expectedTag,
          repoSlug,
          releaseUrl: `https://github.com/${repoSlug}/releases/tag/${expectedTag}`,
          expectedAssets: EXPECTED_ASSETS,
          note: "Expected GitHub Release tag is missing or not published yet."
        }
      });
    }
    printFailure({
      code: "DOCDEX_DOWNLOAD_FAILED",
      message: "failed to query release metadata",
      details: {
        expectedVersion: version,
        expectedTag,
        repoSlug,
        releaseUrl: `https://github.com/${repoSlug}/releases/tag/${expectedTag}`,
        expectedAssets: EXPECTED_ASSETS,
        note: err?.message || "unknown error"
      }
    });
  }

  const releaseUrl = release?.html_url || `https://github.com/${repoSlug}/releases/tag/${expectedTag}`;
  const assetsByName = new Map();
  for (const asset of release?.assets || []) {
    assetsByName.set(asset.name, asset);
  }

  const missingAssets = listMissing(EXPECTED_ASSETS, assetsByName);
  if (missingAssets.length) {
    printFailure({
      code: "DOCDEX_ASSET_MISSING",
      message: "missing artifact/version sync issue (release assets not found)",
      details: {
        expectedVersion: version,
        expectedTag,
        detectedVersion: release?.tag_name || null,
        repoSlug,
        releaseUrl,
        expectedAssets: EXPECTED_ASSETS,
        missingAssets: missingAssets.sort(),
        source: "release"
      }
    });
  }

  const manifestCandidates = manifestCandidateNames();
  const { manifest, manifestName } = await resolveManifestCandidate(assetsByName, manifestCandidates);
  const manifestVersion = manifest ? getManifestVersion(manifest) : null;

  if (manifest) {
    const fatalErrors = [];
    const nonFatalErrors = [];
    const missingTargets = new Set();
    const manifestMissingAssets = new Set();

    for (const targetTriple of EXPECTED_TARGET_TRIPLES) {
      try {
        const resolved = resolveCanonicalAssetForTargetTriple(manifest, targetTriple);
        if (!assetsByName.has(resolved.asset.name)) {
          manifestMissingAssets.add(resolved.asset.name);
        }
      } catch (err) {
        if (err instanceof ManifestResolutionError) {
          if (isFatalManifestError(err)) {
            fatalErrors.push(err);
            missingTargets.add(err.details?.targetTriple || targetTriple);
          } else {
            nonFatalErrors.push(err);
          }
          continue;
        }
        throw err;
      }
    }

    if (fatalErrors.length) {
      const err = fatalErrors[0];
      printFailure({
        code: err.code,
        message: "manifest missing required target(s)",
        details: {
          expectedVersion: version,
          expectedTag,
          detectedVersion: release?.tag_name || null,
          repoSlug,
          releaseUrl,
          manifestName,
          manifestVersion,
          source: `manifest:${manifestName}`,
          expectedAssets: EXPECTED_ASSETS,
          missingTargets: Array.from(missingTargets).sort(),
          note: err.message
        }
      });
    }

    if (manifestMissingAssets.size) {
      printFailure({
        code: "DOCDEX_ASSET_MISSING",
        message: "manifest points to assets missing from the release",
        details: {
          expectedVersion: version,
          expectedTag,
          detectedVersion: release?.tag_name || null,
          repoSlug,
          releaseUrl,
          manifestName,
          manifestVersion,
          source: `manifest:${manifestName}`,
          expectedAssets: EXPECTED_ASSETS,
          missingAssets: Array.from(manifestMissingAssets).sort()
        }
      });
    }

    if (!nonFatalErrors.length) {
      console.log(`[docdex] release guardrail passed for ${expectedTag} (${repoSlug})`);
      return;
    }
  }

  await ensureChecksumsAvailable({
    assetsByName,
    expectedAssets: EXPECTED_ASSETS,
    detailsBase: {
      expectedVersion: version,
      expectedTag,
      detectedVersion: release?.tag_name || null,
      repoSlug,
      releaseUrl
    }
  });

  console.log(`[docdex] release guardrail passed for ${expectedTag} (${repoSlug})`);
}

main().catch((err) => {
  printFailure({
    code: "DOCDEX_DOWNLOAD_FAILED",
    message: "release guardrail failed unexpectedly",
    details: { note: err?.message || "unknown error", expectedAssets: EXPECTED_ASSETS }
  });
});
