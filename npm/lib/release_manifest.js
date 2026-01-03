"use strict";

const EXIT_CODE_BY_CODE = Object.freeze({
  DOCDEX_MANIFEST_MALFORMED: 10,
  DOCDEX_TARGET_TRIPLE_INVALID: 11,
  DOCDEX_ASSET_NO_MATCH: 12,
  DOCDEX_ASSET_MULTI_MATCH: 13,
  DOCDEX_ASSET_MALFORMED: 14
});

class ManifestResolutionError extends Error {
  /**
   * @param {string} code
   * @param {string} message
   * @param {object} [details]
   */
  constructor(code, message, details) {
    super(message);
    this.name = "ManifestResolutionError";
    this.code = code;
    this.exitCode = EXIT_CODE_BY_CODE[code] ?? 1;
    this.details = {
      targetTriple: null,
      manifestVersion: null,
      assetName: null,
      ...(details || {})
    };
  }
}

function isPlainObject(value) {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function getManifestVersion(manifest) {
  if (!isPlainObject(manifest)) return null;
  return manifest.manifestVersion ?? manifest.schemaVersion ?? manifest.version ?? null;
}

function getSupportedTargetTriples(manifest) {
  if (!isPlainObject(manifest)) return [];

  if (isPlainObject(manifest.targets)) return Object.keys(manifest.targets).sort();

  const assets = Array.isArray(manifest.assets) ? manifest.assets : [];
  const triples = [];
  for (const entry of assets) {
    if (!isPlainObject(entry)) continue;
    const triple =
      entry.target_triple ??
      entry.targetTriple ??
      entry.target ??
      entry.triple ??
      entry.platform;
    if (typeof triple === "string" && triple) triples.push(triple);
  }
  return [...new Set(triples)].sort();
}

function normalizeSha256(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(trimmed)) return null;
  return trimmed;
}

function extractAssetAndIntegrity(entry) {
  // Asset identifier/name: tolerate a few common shapes.
  // - entry.asset: string | { name, id }
  // - entry.name / entry.asset_name / entry.assetName: string
  // Integrity:
  // - entry.integrity.sha256
  // - entry.sha256
  const asset = entry.asset;

  let assetName = null;
  let assetId = null;

  if (typeof asset === "string") {
    assetName = asset;
  } else if (isPlainObject(asset)) {
    if (typeof asset.name === "string") assetName = asset.name;
    if (typeof asset.id === "string" || typeof asset.id === "number") assetId = asset.id;
  }

  if (!assetName) {
    const candidate =
      entry.asset_name ??
      entry.assetName ??
      entry.name ??
      entry.filename ??
      entry.file_name ??
      entry.fileName;
    if (typeof candidate === "string") assetName = candidate;
  }

  const sha256 =
    normalizeSha256(entry.integrity?.sha256) ??
    normalizeSha256(entry.sha256) ??
    normalizeSha256(entry.checksum?.sha256);

  return {
    asset: assetName ? { name: assetName, ...(assetId != null ? { id: assetId } : {}) } : null,
    integrity: sha256 ? { sha256 } : null
  };
}

function entriesFromManifest(manifest) {
  if (!isPlainObject(manifest)) {
    throw new ManifestResolutionError(
      "DOCDEX_MANIFEST_MALFORMED",
      "Malformed manifest: expected a JSON object at top-level",
      { manifestVersion: null }
    );
  }

  if (isPlainObject(manifest.targets)) {
    const entries = [];
    for (const [targetTriple, value] of Object.entries(manifest.targets)) {
      if (!isPlainObject(value)) continue;
      entries.push({ targetTriple, entry: value });
    }
    return entries;
  }

  if (Array.isArray(manifest.assets)) {
    const entries = [];
    for (const value of manifest.assets) {
      if (!isPlainObject(value)) continue;
      const targetTriple =
        value.target_triple ??
        value.targetTriple ??
        value.target ??
        value.triple ??
        value.platform;
      if (typeof targetTriple !== "string" || !targetTriple) continue;
      entries.push({ targetTriple, entry: value });
    }
    return entries;
  }

  throw new ManifestResolutionError(
    "DOCDEX_MANIFEST_MALFORMED",
    "Malformed manifest: expected `targets` object or `assets` array",
    { manifestVersion: getManifestVersion(manifest) }
  );
}

/**
 * Deterministically resolve exactly one asset entry (canonical asset identifier/name + integrity metadata)
 * for a given Rust target triple.
 *
 * The manifest is assumed to be validated by the caller, but this function still provides deterministic,
 * actionable errors when the expected structure or entries are missing.
 *
 * @param {object} manifest
 * @param {string} targetTriple
 * @returns {{targetTriple: string, asset: {name: string, id?: (string|number)}, integrity: {sha256: string}}}
 */
function resolveCanonicalAssetForTargetTriple(manifest, targetTriple) {
  const manifestVersion = getManifestVersion(manifest);

  if (typeof targetTriple !== "string" || !targetTriple.trim()) {
    throw new ManifestResolutionError(
      "DOCDEX_TARGET_TRIPLE_INVALID",
      "Invalid target triple: expected a non-empty string",
      { targetTriple: null, manifestVersion }
    );
  }

  const needle = targetTriple.trim();
  const entries = entriesFromManifest(manifest);
  const matches = entries.filter((e) => e.targetTriple === needle);

  if (matches.length === 0) {
    const supported = getSupportedTargetTriples(manifest);
    const supportedMsg = supported.length ? supported.join(", ") : "(none)";
    throw new ManifestResolutionError(
      "DOCDEX_ASSET_NO_MATCH",
      `No asset found in manifest for target triple ${needle}. Supported: ${supportedMsg}`,
      { targetTriple: needle, manifestVersion, supported, assetName: null }
    );
  }

  if (matches.length > 1) {
    const simplified = matches
      .map((m) => extractAssetAndIntegrity(m.entry).asset?.name || "(unknown)")
      .sort();
    throw new ManifestResolutionError(
      "DOCDEX_ASSET_MULTI_MATCH",
      `Multiple assets found in manifest for target triple ${needle}: ${simplified.join(", ")}`,
      { targetTriple: needle, manifestVersion, matches: simplified, assetName: null }
    );
  }

  const resolved = extractAssetAndIntegrity(matches[0].entry);
  if (!resolved.asset?.name) {
    throw new ManifestResolutionError(
      "DOCDEX_ASSET_MALFORMED",
      `Manifest entry for ${needle} is missing a canonical asset name/identifier`,
      { targetTriple: needle, manifestVersion, assetName: null }
    );
  }

  if (!resolved.integrity?.sha256) {
    throw new ManifestResolutionError(
      "DOCDEX_ASSET_MALFORMED",
      `Manifest entry for ${needle} is missing SHA-256 integrity metadata`,
      { targetTriple: needle, manifestVersion, assetName: resolved.asset.name }
    );
  }

  return {
    targetTriple: needle,
    manifestVersion,
    asset: resolved.asset,
    integrity: resolved.integrity
  };
}

module.exports = {
  ManifestResolutionError,
  resolveCanonicalAssetForTargetTriple,
  getSupportedTargetTriples,
  getManifestVersion
};
