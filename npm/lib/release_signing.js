"use strict";

const crypto = require("node:crypto");

// Pinned verifier material for release integrity signatures.
//
// Notes:
// - This public key is used to verify detached signatures over integrity metadata files
//   (e.g. `SHA256SUMS`, `docdex-release-manifest.json`) when present.
// - Forks can override via `DOCDEX_RELEASE_SIGNING_PUBLIC_KEY` (PEM string).
// - Official releases may rotate this key; rotation requires updating this value and
//   re-signing release metadata with the corresponding private key.
const DEFAULT_RELEASE_SIGNING_PUBLIC_KEY_PEM = `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAuifOmifWm19cTMDxg6PVTBo3f997/P0qqTytnhUmjwE=
-----END PUBLIC KEY-----`;

const SIGNATURE_ALGORITHM = "ed25519";
const SIGNATURE_SUFFIX = ".sig";

function getSignaturePolicyFromEnv(envValue) {
  const raw = String(envValue || "").trim().toLowerCase();
  if (!raw) return "optional";
  if (raw === "optional" || raw === "require" || raw === "required" || raw === "disabled" || raw === "off") return raw;
  if (raw === "0" || raw === "false" || raw === "no") return "disabled";
  if (raw === "1" || raw === "true" || raw === "yes") return "required";
  return "invalid";
}

function normalizePolicy(policy) {
  if (policy === "require") return "required";
  if (policy === "off") return "disabled";
  return policy;
}

function signaturePolicy() {
  return normalizePolicy(getSignaturePolicyFromEnv(process.env.DOCDEX_SIGNATURE_POLICY));
}

function getReleaseSigningPublicKeyPem() {
  const envKey = process.env.DOCDEX_RELEASE_SIGNING_PUBLIC_KEY;
  if (envKey && String(envKey).trim()) return String(envKey).trim();
  return DEFAULT_RELEASE_SIGNING_PUBLIC_KEY_PEM;
}

function parseDetachedSignatureBase64(text) {
  const value = String(text || "").trim();
  if (!value) return null;
  // Allow `ed25519:<base64>` for explicitness; otherwise treat as base64.
  const parts = value.split(":");
  const maybeB64 = parts.length === 2 ? parts[1].trim() : value;
  if (!maybeB64) return null;
  return maybeB64;
}

function verifyDetachedSignatureEd25519({ data, signatureText, publicKeyPem }) {
  const sigB64 = parseDetachedSignatureBase64(signatureText);
  if (!sigB64) return { ok: false, reason: "empty_signature" };

  let signature;
  try {
    signature = Buffer.from(sigB64, "base64");
  } catch {
    return { ok: false, reason: "signature_not_base64" };
  }

  if (signature.length !== 64) return { ok: false, reason: "signature_wrong_length" };

  let keyObject;
  try {
    keyObject = crypto.createPublicKey(publicKeyPem);
  } catch {
    return { ok: false, reason: "public_key_invalid" };
  }

  try {
    const ok = crypto.verify(null, Buffer.isBuffer(data) ? data : Buffer.from(data), keyObject, signature);
    return ok ? { ok: true } : { ok: false, reason: "signature_invalid" };
  } catch {
    return { ok: false, reason: "verify_failed" };
  }
}

module.exports = {
  DEFAULT_RELEASE_SIGNING_PUBLIC_KEY_PEM,
  SIGNATURE_ALGORITHM,
  SIGNATURE_SUFFIX,
  signaturePolicy,
  getSignaturePolicyFromEnv,
  getReleaseSigningPublicKeyPem,
  parseDetachedSignatureBase64,
  verifyDetachedSignatureEd25519
};

