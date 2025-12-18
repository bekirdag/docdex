#!/usr/bin/env node
"use strict";

const DEFAULT_COMPONENT = "docdex-installer";

function parseBooleanEnv(value, defaultValue) {
  if (value == null) return defaultValue;
  const normalized = String(value).trim().toLowerCase();
  if (!normalized) return defaultValue;
  if (["1", "true", "yes", "y", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "n", "off"].includes(normalized)) return false;
  return defaultValue;
}

function redactAuthHeader(value) {
  if (typeof value !== "string") return value;
  return value.replace(/\b(Bearer)\s+([^\s]+)/gi, "$1 [REDACTED]");
}

function shouldRedactKey(key) {
  return /token|authorization|password|secret|signature|sig|credential|private[_-]?key|api[_-]?key/i.test(String(key));
}

function shouldRedactUrlParam(key) {
  const k = String(key).toLowerCase();
  if (k.startsWith("x-amz-")) return true;
  return /token|access_token|auth|signature|sig|key|credential|session/i.test(k);
}

function redactUrl(url) {
  if (typeof url !== "string") return url;
  const value = url.trim();
  if (!value) return value;

  try {
    const parsed = new URL(value);
    parsed.username = "";
    parsed.password = "";
    for (const [k] of parsed.searchParams.entries()) {
      if (shouldRedactUrlParam(k)) parsed.searchParams.set(k, "REDACTED");
    }
    return parsed.toString();
  } catch {
    // Best-effort redaction for non-URL strings.
    return value
      .replace(/\/\/([^/@:\s]+):([^/@\s]+)@/g, "//REDACTED:REDACTED@")
      .replace(/([?&])(token|access_token|auth|signature|sig|key|credential)=([^&]+)/gi, "$1$2=REDACTED");
  }
}

function redactValue(value, depth = 0) {
  if (depth > 6) return "[REDACTED_DEPTH]";
  if (value == null) return value;

  if (typeof value === "string") {
    const withRedactedUrls = value.replace(/https?:\/\/[^\s"'()<>]+/gi, (match) => redactUrl(match));
    const maybeUrl = /^https?:\/\//i.test(withRedactedUrls) ? redactUrl(withRedactedUrls) : withRedactedUrls;
    return redactAuthHeader(maybeUrl);
  }

  if (Array.isArray(value)) return value.map((v) => redactValue(v, depth + 1));

  if (typeof value === "object") {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      if (shouldRedactKey(k)) {
        out[k] = "[REDACTED]";
        continue;
      }
      if (/url$/i.test(k) || /_url$/i.test(k) || /url_/i.test(k) || /Url$/.test(k)) {
        out[k] = redactUrl(typeof v === "string" ? v : String(v ?? ""));
        continue;
      }
      out[k] = redactValue(v, depth + 1);
    }
    return out;
  }

  return value;
}

function safeJsonStringify(value) {
  const seen = new WeakSet();
  return JSON.stringify(value, (key, val) => {
    if (val && typeof val === "object") {
      if (seen.has(val)) return "[Circular]";
      seen.add(val);
    }
    return val;
  });
}

function createInstallerStructuredLogger({
  component = DEFAULT_COMPONENT,
  baseFields = {},
  enabled = parseBooleanEnv(process.env.DOCDEX_INSTALLER_STRUCTURED_LOG, false),
  sink = process.stderr
} = {}) {
  function emit({ level = "info", event, message, fields, error } = {}) {
    if (!enabled) return;
    const payload = {
      ts: new Date().toISOString(),
      level,
      component,
      event: typeof event === "string" ? event : "installer.event",
      message: typeof message === "string" ? message : null,
      ...redactValue(baseFields),
      ...redactValue(fields || {})
    };

    if (error) {
      payload.error = redactValue({
        name: error?.name || null,
        code: typeof error?.code === "string" ? error.code : null,
        message: error?.message || String(error)
      });
    }

    try {
      sink.write(`${safeJsonStringify(payload)}\n`);
    } catch {
      // Best-effort: never fail install due to logging.
    }
  }

  return { emit, enabled };
}

module.exports = {
  createInstallerStructuredLogger,
  parseBooleanEnv,
  redactUrl,
  redactValue
};
