"use strict";

const https = require("node:https");

const UPDATE_CHECK_ENV = "DOCDEX_UPDATE_CHECK";
const DEFAULT_REGISTRY_URL = "https://registry.npmjs.org/docdex/latest";
const DEFAULT_TIMEOUT_MS = 1500;
const MAX_RESPONSE_BYTES = 128 * 1024;

let hasChecked = false;

function normalizeVersion(value) {
  if (typeof value !== "string") return "";
  return value.trim().replace(/^v/i, "");
}

function resolveCurrentVersion(packageVersion, installMetadata) {
  const installed = normalizeVersion(installMetadata?.version);
  return installed || normalizeVersion(packageVersion);
}

function parseSemver(value) {
  const normalized = normalizeVersion(value);
  const match = normalized.match(
    /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/u
  );
  if (!match) return null;
  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3]),
    prerelease: match[4] ? match[4].split(".") : null
  };
}

function compareIdentifiers(left, right) {
  const leftNum = /^[0-9]+$/.test(left) ? Number(left) : null;
  const rightNum = /^[0-9]+$/.test(right) ? Number(right) : null;

  if (leftNum != null && rightNum != null) {
    if (leftNum === rightNum) return 0;
    return leftNum > rightNum ? 1 : -1;
  }

  if (leftNum != null) return -1;
  if (rightNum != null) return 1;
  if (left === right) return 0;
  return left > right ? 1 : -1;
}

function comparePrerelease(left, right) {
  if (!left && !right) return 0;
  if (!left) return 1;
  if (!right) return -1;

  const length = Math.max(left.length, right.length);
  for (let i = 0; i < length; i += 1) {
    const leftId = left[i];
    const rightId = right[i];
    if (leftId == null) return -1;
    if (rightId == null) return 1;
    const result = compareIdentifiers(leftId, rightId);
    if (result !== 0) return result;
  }
  return 0;
}

function compareSemver(left, right) {
  if (!left || !right) return null;
  if (left.major !== right.major) return left.major > right.major ? 1 : -1;
  if (left.minor !== right.minor) return left.minor > right.minor ? 1 : -1;
  if (left.patch !== right.patch) return left.patch > right.patch ? 1 : -1;
  return comparePrerelease(left.prerelease, right.prerelease);
}

function isDisabledEnv(value) {
  if (value == null) return false;
  const normalized = String(value).trim().toLowerCase();
  return normalized === "0" || normalized === "false" || normalized === "off" || normalized === "no";
}

function isEnabledEnv(value) {
  if (value == null) return false;
  const normalized = String(value).trim().toLowerCase();
  return normalized === "1" || normalized === "true" || normalized === "on" || normalized === "yes";
}

function isInteractive({ stdout, stderr } = {}) {
  return Boolean(stdout?.isTTY || stderr?.isTTY);
}

function shouldCheckForUpdate({ env, stdout, stderr } = {}) {
  const envValue = env?.[UPDATE_CHECK_ENV];
  if (isDisabledEnv(envValue)) return false;
  if (env?.CI && !isEnabledEnv(envValue)) return false;
  if (!isInteractive({ stdout, stderr }) && !isEnabledEnv(envValue)) return false;
  return true;
}

function fetchLatestVersion({
  httpsModule = https,
  registryUrl = DEFAULT_REGISTRY_URL,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  maxBytes = MAX_RESPONSE_BYTES
} = {}) {
  if (!httpsModule || typeof httpsModule.request !== "function") {
    return Promise.resolve(null);
  }

  return new Promise((resolve) => {
    let resolved = false;
    const finish = (value) => {
      if (resolved) return;
      resolved = true;
      resolve(value);
    };

    const req = httpsModule.request(
      registryUrl,
      {
        method: "GET",
        headers: {
          "User-Agent": "docdex-update-check",
          Accept: "application/json"
        }
      },
      (res) => {
        if (!res || res.statusCode !== 200) {
          res?.resume?.();
          finish(null);
          return;
        }
        res.setEncoding?.("utf8");
        let body = "";
        res.on("data", (chunk) => {
          body += chunk;
          if (body.length > maxBytes) {
            req.destroy?.();
            finish(null);
          }
        });
        res.on("end", () => {
          if (!body) {
            finish(null);
            return;
          }
          try {
            const parsed = JSON.parse(body);
            const version = typeof parsed?.version === "string" ? parsed.version : null;
            finish(version);
          } catch {
            finish(null);
          }
        });
      }
    );

    req.on("error", () => finish(null));
    if (typeof req.setTimeout === "function") {
      req.setTimeout(timeoutMs, () => {
        req.destroy?.();
        finish(null);
      });
    }
    if (typeof req.end === "function") req.end();
  });
}

async function checkForUpdate({
  currentVersion,
  env = process.env,
  stdout = process.stdout,
  stderr = process.stderr,
  logger = console,
  httpsModule = https,
  registryUrl = DEFAULT_REGISTRY_URL,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  maxBytes = MAX_RESPONSE_BYTES
} = {}) {
  if (!shouldCheckForUpdate({ env, stdout, stderr })) {
    return { checked: false, updateAvailable: false };
  }

  const current = normalizeVersion(currentVersion);
  if (!current) {
    return { checked: true, updateAvailable: false };
  }

  const latest = normalizeVersion(
    await fetchLatestVersion({ httpsModule, registryUrl, timeoutMs, maxBytes })
  );
  if (!latest) {
    return { checked: true, updateAvailable: false };
  }

  const comparison = compareSemver(parseSemver(current), parseSemver(latest));
  if (comparison == null || comparison >= 0) {
    return { checked: true, updateAvailable: false, latestVersion: latest };
  }

  logger?.log?.(`[docdex] Update available: v${current} -> v${latest}`);
  logger?.log?.("[docdex] Run: npm i -g docdex@latest");
  logger?.log?.(`[docdex] Disable update checks with ${UPDATE_CHECK_ENV}=0`);

  return { checked: true, updateAvailable: true, latestVersion: latest };
}

async function checkForUpdateOnce(options) {
  if (hasChecked) return { checked: false, updateAvailable: false };
  hasChecked = true;
  return checkForUpdate(options);
}

module.exports = {
  DEFAULT_REGISTRY_URL,
  DEFAULT_TIMEOUT_MS,
  MAX_RESPONSE_BYTES,
  checkForUpdate,
  checkForUpdateOnce,
  compareSemver,
  parseSemver,
  resolveCurrentVersion,
  shouldCheckForUpdate
};
