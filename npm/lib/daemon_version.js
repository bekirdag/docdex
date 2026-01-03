"use strict";

const fs = require("node:fs");
const { execFile } = require("node:child_process");

const DEFAULT_VERSION_PROBE_TIMEOUT_MS = 1500;

function parseDocdexdVersion(output) {
  if (output == null) return null;
  const text = String(output);
  const match = text.match(
    /(?:^|[^0-9A-Za-z])v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)/u
  );
  return match ? match[1] : null;
}

function normalizeExecErrorCode(err) {
  if (!err) return null;
  if (typeof err.code === "string" && err.code) return err.code;
  if (typeof err.errno === "string" && err.errno) return err.errno;
  return null;
}

async function probeDocdexdVersion({
  binaryPath,
  timeoutMs = DEFAULT_VERSION_PROBE_TIMEOUT_MS,
  execFileFn = execFile,
  fsModule = fs
} = {}) {
  if (!binaryPath) {
    return { status: "not_installed", version: null, error: "missing_path" };
  }

  const existsSync = typeof fsModule?.existsSync === "function" ? fsModule.existsSync.bind(fsModule) : null;
  if (!existsSync) {
    return { status: "unknown", version: null, error: "existsSync_unavailable" };
  }

  if (!existsSync(binaryPath)) {
    return { status: "not_installed", version: null, error: "missing_binary" };
  }

  return new Promise((resolve) => {
    execFileFn(
      binaryPath,
      ["--version"],
      { timeout: timeoutMs, windowsHide: true },
      (err, stdout, stderr) => {
        if (err) {
          const code = normalizeExecErrorCode(err);
          if (code === "ENOENT" || code === "EACCES") {
            resolve({ status: "not_installed", version: null, error: code.toLowerCase() });
            return;
          }
          if (code === "ETIMEDOUT" || err.killed) {
            resolve({ status: "error", version: null, error: "timeout" });
            return;
          }
          resolve({ status: "error", version: null, error: err.message || String(err) });
          return;
        }

        const combined = [stdout, stderr].filter(Boolean).join("\n");
        const parsed = parseDocdexdVersion(combined);
        if (!parsed) {
          resolve({ status: "unknown", version: null, error: "unparseable_version", output: combined.trim() });
          return;
        }

        resolve({ status: "installed", version: parsed, error: null });
      }
    );
  });
}

module.exports = {
  DEFAULT_VERSION_PROBE_TIMEOUT_MS,
  parseDocdexdVersion,
  probeDocdexdVersion
};
