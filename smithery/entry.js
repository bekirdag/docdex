"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");

const { runInstaller, handleFatal } = require("../npm/lib/install");
const {
  detectPlatformKey,
  targetTripleForPlatformKey,
  assetPatternForPlatformKey,
  UnsupportedPlatformError
} = require("../npm/lib/platform");

const DIST_BASE_DIR =
  process.env.DOCDEX_SMITHERY_DIST ||
  path.join(os.homedir(), ".docdex", "smithery", "dist");

function reportUnsupportedPlatform(err) {
  const detected = `${err.details?.platform ?? process.platform}/${err.details?.arch ?? process.arch}`;
  const libc = err.details?.libc ? `/${err.details.libc}` : "";
  console.error(`[docdex] unsupported platform (${detected}${libc})`);
  console.error(`[docdex] error code: ${err.code}`);
  console.error("[docdex] No download/run was attempted for this platform.");
  if (Array.isArray(err.details?.supportedPlatformKeys) && err.details.supportedPlatformKeys.length) {
    console.error(`[docdex] Supported platforms: ${err.details.supportedPlatformKeys.join(", ")}`);
  }
  if (typeof err.details?.candidatePlatformKey === "string") {
    console.error(`[docdex] Asset naming pattern: ${assetPatternForPlatformKey(err.details.candidatePlatformKey)}`);
  }
  console.error("[docdex] Next steps: use a supported platform or build from source (Rust).");
  process.exit(err.exitCode || 3);
}

function resolveMcpBinaryPath(platformKey) {
  if (process.env.DOCDEX_MCP_SERVER_BIN) {
    const explicit = process.env.DOCDEX_MCP_SERVER_BIN;
    if (fs.existsSync(explicit)) return explicit;
  }
  const binaryName = process.platform === "win32" ? "docdex-mcp-server.exe" : "docdex-mcp-server";
  return path.join(DIST_BASE_DIR, platformKey, binaryName);
}

async function ensureMcpBinary(platformKey) {
  const binaryPath = resolveMcpBinaryPath(platformKey);
  if (!fs.existsSync(binaryPath)) {
    try {
      await runInstaller({ distBaseDir: DIST_BASE_DIR, logger: console });
    } catch (err) {
      handleFatal(err);
      return null;
    }
  }

  if (!fs.existsSync(binaryPath)) {
    console.error(
      `[docdex] Missing MCP server binary for ${platformKey}. Try reinstalling or set DOCDEX_MCP_SERVER_BIN.`
    );
    try {
      console.error(`[docdex] Expected target triple: ${targetTripleForPlatformKey(platformKey)}`);
      console.error(`[docdex] Asset naming pattern: ${assetPatternForPlatformKey(platformKey)}`);
    } catch {}
    process.exit(1);
  }

  return binaryPath;
}

async function run() {
  let platformKey;
  try {
    platformKey = detectPlatformKey();
  } catch (err) {
    if (err instanceof UnsupportedPlatformError) {
      reportUnsupportedPlatform(err);
      return;
    }
    console.error(`[docdex] failed to detect platform: ${err?.message || String(err)}`);
    process.exit(1);
    return;
  }

  const binaryPath = await ensureMcpBinary(platformKey);
  if (!binaryPath) return;

  const child = spawn(binaryPath, process.argv.slice(2), { stdio: "inherit" });
  child.on("exit", (code) => process.exit(code ?? 1));
  child.on("error", (err) => {
    console.error(`[docdex] failed to launch MCP server: ${err.message}`);
    process.exit(1);
  });
}

run().catch((err) => {
  console.error(`[docdex] unexpected error: ${err?.message || String(err)}`);
  process.exit(1);
});
