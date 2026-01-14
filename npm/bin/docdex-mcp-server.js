#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { spawn } = require("node:child_process");

const {
  detectPlatformKey,
  targetTripleForPlatformKey,
  assetPatternForPlatformKey,
  UnsupportedPlatformError
} = require("../lib/platform");

function envBool(value) {
  if (!value) return false;
  const normalized = String(value).trim().toLowerCase();
  return ["1", "true", "t", "yes", "y", "on"].includes(normalized);
}

function standaloneAllowed(argv, env) {
  if (envBool(env.DOCDEX_ENABLE_STANDALONE_MCP)) return true;
  return argv.includes("--enable-standalone") || argv.includes("--allow-standalone");
}

function run() {
  if (!standaloneAllowed(process.argv, process.env)) {
    console.error(
      "[docdex] docdex-mcp-server is disabled by default. Use the daemon MCP endpoint (/v1/mcp/sse) or `docdexd mcp`.\n[docdex] To run standalone, pass --enable-standalone or set DOCDEX_ENABLE_STANDALONE_MCP=1."
    );
    process.exit(1);
    return;
  }
  let platformKey;
  try {
    platformKey = detectPlatformKey();
  } catch (err) {
    if (err instanceof UnsupportedPlatformError) {
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
      return;
    }
    console.error(`[docdex] failed to detect platform: ${err?.message || String(err)}`);
    process.exit(1);
    return;
  }

  const basePath = path.join(__dirname, "..", "dist", platformKey);
  const binaryPath = path.join(
    basePath,
    process.platform === "win32" ? "docdex-mcp-server.exe" : "docdex-mcp-server"
  );

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

  const child = spawn(binaryPath, process.argv.slice(2), { stdio: "inherit" });
  child.on("exit", (code) => process.exit(code ?? 1));
  child.on("error", (err) => {
    console.error(`[docdex] failed to launch MCP server: ${err.message}`);
    process.exit(1);
  });
}

run();
