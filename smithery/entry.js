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

const DEFAULT_LOG_LEVEL = "warn";
const DEFAULT_MAX_RESULTS = 8;

function normalizeConfig(config) {
  const repoPath = typeof config?.repo_path === "string" && config.repo_path.trim()
    ? config.repo_path
    : ".";
  const logLevel = typeof config?.log_level === "string" && config.log_level.trim()
    ? config.log_level
    : DEFAULT_LOG_LEVEL;
  const maxResults =
    Number.isInteger(config?.max_results) && config.max_results > 0
      ? config.max_results
      : DEFAULT_MAX_RESULTS;

  return { repoPath, logLevel, maxResults };
}

function buildArgs(config) {
  return [
    "--repo",
    config.repoPath,
    "--log",
    config.logLevel,
    "--max-results",
    String(config.maxResults)
  ];
}

function resolveCliArgs(argv) {
  const config = {};
  const passthrough = [];
  let sawConfig = false;

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--repo" && argv[i + 1]) {
      config.repo_path = argv[i + 1];
      sawConfig = true;
      i += 1;
      continue;
    }
    if (arg === "--log" && argv[i + 1]) {
      config.log_level = argv[i + 1];
      sawConfig = true;
      i += 1;
      continue;
    }
    if (arg === "--max-results" && argv[i + 1]) {
      const parsed = Number.parseInt(argv[i + 1], 10);
      if (!Number.isNaN(parsed)) {
        config.max_results = parsed;
        sawConfig = true;
      }
      i += 1;
      continue;
    }
    const kvMatch = arg.match(/^([^=]+)=(.*)$/);
    if (kvMatch) {
      const [, key, rawValue] = kvMatch;
      if (key === "repo_path") {
        config.repo_path = rawValue;
        sawConfig = true;
        continue;
      }
      if (key === "log_level") {
        config.log_level = rawValue;
        sawConfig = true;
        continue;
      }
      if (key === "max_results") {
        const parsed = Number.parseInt(rawValue, 10);
        if (!Number.isNaN(parsed)) {
          config.max_results = parsed;
          sawConfig = true;
          continue;
        }
      }
    }
    passthrough.push(arg);
  }

  if (!sawConfig) {
    return argv;
  }

  const resolved = normalizeConfig(config);
  return [...buildArgs(resolved), ...passthrough];
}

async function spawnMcpServer(args, logger) {
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

  const child = spawn(binaryPath, args, { stdio: "inherit" });
  child.on("exit", (code) => process.exit(code ?? 1));
  child.on("error", (err) => {
    if (logger?.error) {
      logger.error({ error: err }, "Failed to launch MCP server");
    } else {
      console.error(`[docdex] failed to launch MCP server: ${err.message}`);
    }
    process.exit(1);
  });

  await new Promise((resolve, reject) => {
    child.once("spawn", resolve);
    child.once("error", reject);
  });
}

function createServer({ config, logger }) {
  return {
    async connect() {
      const resolved = normalizeConfig(config);
      await spawnMcpServer(buildArgs(resolved), logger);
    }
  };
}

async function runCli() {
  await spawnMcpServer(resolveCliArgs(process.argv.slice(2)));
}

if (require.main === module) {
  runCli().catch((err) => {
    console.error(`[docdex] unexpected error: ${err?.message || String(err)}`);
    process.exit(1);
  });
}

module.exports = {
  default: createServer
};
