#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

function resolveMacHostPlatformOverride() {
  const raw = os.release();
  const major = Number.parseInt(String(raw).split(".")[0], 10);
  if (!Number.isFinite(major)) return null;
  if (major < 18) return "mac10.13-arm64";
  if (major === 18) return "mac10.14-arm64";
  if (major === 19) return "mac10.15-arm64";
  const computed = Math.min(Math.max(major - 9, 10), 15);
  return `mac${computed}-arm64`;
}

function ensurePlaywrightHostPlatformOverride(env = process.env) {
  if (env.PLAYWRIGHT_HOST_PLATFORM_OVERRIDE) return;
  if (process.platform !== "darwin") return;
  if (process.arch !== "arm64") return;
  const override = resolveMacHostPlatformOverride();
  if (override) env.PLAYWRIGHT_HOST_PLATFORM_OVERRIDE = override;
}

ensurePlaywrightHostPlatformOverride();

function isTempPath(value, osModule = os) {
  if (!value) return false;
  const tmpdir = osModule.tmpdir();
  if (!tmpdir) return false;
  const resolvedValue = path.resolve(value);
  const resolvedTmp = path.resolve(tmpdir);
  return resolvedValue === resolvedTmp || resolvedValue.startsWith(resolvedTmp + path.sep);
}

function resolveStableNodeBin({ env = process.env, spawnSyncFn = spawnSync } = {}) {
  const envNode = String(env.DOCDEX_PLAYWRIGHT_NODE_BIN || env.DOCDEX_NODE_BIN || "").trim();
  if (envNode && fs.existsSync(envNode)) return envNode;
  if (process.execPath && fs.existsSync(process.execPath) && !isTempPath(process.execPath)) {
    return process.execPath;
  }
  const locator = process.platform === "win32" ? "where" : "which";
  const resolved = spawnSyncFn(locator, ["node"], { encoding: "utf8" });
  if (resolved && !resolved.error && resolved.status === 0 && resolved.stdout) {
    const line = String(resolved.stdout).split(/\r?\n/).find((entry) => entry.trim());
    if (line && fs.existsSync(line.trim())) return line.trim();
  }
  if (process.execPath && fs.existsSync(process.execPath)) return process.execPath;
  return process.execPath;
}

const DEFAULT_BROWSERS = ["chromium"];
const ALLOWED_BROWSERS = new Set(["chromium", "firefox", "webkit"]);
const MANIFEST_FILE = "manifest.json";

function defaultBrowsersPath() {
  return path.join(os.homedir(), ".docdex", "state", "bin", "playwright");
}

function resolveBrowsersPath(env = process.env, overridePath) {
  if (overridePath) return overridePath;
  const envPath = String(env.PLAYWRIGHT_BROWSERS_PATH || "").trim();
  return envPath || defaultBrowsersPath();
}

function normalizeBrowserList(input) {
  let list = [];
  if (Array.isArray(input)) {
    list = input;
  } else if (typeof input === "string") {
    list = input.split(",");
  }
  const normalized = list
    .map((value) => String(value || "").trim().toLowerCase())
    .filter(Boolean);
  const unique = [];
  const seen = new Set();
  const base = normalized.length > 0 ? normalized : DEFAULT_BROWSERS;
  for (const name of base) {
    if (!ALLOWED_BROWSERS.has(name)) {
      throw new Error(`unsupported browser: ${name}`);
    }
    if (!seen.has(name)) {
      seen.add(name);
      unique.push(name);
    }
  }
  return unique;
}

function resolvePlaywrightCliPath() {
  let pkgPath;
  try {
    pkgPath = require.resolve("playwright/package.json");
  } catch {}
  if (pkgPath) {
    const pkgDir = path.dirname(pkgPath);
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));
      const binRel =
        typeof pkg?.bin === "string" ? pkg.bin : pkg?.bin?.playwright;
      if (binRel) {
        const binPath = path.join(pkgDir, binRel);
        if (fs.existsSync(binPath)) return binPath;
      }
    } catch {}
    const cliPath = path.join(pkgDir, "cli.js");
    if (fs.existsSync(cliPath)) return cliPath;
  }

  const candidates = ["playwright/cli", "playwright/cli.js", "playwright/lib/cli/cli.js"];
  for (const candidate of candidates) {
    try {
      return require.resolve(candidate);
    } catch {
      continue;
    }
  }
  throw new Error("playwright CLI not found; install the playwright dependency");
}

function loadPlaywright() {
  return require("playwright");
}

function loadBrowsersJson() {
  try {
    const corePkg = require.resolve("playwright-core/package.json");
    const coreDir = path.dirname(corePkg);
    const coreBrowsers = path.join(coreDir, "browsers.json");
    if (fs.existsSync(coreBrowsers)) {
      return JSON.parse(fs.readFileSync(coreBrowsers, "utf8"));
    }
  } catch {}
  try {
    return require("playwright/browsers.json");
  } catch {}
  throw new Error("playwright browsers.json not found; install playwright-core");
}

function loadPlaywrightVersion() {
  return require("playwright/package.json").version;
}

function resolveExecutablePath(playwright, name) {
  switch (name) {
    case "chromium":
      return playwright.chromium.executablePath();
    case "firefox":
      return playwright.firefox.executablePath();
    case "webkit":
      return playwright.webkit.executablePath();
    default:
      return "";
  }
}

function resolveRevision(browsersJson, name) {
  const entries = Array.isArray(browsersJson?.browsers) ? browsersJson.browsers : [];
  const match = entries.find((entry) => entry?.name === name);
  return match?.revision ? String(match.revision) : "unknown";
}

function buildManifest({
  browsers,
  browsersPath,
  playwright,
  browsersJson,
  playwrightVersion,
  nodeBin = process.execPath,
  now = new Date(),
  allowMissing = false,
  logger = console
}) {
  const installed = browsers.map((name) => {
    const executablePath = resolveExecutablePath(playwright, name);
    if (!executablePath || !fs.existsSync(executablePath)) {
      if (allowMissing) {
        logger?.warn?.(`[docdex] playwright ${name} executable missing at ${executablePath || "<unknown>"}`);
        return null;
      }
      throw new Error(`playwright ${name} executable missing at ${executablePath || "<unknown>"}`);
    }
    return {
      name,
      version: resolveRevision(browsersJson, name),
      path: executablePath
    };
  }).filter(Boolean);
  return {
    installed_at: now.toISOString(),
    browsers_path: browsersPath,
    playwright_version: playwrightVersion,
    node_bin: nodeBin,
    browsers: installed
  };
}

function installPlaywrightBrowsers({
  browsers,
  env = process.env,
  browsersPath,
  spawnSyncFn = spawnSync,
  logger = console,
  playwright,
  browsersJson,
  playwrightVersion,
  resolveCliPath = resolvePlaywrightCliPath,
  now
} = {}) {
  const baseEnv = { ...env };
  ensurePlaywrightHostPlatformOverride(baseEnv);
  const selected = normalizeBrowserList(browsers);
  const resolvedPath = resolveBrowsersPath(baseEnv, browsersPath);
  fs.mkdirSync(resolvedPath, { recursive: true });

  const cliPath = resolveCliPath();
  const runInstall = (names) =>
    spawnSyncFn(process.execPath, [cliPath, "install", ...names], {
      stdio: "inherit",
      env: childEnv
    });
  const childEnv = {
    ...baseEnv,
    PLAYWRIGHT_BROWSERS_PATH: resolvedPath
  };
  const result = runInstall(selected);
  if (result?.error) {
    throw new Error(result.error.message || String(result.error));
  }
  const installError =
    result?.status && result.status !== 0
      ? (result.stderr ? String(result.stderr).trim() : `playwright install failed (${result.status})`)
      : null;

  process.env.PLAYWRIGHT_BROWSERS_PATH = resolvedPath;
  const playwrightRuntime = playwright || loadPlaywright();
  const browsersMetadata = browsersJson || loadBrowsersJson();
  const version = playwrightVersion || loadPlaywrightVersion();
  const nodeBin = resolveStableNodeBin({ env: baseEnv, spawnSyncFn });
  const manifest = buildManifest({
    browsers: selected,
    browsersPath: resolvedPath,
    playwright: playwrightRuntime,
    browsersJson: browsersMetadata,
    playwrightVersion: version,
    nodeBin,
    now,
    allowMissing: true,
    logger
  });
  if (!manifest.browsers || manifest.browsers.length === 0 && selected.length > 1) {
    const recovered = [];
    for (const name of selected) {
      const attempt = runInstall([name]);
      if (attempt?.error) {
        logger?.warn?.(`[docdex] playwright ${name} install failed: ${attempt.error.message || attempt.error}`);
        continue;
      }
      if (attempt?.status && attempt.status !== 0) {
        logger?.warn?.(
          `[docdex] playwright ${name} install failed (${attempt.status})`
        );
        continue;
      }
      const partial = buildManifest({
        browsers: [name],
        browsersPath: resolvedPath,
        playwright: playwrightRuntime,
        browsersJson: browsersMetadata,
        playwrightVersion: version,
        nodeBin,
        now,
        allowMissing: true,
        logger
      });
      recovered.push(...partial.browsers);
    }
    if (recovered.length > 0) {
      manifest.browsers = recovered;
      logger?.warn?.(
        `[docdex] playwright install partially succeeded: ${recovered
          .map((entry) => entry.name)
          .join(", ")}`
      );
    }
  }
  if (!manifest.browsers || manifest.browsers.length === 0) {
    throw new Error(installError || "playwright install produced no usable browsers");
  }
  if (installError) {
    logger?.warn?.(`[docdex] playwright install completed with errors: ${installError}`);
  }

  const manifestPath = path.join(resolvedPath, MANIFEST_FILE);
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + "\n");
  logger?.warn?.(`[docdex] Playwright browsers installed: ${selected.join(", ")}`);
  logger?.warn?.(`[docdex] Playwright manifest saved: ${manifestPath}`);

  return { manifest, manifestPath };
}

function parseArgs(argv) {
  const parsed = { browsers: null, path: null, json: false };
  for (let i = 0; i < argv.length; i += 1) {
    const value = argv[i];
    if (value === "--browsers" && argv[i + 1]) {
      parsed.browsers = argv[i + 1];
      i += 1;
      continue;
    }
    if (value === "--path" && argv[i + 1]) {
      parsed.path = argv[i + 1];
      i += 1;
      continue;
    }
    if (value === "--json") {
      parsed.json = true;
    }
  }
  return parsed;
}

function main() {
  try {
    const args = parseArgs(process.argv.slice(2));
    const result = installPlaywrightBrowsers({
      browsers: args.browsers,
      browsersPath: args.path
    });
    if (args.json) {
      process.stdout.write(JSON.stringify(result.manifest, null, 2) + "\n");
    }
  } catch (err) {
    const message = err?.message || String(err);
    console.error(`[docdex] playwright install failed: ${message}`);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

module.exports = {
  buildManifest,
  defaultBrowsersPath,
  installPlaywrightBrowsers,
  normalizeBrowserList,
  resolveBrowsersPath,
  resolvePlaywrightCliPath
};
