#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

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

const { chromium, firefox, webkit } = require("playwright");

const DEFAULT_TIMEOUT_MS = 15000;
const DEFAULT_BROWSER = "chromium";
const VIEWPORT = { width: 1920, height: 1080 };
const CHROMIUM_ARGS = [
  "--disable-blink-features=AutomationControlled",
  "--disable-crashpad",
  "--disable-dev-shm-usage",
  "--disable-features=Crashpad",
  "--disable-gpu",
  "--no-sandbox",
  "--no-first-run",
  "--no-default-browser-check"
];

function normalizeBrowser(value) {
  const trimmed = String(value || "").trim().toLowerCase();
  if (trimmed === "chrome" || trimmed === "chromium" || trimmed === "chromium-browser") {
    return "chromium";
  }
  if (trimmed === "firefox") return "firefox";
  if (trimmed === "webkit") return "webkit";
  return DEFAULT_BROWSER;
}

function resolveBrowserType(name) {
  switch (name) {
    case "chromium":
      return chromium;
    case "firefox":
      return firefox;
    case "webkit":
      return webkit;
    default:
      return chromium;
  }
}

function resolveManifestPath(env = process.env) {
  const raw = String(env.PLAYWRIGHT_BROWSERS_PATH || "").trim();
  if (!raw) return null;
  return path.join(raw, "manifest.json");
}

function readManifest(env = process.env) {
  const manifestPath = resolveManifestPath(env);
  if (!manifestPath || !fs.existsSync(manifestPath)) return null;
  try {
    return JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  } catch {
    return null;
  }
}

function resolveExecutablePath(browserName, env = process.env) {
  const manifest = readManifest(env);
  const entries = Array.isArray(manifest?.browsers) ? manifest.browsers : [];
  const match = entries.find(
    (entry) =>
      String(entry?.name || "")
        .trim()
        .toLowerCase() === browserName
  );
  const candidate = match?.path;
  if (candidate && fs.existsSync(candidate)) {
    return candidate;
  }
  return null;
}

function ensureDir(dir) {
  if (!dir) return;
  fs.mkdirSync(dir, { recursive: true });
}

function allocateUserDataDir(baseDir) {
  const candidates = [];
  if (baseDir) candidates.push(baseDir);
  candidates.push(path.join(os.tmpdir(), "docdex-playwright"));
  for (const candidate of candidates) {
    try {
      ensureDir(candidate);
      const dir = fs.mkdtempSync(path.join(candidate, "profile-"));
      return {
        dir,
        cleanup: () => {
          try {
            fs.rmSync(dir, { recursive: true, force: true });
          } catch {
            // Best effort cleanup.
          }
        }
      };
    } catch {
      // Try next candidate.
    }
  }
  return { dir: "", cleanup: null };
}

function resolveCrashpadDir(userDataDir) {
  if (!userDataDir) return null;
  const crashpadDir = path.join(userDataDir, "crashpad");
  try {
    ensureDir(crashpadDir);
    return crashpadDir;
  } catch {
    return null;
  }
}

function parseArgs(argv) {
  const parsed = {
    url: "",
    browser: DEFAULT_BROWSER,
    timeoutMs: DEFAULT_TIMEOUT_MS,
    userAgent: "",
    headless: true,
    userDataDir: ""
  };
  for (let i = 0; i < argv.length; i += 1) {
    const value = argv[i];
    if (value === "--url" && argv[i + 1]) {
      parsed.url = argv[i + 1];
      i += 1;
      continue;
    }
    if (value === "--browser" && argv[i + 1]) {
      parsed.browser = argv[i + 1];
      i += 1;
      continue;
    }
    if (value === "--timeout-ms" && argv[i + 1]) {
      parsed.timeoutMs = Number(argv[i + 1]);
      i += 1;
      continue;
    }
    if (value === "--user-agent" && argv[i + 1]) {
      parsed.userAgent = argv[i + 1];
      i += 1;
      continue;
    }
    if (value === "--user-data-dir" && argv[i + 1]) {
      parsed.userDataDir = argv[i + 1];
      i += 1;
      continue;
    }
    if (value === "--headless") {
      parsed.headless = true;
      continue;
    }
    if (value === "--headed") {
      parsed.headless = false;
      continue;
    }
  }
  parsed.browser = normalizeBrowser(parsed.browser);
  if (!parsed.url) {
    throw new Error("missing --url");
  }
  if (!Number.isFinite(parsed.timeoutMs) || parsed.timeoutMs <= 0) {
    parsed.timeoutMs = DEFAULT_TIMEOUT_MS;
  }
  return parsed;
}

async function fetchWithPlaywright(options) {
  const browserName = normalizeBrowser(options.browser);
  const browserType = resolveBrowserType(browserName);
  const userData = options.userDataDir ? allocateUserDataDir(options.userDataDir) : { dir: "", cleanup: null };
  const userDataDir = userData.dir || "";
  const launchOptions = {
    headless: options.headless
  };
  const executablePath = resolveExecutablePath(browserName);
  if (executablePath) {
    launchOptions.executablePath = executablePath;
  }
  if (browserName === "chromium") {
    const args = [...CHROMIUM_ARGS];
    const crashpadDir = resolveCrashpadDir(userDataDir);
    if (crashpadDir) {
      args.push(`--crash-dumps-dir=${crashpadDir}`);
    }
    launchOptions.args = args;
  }

  let browser;
  let context;
  try {
    if (userDataDir) {
      context = await browserType.launchPersistentContext(userDataDir, {
        ...launchOptions,
        viewport: VIEWPORT,
        userAgent: options.userAgent || undefined
      });
    } else {
      browser = await browserType.launch(launchOptions);
      context = await browser.newContext({
        viewport: VIEWPORT,
        userAgent: options.userAgent || undefined
      });
    }

    await context.addInitScript(() => {
      Object.defineProperty(navigator, "webdriver", { get: () => undefined });
    });

    const page = await context.newPage();
    page.setDefaultTimeout(options.timeoutMs);
    const response = await page.goto(options.url, {
      waitUntil: "domcontentloaded",
      timeout: options.timeoutMs
    });
    const html = await page.content();
    const status = response ? response.status() : null;
    const finalUrl = page.url();
    await page.close();

    if (!html || !String(html).trim()) {
      throw new Error("empty HTML response");
    }

    return { html: String(html), status, final_url: finalUrl };
  } finally {
    if (context) {
      await context.close();
    }
    if (browser) {
      await browser.close();
    }
    if (userData.cleanup) {
      userData.cleanup();
    }
  }
}

async function main() {
  try {
    const options = parseArgs(process.argv.slice(2));
    const result = await fetchWithPlaywright(options);
    process.stdout.write(JSON.stringify(result) + "\n");
  } catch (err) {
    const message = err?.message || String(err);
    console.error(`[docdex] playwright fetch failed: ${message}`);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

module.exports = {
  fetchWithPlaywright,
  normalizeBrowser,
  parseArgs,
  resolveBrowserType
};
