#!/usr/bin/env node
"use strict";

const { chromium, firefox, webkit } = require("playwright");

const DEFAULT_TIMEOUT_MS = 15000;
const DEFAULT_BROWSER = "chromium";
const VIEWPORT = { width: 1920, height: 1080 };
const CHROMIUM_ARGS = [
  "--disable-blink-features=AutomationControlled",
  "--disable-dev-shm-usage",
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
  const launchOptions = {
    headless: options.headless
  };
  if (browserName === "chromium") {
    launchOptions.args = CHROMIUM_ARGS;
  }

  let browser;
  let context;
  try {
    if (options.userDataDir) {
      context = await browserType.launchPersistentContext(options.userDataDir, {
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
