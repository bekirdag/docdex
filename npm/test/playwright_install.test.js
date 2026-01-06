const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");

const {
  buildManifest,
  defaultBrowsersPath,
  installPlaywrightBrowsers,
  normalizeBrowserList,
  resolveBrowsersPath
} = require("../lib/playwright_install");

function makeTempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "docdex-pw-"));
}

test("normalizeBrowserList defaults to chromium and de-dupes", () => {
  assert.deepEqual(normalizeBrowserList(""), ["chromium"]);
  assert.deepEqual(normalizeBrowserList(["Chromium", "firefox", "chromium"]), [
    "chromium",
    "firefox"
  ]);
});

test("resolveBrowsersPath uses env override", () => {
  const env = { PLAYWRIGHT_BROWSERS_PATH: "/tmp/pw-cache" };
  assert.equal(resolveBrowsersPath(env), "/tmp/pw-cache");
  assert.equal(resolveBrowsersPath({}, "/tmp/override"), "/tmp/override");
});

test("defaultBrowsersPath points to docdex state bin", () => {
  const expected = path.join(os.homedir(), ".docdex", "state", "bin", "playwright");
  assert.equal(defaultBrowsersPath(), expected);
});

test("buildManifest records browser paths and revisions", () => {
  const dir = makeTempDir();
  const chromiumPath = path.join(dir, "chromium");
  fs.writeFileSync(chromiumPath, "");
  const playwright = {
    chromium: { executablePath: () => chromiumPath },
    firefox: { executablePath: () => "" },
    webkit: { executablePath: () => "" }
  };
  const browsersJson = { browsers: [{ name: "chromium", revision: "12345" }] };
  const manifest = buildManifest({
    browsers: ["chromium"],
    browsersPath: dir,
    playwright,
    browsersJson,
    playwrightVersion: "1.2.3",
    now: new Date("2024-01-01T00:00:00Z")
  });
  assert.equal(manifest.playwright_version, "1.2.3");
  assert.equal(manifest.browsers[0].name, "chromium");
  assert.equal(manifest.browsers[0].version, "12345");
  assert.equal(manifest.browsers[0].path, chromiumPath);
});

test("installPlaywrightBrowsers writes manifest and invokes cli", () => {
  const dir = makeTempDir();
  const chromiumPath = path.join(dir, "chromium");
  const firefoxPath = path.join(dir, "firefox");
  fs.writeFileSync(chromiumPath, "");
  fs.writeFileSync(firefoxPath, "");

  const calls = [];
  const spawnSyncFn = (cmd, args, opts) => {
    calls.push({ cmd, args, opts });
    return { status: 0, stdout: "", stderr: "" };
  };
  const playwright = {
    chromium: { executablePath: () => chromiumPath },
    firefox: { executablePath: () => firefoxPath },
    webkit: { executablePath: () => "" }
  };
  const browsersJson = {
    browsers: [
      { name: "chromium", revision: "111" },
      { name: "firefox", revision: "222" }
    ]
  };
  const result = installPlaywrightBrowsers({
    browsers: "chromium,firefox",
    browsersPath: dir,
    env: {},
    spawnSyncFn,
    playwright,
    browsersJson,
    playwrightVersion: "9.9.9",
    resolveCliPath: () => "/tmp/playwright-cli.js",
    now: new Date("2024-01-01T00:00:00Z")
  });

  assert.equal(calls.length, 1);
  assert.equal(calls[0].cmd, process.execPath);
  assert.equal(calls[0].args[0], "/tmp/playwright-cli.js");
  assert.equal(calls[0].args[1], "install");
  assert.ok(calls[0].opts.env.PLAYWRIGHT_BROWSERS_PATH);
  assert.ok(fs.existsSync(result.manifestPath));
  assert.equal(result.manifest.browsers.length, 2);
});
