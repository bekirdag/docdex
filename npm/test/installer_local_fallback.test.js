"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { runInstaller } = require("../lib/install");
const { detectPlatformKey, targetTripleForPlatformKey } = require("../lib/platform");

function noopLogger() {
  return { log: () => {}, warn: () => {}, error: () => {} };
}

test("installer falls back to local binary when integrity metadata is missing", async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-local-fallback-"));
  t.after(() => fs.promises.rm(tmp, { recursive: true, force: true }));

  const repoRoot = path.join(tmp, "repo");
  const binaryName = process.platform === "win32" ? "docdexd.exe" : "docdexd";
  const mcpName = process.platform === "win32" ? "docdex-mcp-server.exe" : "docdex-mcp-server";
  const binaryPath = path.join(repoRoot, "target", "release", binaryName);
  const mcpPath = path.join(repoRoot, "target", "release", mcpName);
  await fs.promises.mkdir(path.dirname(binaryPath), { recursive: true });
  await fs.promises.writeFile(binaryPath, "local-binary\n");
  await fs.promises.writeFile(mcpPath, "local-mcp\n");

  const distBaseDir = path.join(tmp, "dist");
  const platformKey = "linux-x64-gnu";
  const targetTriple = "x86_64-unknown-linux-gnu";

  const result = await runInstaller({
    logger: noopLogger(),
    platform: "linux",
    arch: "x64",
    distBaseDir,
    detectPlatformKeyFn: () => platformKey,
    targetTripleForPlatformKeyFn: () => targetTriple,
    parseRepoSlugFn: () => "local/test",
    resolveInstallerDownloadPlanFn: async () => {
      const err = new Error("missing checksums");
      err.code = "DOCDEX_CHECKSUM_UNUSABLE";
      throw err;
    },
    localRepoRoot: repoRoot
  });

  assert.equal(result.outcome, "local");
  assert.ok(fs.existsSync(result.binaryPath));
  const distMcp = path.join(distBaseDir, platformKey, mcpName);
  assert.ok(fs.existsSync(distMcp));
});

test("installer prefers local binary when INIT_CWD points to a docdex repo", async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-local-prefer-"));
  t.after(() => fs.promises.rm(tmp, { recursive: true, force: true }));

  const repoRoot = path.join(tmp, "repo");
  const binaryName = process.platform === "win32" ? "docdexd.exe" : "docdexd";
  const mcpName = process.platform === "win32" ? "docdex-mcp-server.exe" : "docdex-mcp-server";
  const binaryPath = path.join(repoRoot, "target", "release", binaryName);
  const mcpPath = path.join(repoRoot, "target", "release", mcpName);
  await fs.promises.mkdir(path.dirname(binaryPath), { recursive: true });
  await fs.promises.writeFile(binaryPath, "local-binary\n");
  await fs.promises.writeFile(mcpPath, "local-mcp\n");
  await fs.promises.mkdir(path.join(repoRoot, "npm"), { recursive: true });
  await fs.promises.writeFile(
    path.join(repoRoot, "npm", "package.json"),
    JSON.stringify({ name: "docdex", version: "0.0.0" }),
    "utf8"
  );
  await fs.promises.writeFile(
    path.join(repoRoot, "Cargo.toml"),
    ['[package]', 'name = "docdexd"', 'version = "0.0.0"'].join("\n"),
    "utf8"
  );

  const distBaseDir = path.join(tmp, "dist");
  const platformKey = detectPlatformKey();
  const targetTriple = targetTripleForPlatformKey(platformKey);

  const result = await runInstaller({
    logger: noopLogger(),
    platform: process.platform,
    arch: process.arch,
    distBaseDir,
    detectPlatformKeyFn: () => platformKey,
    targetTripleForPlatformKeyFn: () => targetTriple,
    parseRepoSlugFn: () => {
      throw new Error("parseRepoSlug should not run");
    },
    resolveInstallerDownloadPlanFn: async () => {
      throw new Error("download plan should not run");
    },
    env: {
      INIT_CWD: repoRoot,
      npm_lifecycle_event: "postinstall",
      npm_config_argv: JSON.stringify({ original: ["install", "-g", "./npm"] })
    }
  });

  assert.equal(result.outcome, "local");
  assert.ok(fs.existsSync(result.binaryPath));
  const distMcp = path.join(distBaseDir, platformKey, mcpName);
  assert.ok(fs.existsSync(distMcp));
});

test("installer finds local mcp binary in debug folder", async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-local-debug-mcp-"));
  t.after(() => fs.promises.rm(tmp, { recursive: true, force: true }));

  const repoRoot = path.join(tmp, "repo");
  const binaryName = process.platform === "win32" ? "docdexd.exe" : "docdexd";
  const mcpName = process.platform === "win32" ? "docdex-mcp-server.exe" : "docdex-mcp-server";
  const binaryPath = path.join(repoRoot, "target", "release", binaryName);
  const mcpPath = path.join(repoRoot, "target", "debug", mcpName);
  await fs.promises.mkdir(path.dirname(binaryPath), { recursive: true });
  await fs.promises.mkdir(path.dirname(mcpPath), { recursive: true });
  await fs.promises.writeFile(binaryPath, "local-binary\n");
  await fs.promises.writeFile(mcpPath, "local-mcp\n");

  const distBaseDir = path.join(tmp, "dist");
  const platformKey = "linux-x64-gnu";
  const targetTriple = "x86_64-unknown-linux-gnu";

  const result = await runInstaller({
    logger: noopLogger(),
    platform: "linux",
    arch: "x64",
    distBaseDir,
    detectPlatformKeyFn: () => platformKey,
    targetTripleForPlatformKeyFn: () => targetTriple,
    parseRepoSlugFn: () => "local/test",
    resolveInstallerDownloadPlanFn: async () => {
      const err = new Error("missing checksums");
      err.code = "DOCDEX_CHECKSUM_UNUSABLE";
      throw err;
    },
    localRepoRoot: repoRoot
  });

  assert.equal(result.outcome, "local");
  assert.ok(fs.existsSync(result.binaryPath));
  const distMcp = path.join(distBaseDir, platformKey, mcpName);
  assert.ok(fs.existsSync(distMcp));
});

test("installer skips local binary when MCP binary is missing", async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-local-mcp-missing-"));
  t.after(() => fs.promises.rm(tmp, { recursive: true, force: true }));

  const repoRoot = path.join(tmp, "repo");
  const binaryName = process.platform === "win32" ? "docdexd.exe" : "docdexd";
  const mcpName = process.platform === "win32" ? "docdex-mcp-server.exe" : "docdex-mcp-server";
  const binaryPath = path.join(repoRoot, "target", "release", binaryName);
  await fs.promises.mkdir(path.dirname(binaryPath), { recursive: true });
  await fs.promises.writeFile(binaryPath, "local-binary\n");
  await fs.promises.mkdir(path.join(repoRoot, "npm"), { recursive: true });
  await fs.promises.writeFile(
    path.join(repoRoot, "npm", "package.json"),
    JSON.stringify({ name: "docdex", version: "0.0.0" }),
    "utf8"
  );
  await fs.promises.writeFile(
    path.join(repoRoot, "Cargo.toml"),
    ['[package]', 'name = "docdexd"', 'version = "0.0.0"'].join("\n"),
    "utf8"
  );

  const distBaseDir = path.join(tmp, "dist");
  const tmpDir = path.join(tmp, "tmp");
  await fs.promises.mkdir(tmpDir, { recursive: true });

  const platformKey = detectPlatformKey();
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const archive = "docdexd-fake.tar.gz";
  const base = "https://example.test/releases/download";

  const result = await runInstaller({
    logger: noopLogger(),
    platform: process.platform,
    arch: process.arch,
    distBaseDir,
    tmpDir,
    detectPlatformKeyFn: () => platformKey,
    targetTripleForPlatformKeyFn: () => targetTriple,
    parseRepoSlugFn: () => "local/test",
    getDownloadBaseFn: () => base,
    resolveInstallerDownloadPlanFn: async () => ({
      archive,
      expectedSha256: null,
      source: "fallback",
      manifestAttempt: { errors: [], resolved: null, manifestName: null }
    }),
    downloadFn: async (_url, dest) => {
      await fs.promises.mkdir(path.dirname(dest), { recursive: true });
      await fs.promises.writeFile(dest, "fake-archive\n");
    },
    extractTarballFn: async (_archivePath, targetDir) => {
      await fs.promises.mkdir(targetDir, { recursive: true });
      await fs.promises.writeFile(path.join(targetDir, binaryName), "new-binary\n");
      await fs.promises.writeFile(path.join(targetDir, mcpName), "new-mcp\n");
    },
    env: {
      INIT_CWD: repoRoot,
      npm_lifecycle_event: "postinstall",
      npm_config_argv: JSON.stringify({ original: ["install", "-g", "./npm"] })
    }
  });

  assert.notEqual(result.outcome, "local");
  assert.ok(fs.existsSync(result.binaryPath));
  const distMcp = path.join(distBaseDir, platformKey, mcpName);
  assert.ok(fs.existsSync(distMcp));
});
