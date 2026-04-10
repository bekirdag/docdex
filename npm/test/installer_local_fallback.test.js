"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { runInstaller } = require("../lib/install");
const { detectPlatformKey, targetTripleForPlatformKey } = require("../lib/platform");
const { version: PACKAGE_VERSION } = require("../package.json");

function noopLogger() {
  return { log: () => {}, warn: () => {}, error: () => {} };
}

test("installer falls back to local binary when integrity metadata is missing", async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-local-fallback-"));
  t.after(() => fs.promises.rm(tmp, { recursive: true, force: true }));

  const repoRoot = path.join(tmp, "repo");
  const binaryName = process.platform === "win32" ? "docdexd.exe" : "docdexd";
  const binaryPath = path.join(repoRoot, "target", "release", binaryName);
  await fs.promises.mkdir(path.dirname(binaryPath), { recursive: true });
  await fs.promises.writeFile(binaryPath, "local-binary\n");

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
    spawnSyncFn: () => ({
      status: 0,
      stdout: `docdexd ${PACKAGE_VERSION}\n`,
      stderr: ""
    }),
    localRepoRoot: repoRoot
  });

  assert.equal(result.outcome, "local");
  assert.ok(fs.existsSync(result.binaryPath));
});

test("installer prefers local binary for explicit local npm install requests", async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-local-prefer-"));
  t.after(() => fs.promises.rm(tmp, { recursive: true, force: true }));

  const repoRoot = path.join(tmp, "repo");
  const binaryName = process.platform === "win32" ? "docdexd.exe" : "docdexd";
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
    },
    spawnSyncFn: () => ({
      status: 0,
      stdout: `docdexd ${PACKAGE_VERSION}\n`,
      stderr: ""
    })
  });

  assert.equal(result.outcome, "local");
  assert.ok(fs.existsSync(result.binaryPath));
});

test("installer does not prefer a local repo binary for registry installs from the repo cwd", async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-local-registry-"));
  t.after(() => fs.promises.rm(tmp, { recursive: true, force: true }));

  const repoRoot = path.join(tmp, "repo");
  const binaryName = process.platform === "win32" ? "docdexd.exe" : "docdexd";
  const localBinaryPath = path.join(repoRoot, "target", "release", binaryName);
  await fs.promises.mkdir(path.dirname(localBinaryPath), { recursive: true });
  await fs.promises.writeFile(localBinaryPath, "local-binary\n");
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
  const expectedArchive = `docdexd-${platformKey}.tar.gz`;
  let downloadInvoked = false;

  const result = await runInstaller({
    logger: noopLogger(),
    platform: process.platform,
    arch: process.arch,
    distBaseDir,
    detectPlatformKeyFn: () => platformKey,
    targetTripleForPlatformKeyFn: () => targetTriple,
    parseRepoSlugFn: () => "owner/repo",
    resolveInstallerDownloadPlanFn: async () => ({
      archive: expectedArchive,
      expectedSha256: null,
      source: "fallback",
      manifestAttempt: { errors: [], resolved: null, manifestName: null }
    }),
    downloadFn: async (_url, dest) => {
      downloadInvoked = true;
      await fs.promises.mkdir(path.dirname(dest), { recursive: true });
      await fs.promises.writeFile(dest, "fake-archive");
    },
    verifyDownloadedFileIntegrityFn: async () => null,
    extractTarballFn: async (_archivePath, targetDir) => {
      await fs.promises.mkdir(targetDir, { recursive: true });
      const stagedBinaryPath = path.join(targetDir, binaryName);
      await fs.promises.writeFile(stagedBinaryPath, "#!/bin/sh\necho docdexd\n");
      if (process.platform !== "win32") {
        await fs.promises.chmod(stagedBinaryPath, 0o755);
      }
    },
    env: {
      INIT_CWD: repoRoot,
      npm_lifecycle_event: "postinstall",
      npm_config_argv: JSON.stringify({ original: ["install", "-g", "docdex@0.0.0"] })
    },
    localRepoRoot: repoRoot
  });

  assert.notEqual(result.outcome, "local");
  assert.equal(downloadInvoked, true);
  assert.ok(fs.existsSync(result.binaryPath));
});

test("installer rejects explicit local installs when the local binary version mismatches the package version", async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-local-version-mismatch-"));
  t.after(() => fs.promises.rm(tmp, { recursive: true, force: true }));

  const repoRoot = path.join(tmp, "repo");
  const binaryName = process.platform === "win32" ? "docdexd.exe" : "docdexd";
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

  await assert.rejects(
    runInstaller({
      logger: noopLogger(),
      platform: process.platform,
      arch: process.arch,
      distBaseDir: path.join(tmp, "dist"),
      detectPlatformKeyFn: () => detectPlatformKey(),
      targetTripleForPlatformKeyFn: () => targetTripleForPlatformKey(detectPlatformKey()),
      getVersionFn: () => PACKAGE_VERSION,
      parseRepoSlugFn: () => {
        throw new Error("parseRepoSlug should not run");
      },
      resolveInstallerDownloadPlanFn: async () => {
        throw new Error("download plan should not run");
      },
      spawnSyncFn: () => ({
        status: 0,
        stdout: "docdexd 0.2.59\n",
        stderr: ""
      }),
      env: {
        INIT_CWD: repoRoot,
        npm_lifecycle_event: "postinstall",
        npm_config_argv: JSON.stringify({ original: ["install", "-g", "./npm"] })
      },
      localRepoRoot: repoRoot
    }),
    (err) => {
      assert.equal(err.code, "DOCDEX_INSTALLER_CONFIG");
      assert.equal(
        err.message,
        `local Docdex binary is stale or invalid: expected ${PACKAGE_VERSION} but found 0.2.59`
      );
      return true;
    }
  );
});

test("installer skips stale local fallback binaries when remote integrity metadata is unavailable", async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-local-fallback-version-"));
  t.after(() => fs.promises.rm(tmp, { recursive: true, force: true }));

  const repoRoot = path.join(tmp, "repo");
  const binaryName = process.platform === "win32" ? "docdexd.exe" : "docdexd";
  const binaryPath = path.join(repoRoot, "target", "release", binaryName);
  await fs.promises.mkdir(path.dirname(binaryPath), { recursive: true });
  await fs.promises.writeFile(binaryPath, "local-binary\n");

  await assert.rejects(
    runInstaller({
      logger: noopLogger(),
      platform: "linux",
      arch: "x64",
      distBaseDir: path.join(tmp, "dist"),
      detectPlatformKeyFn: () => "linux-x64-gnu",
      targetTripleForPlatformKeyFn: () => "x86_64-unknown-linux-gnu",
      resolveInstallerDownloadPlanFn: async () => {
        const err = new Error("missing checksums");
        err.code = "DOCDEX_CHECKSUM_UNUSABLE";
        throw err;
      },
      spawnSyncFn: () => ({
        status: 0,
        stdout: "docdexd 0.2.59\n",
        stderr: ""
      }),
      localRepoRoot: repoRoot
    }),
    (err) => {
      assert.equal(err.code, "DOCDEX_CHECKSUM_UNUSABLE");
      return true;
    }
  );
});

test("installer honors DOCDEX_LOCAL_BINARY even when installed binary is up to date", async (t) => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-local-force-"));
  t.after(() => fs.promises.rm(tmp, { recursive: true, force: true }));

  const repoRoot = path.join(tmp, "repo");
  const binaryName = process.platform === "win32" ? "docdexd.exe" : "docdexd";
  const binaryPath = path.join(repoRoot, "target", "release", binaryName);
  await fs.promises.mkdir(path.dirname(binaryPath), { recursive: true });
  await fs.promises.writeFile(binaryPath, "local-binary\n");

  const distBaseDir = path.join(tmp, "dist");
  const platformKey = detectPlatformKey();
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const distDir = path.join(distBaseDir, platformKey);
  await fs.promises.mkdir(distDir, { recursive: true });

  const installedBinaryPath = path.join(distDir, binaryName);
  await fs.promises.writeFile(installedBinaryPath, "existing-binary\n");

  const installedSha = crypto
    .createHash("sha256")
    .update(fs.readFileSync(installedBinaryPath))
    .digest("hex");
  const metadataPath = path.join(distDir, "docdexd-install.json");
  await fs.promises.writeFile(
    metadataPath,
    JSON.stringify(
      {
        schemaVersion: 1,
        installedAt: new Date().toISOString(),
        version: "0.0.0",
        repoSlug: "local/test",
        platformKey,
        targetTriple,
        binary: {
          filename: binaryName,
          sha256: installedSha
        },
        archive: {
          name: null,
          sha256: null,
          source: "local",
          downloadUrl: null
        }
      },
      null,
      2
    ) + "\n"
  );

  const result = await runInstaller({
    logger: noopLogger(),
    platform: process.platform,
    arch: process.arch,
    distBaseDir,
    detectPlatformKeyFn: () => platformKey,
    targetTripleForPlatformKeyFn: () => targetTriple,
    getVersionFn: () => "0.0.0",
    parseRepoSlugFn: () => {
      throw new Error("parseRepoSlug should not run");
    },
    resolveInstallerDownloadPlanFn: async () => {
      throw new Error("download plan should not run");
    },
      env: {
        DOCDEX_LOCAL_BINARY: binaryPath
      },
      spawnSyncFn: () => ({
        status: 0,
        stdout: "docdexd 0.0.0\n",
        stderr: ""
      })
    });

  assert.equal(result.outcome, "local");
  const installed = fs.readFileSync(installedBinaryPath, "utf8");
  assert.equal(installed, "local-binary\n");
});
