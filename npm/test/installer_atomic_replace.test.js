"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { runInstaller, sha256File } = require("../lib/install");
const { targetTripleForPlatformKey } = require("../lib/platform");

function createNoopLogger() {
  return {
    log: () => {},
    warn: () => {},
    error: () => {}
  };
}

async function ensureDir(dirPath) {
  await fs.promises.mkdir(dirPath, { recursive: true });
}

async function writeInstalledBinary({ distDir, bytes }) {
  await ensureDir(distDir);
  const binaryPath = path.join(distDir, "docdexd");
  await fs.promises.writeFile(binaryPath, bytes);
  return binaryPath;
}

async function writeInstallMetadata({ distDir, platformKey, version, targetTriple, binarySha256 }) {
  const payload = {
    schemaVersion: 1,
    installedAt: new Date().toISOString(),
    version,
    repoSlug: "owner/repo",
    platformKey,
    targetTriple,
    binary: {
      filename: "docdexd",
      sha256: binarySha256
    },
    archive: {
      name: null,
      sha256: null,
      source: null,
      downloadUrl: null
    }
  };
  await fs.promises.writeFile(path.join(distDir, "docdexd-install.json"), `${JSON.stringify(payload, null, 2)}\n`);
}

function listSiblings(dirPath) {
  try {
    return fs.readdirSync(dirPath);
  } catch {
    return [];
  }
}

test("installer atomic replace: extraction failure leaves existing install untouched", async (t) => {
  const base = "https://example.test/releases/download";
  const expectedVersion = "0.0.2";
  const installedVersion = "0.0.1";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const archive = "docdexd-linux-x64-gnu.tar.gz";

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-atomic-extract-fail-"));
  t.after(async () => {
    await fs.promises.rm(tmpRoot, { recursive: true, force: true });
  });

  const distBaseDir = path.join(tmpRoot, "dist");
  const distDir = path.join(distBaseDir, platformKey);
  const tmpDir = path.join(tmpRoot, "tmp");
  await ensureDir(tmpDir);

  const oldBinaryPath = await writeInstalledBinary({ distDir, bytes: "old-binary\n" });
  const oldBinarySha = await sha256File(oldBinaryPath);
  await writeInstallMetadata({ distDir, platformKey, version: installedVersion, targetTriple, binarySha256: oldBinarySha });

  const metadataBefore = await fs.promises.readFile(path.join(distDir, "docdexd-install.json"), "utf8");
  const binaryBefore = await fs.promises.readFile(oldBinaryPath, "utf8");

  let err;
  try {
    await runInstaller({
      logger: createNoopLogger(),
      platform: "linux",
      arch: "x64",
      tmpDir,
      distBaseDir,
      detectPlatformKeyFn: () => platformKey,
      targetTripleForPlatformKeyFn: () => targetTriple,
      getVersionFn: () => expectedVersion,
      parseRepoSlugFn: () => "owner/repo",
      getDownloadBaseFn: () => base,
      resolveInstallerDownloadPlanFn: async () => ({
        archive,
        expectedSha256: null,
        source: "fallback",
        manifestAttempt: { errors: [], resolved: null, manifestName: null }
      }),
      downloadFn: async (_url, dest) => {
        await ensureDir(path.dirname(dest));
        await fs.promises.writeFile(dest, "fake-archive-bytes");
      },
      verifyDownloadedFileIntegrityFn: async () => null,
      extractTarballFn: async () => {
        throw new Error("boom: extract failed");
      }
    });
  } catch (e) {
    err = e;
  }
  assert.ok(err, "expected install to fail");

  const metadataAfter = await fs.promises.readFile(path.join(distDir, "docdexd-install.json"), "utf8");
  const binaryAfter = await fs.promises.readFile(oldBinaryPath, "utf8");
  assert.equal(metadataAfter, metadataBefore);
  assert.equal(binaryAfter, binaryBefore);

  const siblings = listSiblings(distBaseDir);
  assert.ok(!siblings.some((name) => name.startsWith(`${platformKey}.stage.`)), "expected no leftover staging dirs");
});

test("installer atomic replace: failed swap rolls back to the previous install", async (t) => {
  const base = "https://example.test/releases/download";
  const expectedVersion = "0.0.2";
  const installedVersion = "0.0.1";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const archive = "docdexd-linux-x64-gnu.tar.gz";

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-atomic-swap-fail-"));
  t.after(async () => {
    await fs.promises.rm(tmpRoot, { recursive: true, force: true });
  });

  const distBaseDir = path.join(tmpRoot, "dist");
  const distDir = path.join(distBaseDir, platformKey);
  const tmpDir = path.join(tmpRoot, "tmp");
  await ensureDir(tmpDir);

  const oldBinaryPath = await writeInstalledBinary({ distDir, bytes: "old-binary\n" });
  const oldBinarySha = await sha256File(oldBinaryPath);
  await writeInstallMetadata({ distDir, platformKey, version: installedVersion, targetTriple, binarySha256: oldBinarySha });

  const metadataBefore = await fs.promises.readFile(path.join(distDir, "docdexd-install.json"), "utf8");
  const binaryBefore = await fs.promises.readFile(oldBinaryPath, "utf8");

  const realRename = fs.promises.rename.bind(fs.promises);
  const fsModule = {
    ...fs,
    existsSync: fs.existsSync.bind(fs),
    promises: {
      ...fs.promises,
      rename: async (from, to) => {
        if (to === distDir && typeof from === "string" && from.includes(`${platformKey}.stage.`)) {
          const e = new Error("EACCES: mocked swap failure");
          e.code = "EACCES";
          throw e;
        }
        return realRename(from, to);
      }
    }
  };

  let err;
  try {
    await runInstaller({
      logger: createNoopLogger(),
      platform: "linux",
      arch: "x64",
      tmpDir,
      distBaseDir,
      fsModule,
      detectPlatformKeyFn: () => platformKey,
      targetTripleForPlatformKeyFn: () => targetTriple,
      getVersionFn: () => expectedVersion,
      parseRepoSlugFn: () => "owner/repo",
      getDownloadBaseFn: () => base,
      resolveInstallerDownloadPlanFn: async () => ({
        archive,
        expectedSha256: null,
        source: "fallback",
        manifestAttempt: { errors: [], resolved: null, manifestName: null }
      }),
      downloadFn: async (_url, dest) => {
        await ensureDir(path.dirname(dest));
        await fs.promises.writeFile(dest, "fake-archive-bytes");
      },
      verifyDownloadedFileIntegrityFn: async () => null,
      extractTarballFn: async (_archivePath, targetDir) => {
        await ensureDir(targetDir);
        await fs.promises.writeFile(path.join(targetDir, "docdexd"), "new-binary\n");
      }
    });
  } catch (e) {
    err = e;
  }
  assert.ok(err, "expected install to fail");

  const metadataAfter = await fs.promises.readFile(path.join(distDir, "docdexd-install.json"), "utf8");
  const binaryAfter = await fs.promises.readFile(oldBinaryPath, "utf8");
  assert.equal(metadataAfter, metadataBefore);
  assert.equal(binaryAfter, binaryBefore);

  const siblings = listSiblings(distBaseDir);
  assert.ok(!siblings.some((name) => name.startsWith(`${platformKey}.stage.`)), "expected no leftover staging dirs");
  assert.ok(!siblings.some((name) => name.startsWith(`${platformKey}.backup.`)), "expected no leftover backup dirs");
});
