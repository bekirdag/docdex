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

async function writeInstalledBinary({ distDir, isWin32, bytes }) {
  await ensureDir(distDir);
  const binaryPath = path.join(distDir, isWin32 ? "docdexd.exe" : "docdexd");
  await fs.promises.writeFile(binaryPath, bytes);
  return binaryPath;
}

async function writeInstallMetadata({
  distDir,
  platformKey,
  version,
  targetTriple,
  binarySha256,
  repoSlug = "owner/repo"
}) {
  const metadataPath = path.join(distDir, "docdexd-install.json");
  const payload = {
    schemaVersion: 1,
    installedAt: new Date().toISOString(),
    version,
    repoSlug,
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
  await fs.promises.writeFile(metadataPath, `${JSON.stringify(payload, null, 2)}\n`, "utf8");
  return metadataPath;
}

function listTransientDirs({ baseDir, platformKey }) {
  const prefixes = [`${platformKey}.stage.`, `${platformKey}.backup.`, `${platformKey}.failed.`];
  return fs
    .readdirSync(baseDir, { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && prefixes.some((p) => entry.name.startsWith(p)))
    .map((entry) => entry.name)
    .sort();
}

test("installer cleanup: extract failure keeps prior install and removes staging artifacts", async (t) => {
  const base = "https://example.test/releases/download";
  const installedVersion = "0.0.1";
  const expectedVersion = "0.0.2";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const isWin32 = false;

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-cleanup-extract-fail-"));
  t.after(async () => {
    await fs.promises.rm(tmpRoot, { recursive: true, force: true });
  });

  const distBaseDir = path.join(tmpRoot, "dist");
  const distDir = path.join(distBaseDir, platformKey);
  const tmpDir = path.join(tmpRoot, "tmp");
  await ensureDir(tmpDir);

  const oldBinaryPath = await writeInstalledBinary({ distDir, isWin32, bytes: "old-binary\n" });
  const oldSha = await sha256File(oldBinaryPath);
  await writeInstallMetadata({ distDir, platformKey, version: installedVersion, targetTriple, binarySha256: oldSha });

  const archive = "docdexd-linux-x64-gnu.tar.gz";

  await assert.rejects(
    runInstaller({
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
      extractTarballFn: async (_archivePath, targetDir) => {
        await ensureDir(targetDir);
        await fs.promises.writeFile(path.join(targetDir, "docdexd"), "new-binary\n", "utf8");
        throw new Error("boom: extract failed");
      }
    })
  );

  assert.equal(await fs.promises.readFile(oldBinaryPath, "utf8"), "old-binary\n");
  const metadataPath = path.join(distDir, "docdexd-install.json");
  const meta = JSON.parse(await fs.promises.readFile(metadataPath, "utf8"));
  assert.equal(meta.version, installedVersion);
  assert.deepEqual(listTransientDirs({ baseDir: distBaseDir, platformKey }), []);
});

test("installer cleanup: chmod failure rolls back to prior install", async (t) => {
  const base = "https://example.test/releases/download";
  const installedVersion = "0.0.1";
  const expectedVersion = "0.0.2";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const isWin32 = false;

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-cleanup-chmod-fail-"));
  t.after(async () => {
    await fs.promises.rm(tmpRoot, { recursive: true, force: true });
  });

  const distBaseDir = path.join(tmpRoot, "dist");
  const distDir = path.join(distBaseDir, platformKey);
  const tmpDir = path.join(tmpRoot, "tmp");
  await ensureDir(tmpDir);

  const oldBinaryPath = await writeInstalledBinary({ distDir, isWin32, bytes: "old-binary\n" });
  const oldSha = await sha256File(oldBinaryPath);
  await writeInstallMetadata({ distDir, platformKey, version: installedVersion, targetTriple, binarySha256: oldSha });

  const archive = "docdexd-linux-x64-gnu.tar.gz";

  const fsModule = {
    ...fs,
    promises: {
      ...fs.promises,
      chmod: async () => {
        const err = new Error("EPERM: chmod blocked by test");
        err.code = "EPERM";
        throw err;
      }
    }
  };

  await assert.rejects(
    runInstaller({
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
        await fs.promises.writeFile(path.join(targetDir, "docdexd"), "new-binary\n", "utf8");
      }
    })
  );

  assert.equal(await fs.promises.readFile(oldBinaryPath, "utf8"), "old-binary\n");
  const metadataPath = path.join(distDir, "docdexd-install.json");
  const meta = JSON.parse(await fs.promises.readFile(metadataPath, "utf8"));
  assert.equal(meta.version, installedVersion);
  assert.deepEqual(listTransientDirs({ baseDir: distBaseDir, platformKey }), []);
});
