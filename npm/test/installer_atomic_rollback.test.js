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

test("atomic rollback: failed extract preserves existing install and cleans staging", async (t) => {
  const base = "https://example.test/releases/download";
  const expectedVersion = "0.0.2";
  const installedVersion = "0.0.1";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const isWin32 = false;

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-rollback-extract-"));
  t.after(async () => {
    await fs.promises.rm(tmpRoot, { recursive: true, force: true });
  });

  const distBaseDir = path.join(tmpRoot, "dist");
  const distDir = path.join(distBaseDir, platformKey);
  const tmpDir = path.join(tmpRoot, "tmp");
  await ensureDir(tmpDir);

  const oldBinaryPath = await writeInstalledBinary({ distDir, isWin32, bytes: "old-binary\n" });
  const oldSha = await sha256File(oldBinaryPath);
  await writeInstallMetadata({
    distDir,
    platformKey,
    version: installedVersion,
    targetTriple,
    binarySha256: oldSha
  });

  const archive = "docdexd-linux-x64-gnu.tar.gz";
  const expectedDownloadUrl = `${base}/v${expectedVersion}/${archive}`;

  await assert.rejects(
    () =>
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
        downloadFn: async (url, dest) => {
          assert.equal(url, expectedDownloadUrl);
          await ensureDir(path.dirname(dest));
          await fs.promises.writeFile(dest, "fake-archive-bytes");
        },
        verifyDownloadedFileIntegrityFn: async () => null,
        extractTarballFn: async (_archivePath, targetDir) => {
          await ensureDir(targetDir);
          await fs.promises.writeFile(path.join(targetDir, "docdexd"), "partial\n");
          throw new Error("extract failed");
        }
      }),
    /extract failed/
  );

  assert.equal(await fs.promises.readFile(path.join(distDir, "docdexd"), "utf8"), "old-binary\n");
  const meta = JSON.parse(await fs.promises.readFile(path.join(distDir, "docdexd-install.json"), "utf8"));
  assert.equal(meta.version, installedVersion);

  const entries = await fs.promises.readdir(distBaseDir);
  assert.deepEqual(entries.sort(), [platformKey]);
});

test("atomic rollback: swap failure restores existing install and cleans staging", async (t) => {
  const base = "https://example.test/releases/download";
  const expectedVersion = "0.0.2";
  const installedVersion = "0.0.1";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const isWin32 = false;

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-rollback-swap-"));
  t.after(async () => {
    await fs.promises.rm(tmpRoot, { recursive: true, force: true });
  });

  const distBaseDir = path.join(tmpRoot, "dist");
  const distDir = path.join(distBaseDir, platformKey);
  const tmpDir = path.join(tmpRoot, "tmp");
  await ensureDir(tmpDir);

  const oldBinaryPath = await writeInstalledBinary({ distDir, isWin32, bytes: "old-binary\n" });
  const oldSha = await sha256File(oldBinaryPath);
  await writeInstallMetadata({
    distDir,
    platformKey,
    version: installedVersion,
    targetTriple,
    binarySha256: oldSha
  });

  const archive = "docdexd-linux-x64-gnu.tar.gz";

  const fsModule = {
    ...fs,
    promises: {
      ...fs.promises,
      rename: async (from, to) => {
        if (to === distDir && typeof from === "string" && from.startsWith(`${distDir}.stage.`)) {
          const err = new Error("simulated swap failure");
          err.code = "EACCES";
          throw err;
        }
        return fs.promises.rename(from, to);
      }
    }
  };

  await assert.rejects(
    () =>
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
          await fs.promises.writeFile(path.join(targetDir, "docdexd"), "new-binary\n");
        }
      }),
    /simulated swap failure/
  );

  assert.equal(await fs.promises.readFile(path.join(distDir, "docdexd"), "utf8"), "old-binary\n");
  const meta = JSON.parse(await fs.promises.readFile(path.join(distDir, "docdexd-install.json"), "utf8"));
  assert.equal(meta.version, installedVersion);

  const entries = await fs.promises.readdir(distBaseDir);
  assert.deepEqual(entries.sort(), [platformKey]);
});
