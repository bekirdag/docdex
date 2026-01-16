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

function wrapFsRenameWithFault({ failRename }) {
  return {
    ...fs,
    promises: {
      ...fs.promises,
      rename: async (from, to) => {
        if (failRename(from, to)) {
          const err = new Error(`simulated rename failure: ${from} -> ${to}`);
          err.code = "SIMULATED_RENAME_FAIL";
          throw err;
        }
        return fs.promises.rename(from, to);
      }
    }
  };
}

test("installer: extract failure preserves previous install and cleans temp/staging", async (t) => {
  const base = "https://example.test/releases/download";
  const expectedVersion = "0.0.2";
  const installedVersion = "0.0.1";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const archive = "docdexd-linux-x64-gnu.tar.gz";
  const isWin32 = false;

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-rollback-extract-"));
  t.after(async () => {
    await fs.promises.rm(tmpRoot, { recursive: true, force: true });
  });

  const distBaseDir = path.join(tmpRoot, "dist");
  const distDir = path.join(distBaseDir, platformKey);
  const tmpDir = path.join(tmpRoot, "tmp");
  await ensureDir(tmpDir);

  const oldBinaryBytes = "old-binary\n";
  const oldBinaryPath = await writeInstalledBinary({ distDir, isWin32, bytes: oldBinaryBytes });
  const oldSha = await sha256File(oldBinaryPath);
  const oldMetadataPath = await writeInstallMetadata({
    distDir,
    platformKey,
    version: installedVersion,
    targetTriple,
    binarySha256: oldSha
  });

  const oldMetadataRaw = await fs.promises.readFile(oldMetadataPath, "utf8");

  let downloadDest = null;
  let extractTargetDir = null;

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
        downloadFn: async (_url, dest) => {
          downloadDest = dest;
          await ensureDir(path.dirname(dest));
          await fs.promises.writeFile(dest, "partial-archive-bytes");
        },
        verifyDownloadedFileIntegrityFn: async () => null,
        extractTarballFn: async (_archivePath, targetDir) => {
          extractTargetDir = targetDir;
          await ensureDir(targetDir);
          await fs.promises.writeFile(path.join(targetDir, "docdexd"), "new-binary\n");
          throw new Error("simulated extract failure");
        }
      }),
    /simulated extract failure/
  );

  assert.equal(await fs.promises.readFile(oldBinaryPath, "utf8"), oldBinaryBytes);
  assert.equal(await fs.promises.readFile(oldMetadataPath, "utf8"), oldMetadataRaw);

  assert.ok(downloadDest, "expected download to run");
  assert.equal(fs.existsSync(downloadDest), false, "tmp download should be removed");

  assert.ok(extractTargetDir?.startsWith(`${distDir}.stage.`), `unexpected staging dir: ${extractTargetDir}`);
  assert.equal(fs.existsSync(extractTargetDir), false, "staging dir should be cleaned");
  const leftovers = await fs.promises.readdir(distBaseDir);
  assert.ok(
    leftovers.every((entry) => !entry.startsWith(`${platformKey}.stage.`) && !entry.startsWith(`${platformKey}.backup.`)),
    `expected no staging/backup leftovers, saw: ${leftovers.join(", ")}`
  );
});

test("installer: swap failure rolls back to previous install and cleans artifacts", async (t) => {
  const base = "https://example.test/releases/download";
  const expectedVersion = "0.0.2";
  const installedVersion = "0.0.1";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const archive = "docdexd-linux-x64-gnu.tar.gz";
  const isWin32 = false;

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-rollback-swap-"));
  t.after(async () => {
    await fs.promises.rm(tmpRoot, { recursive: true, force: true });
  });

  const distBaseDir = path.join(tmpRoot, "dist");
  const distDir = path.join(distBaseDir, platformKey);
  const tmpDir = path.join(tmpRoot, "tmp");
  await ensureDir(tmpDir);

  const oldBinaryBytes = "old-binary\n";
  const oldBinaryPath = await writeInstalledBinary({ distDir, isWin32, bytes: oldBinaryBytes });
  const oldSha = await sha256File(oldBinaryPath);
  const oldMetadataPath = await writeInstallMetadata({
    distDir,
    platformKey,
    version: installedVersion,
    targetTriple,
    binarySha256: oldSha
  });
  const oldMetadataRaw = await fs.promises.readFile(oldMetadataPath, "utf8");

  const stagePrefix = `${distDir}.stage.`;

  const fsWithFault = wrapFsRenameWithFault({
    failRename: (from, to) => typeof from === "string" && from.startsWith(stagePrefix) && to === distDir
  });

  let downloadDest = null;

  await assert.rejects(
    () =>
      runInstaller({
        logger: createNoopLogger(),
        fsModule: fsWithFault,
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
          downloadDest = dest;
          await ensureDir(path.dirname(dest));
          await fs.promises.writeFile(dest, "fake-archive-bytes");
        },
        verifyDownloadedFileIntegrityFn: async () => null,
        extractTarballFn: async (_archivePath, targetDir) => {
          await ensureDir(targetDir);
          await fs.promises.writeFile(path.join(targetDir, "docdexd"), "new-binary\n");
        }
      }),
    (err) => {
      assert.equal(err && err.code, "SIMULATED_RENAME_FAIL");
      return true;
    }
  );

  assert.equal(await fs.promises.readFile(oldBinaryPath, "utf8"), oldBinaryBytes);
  assert.equal(await fs.promises.readFile(oldMetadataPath, "utf8"), oldMetadataRaw);

  assert.ok(downloadDest, "expected download to run");
  assert.equal(fs.existsSync(downloadDest), false, "tmp download should be removed");

  const leftovers = await fs.promises.readdir(distBaseDir);
  assert.ok(
    leftovers.every((entry) => !entry.startsWith(`${platformKey}.stage.`) && !entry.startsWith(`${platformKey}.backup.`)),
    `expected no staging/backup leftovers, saw: ${leftovers.join(", ")}`
  );
});

test("installer: retry after interrupted swap cleans leftovers and succeeds", async (t) => {
  const base = "https://example.test/releases/download";
  const expectedVersion = "0.0.2";
  const installedVersion = "0.0.1";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const archive = "docdexd-linux-x64-gnu.tar.gz";
  const isWin32 = false;

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-retry-interrupted-"));
  t.after(async () => {
    await fs.promises.rm(tmpRoot, { recursive: true, force: true });
  });

  const distBaseDir = path.join(tmpRoot, "dist");
  const distDir = path.join(distBaseDir, platformKey);
  const backupDir = `${distDir}.backup.0.0`;
  const stageDir = `${distDir}.stage.0.0`;
  const tmpDir = path.join(tmpRoot, "tmp");
  await ensureDir(tmpDir);

  const oldBinaryBytes = "old-binary\n";
  const backupBinaryPath = await writeInstalledBinary({ distDir: backupDir, isWin32, bytes: oldBinaryBytes });
  const oldSha = await sha256File(backupBinaryPath);
  await writeInstallMetadata({
    distDir: backupDir,
    platformKey,
    version: installedVersion,
    targetTriple,
    binarySha256: oldSha
  });

  await ensureDir(stageDir);
  await fs.promises.writeFile(path.join(stageDir, "docdexd"), "partial-new\n", "utf8");

  let downloadDest = null;

  const result = await runInstaller({
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
      downloadDest = dest;
      await ensureDir(path.dirname(dest));
      await fs.promises.writeFile(dest, "fake-archive-bytes");
    },
    verifyDownloadedFileIntegrityFn: async () => null,
    extractTarballFn: async (_archivePath, targetDir) => {
      await ensureDir(targetDir);
      await fs.promises.writeFile(path.join(targetDir, "docdexd"), "new-binary\n", "utf8");
    }
  });

  assert.equal(result.outcome, "update");
  assert.equal(await fs.promises.readFile(path.join(distDir, "docdexd"), "utf8"), "new-binary\n");
  assert.ok(fs.existsSync(path.join(distDir, "docdexd-install.json")));

  assert.ok(downloadDest, "expected download to run");
  assert.equal(fs.existsSync(downloadDest), false, "tmp download should be removed");

  const leftovers = await fs.promises.readdir(distBaseDir);
  assert.ok(
    leftovers.every((entry) => !entry.startsWith(`${platformKey}.stage.`) && !entry.startsWith(`${platformKey}.backup.`)),
    `expected no staging/backup leftovers, saw: ${leftovers.join(", ")}`
  );
});

test("installer: metadata write failure preserves previous install and cleans staging", async (t) => {
  const base = "https://example.test/releases/download";
  const expectedVersion = "0.0.2";
  const installedVersion = "0.0.1";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const archive = "docdexd-linux-x64-gnu.tar.gz";
  const isWin32 = false;

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-rollback-metadata-"));
  t.after(async () => {
    await fs.promises.rm(tmpRoot, { recursive: true, force: true });
  });

  const distBaseDir = path.join(tmpRoot, "dist");
  const distDir = path.join(distBaseDir, platformKey);
  const tmpDir = path.join(tmpRoot, "tmp");
  await ensureDir(tmpDir);

  const oldBinaryBytes = "old-binary\n";
  const oldBinaryPath = await writeInstalledBinary({ distDir, isWin32, bytes: oldBinaryBytes });
  const oldSha = await sha256File(oldBinaryPath);
  const oldMetadataPath = await writeInstallMetadata({
    distDir,
    platformKey,
    version: installedVersion,
    targetTriple,
    binarySha256: oldSha
  });
  const oldMetadataRaw = await fs.promises.readFile(oldMetadataPath, "utf8");

  let downloadDest = null;

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
        downloadFn: async (_url, dest) => {
          downloadDest = dest;
          await ensureDir(path.dirname(dest));
          await fs.promises.writeFile(dest, "fake-archive-bytes");
        },
        verifyDownloadedFileIntegrityFn: async () => null,
        extractTarballFn: async (_archivePath, targetDir) => {
          await ensureDir(targetDir);
          await fs.promises.writeFile(path.join(targetDir, "docdexd"), "new-binary\n", "utf8");
        },
        writeJsonFileAtomicFn: async () => {
          throw new Error("simulated metadata write failure");
        }
      }),
    /simulated metadata write failure/
  );

  assert.equal(await fs.promises.readFile(oldBinaryPath, "utf8"), oldBinaryBytes);
  assert.equal(await fs.promises.readFile(oldMetadataPath, "utf8"), oldMetadataRaw);

  assert.ok(downloadDest, "expected download to run");
  assert.equal(fs.existsSync(downloadDest), false, "tmp download should be removed");

  const leftovers = await fs.promises.readdir(distBaseDir);
  assert.ok(
    leftovers.every((entry) => !entry.startsWith(`${platformKey}.stage.`) && !entry.startsWith(`${platformKey}.backup.`)),
    `expected no staging/backup leftovers, saw: ${leftovers.join(", ")}`
  );
});
