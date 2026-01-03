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

function listInstallerArtifacts(distBaseDir, platformKey) {
  const entries = fs.existsSync(distBaseDir) ? fs.readdirSync(distBaseDir) : [];
  const prefixes = [`${platformKey}.stage.`, `${platformKey}.backup.`, `${platformKey}.failed.`];
  return entries.filter((name) => prefixes.some((prefix) => name.startsWith(prefix)));
}

test("installer contract: download failure leaves prior install intact and cleans temp archive", async (t) => {
  const version = "0.0.2";
  const installedVersion = "0.0.1";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const archive = "docdexd-linux-x64-gnu.tar.gz";
  const isWin32 = false;

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-contract-download-fail-"));
  t.after(async () => {
    await fs.promises.rm(tmpRoot, { recursive: true, force: true });
  });

  const distBaseDir = path.join(tmpRoot, "dist");
  const distDir = path.join(distBaseDir, platformKey);
  const tmpDir = path.join(tmpRoot, "tmp");
  await ensureDir(tmpDir);

  const oldBinaryPath = await writeInstalledBinary({ distDir, isWin32, bytes: "old-binary\n" });
  const oldSha = await sha256File(oldBinaryPath);
  const oldMetadata = await fs.promises.readFile(
    await writeInstallMetadata({ distDir, platformKey, version: installedVersion, targetTriple, binarySha256: oldSha }),
    "utf8"
  );

  const tmpFile = path.join(tmpDir, `${archive}.${process.pid}.tgz`);

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
      getVersionFn: () => version,
      parseRepoSlugFn: () => "owner/repo",
      resolveInstallerDownloadPlanFn: async () => ({
        archive,
        expectedSha256: null,
        source: "fallback",
        manifestAttempt: { errors: [], resolved: null, manifestName: null }
      }),
      downloadFn: async (_url, dest) => {
        await ensureDir(path.dirname(dest));
        await fs.promises.writeFile(dest, "partial");
        throw new Error("download boom");
      },
      verifyDownloadedFileIntegrityFn: async () => null,
      extractTarballFn: async () => {
        throw new Error("unexpected extract");
      }
    });
  } catch (e) {
    err = e;
  }

  assert.ok(err, "expected installer to fail");
  assert.ok(!fs.existsSync(tmpFile), "expected temp archive to be cleaned");
  assert.deepEqual(listInstallerArtifacts(distBaseDir, platformKey), []);

  const oldBinaryAfter = await fs.promises.readFile(oldBinaryPath, "utf8");
  assert.equal(oldBinaryAfter, "old-binary\n");
  const metadataAfter = await fs.promises.readFile(path.join(distDir, "docdexd-install.json"), "utf8");
  assert.equal(metadataAfter, oldMetadata);
});

test("installer contract: verify failure leaves prior install intact and cleans temp archive", async (t) => {
  const version = "0.0.2";
  const installedVersion = "0.0.1";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const archive = "docdexd-linux-x64-gnu.tar.gz";
  const isWin32 = false;

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-contract-verify-fail-"));
  t.after(async () => {
    await fs.promises.rm(tmpRoot, { recursive: true, force: true });
  });

  const distBaseDir = path.join(tmpRoot, "dist");
  const distDir = path.join(distBaseDir, platformKey);
  const tmpDir = path.join(tmpRoot, "tmp");
  await ensureDir(tmpDir);

  const oldBinaryPath = await writeInstalledBinary({ distDir, isWin32, bytes: "old-binary\n" });
  const oldSha = await sha256File(oldBinaryPath);
  const oldMetadata = await fs.promises.readFile(
    await writeInstallMetadata({ distDir, platformKey, version: installedVersion, targetTriple, binarySha256: oldSha }),
    "utf8"
  );

  const tmpFile = path.join(tmpDir, `${archive}.${process.pid}.tgz`);

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
      getVersionFn: () => version,
      parseRepoSlugFn: () => "owner/repo",
      resolveInstallerDownloadPlanFn: async () => ({
        archive,
        expectedSha256: "a".repeat(64),
        source: "fallback",
        manifestAttempt: { errors: [], resolved: null, manifestName: null }
      }),
      downloadFn: async (_url, dest) => {
        await ensureDir(path.dirname(dest));
        await fs.promises.writeFile(dest, "fake-archive");
      },
      verifyDownloadedFileIntegrityFn: async () => {
        throw new Error("verify boom");
      },
      extractTarballFn: async () => {
        throw new Error("unexpected extract");
      }
    });
  } catch (e) {
    err = e;
  }

  assert.ok(err, "expected installer to fail");
  assert.ok(!fs.existsSync(tmpFile), "expected temp archive to be cleaned");
  assert.deepEqual(listInstallerArtifacts(distBaseDir, platformKey), []);

  const oldBinaryAfter = await fs.promises.readFile(oldBinaryPath, "utf8");
  assert.equal(oldBinaryAfter, "old-binary\n");
  const metadataAfter = await fs.promises.readFile(path.join(distDir, "docdexd-install.json"), "utf8");
  assert.equal(metadataAfter, oldMetadata);
});

test("installer contract: swap failure rolls back and leaves prior install runnable", async (t) => {
  const version = "0.0.2";
  const installedVersion = "0.0.1";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const archive = "docdexd-linux-x64-gnu.tar.gz";
  const isWin32 = false;

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-contract-swap-fail-"));
  t.after(async () => {
    await fs.promises.rm(tmpRoot, { recursive: true, force: true });
  });

  const distBaseDir = path.join(tmpRoot, "dist");
  const distDir = path.join(distBaseDir, platformKey);
  const tmpDir = path.join(tmpRoot, "tmp");
  await ensureDir(tmpDir);
  const tmpFile = path.join(tmpDir, `${archive}.${process.pid}.tgz`);

  const oldBinaryPath = await writeInstalledBinary({ distDir, isWin32, bytes: "old-binary\n" });
  const oldSha = await sha256File(oldBinaryPath);
  await writeInstallMetadata({ distDir, platformKey, version: installedVersion, targetTriple, binarySha256: oldSha });

  const fsModule = {
    ...fs,
    promises: {
      ...fs.promises,
      rename: async (src, dest) => {
        if (dest === distDir && src.includes(`${platformKey}.stage.`)) {
          throw new Error("swap boom");
        }
        return fs.promises.rename(src, dest);
      }
    }
  };

  let err;
  try {
    await runInstaller({
      logger: createNoopLogger(),
      fsModule,
      platform: "linux",
      arch: "x64",
      tmpDir,
      distBaseDir,
      detectPlatformKeyFn: () => platformKey,
      targetTripleForPlatformKeyFn: () => targetTriple,
      getVersionFn: () => version,
      parseRepoSlugFn: () => "owner/repo",
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
    });
  } catch (e) {
    err = e;
  }

  assert.ok(err, "expected installer to fail");
  assert.ok(!fs.existsSync(tmpFile), "expected temp archive to be cleaned");
  assert.deepEqual(listInstallerArtifacts(distBaseDir, platformKey), []);

  const oldBinaryAfter = await fs.promises.readFile(oldBinaryPath, "utf8");
  assert.equal(oldBinaryAfter, "old-binary\n");
});

test("installer contract: restart failure rolls back to previous install", async (t) => {
  const version = "0.0.2";
  const installedVersion = "0.0.1";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const archive = "docdexd-linux-x64-gnu.tar.gz";
  const isWin32 = false;

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-contract-restart-fail-"));
  t.after(async () => {
    await fs.promises.rm(tmpRoot, { recursive: true, force: true });
  });

  const distBaseDir = path.join(tmpRoot, "dist");
  const distDir = path.join(distBaseDir, platformKey);
  const tmpDir = path.join(tmpRoot, "tmp");
  await ensureDir(tmpDir);
  const tmpFile = path.join(tmpDir, `${archive}.${process.pid}.tgz`);

  const oldBinaryPath = await writeInstalledBinary({ distDir, isWin32, bytes: "old-binary\n" });
  const oldSha = await sha256File(oldBinaryPath);
  await writeInstallMetadata({ distDir, platformKey, version: installedVersion, targetTriple, binarySha256: oldSha });

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
      getVersionFn: () => version,
      parseRepoSlugFn: () => "owner/repo",
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
      },
      restartFn: async () => {
        throw new Error("restart boom");
      }
    });
  } catch (e) {
    err = e;
  }

  assert.ok(err, "expected installer to fail");
  assert.ok(!fs.existsSync(tmpFile), "expected temp archive to be cleaned");
  assert.deepEqual(listInstallerArtifacts(distBaseDir, platformKey), []);

  const oldBinaryAfter = await fs.promises.readFile(oldBinaryPath, "utf8");
  assert.equal(oldBinaryAfter, "old-binary\n");
});

test("installer contract: interrupted run artifacts do not block reinstall and are cleaned up", async (t) => {
  const version = "0.0.2";
  const installedVersion = "0.0.1";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const archive = "docdexd-linux-x64-gnu.tar.gz";
  const isWin32 = false;

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-contract-interrupted-"));
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

  // Simulate an interrupted update: distDir moved aside, plus a leftover staging directory.
  const interruptedBackup = path.join(distBaseDir, `${platformKey}.backup.0.0`);
  await ensureDir(distBaseDir);
  await fs.promises.rm(interruptedBackup, { recursive: true, force: true }).catch(() => {});
  await fs.promises.rename(distDir, interruptedBackup);

  const interruptedStage = path.join(distBaseDir, `${platformKey}.stage.0.0`);
  await fs.promises.rm(interruptedStage, { recursive: true, force: true }).catch(() => {});
  await ensureDir(interruptedStage);
  await fs.promises.writeFile(path.join(interruptedStage, "docdexd"), "partial\n", "utf8");

  const result = await runInstaller({
    logger: createNoopLogger(),
    platform: "linux",
    arch: "x64",
    tmpDir,
    distBaseDir,
    detectPlatformKeyFn: () => platformKey,
    targetTripleForPlatformKeyFn: () => targetTriple,
    getVersionFn: () => version,
    parseRepoSlugFn: () => "owner/repo",
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
  });

  assert.equal(result.outcome, "update");
  assert.deepEqual(listInstallerArtifacts(distBaseDir, platformKey), []);
  assert.ok(!fs.existsSync(interruptedBackup), "expected interrupted backup dir to be cleaned");
  assert.ok(!fs.existsSync(interruptedStage), "expected interrupted stage dir to be cleaned");

  const newBinary = await fs.promises.readFile(path.join(distDir, "docdexd"), "utf8");
  assert.equal(newBinary, "new-binary\n");
});

test("installer contract: interrupted artifacts are cleaned even when install is a no-op (no download)", async (t) => {
  const version = "0.0.2";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const isWin32 = false;

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-contract-noop-cleans-"));
  t.after(async () => {
    await fs.promises.rm(tmpRoot, { recursive: true, force: true });
  });

  const distBaseDir = path.join(tmpRoot, "dist");
  const distDir = path.join(distBaseDir, platformKey);

  const binaryPath = await writeInstalledBinary({ distDir, isWin32, bytes: "verified-binary\n" });
  const binarySha = await sha256File(binaryPath);
  await writeInstallMetadata({ distDir, platformKey, version, targetTriple, binarySha256: binarySha });

  const leftoverStage = path.join(distBaseDir, `${platformKey}.stage.0.0`);
  const leftoverBackup = path.join(distBaseDir, `${platformKey}.backup.0.0`);
  const leftoverFailed = path.join(distBaseDir, `${platformKey}.failed.0.0`);
  await ensureDir(leftoverStage);
  await ensureDir(leftoverBackup);
  await ensureDir(leftoverFailed);

  let planCalls = 0;
  let downloadCalls = 0;

  const result = await runInstaller({
    logger: createNoopLogger(),
    platform: "linux",
    arch: "x64",
    distBaseDir,
    detectPlatformKeyFn: () => platformKey,
    targetTripleForPlatformKeyFn: () => targetTriple,
    getVersionFn: () => version,
    parseRepoSlugFn: () => {
      throw new Error("unexpected repo slug resolution");
    },
    resolveInstallerDownloadPlanFn: async () => {
      planCalls += 1;
      throw new Error("unexpected plan resolution");
    },
    downloadFn: async () => {
      downloadCalls += 1;
      throw new Error("unexpected download");
    }
  });

  assert.equal(result.outcome, "no-op");
  assert.equal(planCalls, 0);
  assert.equal(downloadCalls, 0);
  assert.deepEqual(listInstallerArtifacts(distBaseDir, platformKey), []);

  const binaryAfter = await fs.promises.readFile(path.join(distDir, "docdexd"), "utf8");
  assert.equal(binaryAfter, "verified-binary\n");
});

test("installer contract: interrupted run recovers latest backup then no-ops without download", async (t) => {
  const version = "0.0.2";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const isWin32 = false;

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-contract-recover-backup-"));
  t.after(async () => {
    await fs.promises.rm(tmpRoot, { recursive: true, force: true });
  });

  const distBaseDir = path.join(tmpRoot, "dist");
  const distDir = path.join(distBaseDir, platformKey);
  await ensureDir(distBaseDir);

  const olderBackup = path.join(distBaseDir, `${platformKey}.backup.0.0`);
  const newerBackup = path.join(distBaseDir, `${platformKey}.backup.9.9`);

  const olderBinary = await writeInstalledBinary({ distDir: olderBackup, isWin32, bytes: "older\n" });
  const olderSha = await sha256File(olderBinary);
  await writeInstallMetadata({ distDir: olderBackup, platformKey, version, targetTriple, binarySha256: olderSha });

  const newerBinary = await writeInstalledBinary({ distDir: newerBackup, isWin32, bytes: "newer\n" });
  const newerSha = await sha256File(newerBinary);
  await writeInstallMetadata({ distDir: newerBackup, platformKey, version, targetTriple, binarySha256: newerSha });

  const leftoverStage = path.join(distBaseDir, `${platformKey}.stage.0.0`);
  const leftoverFailed = path.join(distBaseDir, `${platformKey}.failed.0.0`);
  await ensureDir(leftoverStage);
  await ensureDir(leftoverFailed);

  let planCalls = 0;
  let downloadCalls = 0;

  const result = await runInstaller({
    logger: createNoopLogger(),
    platform: "linux",
    arch: "x64",
    distBaseDir,
    detectPlatformKeyFn: () => platformKey,
    targetTripleForPlatformKeyFn: () => targetTriple,
    getVersionFn: () => version,
    parseRepoSlugFn: () => {
      throw new Error("unexpected repo slug resolution");
    },
    resolveInstallerDownloadPlanFn: async () => {
      planCalls += 1;
      throw new Error("unexpected plan resolution");
    },
    downloadFn: async () => {
      downloadCalls += 1;
      throw new Error("unexpected download");
    }
  });

  assert.equal(result.outcome, "no-op");
  assert.equal(planCalls, 0);
  assert.equal(downloadCalls, 0);
  assert.deepEqual(listInstallerArtifacts(distBaseDir, platformKey), []);

  assert.ok(fs.existsSync(distDir), "expected backup to be recovered into distDir");
  const recoveredBinary = await fs.promises.readFile(path.join(distDir, "docdexd"), "utf8");
  assert.equal(recoveredBinary, "newer\n");
});

test("installer contract: initial download failure leaves no runnable binary and cleans temp archive", async (t) => {
  const version = "0.0.2";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const archive = "docdexd-linux-x64-gnu.tar.gz";

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-contract-initial-download-fail-"));
  t.after(async () => {
    await fs.promises.rm(tmpRoot, { recursive: true, force: true });
  });

  const distBaseDir = path.join(tmpRoot, "dist");
  const distDir = path.join(distBaseDir, platformKey);
  const tmpDir = path.join(tmpRoot, "tmp");
  await ensureDir(tmpDir);
  const tmpFile = path.join(tmpDir, `${archive}.${process.pid}.tgz`);

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
      getVersionFn: () => version,
      parseRepoSlugFn: () => "owner/repo",
      resolveInstallerDownloadPlanFn: async () => ({
        archive,
        expectedSha256: null,
        source: "fallback",
        manifestAttempt: { errors: [], resolved: null, manifestName: null }
      }),
      downloadFn: async (_url, dest) => {
        await ensureDir(path.dirname(dest));
        await fs.promises.writeFile(dest, "partial");
        throw new Error("download boom");
      },
      verifyDownloadedFileIntegrityFn: async () => null,
      extractTarballFn: async () => {
        throw new Error("unexpected extract");
      }
    });
  } catch (e) {
    err = e;
  }

  assert.ok(err, "expected installer to fail");
  assert.ok(!fs.existsSync(tmpFile), "expected temp archive to be cleaned");
  assert.ok(!fs.existsSync(distDir), "expected no runnable binary in distDir");
  assert.deepEqual(listInstallerArtifacts(distBaseDir, platformKey), []);
});

test("installer contract: initial verify failure leaves no runnable binary and cleans temp archive", async (t) => {
  const version = "0.0.2";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const archive = "docdexd-linux-x64-gnu.tar.gz";

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-contract-initial-verify-fail-"));
  t.after(async () => {
    await fs.promises.rm(tmpRoot, { recursive: true, force: true });
  });

  const distBaseDir = path.join(tmpRoot, "dist");
  const distDir = path.join(distBaseDir, platformKey);
  const tmpDir = path.join(tmpRoot, "tmp");
  await ensureDir(tmpDir);
  const tmpFile = path.join(tmpDir, `${archive}.${process.pid}.tgz`);

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
      getVersionFn: () => version,
      parseRepoSlugFn: () => "owner/repo",
      resolveInstallerDownloadPlanFn: async () => ({
        archive,
        expectedSha256: "a".repeat(64),
        source: "fallback",
        manifestAttempt: { errors: [], resolved: null, manifestName: null }
      }),
      downloadFn: async (_url, dest) => {
        await ensureDir(path.dirname(dest));
        await fs.promises.writeFile(dest, "fake-archive");
      },
      verifyDownloadedFileIntegrityFn: async () => {
        throw new Error("verify boom");
      },
      extractTarballFn: async () => {
        throw new Error("unexpected extract");
      }
    });
  } catch (e) {
    err = e;
  }

  assert.ok(err, "expected installer to fail");
  assert.ok(!fs.existsSync(tmpFile), "expected temp archive to be cleaned");
  assert.ok(!fs.existsSync(distDir), "expected no runnable binary in distDir");
  assert.deepEqual(listInstallerArtifacts(distBaseDir, platformKey), []);
});

test("installer contract: initial swap failure leaves no runnable binary and cleans temp archive", async (t) => {
  const version = "0.0.2";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const archive = "docdexd-linux-x64-gnu.tar.gz";

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-contract-initial-swap-fail-"));
  t.after(async () => {
    await fs.promises.rm(tmpRoot, { recursive: true, force: true });
  });

  const distBaseDir = path.join(tmpRoot, "dist");
  const distDir = path.join(distBaseDir, platformKey);
  const tmpDir = path.join(tmpRoot, "tmp");
  await ensureDir(tmpDir);
  const tmpFile = path.join(tmpDir, `${archive}.${process.pid}.tgz`);

  const fsModule = {
    ...fs,
    promises: {
      ...fs.promises,
      rename: async (src, dest) => {
        if (dest === distDir && src.includes(`${platformKey}.stage.`)) {
          throw new Error("swap boom");
        }
        return fs.promises.rename(src, dest);
      }
    }
  };

  let err;
  try {
    await runInstaller({
      logger: createNoopLogger(),
      fsModule,
      platform: "linux",
      arch: "x64",
      tmpDir,
      distBaseDir,
      detectPlatformKeyFn: () => platformKey,
      targetTripleForPlatformKeyFn: () => targetTriple,
      getVersionFn: () => version,
      parseRepoSlugFn: () => "owner/repo",
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
    });
  } catch (e) {
    err = e;
  }

  assert.ok(err, "expected installer to fail");
  assert.ok(!fs.existsSync(tmpFile), "expected temp archive to be cleaned");
  assert.ok(!fs.existsSync(distDir), "expected no runnable binary in distDir");
  assert.deepEqual(listInstallerArtifacts(distBaseDir, platformKey), []);
});
