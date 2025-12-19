"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { runInstaller, sha256File } = require("../lib/install");
const { targetTripleForPlatformKey } = require("../lib/platform");

const EXPECTED_SHA256 = "a".repeat(64);

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

function createCapturingLogger() {
  const logs = [];
  const warns = [];
  const errors = [];
  return {
    logger: {
      log: (...args) => logs.push(args.join(" ")),
      warn: (...args) => warns.push(args.join(" ")),
      error: (...args) => errors.push(args.join(" "))
    },
    logs,
    warns,
    errors
  };
}

async function writeInstalledBinary({ distDir, isWin32, bytes }) {
  await ensureDir(distDir);
  const binaryPath = path.join(distDir, isWin32 ? "docdexd.exe" : "docdexd");
  await fs.promises.writeFile(binaryPath, bytes);
  return binaryPath;
}

async function writeInstallMetadata({ distDir, platformKey, version, targetTriple, binarySha256, repoSlug = "owner/repo" }) {
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
    }
  };
  await fs.promises.writeFile(metadataPath, `${JSON.stringify(payload, null, 2)}\n`, "utf8");
  return metadataPath;
}

test("installer: repeated runs converge idempotently (no-op is verified and does not download)", async (t) => {
  const base = "https://example.test/releases/download";
  const version = "0.0.0";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const archive = "docdexd-linux-x64-gnu.tar.gz";
  const expectedArchiveSha256 = "a".repeat(64);

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-idempotent-"));
  t.after(async () => {
    await fs.promises.rm(tmpRoot, { recursive: true, force: true });
  });

  const stateRootDir = path.join(tmpRoot, "state");
  const installDir = path.join(stateRootDir, "daemon", platformKey);
  const tmpDir = path.join(tmpRoot, "tmp");
  await ensureDir(tmpDir);

  let firstDownloadCalls = 0;
  let firstExtractCalls = 0;

  const first = await runInstaller({
    logger: createNoopLogger(),
    platform: "linux",
    arch: "x64",
    tmpDir,
    stateRootDir,
    detectPlatformKeyFn: () => platformKey,
    targetTripleForPlatformKeyFn: () => targetTriple,
    getVersionFn: () => version,
    parseRepoSlugFn: () => "owner/repo",
    getDownloadBaseFn: () => base,
    resolveInstallerDownloadPlanFn: async () => ({
      archive,
      expectedSha256: expectedArchiveSha256,
      source: "fallback",
      manifestAttempt: { errors: [], resolved: null, manifestName: null }
    }),
    downloadFn: async (url, dest) => {
      firstDownloadCalls += 1;
      assert.equal(url, `${base}/v${version}/${archive}`);
      await ensureDir(path.dirname(dest));
      await fs.promises.writeFile(dest, "fake-archive-bytes");
    },
    verifyDownloadedFileIntegrityFn: async ({ expectedSha256 }) => ({
      status: "verified_ok",
      reason: "hash_match",
      expectedSha256,
      actualSha256: expectedSha256,
      expectedSource: "fallback",
      error: null
    }),
    extractTarballFn: async (_archivePath, targetDir) => {
      firstExtractCalls += 1;
      await ensureDir(targetDir);
      await fs.promises.writeFile(path.join(targetDir, "docdexd"), `docdexd-${version}\n`, "utf8");
    }
  });

  assert.equal(first.outcome, "install");
  assert.equal(firstDownloadCalls, 1);
  assert.equal(firstExtractCalls, 1);

  const metadataPath = path.join(installDir, "docdexd-install.json");
  const binaryPath = path.join(installDir, "docdexd");
  const metadataAfterFirst = await fs.promises.readFile(metadataPath, "utf8");
  const binaryAfterFirst = await fs.promises.readFile(binaryPath, "utf8");

  let repoSlugCalls = 0;
  let planCalls = 0;
  let downloadCalls = 0;
  let extractCalls = 0;
  let verifyCalls = 0;

  const second = await runInstaller({
    logger: createNoopLogger(),
    platform: "linux",
    arch: "x64",
    tmpDir,
    stateRootDir,
    detectPlatformKeyFn: () => platformKey,
    targetTripleForPlatformKeyFn: () => targetTriple,
    getVersionFn: () => version,
    parseRepoSlugFn: () => {
      repoSlugCalls += 1;
      return "owner/repo";
    },
    resolveInstallerDownloadPlanFn: async () => {
      planCalls += 1;
      return {
        archive,
        expectedSha256: expectedArchiveSha256,
        source: "fallback",
        manifestAttempt: { errors: [], resolved: null, manifestName: null }
      };
    },
    downloadFn: async () => {
      downloadCalls += 1;
      throw new Error("unexpected download");
    },
    verifyDownloadedFileIntegrityFn: async () => {
      verifyCalls += 1;
      throw new Error("unexpected verify");
    },
    extractTarballFn: async () => {
      extractCalls += 1;
      throw new Error("unexpected extract");
    }
  });

  assert.equal(second.outcome, "no-op");
  assert.equal(second.binaryPath, first.binaryPath);
  assert.equal(repoSlugCalls, 1);
  assert.equal(planCalls, 1);
  assert.equal(downloadCalls, 0);
  assert.equal(verifyCalls, 0);
  assert.equal(extractCalls, 0);

  const metadataAfterSecond = await fs.promises.readFile(metadataPath, "utf8");
  const binaryAfterSecond = await fs.promises.readFile(binaryPath, "utf8");
  assert.equal(metadataAfterSecond, metadataAfterFirst);
  assert.equal(binaryAfterSecond, binaryAfterFirst);
});
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
=======

<<<<<<< HEAD
test("installer: upgrade replaces mismatched version and converges idempotently", async (t) => {
  const base = "https://example.test/releases/download";
  const initialVersion = "0.0.1";
  const targetVersion = "0.0.2";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const archive = "docdexd-linux-x64-gnu.tar.gz";
=======
test("installer: upgrade (older->newer) replaces binary then converges to no-op without re-download", async (t) => {
  const base = "https://example.test/releases/download";
  const expectedVersion = "0.0.2";
  const installedVersion = "0.0.1";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const archive = "docdexd-linux-x64-gnu.tar.gz";
  const isWin32 = false;
>>>>>>> mcoda/task/ops-01-us-06-t14

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-upgrade-idempotent-"));
  t.after(async () => {
    await fs.promises.rm(tmpRoot, { recursive: true, force: true });
  });

  const distBaseDir = path.join(tmpRoot, "dist");
  const distDir = path.join(distBaseDir, platformKey);
  const tmpDir = path.join(tmpRoot, "tmp");
  await ensureDir(tmpDir);

<<<<<<< HEAD
  const first = await runInstaller({
    logger: createNoopLogger(),
=======
  const oldBinaryPath = await writeInstalledBinary({
    distDir,
    isWin32,
    bytes: `docdexd-${installedVersion}\n`
  });
  const oldSha = await sha256File(oldBinaryPath);
  await writeInstallMetadata({ distDir, platformKey, version: installedVersion, targetTriple, binarySha256: oldSha });

  let downloadCalls = 0;
  let extractCalls = 0;
  const { logger, logs } = createCapturingLogger();

  const first = await runInstaller({
    logger,
>>>>>>> mcoda/task/ops-01-us-06-t14
    platform: "linux",
    arch: "x64",
    tmpDir,
    distBaseDir,
    detectPlatformKeyFn: () => platformKey,
    targetTripleForPlatformKeyFn: () => targetTriple,
<<<<<<< HEAD
    getVersionFn: () => initialVersion,
=======
    getVersionFn: () => expectedVersion,
>>>>>>> mcoda/task/ops-01-us-06-t14
    parseRepoSlugFn: () => "owner/repo",
    getDownloadBaseFn: () => base,
    resolveInstallerDownloadPlanFn: async () => ({
      archive,
      expectedSha256: null,
      source: "fallback",
      manifestAttempt: { errors: [], resolved: null, manifestName: null }
    }),
    downloadFn: async (url, dest) => {
<<<<<<< HEAD
      assert.equal(url, `${base}/v${initialVersion}/${archive}`);
=======
      downloadCalls += 1;
      assert.equal(url, `${base}/v${expectedVersion}/${archive}`);
>>>>>>> mcoda/task/ops-01-us-06-t14
      await ensureDir(path.dirname(dest));
      await fs.promises.writeFile(dest, "fake-archive-bytes");
    },
    verifyDownloadedFileIntegrityFn: async () => null,
    extractTarballFn: async (_archivePath, targetDir) => {
<<<<<<< HEAD
      await ensureDir(targetDir);
      await fs.promises.writeFile(path.join(targetDir, "docdexd"), `docdexd-${initialVersion}\n`, "utf8");
    }
  });
  assert.equal(first.outcome, "update");

  const metadataPath = path.join(distDir, "docdexd-install.json");
  const binaryPath = path.join(distDir, "docdexd");
  const binaryAfterFirst = await fs.promises.readFile(binaryPath, "utf8");
  assert.equal(binaryAfterFirst, `docdexd-${initialVersion}\n`);

  let upgradeDownloadCalls = 0;
  const second = await runInstaller({
    logger: createNoopLogger(),
    platform: "linux",
    arch: "x64",
    tmpDir,
    distBaseDir,
    detectPlatformKeyFn: () => platformKey,
    targetTripleForPlatformKeyFn: () => targetTriple,
    getVersionFn: () => targetVersion,
    parseRepoSlugFn: () => "owner/repo",
    getDownloadBaseFn: () => base,
    resolveInstallerDownloadPlanFn: async () => ({
      archive,
      expectedSha256: null,
      source: "fallback",
      manifestAttempt: { errors: [], resolved: null, manifestName: null }
    }),
    downloadFn: async (url, dest) => {
      upgradeDownloadCalls += 1;
      assert.equal(url, `${base}/v${targetVersion}/${archive}`);
      await ensureDir(path.dirname(dest));
      await fs.promises.writeFile(dest, "fake-archive-bytes");
    },
    verifyDownloadedFileIntegrityFn: async () => null,
    extractTarballFn: async (_archivePath, targetDir) => {
      await ensureDir(targetDir);
      await fs.promises.writeFile(path.join(targetDir, "docdexd"), `docdexd-${targetVersion}\n`, "utf8");
    }
  });

  assert.equal(second.outcome, "update");
  assert.equal(upgradeDownloadCalls, 1);
  const binaryAfterSecond = await fs.promises.readFile(binaryPath, "utf8");
  assert.equal(binaryAfterSecond, `docdexd-${targetVersion}\n`);

  const metaAfterSecond = JSON.parse(await fs.promises.readFile(metadataPath, "utf8"));
  assert.equal(metaAfterSecond.version, targetVersion);

  const metadataTextAfterSecond = await fs.promises.readFile(metadataPath, "utf8");

  let repoSlugCalls = 0;
  let planCalls = 0;
  let downloadCalls = 0;
  let extractCalls = 0;
  let shaCalls = 0;

  const third = await runInstaller({
    logger: createNoopLogger(),
=======
      extractCalls += 1;
      await ensureDir(targetDir);
      await fs.promises.writeFile(path.join(targetDir, "docdexd"), `docdexd-${expectedVersion}\n`, "utf8");
    }
  });

  assert.equal(first.outcome, "update");
  assert.equal(downloadCalls, 1);
  assert.equal(extractCalls, 1);
  assert.ok(logs.some((line) => line.includes("[docdex] Install outcome: update")));

  const metadataPath = path.join(distDir, "docdexd-install.json");
  const binaryPath = path.join(distDir, "docdexd");
  const metadataAfterFirst = await fs.promises.readFile(metadataPath, "utf8");
  const binaryAfterFirst = await fs.promises.readFile(binaryPath, "utf8");
  assert.equal(binaryAfterFirst, `docdexd-${expectedVersion}\n`);

  const meta = JSON.parse(metadataAfterFirst);
  assert.equal(meta.version, expectedVersion);
  assert.equal(meta.platformKey, platformKey);

  let repoSlugCalls = 0;
  let planCalls = 0;
  let noOpDownloadCalls = 0;
  let noOpExtractCalls = 0;

  const secondLogger = createCapturingLogger();
  const second = await runInstaller({
    logger: secondLogger.logger,
>>>>>>> mcoda/task/ops-01-us-06-t14
    platform: "linux",
    arch: "x64",
    tmpDir,
    distBaseDir,
    detectPlatformKeyFn: () => platformKey,
    targetTripleForPlatformKeyFn: () => targetTriple,
<<<<<<< HEAD
    getVersionFn: () => targetVersion,
=======
    getVersionFn: () => expectedVersion,
>>>>>>> mcoda/task/ops-01-us-06-t14
    parseRepoSlugFn: () => {
      repoSlugCalls += 1;
      throw new Error("unexpected repo slug resolution");
    },
    resolveInstallerDownloadPlanFn: async () => {
      planCalls += 1;
      throw new Error("unexpected plan resolution");
    },
    downloadFn: async () => {
<<<<<<< HEAD
      downloadCalls += 1;
      throw new Error("unexpected download");
    },
    verifyDownloadedFileIntegrityFn: async () => {
      throw new Error("unexpected archive verification");
    },
    extractTarballFn: async () => {
      extractCalls += 1;
      throw new Error("unexpected extract");
    },
    sha256FileFn: async (filePath) => {
      shaCalls += 1;
      return sha256File(filePath);
    }
  });

  assert.equal(third.outcome, "no-op");
  assert.equal(third.binaryPath, second.binaryPath);
  assert.equal(repoSlugCalls, 0);
  assert.equal(planCalls, 0);
  assert.equal(downloadCalls, 0);
  assert.equal(extractCalls, 0);
  assert.ok(shaCalls >= 1);

  const metadataTextAfterThird = await fs.promises.readFile(metadataPath, "utf8");
  const binaryAfterThird = await fs.promises.readFile(binaryPath, "utf8");
  assert.equal(metadataTextAfterThird, metadataTextAfterSecond);
  assert.equal(binaryAfterThird, binaryAfterSecond);
});

test("installer: downgrade replaces mismatched version and converges idempotently", async (t) => {
  const base = "https://example.test/releases/download";
  const initialVersion = "0.0.2";
  const targetVersion = "0.0.1";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const archive = "docdexd-linux-x64-gnu.tar.gz";
=======
      noOpDownloadCalls += 1;
      throw new Error("unexpected download");
    },
    extractTarballFn: async () => {
      noOpExtractCalls += 1;
      throw new Error("unexpected extract");
    }
  });

  assert.equal(second.outcome, "no-op");
  assert.equal(repoSlugCalls, 0);
  assert.equal(planCalls, 0);
  assert.equal(noOpDownloadCalls, 0);
  assert.equal(noOpExtractCalls, 0);
  assert.ok(secondLogger.logs.some((line) => line.includes("[docdex] Install outcome: no-op")));

  const metadataAfterSecond = await fs.promises.readFile(metadataPath, "utf8");
  const binaryAfterSecond = await fs.promises.readFile(binaryPath, "utf8");
  assert.equal(metadataAfterSecond, metadataAfterFirst);
  assert.equal(binaryAfterSecond, binaryAfterFirst);
});

test("installer: downgrade (newer->older) replaces binary then converges to no-op without re-download", async (t) => {
  const base = "https://example.test/releases/download";
  const expectedVersion = "0.0.1";
  const installedVersion = "0.0.2";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const archive = "docdexd-linux-x64-gnu.tar.gz";
  const isWin32 = false;
>>>>>>> mcoda/task/ops-01-us-06-t14

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-downgrade-idempotent-"));
  t.after(async () => {
    await fs.promises.rm(tmpRoot, { recursive: true, force: true });
  });

  const distBaseDir = path.join(tmpRoot, "dist");
  const distDir = path.join(distBaseDir, platformKey);
  const tmpDir = path.join(tmpRoot, "tmp");
  await ensureDir(tmpDir);

<<<<<<< HEAD
=======
  const oldBinaryPath = await writeInstalledBinary({
    distDir,
    isWin32,
    bytes: `docdexd-${installedVersion}\n`
  });
  const oldSha = await sha256File(oldBinaryPath);
  await writeInstallMetadata({ distDir, platformKey, version: installedVersion, targetTriple, binarySha256: oldSha });

  let downloadCalls = 0;
  let extractCalls = 0;

>>>>>>> mcoda/task/ops-01-us-06-t14
  const first = await runInstaller({
    logger: createNoopLogger(),
    platform: "linux",
    arch: "x64",
    tmpDir,
    distBaseDir,
    detectPlatformKeyFn: () => platformKey,
    targetTripleForPlatformKeyFn: () => targetTriple,
<<<<<<< HEAD
    getVersionFn: () => initialVersion,
=======
    getVersionFn: () => expectedVersion,
>>>>>>> mcoda/task/ops-01-us-06-t14
    parseRepoSlugFn: () => "owner/repo",
    getDownloadBaseFn: () => base,
    resolveInstallerDownloadPlanFn: async () => ({
      archive,
      expectedSha256: null,
      source: "fallback",
      manifestAttempt: { errors: [], resolved: null, manifestName: null }
    }),
<<<<<<< HEAD
    downloadFn: async (url, dest) => {
      assert.equal(url, `${base}/v${initialVersion}/${archive}`);
=======
    downloadFn: async (_url, dest) => {
      downloadCalls += 1;
>>>>>>> mcoda/task/ops-01-us-06-t14
      await ensureDir(path.dirname(dest));
      await fs.promises.writeFile(dest, "fake-archive-bytes");
    },
    verifyDownloadedFileIntegrityFn: async () => null,
    extractTarballFn: async (_archivePath, targetDir) => {
<<<<<<< HEAD
      await ensureDir(targetDir);
      await fs.promises.writeFile(path.join(targetDir, "docdexd"), `docdexd-${initialVersion}\n`, "utf8");
    }
  });
  assert.equal(first.outcome, "update");

  const metadataPath = path.join(distDir, "docdexd-install.json");
  const binaryPath = path.join(distDir, "docdexd");
  const binaryAfterFirst = await fs.promises.readFile(binaryPath, "utf8");
  assert.equal(binaryAfterFirst, `docdexd-${initialVersion}\n`);

  let downgradeDownloadCalls = 0;
=======
      extractCalls += 1;
      await ensureDir(targetDir);
      await fs.promises.writeFile(path.join(targetDir, "docdexd"), `docdexd-${expectedVersion}\n`, "utf8");
    }
  });

  assert.equal(first.outcome, "update");
  assert.equal(downloadCalls, 1);
  assert.equal(extractCalls, 1);

  const metadataPath = path.join(distDir, "docdexd-install.json");
  const binaryPath = path.join(distDir, "docdexd");
  const metadataAfterFirst = await fs.promises.readFile(metadataPath, "utf8");
  const binaryAfterFirst = await fs.promises.readFile(binaryPath, "utf8");
  assert.equal(binaryAfterFirst, `docdexd-${expectedVersion}\n`);

  const meta = JSON.parse(metadataAfterFirst);
  assert.equal(meta.version, expectedVersion);

>>>>>>> mcoda/task/ops-01-us-06-t14
  const second = await runInstaller({
    logger: createNoopLogger(),
    platform: "linux",
    arch: "x64",
    tmpDir,
    distBaseDir,
    detectPlatformKeyFn: () => platformKey,
    targetTripleForPlatformKeyFn: () => targetTriple,
<<<<<<< HEAD
    getVersionFn: () => targetVersion,
    parseRepoSlugFn: () => "owner/repo",
    getDownloadBaseFn: () => base,
    resolveInstallerDownloadPlanFn: async () => ({
      archive,
      expectedSha256: null,
      source: "fallback",
      manifestAttempt: { errors: [], resolved: null, manifestName: null }
    }),
    downloadFn: async (url, dest) => {
      downgradeDownloadCalls += 1;
      assert.equal(url, `${base}/v${targetVersion}/${archive}`);
      await ensureDir(path.dirname(dest));
      await fs.promises.writeFile(dest, "fake-archive-bytes");
    },
    verifyDownloadedFileIntegrityFn: async () => null,
    extractTarballFn: async (_archivePath, targetDir) => {
      await ensureDir(targetDir);
      await fs.promises.writeFile(path.join(targetDir, "docdexd"), `docdexd-${targetVersion}\n`, "utf8");
    }
  });

  assert.equal(second.outcome, "update");
  assert.equal(downgradeDownloadCalls, 1);
  const binaryAfterSecond = await fs.promises.readFile(binaryPath, "utf8");
  assert.equal(binaryAfterSecond, `docdexd-${targetVersion}\n`);

  const metaAfterSecond = JSON.parse(await fs.promises.readFile(metadataPath, "utf8"));
  assert.equal(metaAfterSecond.version, targetVersion);

  const metadataTextAfterSecond = await fs.promises.readFile(metadataPath, "utf8");

  let repoSlugCalls = 0;
  let planCalls = 0;
  let downloadCalls = 0;
  let extractCalls = 0;

  const third = await runInstaller({
    logger: createNoopLogger(),
    platform: "linux",
    arch: "x64",
    tmpDir,
    distBaseDir,
    detectPlatformKeyFn: () => platformKey,
    targetTripleForPlatformKeyFn: () => targetTriple,
    getVersionFn: () => targetVersion,
    parseRepoSlugFn: () => {
      repoSlugCalls += 1;
      throw new Error("unexpected repo slug resolution");
    },
    resolveInstallerDownloadPlanFn: async () => {
      planCalls += 1;
      throw new Error("unexpected plan resolution");
    },
    downloadFn: async () => {
      downloadCalls += 1;
      throw new Error("unexpected download");
    },
    verifyDownloadedFileIntegrityFn: async () => {
      throw new Error("unexpected archive verification");
    },
    extractTarballFn: async () => {
      extractCalls += 1;
=======
    getVersionFn: () => expectedVersion,
    parseRepoSlugFn: () => {
      throw new Error("unexpected repo slug resolution");
    },
    resolveInstallerDownloadPlanFn: async () => {
      throw new Error("unexpected plan resolution");
    },
    downloadFn: async () => {
      throw new Error("unexpected download");
    },
    extractTarballFn: async () => {
>>>>>>> mcoda/task/ops-01-us-06-t14
      throw new Error("unexpected extract");
    }
  });

<<<<<<< HEAD
  assert.equal(third.outcome, "no-op");
  assert.equal(repoSlugCalls, 0);
  assert.equal(planCalls, 0);
  assert.equal(downloadCalls, 0);
  assert.equal(extractCalls, 0);

  const metadataTextAfterThird = await fs.promises.readFile(metadataPath, "utf8");
  const binaryAfterThird = await fs.promises.readFile(binaryPath, "utf8");
  assert.equal(metadataTextAfterThird, metadataTextAfterSecond);
  assert.equal(binaryAfterThird, binaryAfterSecond);
});

test("installer: repair replaces corrupted binary and converges idempotently", async (t) => {
=======
  assert.equal(second.outcome, "no-op");
  const metadataAfterSecond = await fs.promises.readFile(metadataPath, "utf8");
  const binaryAfterSecond = await fs.promises.readFile(binaryPath, "utf8");
  assert.equal(metadataAfterSecond, metadataAfterFirst);
  assert.equal(binaryAfterSecond, binaryAfterFirst);
});

test("installer: repair then converges to no-op without re-download", async (t) => {
>>>>>>> mcoda/task/ops-01-us-06-t14
  const base = "https://example.test/releases/download";
  const version = "0.0.0";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const archive = "docdexd-linux-x64-gnu.tar.gz";
<<<<<<< HEAD
=======
  const isWin32 = false;
>>>>>>> mcoda/task/ops-01-us-06-t14

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-repair-idempotent-"));
  t.after(async () => {
    await fs.promises.rm(tmpRoot, { recursive: true, force: true });
  });

  const distBaseDir = path.join(tmpRoot, "dist");
  const distDir = path.join(distBaseDir, platformKey);
  const tmpDir = path.join(tmpRoot, "tmp");
  await ensureDir(tmpDir);

<<<<<<< HEAD
=======
  const binaryPath = await writeInstalledBinary({ distDir, isWin32, bytes: "docdexd-original\n" });
  const originalSha = await sha256File(binaryPath);
  await writeInstallMetadata({ distDir, platformKey, version, targetTriple, binarySha256: originalSha });

  await fs.promises.writeFile(binaryPath, "docdexd-corrupted\n");

  let downloadCalls = 0;
  let extractCalls = 0;

>>>>>>> mcoda/task/ops-01-us-06-t14
  const first = await runInstaller({
    logger: createNoopLogger(),
    platform: "linux",
    arch: "x64",
    tmpDir,
    distBaseDir,
    detectPlatformKeyFn: () => platformKey,
    targetTripleForPlatformKeyFn: () => targetTriple,
    getVersionFn: () => version,
    parseRepoSlugFn: () => "owner/repo",
    getDownloadBaseFn: () => base,
    resolveInstallerDownloadPlanFn: async () => ({
      archive,
<<<<<<< HEAD
      expectedSha256: "a".repeat(64),
<<<<<<< HEAD
      source: "fallback",
      manifestAttempt: { errors: [], resolved: null, manifestName: null }
    }),
<<<<<<< HEAD
    downloadFn: async (url, dest) => {
      assert.equal(url, `${base}/v${version}/${archive}`);
=======
    downloadFn: async (_url, dest) => {
      downloadCalls += 1;
>>>>>>> mcoda/task/ops-01-us-06-t14
      await ensureDir(path.dirname(dest));
      await fs.promises.writeFile(dest, "fake-archive-bytes");
    },
    verifyDownloadedFileIntegrityFn: async () => null,
    extractTarballFn: async (_archivePath, targetDir) => {
<<<<<<< HEAD
      await ensureDir(targetDir);
      await fs.promises.writeFile(path.join(targetDir, "docdexd"), `docdexd-${version}\n`, "utf8");
    }
  });
  assert.equal(first.outcome, "update");

  const metadataPath = path.join(distDir, "docdexd-install.json");
  const binaryPath = path.join(distDir, "docdexd");
  await fs.promises.writeFile(binaryPath, "corrupted\n", "utf8");

  let repairDownloadCalls = 0;
=======
      extractCalls += 1;
      await ensureDir(targetDir);
      await fs.promises.writeFile(path.join(targetDir, "docdexd"), `docdexd-${version}-repaired\n`, "utf8");
    }
  });

  assert.equal(first.outcome, "repair");
  assert.equal(downloadCalls, 1);
  assert.equal(extractCalls, 1);

  const metadataPath = path.join(distDir, "docdexd-install.json");
  const repairedBinaryPath = path.join(distDir, "docdexd");
  const metadataAfterFirst = await fs.promises.readFile(metadataPath, "utf8");
  const binaryAfterFirst = await fs.promises.readFile(repairedBinaryPath, "utf8");
  assert.equal(binaryAfterFirst, `docdexd-${version}-repaired\n`);

>>>>>>> mcoda/task/ops-01-us-06-t14
  const second = await runInstaller({
    logger: createNoopLogger(),
    platform: "linux",
    arch: "x64",
    tmpDir,
    distBaseDir,
    detectPlatformKeyFn: () => platformKey,
    targetTripleForPlatformKeyFn: () => targetTriple,
    getVersionFn: () => version,
<<<<<<< HEAD
    parseRepoSlugFn: () => "owner/repo",
    getDownloadBaseFn: () => base,
    resolveInstallerDownloadPlanFn: async () => ({
      archive,
      expectedSha256: null,
=======
>>>>>>> mcoda/task/ops-01-us-04-t17
=======
      expectedSha256: EXPECTED_SHA256,
>>>>>>> mcoda/task/ops-01-us-04-t18
      source: "fallback",
      manifestAttempt: { errors: [], resolved: null, manifestName: null }
    }),
    downloadFn: async (url, dest) => {
      repairDownloadCalls += 1;
      assert.equal(url, `${base}/v${version}/${archive}`);
      await ensureDir(path.dirname(dest));
      await fs.promises.writeFile(dest, "fake-archive-bytes");
    },
    verifyDownloadedFileIntegrityFn: async ({ expectedSha256 }) => expectedSha256,
    extractTarballFn: async (_archivePath, targetDir) => {
      await ensureDir(targetDir);
      await fs.promises.writeFile(path.join(targetDir, "docdexd"), "repaired\n", "utf8");
    }
  });

  assert.equal(second.outcome, "repair");
  assert.equal(repairDownloadCalls, 1);
  const binaryAfterRepair = await fs.promises.readFile(binaryPath, "utf8");
  assert.equal(binaryAfterRepair, "repaired\n");

  const metadataTextAfterRepair = await fs.promises.readFile(metadataPath, "utf8");
  const metaAfterRepair = JSON.parse(metadataTextAfterRepair);
  assert.equal(metaAfterRepair.version, version);

  let repoSlugCalls = 0;
  let planCalls = 0;
  let downloadCalls = 0;
  let extractCalls = 0;

  const third = await runInstaller({
    logger: createNoopLogger(),
    platform: "linux",
    arch: "x64",
    tmpDir,
    distBaseDir,
    detectPlatformKeyFn: () => platformKey,
    targetTripleForPlatformKeyFn: () => targetTriple,
    getVersionFn: () => version,
    parseRepoSlugFn: () => {
      repoSlugCalls += 1;
      throw new Error("unexpected repo slug resolution");
    },
    resolveInstallerDownloadPlanFn: async () => {
      planCalls += 1;
      throw new Error("unexpected plan resolution");
    },
    downloadFn: async () => {
      downloadCalls += 1;
      throw new Error("unexpected download");
    },
    verifyDownloadedFileIntegrityFn: async () => {
      throw new Error("unexpected archive verification");
    },
    extractTarballFn: async () => {
      extractCalls += 1;
=======
    parseRepoSlugFn: () => {
      throw new Error("unexpected repo slug resolution");
    },
    resolveInstallerDownloadPlanFn: async () => {
      throw new Error("unexpected plan resolution");
    },
    downloadFn: async () => {
      throw new Error("unexpected download");
    },
    extractTarballFn: async () => {
>>>>>>> mcoda/task/ops-01-us-06-t14
      throw new Error("unexpected extract");
    }
  });

<<<<<<< HEAD
  assert.equal(third.outcome, "no-op");
  assert.equal(repoSlugCalls, 0);
  assert.equal(planCalls, 0);
  assert.equal(downloadCalls, 0);
  assert.equal(extractCalls, 0);

  const metadataTextAfterThird = await fs.promises.readFile(metadataPath, "utf8");
  const binaryAfterThird = await fs.promises.readFile(binaryPath, "utf8");
  assert.equal(metadataTextAfterThird, metadataTextAfterRepair);
  assert.equal(binaryAfterThird, binaryAfterRepair);
});
>>>>>>> mcoda/task/ops-01-us-06-t32
=======
>>>>>>> mcoda/task/ops-01-us-06-t40
=======
  assert.equal(second.outcome, "no-op");
  const metadataAfterSecond = await fs.promises.readFile(metadataPath, "utf8");
  const binaryAfterSecond = await fs.promises.readFile(repairedBinaryPath, "utf8");
  assert.equal(metadataAfterSecond, metadataAfterFirst);
  assert.equal(binaryAfterSecond, binaryAfterFirst);
});
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> mcoda/task/ops-01-us-06-t14
=======
>>>>>>> mcoda/task/ops-01-us-06-t03
=======
>>>>>>> mcoda/task/ops-01-us-04-t40
=======
>>>>>>> mcoda/task/ops-01-us-04-t17
=======
>>>>>>> mcoda/task/ops-01-us-04-t18
