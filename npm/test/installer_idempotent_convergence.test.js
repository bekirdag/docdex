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

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-idempotent-"));
  t.after(async () => {
    await fs.promises.rm(tmpRoot, { recursive: true, force: true });
  });

  const distBaseDir = path.join(tmpRoot, "dist");
  const distDir = path.join(distBaseDir, platformKey);
  const tmpDir = path.join(tmpRoot, "tmp");
  await ensureDir(tmpDir);

  let firstDownloadCalls = 0;
  let firstExtractCalls = 0;

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
      expectedSha256: null,
      source: "fallback",
      manifestAttempt: { errors: [], resolved: null, manifestName: null }
    }),
    downloadFn: async (url, dest) => {
      firstDownloadCalls += 1;
      assert.equal(url, `${base}/v${version}/${archive}`);
      await ensureDir(path.dirname(dest));
      await fs.promises.writeFile(dest, "fake-archive-bytes");
    },
    verifyDownloadedFileIntegrityFn: async () => null,
    extractTarballFn: async (_archivePath, targetDir) => {
      firstExtractCalls += 1;
      await ensureDir(targetDir);
      await fs.promises.writeFile(path.join(targetDir, "docdexd"), `docdexd-${version}\n`, "utf8");
    }
  });

  assert.equal(first.outcome, "update");
  assert.equal(firstDownloadCalls, 1);
  assert.equal(firstExtractCalls, 1);

  const metadataPath = path.join(distDir, "docdexd-install.json");
  const binaryPath = path.join(distDir, "docdexd");
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
  assert.equal(repoSlugCalls, 0);
  assert.equal(planCalls, 0);
  assert.equal(downloadCalls, 0);
  assert.equal(verifyCalls, 0);
  assert.equal(extractCalls, 0);

  const metadataAfterSecond = await fs.promises.readFile(metadataPath, "utf8");
  const binaryAfterSecond = await fs.promises.readFile(binaryPath, "utf8");
  assert.equal(metadataAfterSecond, metadataAfterFirst);
  assert.equal(binaryAfterSecond, binaryAfterFirst);
});

test("installer: upgrade (older->newer) replaces binary then converges to no-op without re-download", async (t) => {
  const base = "https://example.test/releases/download";
  const expectedVersion = "0.0.2";
  const installedVersion = "0.0.1";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const archive = "docdexd-linux-x64-gnu.tar.gz";
  const isWin32 = false;

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-upgrade-idempotent-"));
  t.after(async () => {
    await fs.promises.rm(tmpRoot, { recursive: true, force: true });
  });

  const distBaseDir = path.join(tmpRoot, "dist");
  const distDir = path.join(distBaseDir, platformKey);
  const tmpDir = path.join(tmpRoot, "tmp");
  await ensureDir(tmpDir);

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
      downloadCalls += 1;
      assert.equal(url, `${base}/v${expectedVersion}/${archive}`);
      await ensureDir(path.dirname(dest));
      await fs.promises.writeFile(dest, "fake-archive-bytes");
    },
    verifyDownloadedFileIntegrityFn: async () => null,
    extractTarballFn: async (_archivePath, targetDir) => {
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
    platform: "linux",
    arch: "x64",
    tmpDir,
    distBaseDir,
    detectPlatformKeyFn: () => platformKey,
    targetTripleForPlatformKeyFn: () => targetTriple,
    getVersionFn: () => expectedVersion,
    parseRepoSlugFn: () => {
      repoSlugCalls += 1;
      throw new Error("unexpected repo slug resolution");
    },
    resolveInstallerDownloadPlanFn: async () => {
      planCalls += 1;
      throw new Error("unexpected plan resolution");
    },
    downloadFn: async () => {
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

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-downgrade-idempotent-"));
  t.after(async () => {
    await fs.promises.rm(tmpRoot, { recursive: true, force: true });
  });

  const distBaseDir = path.join(tmpRoot, "dist");
  const distDir = path.join(distBaseDir, platformKey);
  const tmpDir = path.join(tmpRoot, "tmp");
  await ensureDir(tmpDir);

  const oldBinaryPath = await writeInstalledBinary({
    distDir,
    isWin32,
    bytes: `docdexd-${installedVersion}\n`
  });
  const oldSha = await sha256File(oldBinaryPath);
  await writeInstallMetadata({ distDir, platformKey, version: installedVersion, targetTriple, binarySha256: oldSha });

  let downloadCalls = 0;
  let extractCalls = 0;

  const first = await runInstaller({
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
      downloadCalls += 1;
      await ensureDir(path.dirname(dest));
      await fs.promises.writeFile(dest, "fake-archive-bytes");
    },
    verifyDownloadedFileIntegrityFn: async () => null,
    extractTarballFn: async (_archivePath, targetDir) => {
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

  const second = await runInstaller({
    logger: createNoopLogger(),
    platform: "linux",
    arch: "x64",
    tmpDir,
    distBaseDir,
    detectPlatformKeyFn: () => platformKey,
    targetTripleForPlatformKeyFn: () => targetTriple,
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
      throw new Error("unexpected extract");
    }
  });

  assert.equal(second.outcome, "no-op");
  const metadataAfterSecond = await fs.promises.readFile(metadataPath, "utf8");
  const binaryAfterSecond = await fs.promises.readFile(binaryPath, "utf8");
  assert.equal(metadataAfterSecond, metadataAfterFirst);
  assert.equal(binaryAfterSecond, binaryAfterFirst);
});

test("installer: repair then converges to no-op without re-download", async (t) => {
  const base = "https://example.test/releases/download";
  const version = "0.0.0";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const archive = "docdexd-linux-x64-gnu.tar.gz";
  const isWin32 = false;

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-repair-idempotent-"));
  t.after(async () => {
    await fs.promises.rm(tmpRoot, { recursive: true, force: true });
  });

  const distBaseDir = path.join(tmpRoot, "dist");
  const distDir = path.join(distBaseDir, platformKey);
  const tmpDir = path.join(tmpRoot, "tmp");
  await ensureDir(tmpDir);

  const binaryPath = await writeInstalledBinary({ distDir, isWin32, bytes: "docdexd-original\n" });
  const originalSha = await sha256File(binaryPath);
  await writeInstallMetadata({ distDir, platformKey, version, targetTriple, binarySha256: originalSha });

  await fs.promises.writeFile(binaryPath, "docdexd-corrupted\n");

  let downloadCalls = 0;
  let extractCalls = 0;

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
      expectedSha256: null,
      source: "fallback",
      manifestAttempt: { errors: [], resolved: null, manifestName: null }
    }),
    downloadFn: async (_url, dest) => {
      downloadCalls += 1;
      await ensureDir(path.dirname(dest));
      await fs.promises.writeFile(dest, "fake-archive-bytes");
    },
    verifyDownloadedFileIntegrityFn: async () => null,
    extractTarballFn: async (_archivePath, targetDir) => {
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

  const second = await runInstaller({
    logger: createNoopLogger(),
    platform: "linux",
    arch: "x64",
    tmpDir,
    distBaseDir,
    detectPlatformKeyFn: () => platformKey,
    targetTripleForPlatformKeyFn: () => targetTriple,
    getVersionFn: () => version,
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
      throw new Error("unexpected extract");
    }
  });

  assert.equal(second.outcome, "no-op");
  const metadataAfterSecond = await fs.promises.readFile(metadataPath, "utf8");
  const binaryAfterSecond = await fs.promises.readFile(repairedBinaryPath, "utf8");
  assert.equal(metadataAfterSecond, metadataAfterFirst);
  assert.equal(binaryAfterSecond, binaryAfterFirst);
});
