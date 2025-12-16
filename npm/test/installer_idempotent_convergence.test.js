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
<<<<<<< HEAD
=======

test("installer: upgrade replaces mismatched version and converges idempotently", async (t) => {
  const base = "https://example.test/releases/download";
  const initialVersion = "0.0.1";
  const targetVersion = "0.0.2";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const archive = "docdexd-linux-x64-gnu.tar.gz";

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-upgrade-idempotent-"));
  t.after(async () => {
    await fs.promises.rm(tmpRoot, { recursive: true, force: true });
  });

  const distBaseDir = path.join(tmpRoot, "dist");
  const distDir = path.join(distBaseDir, platformKey);
  const tmpDir = path.join(tmpRoot, "tmp");
  await ensureDir(tmpDir);

  const first = await runInstaller({
    logger: createNoopLogger(),
    platform: "linux",
    arch: "x64",
    tmpDir,
    distBaseDir,
    detectPlatformKeyFn: () => platformKey,
    targetTripleForPlatformKeyFn: () => targetTriple,
    getVersionFn: () => initialVersion,
    parseRepoSlugFn: () => "owner/repo",
    getDownloadBaseFn: () => base,
    resolveInstallerDownloadPlanFn: async () => ({
      archive,
      expectedSha256: null,
      source: "fallback",
      manifestAttempt: { errors: [], resolved: null, manifestName: null }
    }),
    downloadFn: async (url, dest) => {
      assert.equal(url, `${base}/v${initialVersion}/${archive}`);
      await ensureDir(path.dirname(dest));
      await fs.promises.writeFile(dest, "fake-archive-bytes");
    },
    verifyDownloadedFileIntegrityFn: async () => null,
    extractTarballFn: async (_archivePath, targetDir) => {
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

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-downgrade-idempotent-"));
  t.after(async () => {
    await fs.promises.rm(tmpRoot, { recursive: true, force: true });
  });

  const distBaseDir = path.join(tmpRoot, "dist");
  const distDir = path.join(distBaseDir, platformKey);
  const tmpDir = path.join(tmpRoot, "tmp");
  await ensureDir(tmpDir);

  const first = await runInstaller({
    logger: createNoopLogger(),
    platform: "linux",
    arch: "x64",
    tmpDir,
    distBaseDir,
    detectPlatformKeyFn: () => platformKey,
    targetTripleForPlatformKeyFn: () => targetTriple,
    getVersionFn: () => initialVersion,
    parseRepoSlugFn: () => "owner/repo",
    getDownloadBaseFn: () => base,
    resolveInstallerDownloadPlanFn: async () => ({
      archive,
      expectedSha256: null,
      source: "fallback",
      manifestAttempt: { errors: [], resolved: null, manifestName: null }
    }),
    downloadFn: async (url, dest) => {
      assert.equal(url, `${base}/v${initialVersion}/${archive}`);
      await ensureDir(path.dirname(dest));
      await fs.promises.writeFile(dest, "fake-archive-bytes");
    },
    verifyDownloadedFileIntegrityFn: async () => null,
    extractTarballFn: async (_archivePath, targetDir) => {
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
      throw new Error("unexpected extract");
    }
  });

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
  const base = "https://example.test/releases/download";
  const version = "0.0.0";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const archive = "docdexd-linux-x64-gnu.tar.gz";

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-repair-idempotent-"));
  t.after(async () => {
    await fs.promises.rm(tmpRoot, { recursive: true, force: true });
  });

  const distBaseDir = path.join(tmpRoot, "dist");
  const distDir = path.join(distBaseDir, platformKey);
  const tmpDir = path.join(tmpRoot, "tmp");
  await ensureDir(tmpDir);

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
      assert.equal(url, `${base}/v${version}/${archive}`);
      await ensureDir(path.dirname(dest));
      await fs.promises.writeFile(dest, "fake-archive-bytes");
    },
    verifyDownloadedFileIntegrityFn: async () => null,
    extractTarballFn: async (_archivePath, targetDir) => {
      await ensureDir(targetDir);
      await fs.promises.writeFile(path.join(targetDir, "docdexd"), `docdexd-${version}\n`, "utf8");
    }
  });
  assert.equal(first.outcome, "update");

  const metadataPath = path.join(distDir, "docdexd-install.json");
  const binaryPath = path.join(distDir, "docdexd");
  await fs.promises.writeFile(binaryPath, "corrupted\n", "utf8");

  let repairDownloadCalls = 0;
  const second = await runInstaller({
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
      repairDownloadCalls += 1;
      assert.equal(url, `${base}/v${version}/${archive}`);
      await ensureDir(path.dirname(dest));
      await fs.promises.writeFile(dest, "fake-archive-bytes");
    },
    verifyDownloadedFileIntegrityFn: async () => null,
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
      throw new Error("unexpected extract");
    }
  });

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
