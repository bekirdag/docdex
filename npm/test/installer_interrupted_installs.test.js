"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { runInstaller, sha256File } = require("../lib/install");
const { artifactName, targetTripleForPlatformKey } = require("../lib/platform");

const BASE_URL = "https://example.test/releases/download";
const PLATFORM_KEY = "linux-x64-gnu";
const TARGET_TRIPLE = targetTripleForPlatformKey(PLATFORM_KEY);
const ARCHIVE = artifactName(PLATFORM_KEY);
const EXPECTED_VERSION = "0.0.1";
const INSTALLED_VERSION = "0.0.0";

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

async function assertNoStagingArtifacts(distBaseDir) {
  const entries = await fs.promises.readdir(distBaseDir);
  const leftovers = entries.filter((entry) => entry.includes(".staging.") || entry.includes(".backup."));
  assert.equal(leftovers.length, 0, `expected no staging/backup dirs, found: ${leftovers.join(", ")}`);
}

async function setupFixture(t, suffix) {
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), `docdex-installer-${suffix}-`));
  t.after(async () => {
    await fs.promises.rm(tmpRoot, { recursive: true, force: true });
  });

  const distBaseDir = path.join(tmpRoot, "dist");
  const distDir = path.join(distBaseDir, PLATFORM_KEY);
  const tmpDir = path.join(tmpRoot, "tmp");
  await ensureDir(tmpDir);

  const binaryPath = await writeInstalledBinary({ distDir, isWin32: false, bytes: "old-binary\n" });
  const binarySha = await sha256File(binaryPath);
  const metadataPath = await writeInstallMetadata({
    distDir,
    platformKey: PLATFORM_KEY,
    version: INSTALLED_VERSION,
    targetTriple: TARGET_TRIPLE,
    binarySha256: binarySha
  });

  return {
    tmpRoot,
    distBaseDir,
    distDir,
    tmpDir,
    binaryPath,
    metadataPath,
    binaryBefore: await fs.promises.readFile(binaryPath, "utf8"),
    metadataBefore: await fs.promises.readFile(metadataPath, "utf8")
  };
}

test("installer e2e: interrupted download cleans temp and preserves existing binary; retry succeeds", async (t) => {
  const fixture = await setupFixture(t, "interrupted-download");
  const tmpFile = path.join(fixture.tmpDir, `${ARCHIVE}.${process.pid}.tgz`);

  let downloadCalls = 0;
  let verifyCalls = 0;
  let extractCalls = 0;

  let err;
  try {
    await runInstaller({
      logger: createNoopLogger(),
      platform: "linux",
      arch: "x64",
      tmpDir: fixture.tmpDir,
      distBaseDir: fixture.distBaseDir,
      detectPlatformKeyFn: () => PLATFORM_KEY,
      targetTripleForPlatformKeyFn: () => TARGET_TRIPLE,
      getVersionFn: () => EXPECTED_VERSION,
      parseRepoSlugFn: () => "owner/repo",
      getDownloadBaseFn: () => BASE_URL,
      resolveInstallerDownloadPlanFn: async () => ({
        archive: ARCHIVE,
        expectedSha256: null,
        source: "fallback",
        manifestAttempt: { errors: [], resolved: null, manifestName: null }
      }),
      downloadFn: async (_url, dest) => {
        downloadCalls += 1;
        await ensureDir(path.dirname(dest));
        await fs.promises.writeFile(dest, "partial-download\n");
        const failure = new Error("connection reset");
        failure.statusCode = 500;
        throw failure;
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
  } catch (e) {
    err = e;
  }

  assert.ok(err, "expected install to fail");
  assert.equal(err.code, "DOCDEX_DOWNLOAD_FAILED");
  assert.equal(downloadCalls, 1);
  assert.equal(verifyCalls, 0);
  assert.equal(extractCalls, 0);
  assert.ok(!fs.existsSync(tmpFile), "expected temp download file to be cleaned");
  assert.equal(await fs.promises.readFile(fixture.binaryPath, "utf8"), fixture.binaryBefore);
  assert.equal(await fs.promises.readFile(fixture.metadataPath, "utf8"), fixture.metadataBefore);
  await assertNoStagingArtifacts(fixture.distBaseDir);

  const result = await runInstaller({
    logger: createNoopLogger(),
    platform: "linux",
    arch: "x64",
    tmpDir: fixture.tmpDir,
    distBaseDir: fixture.distBaseDir,
    detectPlatformKeyFn: () => PLATFORM_KEY,
    targetTripleForPlatformKeyFn: () => TARGET_TRIPLE,
    getVersionFn: () => EXPECTED_VERSION,
    parseRepoSlugFn: () => "owner/repo",
    getDownloadBaseFn: () => BASE_URL,
    resolveInstallerDownloadPlanFn: async () => ({
      archive: ARCHIVE,
      expectedSha256: null,
      source: "fallback",
      manifestAttempt: { errors: [], resolved: null, manifestName: null }
    }),
    downloadFn: async (_url, dest) => {
      await ensureDir(path.dirname(dest));
      await fs.promises.writeFile(dest, "archive-bytes\n");
    },
    verifyDownloadedFileIntegrityFn: async () => null,
    extractTarballFn: async (_archivePath, targetDir) => {
      await ensureDir(targetDir);
      await fs.promises.writeFile(path.join(targetDir, "docdexd"), "new-binary\n");
    }
  });

  assert.equal(result.outcome, "update");
  assert.equal(await fs.promises.readFile(fixture.binaryPath, "utf8"), "new-binary\n");
  const meta = JSON.parse(await fs.promises.readFile(fixture.metadataPath, "utf8"));
  assert.equal(meta.version, EXPECTED_VERSION);
  assert.ok(!fs.existsSync(tmpFile), "expected temp download file to be cleaned after retry");
  await assertNoStagingArtifacts(fixture.distBaseDir);
});

test("installer e2e: integrity failure leaves existing binary and cleans staging; retry succeeds", async (t) => {
  const fixture = await setupFixture(t, "integrity-failure");
  const tmpFile = path.join(fixture.tmpDir, `${ARCHIVE}.${process.pid}.tgz`);

  let downloadCalls = 0;
  let extractCalls = 0;

  let err;
  try {
    await runInstaller({
      logger: createNoopLogger(),
      platform: "linux",
      arch: "x64",
      tmpDir: fixture.tmpDir,
      distBaseDir: fixture.distBaseDir,
      detectPlatformKeyFn: () => PLATFORM_KEY,
      targetTripleForPlatformKeyFn: () => TARGET_TRIPLE,
      getVersionFn: () => EXPECTED_VERSION,
      parseRepoSlugFn: () => "owner/repo",
      getDownloadBaseFn: () => BASE_URL,
      resolveInstallerDownloadPlanFn: async () => ({
        archive: ARCHIVE,
        expectedSha256: "0".repeat(64),
        source: "fallback",
        manifestAttempt: { errors: [], resolved: null, manifestName: null }
      }),
      downloadFn: async (_url, dest) => {
        downloadCalls += 1;
        await ensureDir(path.dirname(dest));
        await fs.promises.writeFile(dest, "archive-bytes\n");
      },
      verifyDownloadedFileIntegrityFn: async () => {
        throw new Error("integrity mismatch");
      },
      extractTarballFn: async () => {
        extractCalls += 1;
        throw new Error("unexpected extract");
      }
    });
  } catch (e) {
    err = e;
  }

  assert.ok(err, "expected install to fail");
  assert.equal(downloadCalls, 1);
  assert.equal(extractCalls, 0);
  assert.ok(!fs.existsSync(tmpFile), "expected temp download file to be cleaned");
  assert.equal(await fs.promises.readFile(fixture.binaryPath, "utf8"), fixture.binaryBefore);
  assert.equal(await fs.promises.readFile(fixture.metadataPath, "utf8"), fixture.metadataBefore);
  await assertNoStagingArtifacts(fixture.distBaseDir);

  const result = await runInstaller({
    logger: createNoopLogger(),
    platform: "linux",
    arch: "x64",
    tmpDir: fixture.tmpDir,
    distBaseDir: fixture.distBaseDir,
    detectPlatformKeyFn: () => PLATFORM_KEY,
    targetTripleForPlatformKeyFn: () => TARGET_TRIPLE,
    getVersionFn: () => EXPECTED_VERSION,
    parseRepoSlugFn: () => "owner/repo",
    getDownloadBaseFn: () => BASE_URL,
    resolveInstallerDownloadPlanFn: async () => ({
      archive: ARCHIVE,
      expectedSha256: null,
      source: "fallback",
      manifestAttempt: { errors: [], resolved: null, manifestName: null }
    }),
    downloadFn: async (_url, dest) => {
      await ensureDir(path.dirname(dest));
      await fs.promises.writeFile(dest, "archive-bytes\n");
    },
    verifyDownloadedFileIntegrityFn: async () => null,
    extractTarballFn: async (_archivePath, targetDir) => {
      await ensureDir(targetDir);
      await fs.promises.writeFile(path.join(targetDir, "docdexd"), "new-binary\n");
    }
  });

  assert.equal(result.outcome, "update");
  assert.equal(await fs.promises.readFile(fixture.binaryPath, "utf8"), "new-binary\n");
  const meta = JSON.parse(await fs.promises.readFile(fixture.metadataPath, "utf8"));
  assert.equal(meta.version, EXPECTED_VERSION);
  assert.ok(!fs.existsSync(tmpFile), "expected temp download file to be cleaned after retry");
  await assertNoStagingArtifacts(fixture.distBaseDir);
});

test("installer e2e: mid-install termination keeps previous binary and cleans staging; retry succeeds", async (t) => {
  const fixture = await setupFixture(t, "mid-install-termination");
  const tmpFile = path.join(fixture.tmpDir, `${ARCHIVE}.${process.pid}.tgz`);

  let stagingDir = null;
  let err;

  try {
    await runInstaller({
      logger: createNoopLogger(),
      platform: "linux",
      arch: "x64",
      tmpDir: fixture.tmpDir,
      distBaseDir: fixture.distBaseDir,
      detectPlatformKeyFn: () => PLATFORM_KEY,
      targetTripleForPlatformKeyFn: () => TARGET_TRIPLE,
      getVersionFn: () => EXPECTED_VERSION,
      parseRepoSlugFn: () => "owner/repo",
      getDownloadBaseFn: () => BASE_URL,
      resolveInstallerDownloadPlanFn: async () => ({
        archive: ARCHIVE,
        expectedSha256: null,
        source: "fallback",
        manifestAttempt: { errors: [], resolved: null, manifestName: null }
      }),
      downloadFn: async (_url, dest) => {
        await ensureDir(path.dirname(dest));
        await fs.promises.writeFile(dest, "archive-bytes\n");
      },
      verifyDownloadedFileIntegrityFn: async () => null,
      extractTarballFn: async (_archivePath, targetDir) => {
        stagingDir = targetDir;
        await ensureDir(targetDir);
        await fs.promises.writeFile(path.join(targetDir, "docdexd"), "staged-binary\n");
        throw new Error("simulated crash mid-install");
      }
    });
  } catch (e) {
    err = e;
  }

  assert.ok(err, "expected install to fail");
  assert.ok(stagingDir, "expected staging dir to be set");
  assert.ok(!fs.existsSync(tmpFile), "expected temp download file to be cleaned");
  assert.ok(!fs.existsSync(stagingDir), "expected staging dir to be cleaned");
  assert.equal(await fs.promises.readFile(fixture.binaryPath, "utf8"), fixture.binaryBefore);
  assert.equal(await fs.promises.readFile(fixture.metadataPath, "utf8"), fixture.metadataBefore);
  await assertNoStagingArtifacts(fixture.distBaseDir);

  const result = await runInstaller({
    logger: createNoopLogger(),
    platform: "linux",
    arch: "x64",
    tmpDir: fixture.tmpDir,
    distBaseDir: fixture.distBaseDir,
    detectPlatformKeyFn: () => PLATFORM_KEY,
    targetTripleForPlatformKeyFn: () => TARGET_TRIPLE,
    getVersionFn: () => EXPECTED_VERSION,
    parseRepoSlugFn: () => "owner/repo",
    getDownloadBaseFn: () => BASE_URL,
    resolveInstallerDownloadPlanFn: async () => ({
      archive: ARCHIVE,
      expectedSha256: null,
      source: "fallback",
      manifestAttempt: { errors: [], resolved: null, manifestName: null }
    }),
    downloadFn: async (_url, dest) => {
      await ensureDir(path.dirname(dest));
      await fs.promises.writeFile(dest, "archive-bytes\n");
    },
    verifyDownloadedFileIntegrityFn: async () => null,
    extractTarballFn: async (_archivePath, targetDir) => {
      await ensureDir(targetDir);
      await fs.promises.writeFile(path.join(targetDir, "docdexd"), "new-binary\n");
    }
  });

  assert.equal(result.outcome, "update");
  assert.equal(await fs.promises.readFile(fixture.binaryPath, "utf8"), "new-binary\n");
  const meta = JSON.parse(await fs.promises.readFile(fixture.metadataPath, "utf8"));
  assert.equal(meta.version, EXPECTED_VERSION);
  assert.ok(!fs.existsSync(tmpFile), "expected temp download file to be cleaned after retry");
  await assertNoStagingArtifacts(fixture.distBaseDir);
});
