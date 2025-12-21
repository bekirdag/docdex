"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");

<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
const { runInstaller, sha256File, buildInstallOutcomeReport } = require("../lib/install");
=======
const { runInstaller, sha256File, verifyDownloadedFileIntegrity } = require("../lib/install");
>>>>>>> mcoda/task/ops-01-us-06-t21
=======
const { runInstaller, sha256File, STAGING_ROOT_NAME, STAGING_BACKUP_PREFIX } = require("../lib/install");
>>>>>>> mcoda/task/ops-01-us-05-t33
const { targetTripleForPlatformKey } = require("../lib/platform");
=======
const { runInstaller, sha256File } = require("../lib/install");
const { artifactName, targetTripleForPlatformKey } = require("../lib/platform");
>>>>>>> mcoda/task/ops-01-us-06-t29

const EXPECTED_SHA256 = "a".repeat(64);

function sha256String(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

const ARCHIVE_BYTES = "fake-archive-bytes";
const ARCHIVE_SHA256 = sha256String(ARCHIVE_BYTES);

function createNoopLogger() {
  return {
    log: () => {},
    warn: () => {},
    error: () => {}
  };
}

<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
async function readBinaryVersionStub({ expectedVersion }) {
  return { version: expectedVersion, output: `docdexd ${expectedVersion}` };
=======
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
>>>>>>> mcoda/task/ops-01-us-01-t13
=======
function createVersionDetector(version) {
  return async () => ({ version, raw: `docdexd ${version}`, error: null });
}

function createSequencedVersionDetector(versions) {
  let calls = 0;
  return async () => {
    const version = versions[Math.min(calls, versions.length - 1)];
    calls += 1;
    return { version, raw: version ? `docdexd ${version}` : "", error: null };
  };
>>>>>>> mcoda/task/ops-01-us-03-t06
}
=======
const noopSmokeTest = async () => {};
>>>>>>> mcoda/task/ops-01-us-01-t41

async function ensureDir(dirPath) {
  await fs.promises.mkdir(dirPath, { recursive: true });
}

async function writeInstalledBinary({ installDir, isWin32, bytes }) {
  await ensureDir(installDir);
  const binaryPath = path.join(installDir, isWin32 ? "docdexd.exe" : "docdexd");
  await fs.promises.writeFile(binaryPath, bytes);
  if (!isWin32) {
    await fs.promises.chmod(binaryPath, 0o755).catch(() => {});
  }
  return binaryPath;
}

async function writeInstallMetadata({
  installDir,
  platformKey,
  installedVersion,
  expectedVersion,
  targetTriple,
  binaryPath,
  binarySha256,
  repoSlug = "owner/repo",
<<<<<<< HEAD
  assetUrl = null
}) {
  const metadataPath = path.join(installDir, "docdexd-install.json");
  const installedAt = new Date().toISOString();
=======
  archiveName = null,
  archiveSha256 = null,
  archiveSource = "fallback",
  archiveDownloadUrl = null
}) {
  const metadataPath = path.join(distDir, "docdexd-install.json");
  const resolvedArchiveName =
    typeof archiveName === "string" && archiveName.trim() ? archiveName.trim() : `docdexd-${platformKey}.tar.gz`;
>>>>>>> mcoda/task/ops-01-us-06-t03
  const payload = {
<<<<<<< HEAD
    schemaVersion: 2,
    installedVersion,
    expectedVersion,
=======
    schemaVersion: 1,
    installedAt: new Date().toISOString(),
    version,
    expectedVersion: version,
    installedVersion: version,
    releaseTag: `v${version}`,
    repoSlug,
>>>>>>> mcoda/task/ops-01-us-03-t43
    platformKey,
    targetTriple,
    binaryPath,
    binaryHash: binarySha256,
    provenance: {
      repoSlug,
      releaseTag: `v${expectedVersion}`,
      releaseId: null,
      assetName: null,
      assetUrl,
      assetSha256: null,
      source: "test"
    },
<<<<<<< HEAD
    installedAt,
    lastVerifiedAt: installedAt
=======
    archive: {
<<<<<<< HEAD
      name: resolvedArchiveName,
      sha256: archiveSha256,
      source: archiveSource,
      downloadUrl: archiveDownloadUrl
=======
      name: null,
      tag: `v${version}`,
      sha256: null,
      source: null,
      downloadUrl: null
>>>>>>> mcoda/task/ops-01-us-03-t43
    }
>>>>>>> mcoda/task/ops-01-us-06-t03
  };
  await fs.promises.writeFile(metadataPath, `${JSON.stringify(payload, null, 2)}\n`, "utf8");
  return metadataPath;
}

test("installer outcome: no-op skips plan/download when local install is verified", async (t) => {
  const base = "https://example.test/releases/download";
  const version = "0.0.0";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const archive = artifactName(platformKey);
  const isWin32 = false;
  const archive = "docdexd-linux-x64-gnu.tar.gz";
  const archiveSha256 = "a".repeat(64);

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-outcome-noop-"));
  t.after(async () => {
    await fs.promises.rm(tmpRoot, { recursive: true, force: true });
  });

  const stateRootDir = path.join(tmpRoot, "state");
  const installDir = path.join(stateRootDir, "daemon", platformKey);

  const binaryPath = await writeInstalledBinary({ installDir, isWin32, bytes: "verified-binary\n" });
  const binarySha = await sha256File(binaryPath);
  await writeInstallMetadata({
<<<<<<< HEAD
    installDir,
    platformKey,
    installedVersion: version,
    expectedVersion: version,
    targetTriple,
    binaryPath,
    binarySha256: binarySha
=======
    distDir,
    platformKey,
    version,
    targetTriple,
    binarySha256: binarySha,
    archiveName: archive,
    archiveSha256
>>>>>>> mcoda/task/ops-01-us-06-t03
  });

  let parseRepoSlugCalls = 0;
  let planCalls = 0;
  let downloadCalls = 0;
  let extractCalls = 0;

  const { logger, logs } = createCapturingLogger();
  const result = await runInstaller({
<<<<<<< HEAD
    logger,
=======
    logger: createNoopLogger(),
    smokeTestBinaryFn: noopSmokeTest,
>>>>>>> mcoda/task/ops-01-us-01-t41
    platform: "linux",
    arch: "x64",
<<<<<<< HEAD
    stateRootDir,
=======
    distBaseDir,
    getBinaryVersionFn: createVersionDetector(version),
>>>>>>> mcoda/task/ops-01-us-03-t06
    detectPlatformKeyFn: () => platformKey,
    targetTripleForPlatformKeyFn: () => targetTriple,
    getVersionFn: () => version,
    parseRepoSlugFn: () => {
      parseRepoSlugCalls += 1;
      return "owner/repo";
    },
    resolveInstallerDownloadPlanFn: async () => {
      planCalls += 1;
      return {
        archive,
        expectedSha256: archiveSha256,
        source: "fallback",
        manifestAttempt: { errors: [], resolved: null, manifestName: null }
      };
    },
    downloadFn: async () => {
      downloadCalls += 1;
      throw new Error("unexpected download");
    },
    extractTarballFn: async () => {
      extractCalls += 1;
      throw new Error("unexpected extract");
    },
    getDownloadBaseFn: () => base
  });

  assert.equal(result.binaryPath, binaryPath);
  assert.equal(result.outcome, "no-op");
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
  assert.equal(result.outcomeCode, "skipped_noop");
  assert.equal(typeof result.outcomeMessage, "string");
=======
  assert.equal(result.plan, "no-op");
>>>>>>> mcoda/task/ops-01-us-06-t37
=======
  assert.equal(result.action, "no-op");
  assert.equal(result.decision.schemaVersion, 1);
  assert.equal(result.decision.outcome, "no-op");
  assert.equal(result.decision.action, "no-op");
>>>>>>> mcoda/task/ops-01-us-06-t02
  assert.equal(parseRepoSlugCalls, 0);
  assert.equal(planCalls, 0);
=======
  assert.equal(parseRepoSlugCalls, 1);
  assert.equal(planCalls, 1);
>>>>>>> mcoda/task/ops-01-us-06-t03
  assert.equal(downloadCalls, 0);
  assert.equal(extractCalls, 0);
<<<<<<< HEAD
<<<<<<< HEAD

  const metadataPath = path.join(distDir, "docdexd-install.json");
  const meta = JSON.parse(await fs.promises.readFile(metadataPath, "utf8"));
  assert.equal(meta.expectedVersion, version);
  assert.equal(meta.installedVersion, version);
  assert.equal(meta.lastOutcome, "no-op");
  assert.equal(meta.lastOutcomeReason, "verified");
  assert.equal(meta.lastOutcomeAt, meta.installedAt);
  assert.equal(meta.sourceUri, `${base}/v${version}/${archive}`);
  assert.equal(meta.archive?.name, archive);
  assert.equal(meta.archive?.downloadUrl, `${base}/v${version}/${archive}`);
=======
  assert.ok(logs.some((line) => line.includes("Detected platform: linux/x64")));
  assert.ok(logs.some((line) => line.includes(`Expected target triple: ${targetTriple}`)));
  assert.ok(logs.some((line) => line.includes(`Resolved daemon version: v${version}`)));
  assert.ok(logs.some((line) => line.includes("Resolved daemon asset: docdexd-linux-x64-gnu.tar.gz")));
  assert.ok(logs.some((line) => line.includes("Cache hit: existing docdexd matches expected version/target")));
  assert.ok(logs.some((line) => line.includes("Install outcome: no-op")));
>>>>>>> mcoda/task/ops-01-us-01-t13
=======

  const metadataPath = path.join(distDir, "docdexd-install.json");
  const meta = JSON.parse(await fs.promises.readFile(metadataPath, "utf8"));
  assert.equal(meta.version, version);
  assert.equal(meta.platformKey, platformKey);
>>>>>>> mcoda/task/ops-01-us-03-t15
});

<<<<<<< HEAD
test("installer outcome: upgrade installs when expected version is newer and writes fresh metadata", async (t) => {
=======
test("installer outcome: version mismatch forces update even with verified metadata", async (t) => {
  const base = "https://example.test/releases/download";
  const expectedVersion = "0.0.2";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const isWin32 = false;

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-outcome-version-mismatch-"));
  t.after(async () => {
    await fs.promises.rm(tmpRoot, { recursive: true, force: true });
  });

  const distBaseDir = path.join(tmpRoot, "dist");
  const distDir = path.join(distBaseDir, platformKey);
  const tmpDir = path.join(tmpRoot, "tmp");
  await ensureDir(tmpDir);

  const binaryPath = await writeInstalledBinary({ distDir, isWin32, bytes: "verified-binary\n" });
  const binarySha = await sha256File(binaryPath);
  await writeInstallMetadata({ distDir, platformKey, version: expectedVersion, targetTriple, binarySha256: binarySha });

  const archive = "docdexd-linux-x64-gnu.tar.gz";
  let downloadCalls = 0;
  let extractCalls = 0;

  const result = await runInstaller({
    logger: createNoopLogger(),
    platform: "linux",
    arch: "x64",
    tmpDir,
    distBaseDir,
    getBinaryVersionFn: createSequencedVersionDetector(["0.0.1", expectedVersion]),
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
      await fs.promises.writeFile(path.join(targetDir, "docdexd"), "new-binary\n");
    }
  });

  assert.equal(result.outcome, "update");
  assert.equal(downloadCalls, 1);
  assert.equal(extractCalls, 1);

  const metadataPath = path.join(distDir, "docdexd-install.json");
  const meta = JSON.parse(await fs.promises.readFile(metadataPath, "utf8"));
  assert.equal(meta.version, expectedVersion);
});

test("installer outcome: update installs when version differs and writes fresh metadata", async (t) => {
>>>>>>> mcoda/task/ops-01-us-03-t06
  const base = "https://example.test/releases/download";
  const expectedVersion = "0.0.2";
  const installedVersion = "0.0.1";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const isWin32 = false;
  const archive = "docdexd-linux-x64-gnu.tar.gz";
  const expectedSha256 = "b".repeat(64);

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-outcome-upgrade-"));
  t.after(async () => {
    await fs.promises.rm(tmpRoot, { recursive: true, force: true });
  });

  const stateRootDir = path.join(tmpRoot, "state");
  const installDir = path.join(stateRootDir, "daemon", platformKey);
  const tmpDir = path.join(tmpRoot, "tmp");
  await ensureDir(tmpDir);

  const oldBinaryPath = await writeInstalledBinary({ installDir, isWin32, bytes: "old-binary\n" });
  const oldSha = await sha256File(oldBinaryPath);
  await writeInstallMetadata({
    installDir,
    platformKey,
    installedVersion,
    expectedVersion: installedVersion,
    targetTriple,
<<<<<<< HEAD
    binaryPath: oldBinaryPath,
    binarySha256: oldSha
=======
    binarySha256: oldSha,
    archiveName: archive,
    archiveSha256: "a".repeat(64)
>>>>>>> mcoda/task/ops-01-us-06-t03
  });

  const expectedDownloadUrl = `${base}/v${expectedVersion}/${archive}`;

  let downloadUrl = null;
  let downloadDest = null;

  const result = await runInstaller({
    logger: createNoopLogger(),
    platform: "linux",
    arch: "x64",
    tmpDir,
    stateRootDir,
    detectPlatformKeyFn: () => platformKey,
    targetTripleForPlatformKeyFn: () => targetTriple,
    getVersionFn: () => expectedVersion,
    parseRepoSlugFn: () => "owner/repo",
    getDownloadBaseFn: () => base,
    resolveInstallerDownloadPlanFn: async () => ({
      archive,
      expectedSha256,
      source: "fallback",
      manifestAttempt: { errors: [], resolved: null, manifestName: null }
    }),
    downloadFn: async (url, dest) => {
      downloadUrl = url;
      downloadDest = dest;
      await ensureDir(path.dirname(dest));
      await fs.promises.writeFile(dest, "fake-archive-bytes");
    },
    verifyDownloadedFileIntegrityFn: async ({ filePath, expectedSha256: sha }) => {
      assert.equal(filePath, downloadDest);
      assert.equal(sha, expectedSha256);
      assert.ok(fs.existsSync(filePath));
      return {
        status: "verified_ok",
        reason: "hash_match",
        expectedSha256: sha,
        actualSha256: sha,
        expectedSource: "fallback",
        error: null
      };
    },
    extractTarballFn: async (_archivePath, targetDir) => {
      await ensureDir(targetDir);
      const newBinaryPath = path.join(targetDir, "docdexd");
      await fs.promises.writeFile(newBinaryPath, "new-binary\n");
    }
  });

  assert.equal(downloadUrl, expectedDownloadUrl);
<<<<<<< HEAD
  assert.equal(result.outcome, "update");
<<<<<<< HEAD
<<<<<<< HEAD
  assert.equal(result.outcomeCode, "updated");
=======
  assert.equal(result.plan, "upgrade");
>>>>>>> mcoda/task/ops-01-us-06-t37
=======
  assert.equal(result.outcome, "upgrade");
=======
  assert.equal(result.action, "upgrade");
>>>>>>> mcoda/task/ops-01-us-06-t02

  const metadataPath = path.join(distDir, "docdexd-install.json");
  assert.ok(fs.existsSync(metadataPath));
  const meta = JSON.parse(await fs.promises.readFile(metadataPath, "utf8"));
  assert.equal(meta.version, expectedVersion);
  assert.equal(meta.platformKey, platformKey);
  assert.equal(meta.archive.sha256, expectedSha256);
  assert.equal(typeof meta.binary?.sha256, "string");
  assert.equal(meta.binary.sha256.length, 64);
});

test("installer outcome: downgrade installs when expected version is older and writes fresh metadata", async (t) => {
  const base = "https://example.test/releases/download";
  const expectedVersion = "0.0.1";
  const installedVersion = "0.0.2";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const isWin32 = false;

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-outcome-downgrade-"));
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
  const archiveBytes = "fake-archive-bytes";
  const archiveSha256 = crypto.createHash("sha256").update(archiveBytes).digest("hex");

  let downloadUrl = null;
  let downloadDest = null;
  let smokeCalls = 0;
  let smokeBinaryPath = null;

  const result = await runInstaller({
    logger: createNoopLogger(),
    smokeTestBinaryFn: async ({ binaryPath }) => {
      smokeCalls += 1;
      smokeBinaryPath = binaryPath;
    },
    platform: "linux",
    arch: "x64",
    tmpDir,
    distBaseDir,
    getBinaryVersionFn: createVersionDetector(expectedVersion),
    detectPlatformKeyFn: () => platformKey,
    targetTripleForPlatformKeyFn: () => targetTriple,
    getVersionFn: () => expectedVersion,
    parseRepoSlugFn: () => "owner/repo",
    getDownloadBaseFn: () => base,
    resolveInstallerDownloadPlanFn: async () => ({
      archive,
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
      expectedSha256: archiveSha256,
      source: "fallback",
      assetId: null,
      integrity: {
        method: "sha256",
        expectedSha256: archiveSha256,
        sourceType: "sha256sums",
        sourceName: "SHA256SUMS",
        sourceUrl: `${base}/v${expectedVersion}/SHA256SUMS`
      },
      manifestAttempt: { errors: [], resolved: null, manifestName: null }
    }),
    downloadFn: async (url, dest) => {
      downloadUrl = url;
      downloadDest = dest;
      await ensureDir(path.dirname(dest));
      await fs.promises.writeFile(dest, archiveBytes);
    },
    verifyDownloadedFileIntegrityFn: verifyDownloadedFileIntegrity,
    extractTarballFn: async (_archivePath, targetDir) => {
      await ensureDir(targetDir);
      const newBinaryPath = path.join(targetDir, "docdexd");
      await fs.promises.writeFile(newBinaryPath, "new-binary\n");
    }
  });

  assert.equal(downloadUrl, expectedDownloadUrl);
  assert.equal(result.outcome, "downgrade");
>>>>>>> mcoda/task/ops-01-us-06-t40

  const metadataPath = path.join(installDir, "docdexd-install.json");
  assert.ok(fs.existsSync(metadataPath));
  const meta = JSON.parse(await fs.promises.readFile(metadataPath, "utf8"));
  assert.equal(meta.installedVersion, expectedVersion);
  assert.equal(meta.expectedVersion, expectedVersion);
  assert.equal(meta.platformKey, platformKey);
<<<<<<< HEAD
  assert.equal(typeof meta.binaryHash, "string");
  assert.equal(meta.binaryHash.length, 64);
=======
  assert.equal(meta.archive.downloadUrl, expectedDownloadUrl);
  assert.equal(meta.archive.name, archive);
  assert.equal(meta.archive.sha256, archiveSha256);
  assert.equal(meta.archive.integrity.method, "sha256");
  assert.equal(meta.archive.integrity.expectedSha256, archiveSha256);
  assert.equal(meta.archive.integrity.actualSha256, archiveSha256);
  assert.equal(meta.archive.integrity.sourceType, "sha256sums");
  assert.equal(typeof meta.binary?.sha256, "string");
  assert.equal(meta.binary.sha256.length, 64);
>>>>>>> mcoda/task/ops-01-us-06-t21
});

test("installer outcome: repair reinstalls when binary hash mismatches metadata", async (t) => {
  const base = "https://example.test/releases/download";
  const version = "0.0.0";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const isWin32 = false;
  const archive = "docdexd-linux-x64-gnu.tar.gz";
  const expectedSha256 = "c".repeat(64);

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-outcome-repair-"));
  t.after(async () => {
    await fs.promises.rm(tmpRoot, { recursive: true, force: true });
  });

  const stateRootDir = path.join(tmpRoot, "state");
  const installDir = path.join(stateRootDir, "daemon", platformKey);
  const tmpDir = path.join(tmpRoot, "tmp");
  await ensureDir(tmpDir);

  const binaryPath = await writeInstalledBinary({ installDir, isWin32, bytes: "original\n" });
  const originalSha = await sha256File(binaryPath);
  await writeInstallMetadata({
<<<<<<< HEAD
    installDir,
    platformKey,
    installedVersion: version,
    expectedVersion: version,
    targetTriple,
    binaryPath,
    binarySha256: originalSha
=======
    distDir,
    platformKey,
    version,
    targetTriple,
    binarySha256: originalSha,
    archiveName: archive,
    archiveSha256: expectedSha256
>>>>>>> mcoda/task/ops-01-us-06-t03
  });

  await fs.promises.writeFile(binaryPath, "corrupted\n");

<<<<<<< HEAD
  const archive = "docdexd-linux-x64-gnu.tar.gz";
  const archiveBytes = "fake-archive-bytes";
  const archiveSha256 = crypto.createHash("sha256").update(archiveBytes).digest("hex");

=======
>>>>>>> mcoda/task/ops-01-us-06-t03
  const result = await runInstaller({
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
<<<<<<< HEAD
      expectedSha256: archiveSha256,
=======
      expectedSha256,
>>>>>>> mcoda/task/ops-01-us-06-t03
      source: "fallback",
      assetId: null,
      integrity: {
        method: "sha256",
        expectedSha256: archiveSha256,
        sourceType: "sha256sums",
        sourceName: "SHA256SUMS",
        sourceUrl: `${base}/v${version}/SHA256SUMS`
      },
      manifestAttempt: { errors: [], resolved: null, manifestName: null }
    }),
    downloadFn: async (_url, dest) => {
      await ensureDir(path.dirname(dest));
      await fs.promises.writeFile(dest, archiveBytes);
    },
<<<<<<< HEAD
    verifyDownloadedFileIntegrityFn: verifyDownloadedFileIntegrity,
=======
    verifyDownloadedFileIntegrityFn: async ({ expectedSha256: sha }) => ({
      status: "verified_ok",
      reason: "hash_match",
      expectedSha256: sha,
      actualSha256: sha,
      expectedSource: "fallback",
      error: null
    }),
>>>>>>> mcoda/task/ops-01-us-06-t03
    extractTarballFn: async (_archivePath, targetDir) => {
      await ensureDir(targetDir);
      const repaired = path.join(targetDir, "docdexd");
      await fs.promises.writeFile(repaired, "repaired\n");
    }
  });

  assert.equal(result.outcome, "repair");
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
  assert.equal(result.outcomeCode, "repaired");
=======
  assert.equal(result.plan, "repair");
>>>>>>> mcoda/task/ops-01-us-06-t37
=======
  assert.equal(result.action, "repair");
>>>>>>> mcoda/task/ops-01-us-06-t02
  const metadataPath = path.join(distDir, "docdexd-install.json");
=======
  const metadataPath = path.join(installDir, "docdexd-install.json");
>>>>>>> mcoda/task/ops-01-us-06-t45
  const meta = JSON.parse(await fs.promises.readFile(metadataPath, "utf8"));
<<<<<<< HEAD
  assert.equal(meta.installedVersion, version);
  const repairedBinaryPath = path.join(installDir, "docdexd");
=======
  assert.equal(meta.version, version);
  assert.equal(meta.archive.downloadUrl, `${base}/v${version}/${archive}`);
  assert.equal(meta.archive.sha256, archiveSha256);
  assert.equal(meta.archive.integrity.method, "sha256");
  assert.equal(meta.archive.integrity.actualSha256, archiveSha256);
  const repairedBinaryPath = path.join(distDir, "docdexd");
>>>>>>> mcoda/task/ops-01-us-06-t21
  const repairedSha = await sha256File(repairedBinaryPath);
  assert.equal(meta.binaryHash, repairedSha);
});

test("installer outcome: reinstall_unknown reinstalls when metadata is missing", async (t) => {
  const base = "https://example.test/releases/download";
  const version = "0.0.0";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const isWin32 = false;
  const archive = "docdexd-linux-x64-gnu.tar.gz";
  const expectedSha256 = "d".repeat(64);

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-outcome-unknown-"));
  t.after(async () => {
    await fs.promises.rm(tmpRoot, { recursive: true, force: true });
  });

  const stateRootDir = path.join(tmpRoot, "state");
  const installDir = path.join(stateRootDir, "daemon", platformKey);
  const tmpDir = path.join(tmpRoot, "tmp");
  await ensureDir(tmpDir);

  await writeInstalledBinary({ installDir, isWin32, bytes: "no-metadata\n" });
  assert.ok(!fs.existsSync(path.join(installDir, "docdexd-install.json")));

  const result = await runInstaller({
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
      expectedSha256,
      source: "fallback",
      manifestAttempt: { errors: [], resolved: null, manifestName: null }
    }),
    downloadFn: async (_url, dest) => {
      await ensureDir(path.dirname(dest));
      await fs.promises.writeFile(dest, "fake-archive-bytes");
    },
    verifyDownloadedFileIntegrityFn: async ({ expectedSha256: sha }) => ({
      status: "verified_ok",
      reason: "hash_match",
      expectedSha256: sha,
      actualSha256: sha,
      expectedSource: "fallback",
      error: null
    }),
    extractTarballFn: async (_archivePath, targetDir) => {
      await ensureDir(targetDir);
      const repaired = path.join(targetDir, "docdexd");
      await fs.promises.writeFile(repaired, "fresh\n");
    }
  });

  assert.equal(result.outcome, "reinstall_unknown");
<<<<<<< HEAD
<<<<<<< HEAD
  assert.equal(result.outcomeCode, "reinstalled_unknown");
=======
  assert.equal(result.plan, "repair");
>>>>>>> mcoda/task/ops-01-us-06-t37
  const metadataPath = path.join(distDir, "docdexd-install.json");
=======
  const metadataPath = path.join(installDir, "docdexd-install.json");
>>>>>>> mcoda/task/ops-01-us-06-t45
  const meta = JSON.parse(await fs.promises.readFile(metadataPath, "utf8"));
  assert.equal(meta.installedVersion, version);
  assert.equal(meta.expectedVersion, version);
  assert.equal(meta.platformKey, platformKey);
  assert.equal(meta.targetTriple, targetTriple);
});

<<<<<<< HEAD
test("installer outcome: reinstall_unknown reinstalls when integrity cannot be verified", async (t) => {
  const base = "https://example.test/releases/download";
=======
test("installer outputFormat=json emits a single JSON outcome report", async (t) => {
>>>>>>> mcoda/task/ops-01-us-06-t47
  const version = "0.0.0";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const isWin32 = false;
  const archive = "docdexd-linux-x64-gnu.tar.gz";
  const expectedSha256 = "e".repeat(64);

<<<<<<< HEAD
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-outcome-unverifiable-"));
=======
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-outcome-json-"));
>>>>>>> mcoda/task/ops-01-us-06-t47
  t.after(async () => {
    await fs.promises.rm(tmpRoot, { recursive: true, force: true });
  });

<<<<<<< HEAD
  const distBaseDir = path.join(tmpRoot, "dist");
  const distDir = path.join(distBaseDir, platformKey);
<<<<<<< HEAD
=======
  const stateRootDir = path.join(tmpRoot, "state");
  const installDir = path.join(stateRootDir, "daemon", platformKey);
>>>>>>> mcoda/task/ops-01-us-06-t45
  const tmpDir = path.join(tmpRoot, "tmp");
  await ensureDir(tmpDir);
=======
>>>>>>> mcoda/task/ops-01-us-06-t47

  const binaryPath = await writeInstalledBinary({ installDir, isWin32, bytes: "verified-binary\n" });
  const binarySha = await sha256File(binaryPath);
  await writeInstallMetadata({
<<<<<<< HEAD
    installDir,
    platformKey,
    installedVersion: version,
    expectedVersion: version,
    targetTriple,
    binaryPath,
    binarySha256: binarySha
  });

<<<<<<< HEAD
  const archive = "docdexd-linux-x64-gnu.tar.gz";
=======
    distDir,
    platformKey,
    version,
    targetTriple,
    binarySha256: binarySha,
    archiveName: archive,
    archiveSha256: expectedSha256
  });
>>>>>>> mcoda/task/ops-01-us-06-t03

  let shaCalls = 0;
  let downloadCalls = 0;
  let extractCalls = 0;

  const result = await runInstaller({
    logger: createNoopLogger(),
    platform: "linux",
    arch: "x64",
    tmpDir,
<<<<<<< HEAD
=======
  const logs = [];
  const captureLogger = {
    log: (line) => logs.push(String(line)),
    warn: () => {},
    error: () => {}
  };

  const result = await runInstaller({
    logger: captureLogger,
    outputFormat: "json",
    platform: "linux",
    arch: "x64",
>>>>>>> mcoda/task/ops-01-us-06-t47
    distBaseDir,
=======
    stateRootDir,
>>>>>>> mcoda/task/ops-01-us-06-t45
    detectPlatformKeyFn: () => platformKey,
    targetTripleForPlatformKeyFn: () => targetTriple,
    getVersionFn: () => version,
<<<<<<< HEAD
    parseRepoSlugFn: () => "owner/repo",
    getDownloadBaseFn: () => base,
    resolveInstallerDownloadPlanFn: async () => ({
      archive,
      expectedSha256,
      source: "fallback",
      manifestAttempt: { errors: [], resolved: null, manifestName: null }
    }),
    downloadFn: async (_url, dest) => {
      downloadCalls += 1;
      await ensureDir(path.dirname(dest));
      await fs.promises.writeFile(dest, "fake-archive-bytes");
    },
    verifyDownloadedFileIntegrityFn: async ({ expectedSha256: sha }) => ({
      status: "verified_ok",
      reason: "hash_match",
      expectedSha256: sha,
      actualSha256: sha,
      expectedSource: "fallback",
      error: null
    }),
    extractTarballFn: async (_archivePath, targetDir) => {
      extractCalls += 1;
      await ensureDir(targetDir);
      await fs.promises.writeFile(path.join(targetDir, "docdexd"), "fresh\n");
    },
    sha256FileFn: async (filePath) => {
      shaCalls += 1;
      if (shaCalls === 1) throw new Error("EACCES: permission denied");
      return sha256File(filePath);
    }
  });

  assert.equal(result.outcome, "reinstall_unknown");
  assert.equal(result.plan, "repair");
  assert.equal(downloadCalls, 1);
  assert.equal(extractCalls, 1);
  assert.ok(shaCalls >= 2, "expected sha256 to be attempted for local check and after install");

  const metadataPath = path.join(installDir, "docdexd-install.json");
  const meta = JSON.parse(await fs.promises.readFile(metadataPath, "utf8"));
  assert.equal(meta.installedVersion, version);
  assert.equal(meta.platformKey, platformKey);
  assert.equal(meta.targetTriple, targetTriple);
=======
    parseRepoSlugFn: () => {
      throw new Error("unexpected repo slug resolution");
    }
  });

  assert.equal(result.outcome, "no-op");
  assert.equal(result.outcomeCode, "skipped_noop");
  assert.equal(logs.length, 1);
  const payload = JSON.parse(logs[0]);
  assert.equal(payload.kind, "docdex_installer_outcome");
  assert.equal(payload.code, "skipped_noop");
  assert.equal(payload.legacyOutcome, "no-op");
  assert.equal(payload.expectedVersion, version);
});

test("installer outcome code: supports `no_op` alias for `no-op`", () => {
  const report = buildInstallOutcomeReport({
    decision: { outcome: "no_op", reason: "verified", installedVersion: "0.0.0" },
    expectedVersion: "0.0.0",
    platformKey: null,
    targetTriple: null,
    repoSlug: null,
    archive: null,
    downloadUrl: null,
    source: null
  });

  assert.equal(report.code, "skipped_noop");
  assert.equal(report.downloaded, false);
>>>>>>> mcoda/task/ops-01-us-06-t47
});

test("installer lifecycle: no-op does not attempt daemon restart", async (t) => {
  const base = "https://example.test/releases/download";
  const version = "0.0.0";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const isWin32 = false;

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-restart-noop-"));
  t.after(async () => {
    await fs.promises.rm(tmpRoot, { recursive: true, force: true });
  });

  const distBaseDir = path.join(tmpRoot, "dist");
  const distDir = path.join(distBaseDir, platformKey);

  const binaryPath = await writeInstalledBinary({ distDir, isWin32, bytes: "verified-binary\n" });
  const binarySha = await sha256File(binaryPath);
  await writeInstallMetadata({ distDir, platformKey, version, targetTriple, binarySha256: binarySha });

  let restartCalls = 0;
  const result = await runInstaller({
    logger: createNoopLogger(),
    platform: "linux",
    arch: "x64",
    distBaseDir,
    detectPlatformKeyFn: () => platformKey,
    targetTripleForPlatformKeyFn: () => targetTriple,
    getVersionFn: () => version,
    restartDaemonFn: async () => {
      restartCalls += 1;
      throw new Error("unexpected restart");
    },
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
    },
    getDownloadBaseFn: () => base
  });

  assert.equal(result.binaryPath, binaryPath);
  assert.equal(result.outcome, "no-op");
  assert.equal(restartCalls, 0);
});

test("installer lifecycle: update calls restart hook when binary changes", async (t) => {
  const base = "https://example.test/releases/download";
  const expectedVersion = "0.0.2";
  const installedVersion = "0.0.1";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const isWin32 = false;

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-restart-update-"));
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

  let restartCalls = 0;
  let restartOutcome = null;
  let restartBinaryPath = null;

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
=======
      expectedSha256: "a".repeat(64),
>>>>>>> mcoda/task/ops-01-us-04-t17
      source: "fallback",
      manifestAttempt: { errors: [], resolved: null, manifestName: null }
    }),
=======
      expectedSha256: "a".repeat(64),
=======
      expectedSha256: EXPECTED_SHA256,
>>>>>>> mcoda/task/ops-01-us-04-t18
=======
      expectedSha256: ARCHIVE_SHA256,
>>>>>>> mcoda/task/ops-01-us-04-t11
      source: "fallback",
      manifestAttempt: { errors: [], resolved: null, manifestName: null }
    }),
    downloadFn: async (url, dest) => {
      downloadUrl = url;
      downloadDest = dest;
      await ensureDir(path.dirname(dest));
      await fs.promises.writeFile(dest, ARCHIVE_BYTES);
    },
    verifyDownloadedFileIntegrityFn: async ({ filePath, expectedSha256 }) => {
      assert.equal(filePath, downloadDest);
      assert.equal(expectedSha256, EXPECTED_SHA256);
      assert.ok(fs.existsSync(filePath));
<<<<<<< HEAD
=======
      assert.equal(expectedSha256, ARCHIVE_SHA256);
>>>>>>> mcoda/task/ops-01-us-04-t11
      return expectedSha256;
    },
    extractTarballFn: async (_archivePath, targetDir) => {
      await ensureDir(targetDir);
      const newBinaryPath = path.join(targetDir, "docdexd");
      await fs.promises.writeFile(newBinaryPath, "new-binary\n");
    },
    readBinaryVersionFn: readBinaryVersionStub
  });

  assert.equal(downloadUrl, expectedDownloadUrl);
  assert.equal(result.outcome, "update");

  const metadataPath = path.join(distDir, "docdexd-install.json");
  assert.ok(fs.existsSync(metadataPath));
  const meta = JSON.parse(await fs.promises.readFile(metadataPath, "utf8"));
  assert.equal(meta.version, expectedVersion);
  assert.equal(meta.expectedVersion, expectedVersion);
  assert.equal(meta.installedVersion, expectedVersion);
  assert.equal(meta.releaseTag, `v${expectedVersion}`);
  assert.equal(meta.archive?.tag, `v${expectedVersion}`);
  assert.equal(meta.platformKey, platformKey);
  assert.equal(typeof meta.binary?.sha256, "string");
  assert.equal(meta.binary.sha256.length, 64);
});

<<<<<<< HEAD
test("installer atomicity: extract failure preserves existing install and cleans staging", async (t) => {
  const base = "https://example.test/releases/download";
  const expectedVersion = "0.0.2";
  const installedVersion = "0.0.1";
=======
test("installer outcome: update installs when no daemon is present", async (t) => {
  const base = "https://example.test/releases/download";
  const expectedVersion = "0.0.2";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-outcome-missing-"));
  t.after(async () => {
    await fs.promises.rm(tmpRoot, { recursive: true, force: true });
  });

  const distBaseDir = path.join(tmpRoot, "dist");
  const distDir = path.join(distBaseDir, platformKey);
  const tmpDir = path.join(tmpRoot, "tmp");
  await ensureDir(tmpDir);

  const archive = "docdexd-linux-x64-gnu.tar.gz";

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
      await ensureDir(path.dirname(dest));
      await fs.promises.writeFile(dest, "fake-archive-bytes");
    },
    verifyDownloadedFileIntegrityFn: async () => null,
    extractTarballFn: async (_archivePath, targetDir) => {
      await ensureDir(targetDir);
      await fs.promises.writeFile(path.join(targetDir, "docdexd"), "fresh\n");
    },
    readBinaryVersionFn: readBinaryVersionStub
  });

  assert.equal(result.outcome, "update");
  const metadataPath = path.join(distDir, "docdexd-install.json");
  const meta = JSON.parse(await fs.promises.readFile(metadataPath, "utf8"));
  assert.equal(meta.version, expectedVersion);
});

test("installer outcome: update installs when installed version is newer", async (t) => {
  const base = "https://example.test/releases/download";
  const expectedVersion = "0.0.2";
  const installedVersion = "0.0.3";
>>>>>>> mcoda/task/ops-01-us-03-t44
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const isWin32 = false;

<<<<<<< HEAD
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-atomicity-extract-"));
=======
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-outcome-downgrade-"));
>>>>>>> mcoda/task/ops-01-us-03-t44
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

<<<<<<< HEAD
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
          expectedSha256: "a".repeat(64),
          source: "fallback",
          manifestAttempt: { errors: [], resolved: null, manifestName: null }
        }),
        downloadFn: async (_url, dest) => {
          await ensureDir(path.dirname(dest));
          await fs.promises.writeFile(dest, "fake-archive-bytes");
        },
        verifyDownloadedFileIntegrityFn: async () => "a".repeat(64),
        extractTarballFn: async () => {
          throw new Error("boom: extract failed");
        }
      }),
    (err) => {
      assert.equal(err.code, "DOCDEX_ARCHIVE_INVALID");
      assert.ok(String(err.message).includes("Failed to extract archive"));
      return true;
    }
  );

  assert.equal(await fs.promises.readFile(oldBinaryPath, "utf8"), "old-binary\n");
  const meta = JSON.parse(await fs.promises.readFile(path.join(distDir, "docdexd-install.json"), "utf8"));
  assert.equal(meta.version, installedVersion);

  const entries = await fs.promises.readdir(distBaseDir);
  assert.ok(!entries.some((e) => e.startsWith(`${platformKey}.staging-`)), "expected staging dir cleanup");
=======
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
      await ensureDir(path.dirname(dest));
      await fs.promises.writeFile(dest, "fake-archive-bytes");
    },
    verifyDownloadedFileIntegrityFn: async () => null,
    extractTarballFn: async (_archivePath, targetDir) => {
      await ensureDir(targetDir);
      const newBinaryPath = path.join(targetDir, "docdexd");
      await fs.promises.writeFile(newBinaryPath, "new-binary\n");
    },
    readBinaryVersionFn: readBinaryVersionStub
  });

  assert.equal(result.outcome, "update");
<<<<<<< HEAD
=======
  assert.equal(smokeCalls, 1);
  assert.equal(smokeBinaryPath, path.join(distDir, "docdexd"));

>>>>>>> mcoda/task/ops-01-us-01-t41
  const metadataPath = path.join(distDir, "docdexd-install.json");
  const meta = JSON.parse(await fs.promises.readFile(metadataPath, "utf8"));
  assert.equal(meta.version, expectedVersion);
<<<<<<< HEAD
});

test("installer outcome: version mismatch after install fails and preserves existing binary", async (t) => {
  const base = "https://example.test/releases/download";
  const expectedVersion = "0.0.2";
  const installedVersion = "0.0.1";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const isWin32 = false;

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-outcome-version-mismatch-"));
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
      extractTarballFn: async (_archivePath, targetDir) => {
        await ensureDir(targetDir);
        const newBinaryPath = path.join(targetDir, "docdexd");
        await fs.promises.writeFile(newBinaryPath, "new-binary\n");
      },
      readBinaryVersionFn: async () => ({ version: "0.0.0", output: "docdexd 0.0.0" })
    });
  } catch (e) {
    err = e;
  }

  assert.ok(err, "expected an error");
  assert.equal(err.code, "DOCDEX_ARCHIVE_INVALID");
  const persisted = await fs.promises.readFile(oldBinaryPath, "utf8");
  assert.equal(persisted, "old-binary\n");
  const metadataPath = path.join(distDir, "docdexd-install.json");
  const meta = JSON.parse(await fs.promises.readFile(metadataPath, "utf8"));
  assert.equal(meta.version, installedVersion);
>>>>>>> mcoda/task/ops-01-us-03-t44
=======
  assert.equal(meta.platformKey, platformKey);
  assert.equal(typeof meta.binary?.sha256, "string");
  assert.equal(meta.binary.sha256.length, 64);

  const installedBinary = await fs.promises.readFile(path.join(distDir, "docdexd"), "utf8");
  assert.equal(installedBinary, "new-binary\n");
>>>>>>> mcoda/task/ops-01-us-03-t15
});

test("installer outcome: repair reinstalls when binary hash mismatches metadata", async (t) => {
  const base = "https://example.test/releases/download";
  const version = "0.0.0";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const isWin32 = false;

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-outcome-repair-"));
  t.after(async () => {
    await fs.promises.rm(tmpRoot, { recursive: true, force: true });
  });

  const distBaseDir = path.join(tmpRoot, "dist");
  const distDir = path.join(distBaseDir, platformKey);
  const tmpDir = path.join(tmpRoot, "tmp");
  await ensureDir(tmpDir);

  const binaryPath = await writeInstalledBinary({ distDir, isWin32, bytes: "original\n" });
  const originalSha = await sha256File(binaryPath);
  await writeInstallMetadata({ distDir, platformKey, version, targetTriple, binarySha256: originalSha });

  await fs.promises.writeFile(binaryPath, "corrupted\n");

  const archive = "docdexd-linux-x64-gnu.tar.gz";

  const result = await runInstaller({
    logger: createNoopLogger(),
    smokeTestBinaryFn: noopSmokeTest,
    platform: "linux",
    arch: "x64",
    tmpDir,
    distBaseDir,
    getBinaryVersionFn: createVersionDetector(version),
    detectPlatformKeyFn: () => platformKey,
    targetTripleForPlatformKeyFn: () => targetTriple,
    getVersionFn: () => version,
    parseRepoSlugFn: () => "owner/repo",
    getDownloadBaseFn: () => base,
    resolveInstallerDownloadPlanFn: async () => ({
      archive,
<<<<<<< HEAD
<<<<<<< HEAD
      expectedSha256: "a".repeat(64),
=======
      expectedSha256: EXPECTED_SHA256,
>>>>>>> mcoda/task/ops-01-us-04-t18
=======
      expectedSha256: ARCHIVE_SHA256,
>>>>>>> mcoda/task/ops-01-us-04-t11
      source: "fallback",
      manifestAttempt: { errors: [], resolved: null, manifestName: null }
    }),
>>>>>>> mcoda/task/ops-01-us-04-t40
    downloadFn: async (_url, dest) => {
      await ensureDir(path.dirname(dest));
      await fs.promises.writeFile(dest, ARCHIVE_BYTES);
    },
<<<<<<< HEAD
    verifyDownloadedFileIntegrityFn: async ({ expectedSha256 }) => expectedSha256,
=======
    verifyDownloadedFileIntegrityFn: async () => ARCHIVE_SHA256,
>>>>>>> mcoda/task/ops-01-us-04-t11
    extractTarballFn: async (_archivePath, targetDir) => {
      await ensureDir(targetDir);
<<<<<<< HEAD
      await fs.promises.writeFile(path.join(targetDir, "docdexd"), "new-binary\n");
    },
    restartDaemonFn: async ({ binaryPath, outcome }) => {
      restartCalls += 1;
      restartOutcome = outcome;
      restartBinaryPath = binaryPath;
      return { attempted: true };
    }
=======
      const repaired = path.join(targetDir, "docdexd");
      await fs.promises.writeFile(repaired, "repaired\n");
    },
    readBinaryVersionFn: readBinaryVersionStub
>>>>>>> mcoda/task/ops-01-us-03-t44
  });

  assert.equal(result.outcome, "update");
  assert.equal(restartCalls, 1);
  assert.equal(restartOutcome, "update");
  assert.equal(restartBinaryPath, path.join(distDir, "docdexd"));
  assert.equal(result.binaryPath, path.join(distDir, "docdexd"));
});

<<<<<<< HEAD
test("installer lifecycle: reinstall_unknown does not restart when binary is unchanged", async (t) => {
=======
test("installer outcome: repair converges to no-op without network calls", async (t) => {
  const base = "https://example.test/releases/download";
  const version = "0.0.0";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const isWin32 = false;

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-outcome-repair-noop-"));
  t.after(async () => {
    await fs.promises.rm(tmpRoot, { recursive: true, force: true });
  });

  const distBaseDir = path.join(tmpRoot, "dist");
  const distDir = path.join(distBaseDir, platformKey);
  const tmpDir = path.join(tmpRoot, "tmp");
  await ensureDir(tmpDir);

  const binaryPath = await writeInstalledBinary({ distDir, isWin32, bytes: "original\n" });
  const originalSha = await sha256File(binaryPath);
  await writeInstallMetadata({ distDir, platformKey, version, targetTriple, binarySha256: originalSha });

  await fs.promises.writeFile(binaryPath, "corrupted\n");

  const archive = "docdexd-linux-x64-gnu.tar.gz";

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
      await ensureDir(path.dirname(dest));
      await fs.promises.writeFile(dest, "fake-archive-bytes");
    },
    verifyDownloadedFileIntegrityFn: async () => null,
    extractTarballFn: async (_archivePath, targetDir) => {
      await ensureDir(targetDir);
      const repaired = path.join(targetDir, "docdexd");
      await fs.promises.writeFile(repaired, "repaired\n");
    }
  });

  assert.equal(first.outcome, "repair");
  const metadataPath = path.join(distDir, "docdexd-install.json");
  const metadataAfterRepair = await fs.promises.readFile(metadataPath, "utf8");
  const binaryAfterRepair = await fs.promises.readFile(path.join(distDir, "docdexd"), "utf8");

  let planCalls = 0;
  let downloadCalls = 0;
  let extractCalls = 0;
  let verifyCalls = 0;
  let repoSlugCalls = 0;

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
    },
    getDownloadBaseFn: () => base
  });

  assert.equal(second.outcome, "no-op");
  assert.equal(second.binaryPath, first.binaryPath);
  assert.equal(repoSlugCalls, 0);
  assert.equal(planCalls, 0);
  assert.equal(downloadCalls, 0);
  assert.equal(verifyCalls, 0);
  assert.equal(extractCalls, 0);

  const metadataAfterSecond = await fs.promises.readFile(metadataPath, "utf8");
  const binaryAfterSecond = await fs.promises.readFile(path.join(distDir, "docdexd"), "utf8");
  assert.equal(metadataAfterSecond, metadataAfterRepair);
  assert.equal(binaryAfterSecond, binaryAfterRepair);
});

test("installer outcome: reinstall_unknown reinstalls when metadata is missing", async (t) => {
>>>>>>> mcoda/task/bck-05-us-06-t48
  const base = "https://example.test/releases/download";
  const version = "0.0.0";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const isWin32 = false;

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-restart-unchanged-"));
  t.after(async () => {
    await fs.promises.rm(tmpRoot, { recursive: true, force: true });
  });

  const distBaseDir = path.join(tmpRoot, "dist");
  const distDir = path.join(distBaseDir, platformKey);
  const tmpDir = path.join(tmpRoot, "tmp");
  await ensureDir(tmpDir);

  await writeInstalledBinary({ distDir, isWin32, bytes: "same-binary\n" });
  assert.ok(!fs.existsSync(path.join(distDir, "docdexd-install.json")));

  const archive = "docdexd-linux-x64-gnu.tar.gz";
  let restartCalls = 0;

  const result = await runInstaller({
    logger: createNoopLogger(),
    smokeTestBinaryFn: noopSmokeTest,
    platform: "linux",
    arch: "x64",
    tmpDir,
    distBaseDir,
    getBinaryVersionFn: createVersionDetector(version),
    detectPlatformKeyFn: () => platformKey,
    targetTripleForPlatformKeyFn: () => targetTriple,
    getVersionFn: () => version,
    parseRepoSlugFn: () => "owner/repo",
    getDownloadBaseFn: () => base,
    resolveInstallerDownloadPlanFn: async () => ({
      archive,
<<<<<<< HEAD
<<<<<<< HEAD
      expectedSha256: "a".repeat(64),
=======
      expectedSha256: EXPECTED_SHA256,
>>>>>>> mcoda/task/ops-01-us-04-t18
=======
      expectedSha256: ARCHIVE_SHA256,
>>>>>>> mcoda/task/ops-01-us-04-t11
      source: "fallback",
      manifestAttempt: { errors: [], resolved: null, manifestName: null }
    }),
    downloadFn: async (_url, dest) => {
      await ensureDir(path.dirname(dest));
      await fs.promises.writeFile(dest, ARCHIVE_BYTES);
    },
<<<<<<< HEAD
    verifyDownloadedFileIntegrityFn: async ({ expectedSha256 }) => expectedSha256,
=======
    verifyDownloadedFileIntegrityFn: async () => ARCHIVE_SHA256,
>>>>>>> mcoda/task/ops-01-us-04-t11
    extractTarballFn: async (_archivePath, targetDir) => {
      await ensureDir(targetDir);
<<<<<<< HEAD
      await fs.promises.writeFile(path.join(targetDir, "docdexd"), "same-binary\n");
    },
    restartDaemonFn: async () => {
      restartCalls += 1;
      return { attempted: true };
    }
=======
      const repaired = path.join(targetDir, "docdexd");
      await fs.promises.writeFile(repaired, "fresh\n");
    },
    readBinaryVersionFn: readBinaryVersionStub
>>>>>>> mcoda/task/ops-01-us-03-t44
  });

  assert.equal(result.outcome, "reinstall_unknown");
  assert.equal(restartCalls, 0);
  assert.equal(result.restart.reason, "binary_unchanged");
});

test("installer atomic replace: failed extraction leaves existing binary untouched", async (t) => {
  const base = "https://example.test/releases/download";
  const expectedVersion = "0.0.2";
  const installedVersion = "0.0.1";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const isWin32 = false;

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-atomic-extract-fail-"));
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
          await ensureDir(path.dirname(dest));
          await fs.promises.writeFile(dest, "fake-archive-bytes");
        },
        verifyDownloadedFileIntegrityFn: async () => null,
        extractTarballFn: async (_archivePath, targetDir) => {
          await ensureDir(targetDir);
          await fs.promises.writeFile(path.join(targetDir, "docdexd"), "partial\n");
          throw new Error("simulated extract failure");
        }
      }),
    /simulated extract failure/
  );

  assert.equal(await fs.promises.readFile(path.join(distDir, "docdexd"), "utf8"), "old-binary\n");
  const meta = JSON.parse(await fs.promises.readFile(path.join(distDir, "docdexd-install.json"), "utf8"));
  assert.equal(meta.version, installedVersion);
});

test("installer rollback: failed extract keeps prior binary and rerun succeeds without manual cleanup", async (t) => {
  const base = "https://example.test/releases/download";
  const expectedVersion = "0.0.2";
  const installedVersion = "0.0.1";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const isWin32 = false;

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-rollback-"));
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

  let firstError = null;
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
        throw new Error("extract failed");
      }
    });
    assert.fail("expected install to fail");
  } catch (err) {
    firstError = err;
  }

  assert.ok(firstError, "expected failure");

  // Old binary + metadata remain intact (the system is not left in a worse state).
  assert.equal(await fs.promises.readFile(oldBinaryPath, "utf8"), "old-binary\n");
  const metadataPath = path.join(distDir, "docdexd-install.json");
  const metaAfterFail = JSON.parse(await fs.promises.readFile(metadataPath, "utf8"));
  assert.equal(metaAfterFail.version, installedVersion);

  // No leftover staging artifacts are required to be cleaned up manually.
  const baseEntries = await fs.promises.readdir(distBaseDir);
  assert.equal(baseEntries.filter((n) => n.startsWith(`${platformKey}.staging.`)).length, 0);
  const distEntries = await fs.promises.readdir(distDir);
  assert.equal(distEntries.filter((n) => n.endsWith(".new")).length, 0);

  // Re-run converges successfully.
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
<<<<<<< HEAD
<<<<<<< HEAD
      expectedSha256: "a".repeat(64),
=======
      expectedSha256: EXPECTED_SHA256,
>>>>>>> mcoda/task/ops-01-us-04-t18
=======
      expectedSha256: ARCHIVE_SHA256,
>>>>>>> mcoda/task/ops-01-us-04-t11
      source: "fallback",
      manifestAttempt: { errors: [], resolved: null, manifestName: null }
    }),
    downloadFn: async (_url, dest) => {
      await ensureDir(path.dirname(dest));
      await fs.promises.writeFile(dest, ARCHIVE_BYTES);
    },
<<<<<<< HEAD
    verifyDownloadedFileIntegrityFn: async ({ expectedSha256 }) => expectedSha256,
=======
    verifyDownloadedFileIntegrityFn: async () => ARCHIVE_SHA256,
>>>>>>> mcoda/task/ops-01-us-04-t11
    extractTarballFn: async (_archivePath, targetDir) => {
      await ensureDir(targetDir);
      await fs.promises.writeFile(path.join(targetDir, "docdexd"), "new-binary\n");
    }
  });

  assert.equal(result.outcome, "update");
  assert.equal(await fs.promises.readFile(path.join(distDir, "docdexd"), "utf8"), "new-binary\n");
  const metaAfterSuccess = JSON.parse(await fs.promises.readFile(metadataPath, "utf8"));
  assert.equal(metaAfterSuccess.version, expectedVersion);
});

test("installer: failed extract keeps existing binary and cleans staging artifacts", async (t) => {
  const base = "https://example.test/releases/download";
  const expectedVersion = "0.0.1";
  const installedVersion = "0.0.0";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const isWin32 = false;

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-staging-fail-"));
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
        throw new Error("extract failed");
      }
    });
  } catch (e) {
    err = e;
  }

  assert.ok(err, "expected an error");
  const binaryAfter = await fs.promises.readFile(oldBinaryPath, "utf8");
  assert.equal(binaryAfter, "old-binary\n");
  const meta = JSON.parse(await fs.promises.readFile(path.join(distDir, "docdexd-install.json"), "utf8"));
  assert.equal(meta.version, installedVersion);

  const stagingRoot = path.join(distBaseDir, STAGING_ROOT_NAME);
  if (fs.existsSync(stagingRoot)) {
    const entries = await fs.promises.readdir(stagingRoot);
    assert.equal(entries.length, 0);
  }
});

test("installer: restores prior backup before deciding no-op", async (t) => {
  const version = "0.0.0";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const isWin32 = false;

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-staging-restore-"));
  t.after(async () => {
    await fs.promises.rm(tmpRoot, { recursive: true, force: true });
  });

  const distBaseDir = path.join(tmpRoot, "dist");
  const distDir = path.join(distBaseDir, platformKey);

  const binaryPath = await writeInstalledBinary({ distDir, isWin32, bytes: "restorable\n" });
  const binarySha = await sha256File(binaryPath);
  await writeInstallMetadata({ distDir, platformKey, version, targetTriple, binarySha256: binarySha });

  const stagingRoot = path.join(distBaseDir, STAGING_ROOT_NAME);
  await fs.promises.mkdir(stagingRoot, { recursive: true });
  const backupDir = path.join(stagingRoot, `${STAGING_BACKUP_PREFIX}${platformKey}-test`);
  await fs.promises.rename(distDir, backupDir);
  assert.ok(!fs.existsSync(distDir), "dist dir should be missing before restore");

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
      planCalls += 1;
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
    extractTarballFn: async () => {
      throw new Error("unexpected extract");
    }
  });

  assert.equal(result.outcome, "no-op");
  assert.equal(planCalls, 0);
  assert.equal(downloadCalls, 0);
  assert.ok(fs.existsSync(distDir));
  assert.ok(!fs.existsSync(backupDir));
});

test("installer rollback: keeps existing binary when extract fails", async (t) => {
  const base = "https://example.test/releases/download";
  const expectedVersion = "0.0.2";
  const installedVersion = "0.0.1";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const isWin32 = false;

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-outcome-extract-fail-"));
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
          await ensureDir(path.dirname(dest));
          await fs.promises.writeFile(dest, "fake-archive-bytes");
        },
        verifyDownloadedFileIntegrityFn: async () => null,
        extractTarballFn: async () => {
          throw new Error("extract failed");
        }
      }),
    /extract failed/
  );

  const currentBytes = await fs.promises.readFile(oldBinaryPath, "utf8");
  assert.equal(currentBytes, "old-binary\n");
});

test("installer recovery: restores backup before no-op decision", async (t) => {
  const base = "https://example.test/releases/download";
  const version = "0.0.0";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const isWin32 = false;

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-outcome-backup-"));
  t.after(async () => {
    await fs.promises.rm(tmpRoot, { recursive: true, force: true });
  });

  const distBaseDir = path.join(tmpRoot, "dist");
  const distDir = path.join(distBaseDir, platformKey);
  const backupDir = path.join(distBaseDir, `.docdexd-backup-${platformKey}`);

  const binaryPath = await writeInstalledBinary({ distDir: backupDir, isWin32, bytes: "verified\n" });
  const binarySha = await sha256File(binaryPath);
  await writeInstallMetadata({
    distDir: backupDir,
    platformKey,
    version,
    targetTriple,
    binarySha256: binarySha
  });

  let parseRepoSlugCalls = 0;
  let planCalls = 0;
  let downloadCalls = 0;
  let extractCalls = 0;

  const result = await runInstaller({
    logger: createNoopLogger(),
    smokeTestBinaryFn: noopSmokeTest,
    platform: "linux",
    arch: "x64",
    distBaseDir,
    getBinaryVersionFn: createVersionDetector(version),
    detectPlatformKeyFn: () => platformKey,
    targetTripleForPlatformKeyFn: () => targetTriple,
    getVersionFn: () => version,
    parseRepoSlugFn: () => {
      parseRepoSlugCalls += 1;
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
    extractTarballFn: async () => {
      extractCalls += 1;
      throw new Error("unexpected extract");
    },
<<<<<<< HEAD
    getDownloadBaseFn: () => base
=======
    sha256FileFn: async (filePath) => {
      shaCalls += 1;
      if (shaCalls === 1) throw new Error("EACCES: permission denied");
      return sha256File(filePath);
    },
    readBinaryVersionFn: readBinaryVersionStub
>>>>>>> mcoda/task/ops-01-us-03-t44
  });

  assert.equal(result.outcome, "no-op");
  assert.equal(parseRepoSlugCalls, 0);
  assert.equal(planCalls, 0);
  assert.equal(downloadCalls, 0);
  assert.equal(extractCalls, 0);
  assert.ok(fs.existsSync(path.join(distDir, "docdexd")));
  assert.ok(!fs.existsSync(backupDir));
});
