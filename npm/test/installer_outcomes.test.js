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

test("installer outcome: no-op skips plan/download when local install is verified", async (t) => {
  const base = "https://example.test/releases/download";
  const version = "0.0.0";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const isWin32 = false;

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-outcome-noop-"));
  t.after(async () => {
    await fs.promises.rm(tmpRoot, { recursive: true, force: true });
  });

  const distBaseDir = path.join(tmpRoot, "dist");
  const distDir = path.join(distBaseDir, platformKey);

  const binaryPath = await writeInstalledBinary({ distDir, isWin32, bytes: "verified-binary\n" });
  const binarySha = await sha256File(binaryPath);
  await writeInstallMetadata({ distDir, platformKey, version, targetTriple, binarySha256: binarySha });

  let parseRepoSlugCalls = 0;
  let planCalls = 0;
  let downloadCalls = 0;
  let extractCalls = 0;

  const result = await runInstaller({
    logger: createNoopLogger(),
    platform: "linux",
    arch: "x64",
    distBaseDir,
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
    getDownloadBaseFn: () => base
  });

  assert.equal(result.binaryPath, binaryPath);
  assert.equal(result.outcome, "no-op");
  assert.equal(parseRepoSlugCalls, 0);
  assert.equal(planCalls, 0);
  assert.equal(downloadCalls, 0);
  assert.equal(extractCalls, 0);
});

test("installer outcome: update installs when version differs and writes fresh metadata", async (t) => {
  const base = "https://example.test/releases/download";
  const expectedVersion = "0.0.2";
  const installedVersion = "0.0.1";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const isWin32 = false;

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-outcome-update-"));
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

  let downloadUrl = null;
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
    downloadFn: async (url, dest) => {
      downloadUrl = url;
      downloadDest = dest;
      await ensureDir(path.dirname(dest));
      await fs.promises.writeFile(dest, "fake-archive-bytes");
    },
    verifyDownloadedFileIntegrityFn: async ({ filePath }) => {
      assert.equal(filePath, downloadDest);
      assert.ok(fs.existsSync(filePath));
      return null;
    },
    extractTarballFn: async (_archivePath, targetDir) => {
      await ensureDir(targetDir);
      const newBinaryPath = path.join(targetDir, "docdexd");
      await fs.promises.writeFile(newBinaryPath, "new-binary\n");
    }
  });

  assert.equal(downloadUrl, expectedDownloadUrl);
  assert.equal(result.outcome, "update");

  const metadataPath = path.join(distDir, "docdexd-install.json");
  assert.ok(fs.existsSync(metadataPath));
  const meta = JSON.parse(await fs.promises.readFile(metadataPath, "utf8"));
  assert.equal(meta.version, expectedVersion);
  assert.equal(meta.platformKey, platformKey);
  assert.equal(typeof meta.binary?.sha256, "string");
  assert.equal(meta.binary.sha256.length, 64);
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

  assert.equal(result.outcome, "repair");
  const metadataPath = path.join(distDir, "docdexd-install.json");
  const meta = JSON.parse(await fs.promises.readFile(metadataPath, "utf8"));
  assert.equal(meta.version, version);
  const repairedBinaryPath = path.join(distDir, "docdexd");
  const repairedSha = await sha256File(repairedBinaryPath);
  assert.equal(meta.binary.sha256, repairedSha);
});

test("installer outcome: reinstall_unknown reinstalls when metadata is missing", async (t) => {
  const base = "https://example.test/releases/download";
  const version = "0.0.0";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const isWin32 = false;

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-outcome-unknown-"));
  t.after(async () => {
    await fs.promises.rm(tmpRoot, { recursive: true, force: true });
  });

  const distBaseDir = path.join(tmpRoot, "dist");
  const distDir = path.join(distBaseDir, platformKey);
  const tmpDir = path.join(tmpRoot, "tmp");
  await ensureDir(tmpDir);

  await writeInstalledBinary({ distDir, isWin32, bytes: "no-metadata\n" });
  assert.ok(!fs.existsSync(path.join(distDir, "docdexd-install.json")));

  const archive = "docdexd-linux-x64-gnu.tar.gz";

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
      await fs.promises.writeFile(repaired, "fresh\n");
    }
  });

  assert.equal(result.outcome, "reinstall_unknown");
  const metadataPath = path.join(distDir, "docdexd-install.json");
  const meta = JSON.parse(await fs.promises.readFile(metadataPath, "utf8"));
  assert.equal(meta.version, version);
  assert.equal(meta.platformKey, platformKey);
  assert.equal(meta.targetTriple, targetTriple);
});

test("installer outcome: reinstall_unknown reinstalls when integrity cannot be verified", async (t) => {
  const base = "https://example.test/releases/download";
  const version = "0.0.0";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const isWin32 = false;

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-outcome-unverifiable-"));
  t.after(async () => {
    await fs.promises.rm(tmpRoot, { recursive: true, force: true });
  });

  const distBaseDir = path.join(tmpRoot, "dist");
  const distDir = path.join(distBaseDir, platformKey);
  const tmpDir = path.join(tmpRoot, "tmp");
  await ensureDir(tmpDir);

  const binaryPath = await writeInstalledBinary({ distDir, isWin32, bytes: "verified-binary\n" });
  const binarySha = await sha256File(binaryPath);
  await writeInstallMetadata({ distDir, platformKey, version, targetTriple, binarySha256: binarySha });

  const archive = "docdexd-linux-x64-gnu.tar.gz";

  let shaCalls = 0;
  let downloadCalls = 0;
  let extractCalls = 0;

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
      await fs.promises.writeFile(path.join(targetDir, "docdexd"), "fresh\n");
    },
    sha256FileFn: async (filePath) => {
      shaCalls += 1;
      if (shaCalls === 1) throw new Error("EACCES: permission denied");
      return sha256File(filePath);
    }
  });

  assert.equal(result.outcome, "reinstall_unknown");
  assert.equal(downloadCalls, 1);
  assert.equal(extractCalls, 1);
  assert.ok(shaCalls >= 2, "expected sha256 to be attempted for local check and after install");

  const metadataPath = path.join(distDir, "docdexd-install.json");
  const meta = JSON.parse(await fs.promises.readFile(metadataPath, "utf8"));
  assert.equal(meta.version, version);
  assert.equal(meta.platformKey, platformKey);
  assert.equal(meta.targetTriple, targetTriple);
});
