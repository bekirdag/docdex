"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { runInstaller, sha256File } = require("../lib/install");
const { targetTripleForPlatformKey } = require("../lib/platform");

function createCaptureLogger() {
  const entries = [];
  const push = (level, msg) => entries.push({ level, msg: String(msg) });
  return {
    entries,
    log: (msg) => push("log", msg),
    warn: (msg) => push("warn", msg),
    error: (msg) => push("error", msg)
  };
}

function parseInstallerEvents(logger) {
  const prefix = "[docdex] event ";
  const out = [];
  for (const entry of logger.entries) {
    const msg = entry.msg;
    if (!msg.startsWith(prefix)) continue;
    const jsonText = msg.slice(prefix.length);
    out.push(JSON.parse(jsonText));
  }
  return out;
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

async function writeInstallMetadata({ distDir, platformKey, version, targetTriple, binarySha256 }) {
  const metadataPath = path.join(distDir, "docdexd-install.json");
  const payload = {
    schemaVersion: 1,
    installedAt: new Date().toISOString(),
    version,
    repoSlug: "owner/repo",
    platformKey,
    targetTriple,
    binary: { filename: "docdexd", sha256: binarySha256 },
    archive: { name: null, sha256: null, source: null, downloadUrl: null }
  };
  await fs.promises.writeFile(metadataPath, `${JSON.stringify(payload, null, 2)}\n`, "utf8");
  return metadataPath;
}

test("installer telemetry: no-op emits stable outcomeCode=noop and no download", async (t) => {
  const version = "0.0.0";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const isWin32 = false;

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-telemetry-noop-"));
  t.after(async () => {
    await fs.promises.rm(tmpRoot, { recursive: true, force: true });
  });

  const distBaseDir = path.join(tmpRoot, "dist");
  const distDir = path.join(distBaseDir, platformKey);

  const binaryPath = await writeInstalledBinary({ distDir, isWin32, bytes: "verified-binary\n" });
  const binarySha = await sha256File(binaryPath);
  await writeInstallMetadata({ distDir, platformKey, version, targetTriple, binarySha256: binarySha });

  const logger = createCaptureLogger();
  let downloadCalls = 0;

  const result = await runInstaller({
    logger,
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
      throw new Error("unexpected plan resolution");
    },
    downloadFn: async () => {
      downloadCalls += 1;
      throw new Error("unexpected download");
    }
  });

  assert.equal(result.outcome, "no-op");
  assert.equal(result.outcomeCode, "noop");
  assert.equal(downloadCalls, 0);

  const events = parseInstallerEvents(logger);
  const outcome = events.find((e) => e.code === "DOCDEX_INSTALL_OUTCOME");
  assert.ok(outcome, "expected DOCDEX_INSTALL_OUTCOME event");
  assert.equal(outcome.details.outcomeCode, "noop");
  assert.equal(outcome.details.downloadAttempted, false);
});

test("installer telemetry: update emits stable outcomeCode=replace and downloadAttempted=true", async (t) => {
  const base = "https://example.test/releases/download";
  const expectedVersion = "0.0.2";
  const installedVersion = "0.0.1";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const isWin32 = false;

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-telemetry-update-"));
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
  const logger = createCaptureLogger();

  const result = await runInstaller({
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
      manifestAttempt: { errors: [], resolved: null, manifestName: null, fallbackAttempted: true }
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
  });

  assert.equal(result.outcome, "update");
  assert.equal(result.outcomeCode, "replace");

  const events = parseInstallerEvents(logger);
  const outcome = events.find((e) => e.code === "DOCDEX_INSTALL_OUTCOME");
  assert.ok(outcome, "expected DOCDEX_INSTALL_OUTCOME event");
  assert.equal(outcome.details.outcomeCode, "replace");
  assert.equal(outcome.details.downloadAttempted, true);
});

test("installer telemetry: repair emits stable outcomeCode=repair", async (t) => {
  const base = "https://example.test/releases/download";
  const version = "0.0.0";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const isWin32 = false;

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-telemetry-repair-"));
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
  const logger = createCaptureLogger();

  const result = await runInstaller({
    logger,
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
      manifestAttempt: { errors: [], resolved: null, manifestName: null, fallbackAttempted: true }
    }),
    downloadFn: async (_url, dest) => {
      await ensureDir(path.dirname(dest));
      await fs.promises.writeFile(dest, "fake-archive-bytes");
    },
    verifyDownloadedFileIntegrityFn: async () => null,
    extractTarballFn: async (_archivePath, targetDir) => {
      await ensureDir(targetDir);
      await fs.promises.writeFile(path.join(targetDir, "docdexd"), "repaired\n");
    }
  });

  assert.equal(result.outcome, "repair");
  assert.equal(result.outcomeCode, "repair");

  const events = parseInstallerEvents(logger);
  const outcome = events.find((e) => e.code === "DOCDEX_INSTALL_OUTCOME");
  assert.ok(outcome, "expected DOCDEX_INSTALL_OUTCOME event");
  assert.equal(outcome.details.outcomeCode, "repair");
});

test("installer telemetry: archive integrity mismatch emits DOCDEX_INSTALL_INTEGRITY_ARCHIVE status=mismatch", async (t) => {
  const base = "https://example.test/releases/download";
  const version = "0.0.0";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-telemetry-archive-mismatch-"));
  t.after(async () => {
    await fs.promises.rm(tmpRoot, { recursive: true, force: true });
  });

  const distBaseDir = path.join(tmpRoot, "dist");
  const tmpDir = path.join(tmpRoot, "tmp");
  await ensureDir(tmpDir);

  const archive = "docdexd-linux-x64-gnu.tar.gz";
  const logger = createCaptureLogger();

  let err;
  try {
    await runInstaller({
      logger,
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
        expectedSha256: "a".repeat(64),
        source: "fallback",
        manifestAttempt: { errors: [], resolved: null, manifestName: null, fallbackAttempted: true }
      }),
      downloadFn: async (_url, dest) => {
        await ensureDir(path.dirname(dest));
        await fs.promises.writeFile(dest, "fake-archive-bytes");
      }
    });
  } catch (e) {
    err = e;
  }

  assert.ok(err, "expected an install error");
  assert.equal(err.code, "DOCDEX_INTEGRITY_MISMATCH");

  const events = parseInstallerEvents(logger);
  const integrity = events.find((e) => e.code === "DOCDEX_INSTALL_INTEGRITY_ARCHIVE");
  assert.ok(integrity, "expected DOCDEX_INSTALL_INTEGRITY_ARCHIVE event");
  assert.equal(integrity.details.status, "mismatch");
  assert.equal(integrity.details.expectedSha256, "a".repeat(64));
  assert.equal(typeof integrity.details.actualSha256, "string");
  assert.equal(integrity.details.actualSha256.length, 64);
});
