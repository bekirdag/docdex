"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { recoverInterruptedInstall, runInstaller, sha256File } = require("../lib/install");
const { targetTripleForPlatformKey } = require("../lib/platform");

const STAGING_SUFFIX = ".__docdexd_install_staging";
const BACKUP_SUFFIX = ".__docdexd_install_backup";

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

async function writeBinary({ distDir, isWin32, bytes }) {
  await ensureDir(distDir);
  const binaryPath = path.join(distDir, isWin32 ? "docdexd.exe" : "docdexd");
  const mcpBinaryPath = path.join(
    distDir,
    isWin32 ? "docdex-mcp-server.exe" : "docdex-mcp-server"
  );
  await fs.promises.writeFile(binaryPath, bytes);
  await fs.promises.writeFile(mcpBinaryPath, bytes);
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

test("startup recovery: restores backup when install interrupted between swap steps", async (t) => {
  const version = "0.0.0";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const isWin32 = false;

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-recovery-restore-"));
  t.after(async () => {
    await fs.promises.rm(tmpRoot, { recursive: true, force: true });
  });

  const distBaseDir = path.join(tmpRoot, "dist");
  const distDir = path.join(distBaseDir, platformKey);
  const backupDir = `${distDir}${BACKUP_SUFFIX}`;
  const stagingDir = `${distDir}${STAGING_SUFFIX}`;

  const backupBinaryPath = await writeBinary({ distDir: backupDir, isWin32, bytes: "known-good\n" });
  const backupSha = await sha256File(backupBinaryPath);
  await writeInstallMetadata({ distDir: backupDir, platformKey, version, targetTriple, binarySha256: backupSha });

  await ensureDir(stagingDir);
  await fs.promises.writeFile(path.join(stagingDir, "docdexd"), "partial\n");
  assert.ok(!fs.existsSync(distDir));

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
  assert.ok(fs.existsSync(path.join(distDir, "docdexd")));
  assert.ok(!fs.existsSync(backupDir));
  assert.ok(!fs.existsSync(stagingDir));
});

test("installer rollback: keeps previous install runnable when extract fails", async (t) => {
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

  const oldBinaryPath = await writeBinary({ distDir, isWin32, bytes: "old-binary\n" });
  const oldSha = await sha256File(oldBinaryPath);
  await writeInstallMetadata({
    distDir,
    platformKey,
    version: installedVersion,
    targetTriple,
    binarySha256: oldSha
  });

  const archive = "docdexd-linux-x64-gnu.tar.gz";

  let downloadDest = null;
  let extractedTo = null;

  await assert.rejects(
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
        extractedTo = targetDir;
        await ensureDir(targetDir);
        await fs.promises.writeFile(path.join(targetDir, "docdexd"), "partial\n");
        await fs.promises.writeFile(path.join(targetDir, "docdex-mcp-server"), "partial\n");
        throw new Error("extract failed");
      }
    }),
    /extract failed/
  );

  assert.equal(await fs.promises.readFile(oldBinaryPath, "utf8"), "old-binary\n");
  assert.ok(downloadDest, "expected a download destination to be used");
  assert.ok(!fs.existsSync(downloadDest), "expected downloaded archive to be cleaned up");
  assert.ok(extractedTo, "expected extract to be attempted");
  assert.ok(!fs.existsSync(extractedTo), "expected staging directory to be cleaned up");
  assert.ok(!fs.existsSync(`${distDir}${BACKUP_SUFFIX}`), "expected backup directory to not be left behind on failure");
});

test("startup recovery: removes leftover backup after successful swap", async (t) => {
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const version = "0.0.0";
  const isWin32 = false;

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-recovery-cleanup-"));
  t.after(async () => {
    await fs.promises.rm(tmpRoot, { recursive: true, force: true });
  });

  const distBaseDir = path.join(tmpRoot, "dist");
  const distDir = path.join(distBaseDir, platformKey);
  const backupDir = `${distDir}${BACKUP_SUFFIX}`;

  const binaryPath = await writeBinary({ distDir, isWin32, bytes: "current\n" });
  const sha = await sha256File(binaryPath);
  await writeInstallMetadata({ distDir, platformKey, version, targetTriple, binarySha256: sha });

  await writeBinary({ distDir: backupDir, isWin32, bytes: "old\n" });

  await recoverInterruptedInstall({ fsModule: fs, pathModule: path, distDir, isWin32, logger: null });
  assert.ok(!fs.existsSync(backupDir));
});
