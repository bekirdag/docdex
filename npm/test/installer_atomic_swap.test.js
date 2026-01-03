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

test("installer: failed extraction preserves existing install and cleans per-run staging dir", async (t) => {
  const base = "https://example.test/releases/download";
  const expectedVersion = "0.0.2";
  const installedVersion = "0.0.1";
  const platformKey = "linux-x64-gnu";
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const isWin32 = false;

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-atomic-failure-"));
  t.after(async () => {
    await fs.promises.rm(tmpRoot, { recursive: true, force: true });
  });

  const distBaseDir = path.join(tmpRoot, "dist");
  const distDir = path.join(distBaseDir, platformKey);

  const oldBinaryPath = await writeInstalledBinary({ distDir, isWin32, bytes: "old-binary\n" });
  const oldSha = await sha256File(oldBinaryPath);
  const oldMetadataPath = await writeInstallMetadata({
    distDir,
    platformKey,
    version: installedVersion,
    targetTriple,
    binarySha256: oldSha
  });

  const archive = "docdexd-linux-x64-gnu.tar.gz";
  let downloadDest = null;

  let err;
  try {
    await runInstaller({
      logger: createNoopLogger(),
      platform: "linux",
      arch: "x64",
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
      extractTarballFn: async () => {
        throw new Error("boom: extract failed");
      }
    });
  } catch (e) {
    err = e;
  }

  assert.ok(err, "expected the installer to throw");
  assert.equal(await fs.promises.readFile(oldBinaryPath, "utf8"), "old-binary\n");
  assert.equal(JSON.parse(await fs.promises.readFile(oldMetadataPath, "utf8")).version, installedVersion);

  const stagingPrefix = path.join(distBaseDir, ".staging", platformKey);
  if (fs.existsSync(stagingPrefix)) {
    const entries = await fs.promises.readdir(stagingPrefix);
    assert.equal(entries.length, 0);
  }

  assert.ok(downloadDest && downloadDest.includes(path.join(distBaseDir, ".staging")), "expected staged download path");
});

