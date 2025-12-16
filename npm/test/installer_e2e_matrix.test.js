"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { runInstaller } = require("../lib/install");
const { artifactName, targetTripleForPlatformKey } = require("../lib/platform");
const { PUBLISHED_PLATFORM_KEYS, PLATFORM_ENTRY_BY_KEY } = require("../lib/platform_matrix");

function createNoopLogger() {
  return {
    log: () => {},
    warn: () => {},
    error: () => {}
  };
}

async function ensureParentDir(filePath) {
  await fs.promises.mkdir(path.dirname(filePath), { recursive: true });
}

test("installer e2e: supported platform matrix installs expected binary layout", async (t) => {
  const base = "https://example.test/releases/download";
  const version = "0.0.0";
  const repoSlug = "owner/repo";

  for (const platformKey of PUBLISHED_PLATFORM_KEYS) {
    await t.test(platformKey, async (st) => {
      const entry = PLATFORM_ENTRY_BY_KEY[platformKey];
      assert.ok(entry, `missing PLATFORM_ENTRY_BY_KEY for ${platformKey}`);
      assert.ok(entry.published, `expected ${platformKey} to be published`);

      const targetTriple = targetTripleForPlatformKey(platformKey);
      assert.equal(targetTriple, entry.targetTriple);

      const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), `docdex-installer-e2e-${platformKey}-`));
      const tmpDir = path.join(tmpRoot, "tmp");
      const stateRootDir = path.join(tmpRoot, "state");
      await fs.promises.mkdir(tmpDir, { recursive: true });

      st.after(async () => {
        await fs.promises.rm(tmpRoot, { recursive: true, force: true });
      });

      let downloadUrl = null;
      let downloadDest = null;
      let extractArchive = null;
      let extractDir = null;

      const expectedArchive = artifactName(platformKey);
      const expectedDownloadUrl = `${base}/v${version}/${expectedArchive}`;

      const result = await runInstaller({
        logger: createNoopLogger(),
        platform: entry.platform,
        arch: entry.arch,
        tmpDir,
        stateRootDir,
        detectPlatformKeyFn: () => platformKey,
        targetTripleForPlatformKeyFn: (key) => targetTripleForPlatformKey(key),
        getVersionFn: () => version,
        parseRepoSlugFn: () => repoSlug,
        getDownloadBaseFn: () => base,
        resolveInstallerDownloadPlanFn: async ({ platformKey: key, targetTriple: triple }) => {
          assert.equal(key, platformKey);
          assert.equal(triple, targetTriple);
          return {
            archive: expectedArchive,
            expectedSha256: null,
            source: "fallback",
            manifestAttempt: { errors: [], resolved: null, manifestName: null }
          };
        },
        downloadFn: async (url, dest) => {
          downloadUrl = url;
          downloadDest = dest;
          await ensureParentDir(dest);
          await fs.promises.writeFile(dest, "fake-archive-bytes");
        },
        verifyDownloadedFileIntegrityFn: async ({ filePath, expectedSha256, archiveName, details }) => {
          assert.equal(filePath, downloadDest);
          assert.equal(expectedSha256, null);
          assert.equal(archiveName, expectedArchive);
          assert.ok(fs.existsSync(filePath));
          assert.equal(details.platformKey, platformKey);
          assert.equal(details.targetTriple, targetTriple);
          return null;
        },
        extractTarballFn: async (archivePath, targetDir) => {
          extractArchive = archivePath;
          extractDir = targetDir;
          await fs.promises.mkdir(targetDir, { recursive: true });
          const isWin32 = entry.platform === "win32";
          const binaryPath = path.join(targetDir, isWin32 ? "docdexd.exe" : "docdexd");
          await fs.promises.writeFile(binaryPath, "#!/bin/sh\necho docdexd\n");
        }
      });

      const isWin32 = entry.platform === "win32";
      const expectedBinaryPath = path.join(stateRootDir, "daemon", platformKey, isWin32 ? "docdexd.exe" : "docdexd");

      assert.equal(downloadUrl, expectedDownloadUrl);
      assert.equal(extractArchive, downloadDest);
<<<<<<< HEAD
      assert.equal(extractDir, path.join(stateRootDir, "daemon", platformKey));
=======
      const expectedDistDir = path.join(distBaseDir, platformKey);
      assert.ok(
        extractDir && extractDir.startsWith(`${expectedDistDir}.staging-`),
        `expected extract into staging dir under ${expectedDistDir}`
      );
>>>>>>> mcoda/task/ops-01-us-06-t35
      assert.equal(result.binaryPath, expectedBinaryPath);
      assert.ok(!fs.existsSync(extractDir), "staging dir should have been swapped into place");
      assert.ok(fs.existsSync(expectedBinaryPath));
    });
  }
});
