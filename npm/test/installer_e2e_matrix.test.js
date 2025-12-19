"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { runInstaller } = require("../lib/install");
const { artifactName, targetTripleForPlatformKey } = require("../lib/platform");
const { PUBLISHED_PLATFORM_KEYS, PLATFORM_ENTRY_BY_KEY } = require("../lib/platform_matrix");

const EXPECTED_SHA256 = "a".repeat(64);

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
  const expectedArchiveSha256 = "a".repeat(64);

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
<<<<<<< HEAD
      const expectedSha256 = "a".repeat(64);
=======
      const expectedSha256Hex = "a".repeat(64);
>>>>>>> mcoda/task/ops-01-us-04-t40

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
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
            expectedSha256,
=======
            expectedSha256: expectedSha256Hex,
>>>>>>> mcoda/task/ops-01-us-04-t40
=======
            expectedSha256: expectedArchiveSha256,
>>>>>>> mcoda/task/ops-01-us-04-t17
=======
            expectedSha256: EXPECTED_SHA256,
>>>>>>> mcoda/task/ops-01-us-04-t18
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
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
          assert.equal(expectedSha256, "a".repeat(64));
=======
          assert.equal(expectedSha256, expectedSha256Hex);
>>>>>>> mcoda/task/ops-01-us-04-t40
=======
          assert.equal(expectedSha256, expectedArchiveSha256);
>>>>>>> mcoda/task/ops-01-us-04-t17
=======
          assert.equal(expectedSha256, EXPECTED_SHA256);
>>>>>>> mcoda/task/ops-01-us-04-t18
          assert.equal(archiveName, expectedArchive);
          assert.ok(fs.existsSync(filePath));
          assert.equal(details.platformKey, platformKey);
          assert.equal(details.targetTriple, targetTriple);
<<<<<<< HEAD
<<<<<<< HEAD
          return {
            status: "verified_ok",
            reason: "hash_match",
            expectedSha256,
            actualSha256: expectedSha256,
            expectedSource: "fallback",
            error: null
          };
=======
          return expectedArchiveSha256;
>>>>>>> mcoda/task/ops-01-us-04-t17
=======
          return expectedSha256;
>>>>>>> mcoda/task/ops-01-us-04-t18
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
<<<<<<< HEAD
<<<<<<< HEAD
      const expectedBinaryPath = path.join(stateRootDir, "daemon", platformKey, isWin32 ? "docdexd.exe" : "docdexd");

      assert.equal(downloadUrl, expectedDownloadUrl);
      assert.equal(extractArchive, downloadDest);
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
      assert.equal(extractDir, path.join(stateRootDir, "daemon", platformKey));
=======
      const expectedDistDir = path.join(distBaseDir, platformKey);
      assert.ok(
        extractDir && extractDir.startsWith(`${expectedDistDir}.staging-`),
        `expected extract into staging dir under ${expectedDistDir}`
      );
>>>>>>> mcoda/task/ops-01-us-06-t35
=======
      assert.equal(path.dirname(extractDir), path.join(distBaseDir, platformKey));
>>>>>>> mcoda/task/ops-01-us-06-t20
=======
      assert.ok(
        typeof extractDir === "string" &&
          extractDir.startsWith(path.join(distBaseDir, `${platformKey}.staging.`)),
        `expected extractDir to be a staging directory under dist/ for ${platformKey}`
      );
>>>>>>> mcoda/task/ops-01-us-05-t41
=======
      assert.ok(extractDir, "expected a staging extract dir");
      assert.equal(path.basename(extractDir), "extract");
      assert.ok(
        path.basename(path.dirname(extractDir)).startsWith(`.docdex-install-staging-${platformKey}-`),
        `unexpected staging directory name: ${extractDir}`
      );
>>>>>>> mcoda/task/ops-01-us-05-t36
=======
      assert.ok(
        typeof extractDir === "string" &&
          extractDir.startsWith(path.join(distBaseDir, `${platformKey}.staging.`)),
        `expected extractDir to be a staging dir under ${distBaseDir}`
      );
>>>>>>> mcoda/task/ops-01-us-05-t37
=======
      assert.equal(extractDir, `${path.join(distBaseDir, platformKey)}.incoming`);
>>>>>>> mcoda/task/ops-01-us-05-t40
=======
      assert.equal(path.dirname(extractDir), distBaseDir);
      assert.ok(path.basename(extractDir).startsWith(`.${platformKey}.staging.`));
>>>>>>> mcoda/task/ops-01-us-05-t39
=======
      const distDir = path.join(distBaseDir, platformKey);
      const expectedExtractDir = `${distDir}.__docdexd_install_staging`;
      const expectedBinaryPath = path.join(distDir, isWin32 ? "docdexd.exe" : "docdexd");

      assert.equal(downloadUrl, expectedDownloadUrl);
      assert.equal(extractArchive, downloadDest);
      assert.equal(extractDir, expectedExtractDir);
      assert.ok(!fs.existsSync(expectedExtractDir));
>>>>>>> mcoda/task/ops-01-us-05-t05
=======
      const expectedBinaryPath = path.join(distBaseDir, platformKey, isWin32 ? "docdexd.exe" : "docdexd");
      const expectedStagingPrefix = `${path.join(distBaseDir, platformKey)}.staging.`;

      assert.equal(downloadUrl, expectedDownloadUrl);
      assert.equal(extractArchive, downloadDest);
      assert.ok(
        typeof extractDir === "string" && extractDir.startsWith(expectedStagingPrefix),
        `expected extract dir to start with ${expectedStagingPrefix} but got ${extractDir}`
      );
>>>>>>> mcoda/task/ops-01-us-05-t22
=======
      assert.ok(
        typeof extractDir === "string" && extractDir.startsWith(path.join(distBaseDir, `${platformKey}.stage.`)),
        `expected staged extract dir under distBaseDir (got: ${extractDir})`
      );
>>>>>>> mcoda/task/ops-01-us-05-t27
=======
      const stagingPrefix = path.join(distBaseDir, ".staging", platformKey);
      assert.ok(
        typeof extractDir === "string" &&
          extractDir !== path.join(distBaseDir, platformKey) &&
          (extractDir === stagingPrefix || extractDir.startsWith(`${stagingPrefix}${path.sep}`)),
        `expected extraction to occur under staging prefix (${stagingPrefix}); got ${extractDir}`
      );
>>>>>>> mcoda/task/ops-01-us-05-t07
=======
      assert.ok(
        extractDir && extractDir.startsWith(path.join(distBaseDir, `${platformKey}.stage.`)),
        `expected extract dir to be a staging dir for ${platformKey}, got ${extractDir}`
      );
>>>>>>> mcoda/task/ops-01-us-05-t14
=======
      assert.ok(
        typeof extractDir === "string" && extractDir.startsWith(path.join(distBaseDir, `${platformKey}.staging-`)),
        `expected extractDir to be a staging directory under distBaseDir, got: ${extractDir}`
      );
>>>>>>> mcoda/task/ops-01-us-04-t40
=======
      assert.ok(extractDir);
      assert.equal(path.dirname(extractDir), distBaseDir);
      assert.ok(path.basename(extractDir).startsWith(`${platformKey}.staging.`));
>>>>>>> mcoda/task/ops-01-us-04-t13
=======
      assert.equal(path.dirname(extractDir), distBaseDir);
      assert.ok(path.basename(extractDir).startsWith(`${platformKey}.staging-`));
>>>>>>> mcoda/task/ops-01-us-04-t05
      assert.equal(result.binaryPath, expectedBinaryPath);
      assert.ok(!fs.existsSync(extractDir), "staging dir should have been swapped into place");
      assert.ok(fs.existsSync(expectedBinaryPath));
      assert.ok(!fs.existsSync(extractDir), "expected staging directory to be cleaned up");
    });
  }
});
