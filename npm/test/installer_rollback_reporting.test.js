"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { describeFatalError, runInstaller } = require("../lib/install");

function noopLogger() {
  return { log: () => {}, warn: () => {}, error: () => {} };
}

test("installer failure reports rollback/cleanup and preserves prior docdexd", async () => {
  const baseDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), "docdex-installer-test-"));
  try {
    const distBaseDir = path.join(baseDir, "dist");
    const platformKey = "linux-x64-gnu";
    const targetTriple = "x86_64-unknown-linux-gnu";
    const distDir = path.join(distBaseDir, platformKey);

    await fs.promises.mkdir(distDir, { recursive: true });
    const priorBinaryPath = path.join(distDir, "docdexd");
    await fs.promises.writeFile(priorBinaryPath, "old-binary");
    await fs.promises.chmod(priorBinaryPath, 0o755);

    await fs.promises.writeFile(
      path.join(distDir, "docdexd-install.json"),
      `${JSON.stringify(
        {
          schemaVersion: 1,
          installedAt: new Date().toISOString(),
          version: "0.0.0",
          repoSlug: "owner/repo",
          platformKey,
          targetTriple,
          binary: { filename: "docdexd", sha256: "a".repeat(64) },
          archive: { name: "n/a", sha256: null, source: "n/a", downloadUrl: null }
        },
        null,
        2
      )}\n`
    );

    let failPromoteOnce = true;
    const wrappedFs = Object.create(fs);
    wrappedFs.promises = Object.create(fs.promises);
    wrappedFs.promises.rename = async (from, to) => {
      if (failPromoteOnce && to === distDir) {
        failPromoteOnce = false;
        const err = new Error("injected rename failure");
        err.code = "EACCES";
        throw err;
      }
      return fs.promises.rename(from, to);
    };

    let err;
    try {
      await runInstaller({
        logger: noopLogger(),
        platform: "linux",
        arch: "x64",
        resolvePlatformPolicyFn: () => ({
          detected: { platform: "linux", arch: "x64" },
          platformKey,
          targetTriple,
          expectedAssetName: "docdexd-linux-x64-gnu.tar.gz",
          expectedAssetPattern: "docdexd-<platformKey>.tar.gz"
        }),
        getVersionFn: () => "0.0.1",
        parseRepoSlugFn: () => "owner/repo",
        resolveInstallerDownloadPlanFn: async () => ({
          archive: "docdexd-linux-x64-gnu.tar.gz",
          expectedSha256: null,
          source: "fallback",
          manifestAttempt: { manifestName: null, resolved: null, errors: [] }
        }),
        getDownloadBaseFn: () => "https://example.test/releases/download",
        downloadFn: async (_url, dest) => {
          await fs.promises.writeFile(dest, "fake archive");
        },
        extractTarballFn: async (_archivePath, targetDir) => {
          await fs.promises.mkdir(targetDir, { recursive: true });
          const stagedBinaryPath = path.join(targetDir, "docdexd");
          await fs.promises.writeFile(stagedBinaryPath, "new-binary");
          await fs.promises.chmod(stagedBinaryPath, 0o755);
        },
        fsModule: wrappedFs,
        distBaseDir,
        tmpDir: baseDir
      });
    } catch (e) {
      err = e;
    }

    assert.ok(err, "expected installer to fail");
    assert.equal(await fs.promises.readFile(priorBinaryPath, "utf8"), "old-binary");

    const report = describeFatalError(err);
    assert.ok(report.lines.some((l) => l.includes("Install safety status:")));
    assert.ok(report.lines.some((l) => l.includes("Rollback: restored previous installation")));
    assert.ok(report.lines.some((l) => l.includes("Prior docdexd runnable: yes")));
    assert.ok(report.lines.some((l) => l.includes("Cleanup:")));

    const attempt = err.details?.installAttempt;
    assert.ok(attempt?.stagingDir, "expected installAttempt.stagingDir to be present on error details");
    assert.equal(fs.existsSync(attempt.stagingDir), false);
  } finally {
    await fs.promises.rm(baseDir, { recursive: true, force: true });
  }
});

