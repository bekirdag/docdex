"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");

const { resolvePlatformPolicy } = require("../lib/platform");
const { describeFatalError, runInstaller, resolveInstallerDownloadPlan } = require("../lib/install");

function createNoopLogger() {
  return {
    log: () => {},
    warn: () => {},
    error: () => {}
  };
}

function httpError(statusCode, message) {
  const err = new Error(message || `HTTP ${statusCode}`);
  err.statusCode = statusCode;
  return err;
}

test("installer: unsupported OS/arch fails before any plan resolution or download", async () => {
  let planCalls = 0;
  let downloadCalls = 0;
  let extractCalls = 0;
  let versionCalls = 0;
  let repoSlugCalls = 0;
  let tripleCalls = 0;

  let err;
  try {
    await runInstaller({
      logger: createNoopLogger(),
      platform: "freebsd",
      arch: "x64",
      resolvePlatformPolicyFn: (args) => resolvePlatformPolicy(args),
      targetTripleForPlatformKeyFn: () => {
        tripleCalls += 1;
        throw new Error("unexpected target triple resolution");
      },
      getVersionFn: () => {
        versionCalls += 1;
        throw new Error("unexpected version resolution");
      },
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
      extractTarballFn: async () => {
        extractCalls += 1;
        throw new Error("unexpected extract");
      }
    });
  } catch (e) {
    err = e;
  }

  assert.ok(err, "expected an error");
  const report = describeFatalError(err);
  assert.equal(report.code, "DOCDEX_UNSUPPORTED_PLATFORM");
  assert.ok(report.lines.some((l) => l.includes("unsupported platform (freebsd/x64)")));
  assert.ok(report.lines.some((l) => l.includes("No download was attempted")));

  assert.equal(planCalls, 0);
  assert.equal(downloadCalls, 0);
  assert.equal(extractCalls, 0);
  assert.equal(tripleCalls, 0);
  assert.equal(versionCalls, 0);
  assert.equal(repoSlugCalls, 0);
});

test("installer: unpublished linux arm64 musl fails before any plan resolution or download", async () => {
  let planCalls = 0;
  let downloadCalls = 0;
  let extractCalls = 0;
  let versionCalls = 0;
  let repoSlugCalls = 0;
  let tripleCalls = 0;

  let err;
  try {
    await runInstaller({
      logger: createNoopLogger(),
      platform: "linux",
      arch: "arm64",
      env: { DOCDEX_LIBC: "musl" },
      report: null,
      resolvePlatformPolicyFn: (args) => resolvePlatformPolicy(args),
      targetTripleForPlatformKeyFn: () => {
        tripleCalls += 1;
        throw new Error("unexpected target triple resolution");
      },
      getVersionFn: () => {
        versionCalls += 1;
        throw new Error("unexpected version resolution");
      },
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
      extractTarballFn: async () => {
        extractCalls += 1;
        throw new Error("unexpected extract");
      }
    });
  } catch (e) {
    err = e;
  }

  assert.ok(err, "expected an error");
  const report = describeFatalError(err);
  assert.equal(report.code, "DOCDEX_UNSUPPORTED_PLATFORM");
  assert.ok(report.lines.some((l) => l.includes("unsupported platform (linux/arm64)")));
  assert.ok(report.lines.some((l) => l.includes("Detected libc: musl")));
  assert.ok(report.lines.some((l) => l.includes("no published binary")));
  assert.ok(report.lines.some((l) => l.includes("No download was attempted")));

  assert.equal(planCalls, 0);
  assert.equal(downloadCalls, 0);
  assert.equal(extractCalls, 0);
  assert.equal(tripleCalls, 0);
  assert.equal(versionCalls, 0);
  assert.equal(repoSlugCalls, 0);
});

test("installer: unpublished win32 arm64 fails before any plan resolution or download", async () => {
  let planCalls = 0;
  let downloadCalls = 0;
  let extractCalls = 0;
  let versionCalls = 0;
  let repoSlugCalls = 0;
  let tripleCalls = 0;

  let err;
  try {
    await runInstaller({
      logger: createNoopLogger(),
      platform: "win32",
      arch: "arm64",
      resolvePlatformPolicyFn: (args) => resolvePlatformPolicy(args),
      targetTripleForPlatformKeyFn: () => {
        tripleCalls += 1;
        throw new Error("unexpected target triple resolution");
      },
      getVersionFn: () => {
        versionCalls += 1;
        throw new Error("unexpected version resolution");
      },
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
      extractTarballFn: async () => {
        extractCalls += 1;
        throw new Error("unexpected extract");
      }
    });
  } catch (e) {
    err = e;
  }

  assert.ok(err, "expected an error");
  const report = describeFatalError(err);
  assert.equal(report.code, "DOCDEX_UNSUPPORTED_PLATFORM");
  assert.ok(report.lines.some((l) => l.includes("unsupported platform (win32/arm64)")));
  assert.ok(report.lines.some((l) => l.includes("no published binary")));
  assert.ok(report.lines.some((l) => l.includes("No download was attempted")));

  assert.equal(planCalls, 0);
  assert.equal(downloadCalls, 0);
  assert.equal(extractCalls, 0);
  assert.equal(tripleCalls, 0);
  assert.equal(versionCalls, 0);
  assert.equal(repoSlugCalls, 0);
});

test("installer: supported runtime with missing manifest target triple never downloads/extracts the docdexd asset", async () => {
  let downloadTextCalls = 0;
  let assetDownloadCalls = 0;
  let extractCalls = 0;

  const base = "https://example.test/releases/download";
  const version = "0.0.0";
  const manifestName = "docdexd-manifest.json";
  const manifestText = JSON.stringify(
    {
      manifestVersion: 1,
      targets: {
        // Intentionally does NOT include x86_64-unknown-linux-gnu
        "aarch64-unknown-linux-gnu": {
          asset: { name: "docdexd-linux-arm64-gnu.tar.gz" },
          integrity: { sha256: "a".repeat(64) }
        }
      }
    },
    null,
    2
  );

  const downloadTextFn = async (url) => {
    downloadTextCalls += 1;
    if (url === `${base}/v${version}/${manifestName}`) return manifestText;
    throw httpError(404, `not found: ${url}`);
  };

  let err;
  try {
    await runInstaller({
      logger: createNoopLogger(),
      detectPlatformKeyFn: () => "linux-x64-gnu",
      getVersionFn: () => version,
      parseRepoSlugFn: () => "owner/repo",
      getDownloadBaseFn: () => base,
      resolveInstallerDownloadPlanFn: (args) =>
        resolveInstallerDownloadPlan({
          ...args,
          downloadTextFn,
          getDownloadBaseFn: () => base,
          manifestCandidateNamesFn: () => [manifestName]
        }),
      downloadFn: async () => {
        assetDownloadCalls += 1;
        throw new Error("unexpected asset download");
      },
      extractTarballFn: async () => {
        extractCalls += 1;
        throw new Error("unexpected extract");
      }
    });
  } catch (e) {
    err = e;
  }

  assert.ok(err, "expected an error");
  const report = describeFatalError(err);
  assert.equal(report.code, "DOCDEX_ASSET_NO_MATCH");
  assert.ok(report.lines.some((l) => l.includes("missing artifact/version sync issue")));
  assert.ok(report.lines.some((l) => l.includes("Expected target triple: x86_64-unknown-linux-gnu")));
  assert.ok(report.lines.some((l) => l.includes("Asset naming pattern: docdexd-<platformKey>.tar.gz")));

  assert.ok(downloadTextCalls >= 1, "expected metadata fetches (manifest/signature) but no asset download");
  assert.equal(assetDownloadCalls, 0);
  assert.equal(extractCalls, 0);
});

test("installer: supported runtime with missing release asset (404) exits non-zero and does not install", async () => {
  let downloadCalls = 0;
<<<<<<< HEAD
  let tmpCleanupRmCalls = 0;
  let stagingCleanupRmCalls = 0;
  let installRmCalls = 0;
  let stagingRmCalls = 0;
=======
>>>>>>> mcoda/task/ops-01-us-05-t07
  let extractCalls = 0;

  const base = "https://example.test/releases/download";
  const version = "0.0.0";
  const platformKey = "linux-x64-gnu";
<<<<<<< HEAD
  const distBaseDir = "/tmp/docdex-installer-dist";
  const distDir = `${distBaseDir}/${platformKey}`;
=======
  const distBaseDir = "/tmp/docdex-installer-test-dist";
  const distDir = path.join(distBaseDir, platformKey);
>>>>>>> mcoda/task/ops-01-us-05-t07

  const rmCalls = [];
  const fsModule = {
    promises: {
<<<<<<< HEAD
<<<<<<< HEAD
      rm: async (_path, options) => {
        if (options && options.recursive) {
<<<<<<< HEAD
          const p = String(_path);
          if (p.endsWith(`/${platformKey}`) || p.endsWith(`\\${platformKey}`)) installRmCalls += 1;
          else stagingRmCalls += 1;
          return;
        }
=======
      rm: async (targetPath, options) => {
        const value = String(targetPath || "");
        if (value.includes(".staging.")) {
          stagingCleanupRmCalls += 1;
          return;
        }
        if (options && options.recursive) installRmCalls += 1;
>>>>>>> mcoda/task/ops-01-us-05-t22
        else tmpCleanupRmCalls += 1;
=======
          if (_path === distDir) installRmCalls += 1;
          else stagingRmCalls += 1;
          return;
        }
        tmpCleanupRmCalls += 1;
>>>>>>> mcoda/task/ops-01-us-05-t39
      }
=======
      mkdir: async () => {},
      rm: async (rmPath, options) => rmCalls.push({ rmPath, options })
>>>>>>> mcoda/task/ops-01-us-05-t07
    },
    existsSync: () => true
  };

  let err;
  try {
    await runInstaller({
      logger: createNoopLogger(),
      platform: "linux",
      arch: "x64",
      tmpDir: "/tmp/docdex-installer-test",
      distBaseDir,
      detectPlatformKeyFn: () => platformKey,
      getVersionFn: () => version,
      parseRepoSlugFn: () => "owner/repo",
      getDownloadBaseFn: () => base,
      resolveInstallerDownloadPlanFn: async () => ({
        archive: "docdexd-linux-x64-gnu.tar.gz",
        expectedSha256: null,
        source: "fallback",
        manifestAttempt: { errors: [], resolved: null, manifestName: null }
      }),
      downloadFn: async () => {
        downloadCalls += 1;
        throw httpError(404, "not found");
      },
      verifyDownloadedFileIntegrityFn: async () => {
        throw new Error("unexpected integrity check");
      },
      extractTarballFn: async () => {
        extractCalls += 1;
        throw new Error("unexpected extract");
      },
      fsModule
    });
  } catch (e) {
    err = e;
  }

  assert.ok(err, "expected an error");
  assert.equal(err.name, "MissingArtifactError");
  assert.equal(err.code, "DOCDEX_ASSET_MISSING");
  assert.equal(err.details.targetTriple, "x86_64-unknown-linux-gnu");
  assert.ok(String(err.details.expectedAssetPattern || "").includes("docdexd-<platformKey>.tar.gz"));
  const report = describeFatalError(err);
  assert.equal(report.code, "DOCDEX_ASSET_MISSING");
  assert.equal(report.exitCode, 21);
  assert.ok(report.lines.some((l) => l.includes("missing artifact/version sync issue")));
  assert.ok(report.lines.some((l) => l.includes("Detected platform: linux/x64")));
  assert.ok(report.lines.some((l) => l.includes("Expected target triple: x86_64-unknown-linux-gnu")));
  assert.ok(report.lines.some((l) => l.includes("Asset naming pattern: docdexd-<platformKey>.tar.gz")));
  assert.ok(!report.lines.some((l) => l.includes("unsupported platform")));

  assert.equal(downloadCalls, 1);
  assert.equal(extractCalls, 0);
<<<<<<< HEAD
  assert.equal(installRmCalls, 0, "should not remove existing install on 404");
<<<<<<< HEAD
<<<<<<< HEAD
  assert.equal(stagingRmCalls, 1, "should still attempt staging cleanup");
=======
  assert.equal(stagingRmCalls, 1, "should still attempt staged cleanup");
>>>>>>> mcoda/task/ops-01-us-05-t39
  assert.equal(tmpCleanupRmCalls, 1, "should still attempt tmp cleanup");
=======
  assert.equal(tmpCleanupRmCalls, 2, "should still attempt tmp cleanup");
  assert.equal(stagingCleanupRmCalls, 1, "should still attempt staging cleanup");
>>>>>>> mcoda/task/ops-01-us-05-t22
=======
  assert.equal(
    rmCalls.filter((c) => c.options && c.options.recursive).length,
    1,
    "should still attempt to clean up the per-run staging directory"
  );
  assert.ok(!rmCalls.some((c) => c.rmPath === distDir), "should not remove existing install on 404");
>>>>>>> mcoda/task/ops-01-us-05-t07
});
