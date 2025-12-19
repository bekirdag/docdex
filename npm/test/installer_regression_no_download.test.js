"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
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

async function writeInstallMetadata({ distDir, platformKey, version, targetTriple, repoSlug = "owner/repo" }) {
  await fs.promises.mkdir(distDir, { recursive: true });
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
      sha256: "a".repeat(64)
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

  assert.equal(downloadTextCalls, 1, "expected a metadata fetch (manifest) but no asset download");
  assert.equal(assetDownloadCalls, 0);
  assert.equal(extractCalls, 0);
});

test("installer: supported runtime with missing release asset (404) exits non-zero and does not install", async () => {
  let downloadCalls = 0;
  let tmpCleanupRmCalls = 0;
  let installRmCalls = 0;
  let extractCalls = 0;

  const base = "https://example.test/releases/download";
  const version = "0.0.0";
  const platformKey = "linux-x64-gnu";

  const fsModule = {
    promises: {
      rm: async (_path, options) => {
        if (options && options.recursive) installRmCalls += 1;
        else tmpCleanupRmCalls += 1;
      }
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
  assert.equal(installRmCalls, 0, "should not remove existing install on 404");
  assert.equal(tmpCleanupRmCalls, 1, "should still attempt tmp cleanup");
});

test("installer: missing release asset includes expected/detected versions and release source", async (t) => {
  const base = "https://example.test/releases/download";
  const expectedVersion = "0.2.0";
  const installedVersion = "0.1.0";
  const platformKey = "linux-x64-gnu";
  const targetTriple = "x86_64-unknown-linux-gnu";

  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-missing-asset-"));
  t.after(async () => {
    await fs.promises.rm(tmpRoot, { recursive: true, force: true });
  });

  const distBaseDir = path.join(tmpRoot, "dist");
  const distDir = path.join(distBaseDir, platformKey);
  await fs.promises.mkdir(distDir, { recursive: true });
  await fs.promises.writeFile(path.join(distDir, "docdexd"), "old-binary\n", "utf8");
  await writeInstallMetadata({ distDir, platformKey, version: installedVersion, targetTriple });

  const tmpDir = path.join(tmpRoot, "tmp");
  await fs.promises.mkdir(tmpDir, { recursive: true });

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
        archive: "docdexd-linux-x64-gnu.tar.gz",
        expectedSha256: null,
        source: "fallback",
        manifestAttempt: { errors: [], resolved: null, manifestName: null }
      }),
      downloadFn: async () => {
        throw httpError(404, "not found");
      },
      verifyDownloadedFileIntegrityFn: async () => {
        throw new Error("unexpected integrity check");
      },
      extractTarballFn: async () => {
        throw new Error("unexpected extract");
      }
    });
  } catch (e) {
    err = e;
  }

  assert.ok(err, "expected an error");
  assert.equal(err.name, "MissingArtifactError");
  assert.equal(err.details.version, expectedVersion);
  assert.equal(err.details.installedVersion, installedVersion);

  const report = describeFatalError(err);
  assert.ok(report.lines.some((l) => l.includes(`Expected version: v${expectedVersion}`)));
  assert.ok(report.lines.some((l) => l.includes(`Detected version: v${installedVersion}`)));
  assert.ok(report.lines.some((l) => l.includes("Release source: fallback")));
  assert.ok(report.lines.some((l) => l.includes("Download repo: owner/repo")));
  assert.ok(
    report.lines.some((l) =>
      l.includes(`URL tried: ${base}/v${expectedVersion}/docdexd-linux-x64-gnu.tar.gz`)
    )
  );
});
