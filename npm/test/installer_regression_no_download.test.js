"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const { detectPlatformKey } = require("../lib/platform");
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

  let err;
  try {
    await runInstaller({
      logger: createNoopLogger(),
      detectPlatformKeyFn: () => detectPlatformKey({ platform: "freebsd", arch: "x64" }),
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
