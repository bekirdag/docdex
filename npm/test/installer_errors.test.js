"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const { detectPlatformKey } = require("../lib/platform");
const { MissingArtifactError, describeFatalError } = require("../lib/install");

test("describeFatalError: unsupported platform includes detected OS/arch and no-download note", () => {
  let err;
  try {
    detectPlatformKey({ platform: "freebsd", arch: "x64" });
  } catch (e) {
    err = e;
  }

  assert.ok(err, "expected an error");
  const report = describeFatalError(err);
  assert.equal(report.code, "DOCDEX_UNSUPPORTED_PLATFORM");
  assert.equal(report.exitCode, 3);
  assert.equal(report.details.targetTriple, null);
  assert.equal(report.details.manifestVersion, null);
  assert.equal(report.details.assetName, null);
  assert.ok(report.lines.some((l) => l.includes("unsupported platform (freebsd/x64)")));
  assert.ok(report.lines.some((l) => l.includes("No download was attempted")));
});

test("describeFatalError: missing artifact distinguishes from unsupported and includes target triple + pattern", () => {
  const err = new MissingArtifactError({
    detected: { os: "linux", arch: "arm64" },
    platformKey: "linux-arm64-musl",
    targetTriple: "aarch64-unknown-linux-musl",
    version: "0.1.11",
    repoSlug: "owner/repo",
    downloadUrl: "https://example.test/releases/download/v0.1.11/docdexd-linux-arm64-musl.tar.gz",
    assetName: "docdexd-linux-arm64-musl.tar.gz",
    expectedAsset: "docdexd-linux-arm64-musl.tar.gz",
    expectedAssetPattern: "docdexd-<platform>.tar.gz"
  });

  const report = describeFatalError(err);
  assert.equal(report.code, "DOCDEX_ASSET_MISSING");
  assert.equal(report.exitCode, 21);
  assert.equal(report.details.targetTriple, "aarch64-unknown-linux-musl");
  assert.equal(report.details.manifestVersion, null);
  assert.equal(report.details.assetName, "docdexd-linux-arm64-musl.tar.gz");
  assert.ok(report.lines.some((l) => l.includes("missing release artifact")));
  assert.ok(report.lines.some((l) => l.includes("Expected target triple: aarch64-unknown-linux-musl")));
  assert.ok(report.lines.some((l) => l.includes("Asset naming pattern: docdexd-<platform>.tar.gz")));
});
