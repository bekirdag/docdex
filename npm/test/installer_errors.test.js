"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const { detectPlatformKey } = require("../lib/platform");
const {
  ChecksumResolutionError,
  IntegritySignatureError,
  MissingArtifactError,
  describeFatalError,
  verifyDownloadedFileIntegrity,
  runInstaller
} = require("../lib/install");
const { ManifestResolutionError } = require("../lib/release_manifest");

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
    detected: { os: "linux", arch: "arm64", libc: "gnu" },
    platformKey: "linux-arm64-gnu",
    targetTriple: "aarch64-unknown-linux-gnu",
    version: "0.1.11",
<<<<<<< HEAD
=======
    expectedVersion: "0.1.11",
>>>>>>> mcoda/task/ops-01-us-03-t39
    detectedVersion: "0.1.10",
    repoSlug: "owner/repo",
    source: "fallback",
    downloadUrl: "https://example.test/releases/download/v0.1.11/docdexd-linux-arm64-gnu.tar.gz",
    assetName: "docdexd-linux-arm64-gnu.tar.gz",
    expectedAsset: "docdexd-linux-arm64-gnu.tar.gz",
    expectedAssetPattern: "docdexd-<platformKey>.tar.gz",
    source: "manifest:docdexd-manifest.json"
  });

  const report = describeFatalError(err);
  assert.equal(report.code, "DOCDEX_ASSET_MISSING");
  assert.equal(report.exitCode, 21);
  assert.equal(report.details.targetTriple, "aarch64-unknown-linux-gnu");
  assert.equal(report.details.manifestVersion, null);
  assert.equal(report.details.assetName, "docdexd-linux-arm64-gnu.tar.gz");
  assert.ok(report.lines.some((l) => l.includes("missing artifact/version sync issue")));
  assert.ok(report.lines.some((l) => l.includes("Expected target triple: aarch64-unknown-linux-gnu")));
  assert.ok(report.lines.some((l) => l.includes("Asset naming pattern: docdexd-<platformKey>.tar.gz")));
<<<<<<< HEAD
<<<<<<< HEAD
  assert.ok(report.lines.some((l) => l.includes("Detected platform: linux/arm64/gnu")));
=======
  assert.ok(report.lines.some((l) => l.includes("Detected version: v0.1.10")));
  assert.ok(report.lines.some((l) => l.includes("Release source: fallback")));
>>>>>>> mcoda/task/ops-01-us-03-t37
=======
  assert.ok(report.lines.some((l) => l.includes("Expected version: v0.1.11")));
  assert.ok(report.lines.some((l) => l.includes("Detected version: v0.1.10")));
  assert.ok(report.lines.some((l) => l.includes("Release source: manifest:docdexd-manifest.json")));
>>>>>>> mcoda/task/ops-01-us-03-t39
});

test("describeFatalError: manifest no-match reads as missing artifact/version sync issue and includes triple + pattern", () => {
  const err = new ManifestResolutionError(
    "DOCDEX_ASSET_NO_MATCH",
    "Manifest docdexd-manifest.json: No asset found in manifest for target triple x86_64-unknown-linux-gnu.",
    {
      targetTriple: "x86_64-unknown-linux-gnu",
      platformKey: "linux-x64-gnu"
    }
  );

  const report = describeFatalError(err);
  assert.equal(report.code, "DOCDEX_ASSET_NO_MATCH");
  assert.ok(report.lines.some((l) => l.includes("missing artifact/version sync issue")));
  assert.ok(report.lines.some((l) => l.includes("Platform key: linux-x64-gnu")));
  assert.ok(report.lines.some((l) => l.includes("Expected target triple: x86_64-unknown-linux-gnu")));
  assert.ok(report.lines.some((l) => l.includes("Asset naming pattern: docdexd-<platformKey>.tar.gz")));
});

test("describeFatalError: manifest errors report whether fallback was attempted and include supported/matches", () => {
  const err = new ManifestResolutionError("DOCDEX_ASSET_MULTI_MATCH", "Manifest docdexd-manifest.json: boom", {
    fallbackAttempted: false,
    supported: ["x86_64-unknown-linux-gnu"],
    matches: ["a.tar.gz", "b.tar.gz"]
  });

  const report = describeFatalError(err);
  assert.equal(report.code, "DOCDEX_ASSET_MULTI_MATCH");
  assert.ok(report.lines.some((l) => l.includes("Fallback was not attempted")));
  assert.ok(report.lines.some((l) => l.includes("supported targets: x86_64-unknown-linux-gnu")));
  assert.ok(report.lines.some((l) => l.includes("matched assets: a.tar.gz, b.tar.gz")));
});

test("describeFatalError: integrity mismatch includes expected/actual sha256 and next steps", async () => {
  const archiveName = "docdexd-linux-x64-gnu.tar.gz";
  const filePath = path.join(__dirname, "fixtures", "archive", "fake-archive.bin");

  let err;
  try {
    await verifyDownloadedFileIntegrity({
      filePath,
      expectedSha256: "a".repeat(64),
      archiveName,
      details: {
        platformKey: "linux-x64-gnu",
        targetTriple: "x86_64-unknown-linux-gnu",
        version: "0.0.0",
        repoSlug: "owner/repo",
        downloadUrl: `https://example.test/releases/download/v0.0.0/${archiveName}`,
        source: "manifest:docdexd-manifest.json",
        manifestName: "docdexd-manifest.json",
        manifestVersion: 1,
        fallbackAttempted: false
      }
    });
  } catch (e) {
    err = e;
  }

  assert.ok(err, "expected an integrity mismatch error");

  const report = describeFatalError(err);
  assert.equal(report.code, "DOCDEX_INTEGRITY_MISMATCH");
  assert.equal(report.exitCode, 22);
  assert.equal(report.details.assetName, archiveName);
  assert.ok(report.lines.some((l) => l.includes("Expected sha256:")));
  assert.ok(report.lines.some((l) => l.includes("Actual sha256:")));
  assert.ok(report.lines.some((l) => l.includes("Next steps")));
  assert.ok(report.lines.some((l) => l.includes("DOCDEX_DOWNLOAD_REPO")));
});

test("describeFatalError: checksum unusable includes candidates and next steps", () => {
  const err = new ChecksumResolutionError("Missing SHA-256 integrity metadata for docdexd-linux-x64-gnu.tar.gz", {
    assetName: "docdexd-linux-x64-gnu.tar.gz",
    targetTriple: "x86_64-unknown-linux-gnu",
    checksumCandidates: ["SHA256SUMS", "SHA256SUMS.txt"],
    fallbackReason: "manifest_not_found"
  });

  const report = describeFatalError(err);
  assert.equal(report.code, "DOCDEX_CHECKSUM_UNUSABLE");
  assert.equal(report.exitCode, 24);
  assert.equal(report.details.assetName, "docdexd-linux-x64-gnu.tar.gz");
  assert.ok(report.lines.some((l) => l.includes("Checksum candidates tried: SHA256SUMS, SHA256SUMS.txt")));
  assert.ok(report.lines.some((l) => l.includes("Next steps")));
});

<<<<<<< HEAD
test("describeFatalError: integrity signature errors include method and remediation", () => {
  const err = new IntegritySignatureError(
    "DOCDEX_INTEGRITY_SIGNATURE_INVALID",
    "Signature verification failed for SHA256SUMS (SHA256SUMS.sig)",
    {
      signedName: "SHA256SUMS",
      signatureName: "SHA256SUMS.sig",
      signatureUrl: "https://example.test/releases/download/v0.0.0/SHA256SUMS.sig",
      signatureAlgorithm: "ed25519",
      signaturePolicy: "optional"
    }
  );

  const report = describeFatalError(err);
  assert.equal(report.code, "DOCDEX_INTEGRITY_SIGNATURE_INVALID");
  assert.equal(report.exitCode, 16);
  assert.ok(report.lines.some((l) => l.includes("detached signature (ed25519)")));
  assert.ok(report.lines.some((l) => l.includes("DOCDEX_SIGNATURE_POLICY=disabled")));
=======
test("runInstaller: required integrity policy fails closed when download plan has no sha256", async () => {
  const tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "docdex-installer-integrity-required-"));
  try {
    let downloadCalls = 0;
    await assert.rejects(
      () =>
        runInstaller({
          logger: { log: () => {}, warn: () => {}, error: () => {} },
          platform: "linux",
          arch: "x64",
          distBaseDir: path.join(tmpRoot, "dist"),
          tmpDir: path.join(tmpRoot, "tmp"),
          detectPlatformKeyFn: () => "linux-x64-gnu",
          targetTripleForPlatformKeyFn: () => "x86_64-unknown-linux-gnu",
          getVersionFn: () => "0.0.0",
          parseRepoSlugFn: () => "owner/repo",
          getDownloadBaseFn: () => "https://example.test/releases/download",
          resolveInstallerDownloadPlanFn: async () => ({
            archive: "docdexd-linux-x64-gnu.tar.gz",
            expectedSha256: null,
            source: "fallback",
            manifestAttempt: { errors: [], resolved: null, manifestName: null }
          }),
          downloadFn: async () => {
            downloadCalls += 1;
          }
        }),
      (err) => {
        assert.equal(err.code, "DOCDEX_CHECKSUM_UNUSABLE");
        assert.ok(String(err.message).includes("Missing SHA-256 integrity metadata"));
        return true;
      }
    );
    assert.equal(downloadCalls, 0);
  } finally {
    await fs.promises.rm(tmpRoot, { recursive: true, force: true });
  }
>>>>>>> mcoda/task/ops-01-us-04-t17
});
