"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const { detectPlatformKey } = require("../lib/platform");
const {
  ChecksumResolutionError,
  MissingArtifactError,
  describeFatalError,
  getVersion,
  parseRepoSlug,
  verifyDownloadedFileIntegrity
} = require("../lib/install");
const { ManifestResolutionError } = require("../lib/release_manifest");

test("release verifier configuration helpers remain exported and usable", () => {
  const previousRepo = process.env.DOCDEX_DOWNLOAD_REPO;
  const previousVersion = process.env.DOCDEX_VERSION;
  process.env.DOCDEX_DOWNLOAD_REPO = "owner/repo";
  process.env.DOCDEX_VERSION = "v1.2.3";
  try {
    assert.equal(parseRepoSlug(), "owner/repo");
    assert.equal(getVersion(), "1.2.3");
  } finally {
    if (previousRepo === undefined) delete process.env.DOCDEX_DOWNLOAD_REPO;
    else process.env.DOCDEX_DOWNLOAD_REPO = previousRepo;
    if (previousVersion === undefined) delete process.env.DOCDEX_VERSION;
    else process.env.DOCDEX_VERSION = previousVersion;
  }
});

test("postinstall banner describes provider-neutral local LLM setup", () => {
  const source = fs.readFileSync(path.join(__dirname, "..", "lib", "install.js"), "utf8");
  assert.equal(source.includes("Setup configures Ollama/models"), false);
  assert.equal(source.includes("Setup detects local LLM services"), true);
  assert.equal(source.includes("offers the Ollama fallback"), true);
});

test("release version metadata stays in sync across package and MCP files", () => {
  const repoRoot = path.join(__dirname, "..", "..");
  const rootPackage = JSON.parse(fs.readFileSync(path.join(repoRoot, "package.json"), "utf8"));
  const npmPackage = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "package.json"), "utf8"));
  const npmLock = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "package-lock.json"), "utf8"));
  const releaseManifest = JSON.parse(
    fs.readFileSync(path.join(repoRoot, ".release-please-manifest.json"), "utf8")
  );
  const serverManifest = JSON.parse(fs.readFileSync(path.join(repoRoot, "server.json"), "utf8"));
  const serverCard = JSON.parse(
    fs.readFileSync(path.join(repoRoot, ".well-known", "mcp", "server-card.json"), "utf8")
  );
  const legacyServerCard = JSON.parse(
    fs.readFileSync(path.join(repoRoot, ".well-known", "mcp.json"), "utf8")
  );
  const promptVersion = (filePath) => {
    const firstLine = fs.readFileSync(filePath, "utf8").split(/\r?\n/, 1)[0];
    return /^---- START OF DOCDEX INFO V([^ ]+) ----$/.exec(firstLine)?.[1] ?? null;
  };

  assert.equal(npmPackage.version, rootPackage.version);
  assert.equal(npmLock.version, rootPackage.version);
  assert.equal(npmLock.packages[""].version, rootPackage.version);
  assert.equal(releaseManifest["."], rootPackage.version);
  assert.equal(releaseManifest.npm, rootPackage.version);
  assert.equal(serverManifest.version, rootPackage.version);
  assert.equal(serverManifest.packages[0].version, rootPackage.version);
  assert.equal(serverCard.version, rootPackage.version);
  assert.equal(serverCard.serverInfo.version, rootPackage.version);
  assert.equal(legacyServerCard.version, rootPackage.version);
  assert.equal(legacyServerCard.serverInfo.version, rootPackage.version);
  assert.equal(promptVersion(path.join(repoRoot, "AGENTS.md")), rootPackage.version);
  assert.equal(promptVersion(path.join(repoRoot, "AGENT_PROMPT.md")), rootPackage.version);
  assert.equal(promptVersion(path.join(__dirname, "..", "assets", "agents.md")), rootPackage.version);
});

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
    platformKey: "linux-arm64-gnu",
    targetTriple: "aarch64-unknown-linux-gnu",
    version: "0.2.23",
    repoSlug: "owner/repo",
    downloadUrl: "https://example.test/releases/download/v0.2.27/docdexd-linux-arm64-gnu.tar.gz",
    assetName: "docdexd-linux-arm64-gnu.tar.gz",
    expectedAsset: "docdexd-linux-arm64-gnu.tar.gz",
    expectedAssetPattern: "docdexd-<platformKey>.tar.gz"
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
