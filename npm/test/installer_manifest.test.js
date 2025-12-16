"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const { ManifestResolutionError } = require("../lib/release_manifest");
const {
  resolveInstallerDownloadPlan,
  sha256File,
  verifyDownloadedFileIntegrity
} = require("../lib/install");

function fixture(relPath) {
  return fs.readFileSync(path.join(__dirname, "fixtures", relPath), "utf8");
}

function httpError(statusCode, message) {
  const err = new Error(message || `HTTP ${statusCode}`);
  err.statusCode = statusCode;
  return err;
}

function createCapturingLogger() {
  const logs = [];
  const warns = [];
  return {
    logger: {
      log: (...args) => logs.push(args.join(" ")),
      warn: (...args) => warns.push(args.join(" "))
    },
    logs,
    warns
  };
}

test("installer resolves asset + sha256 via first available manifest candidate deterministically", async () => {
  const base = "https://example.test/releases/download";
  const version = "0.0.0";

  const manifestText = fixture("manifest/valid-targets.json");
  const downloadTextFn = async (url) => {
    if (url === `${base}/v${version}/docdexd-manifest.json`) return manifestText;
    throw httpError(404, `not found: ${url}`);
  };

  const plan = await resolveInstallerDownloadPlan({
    repoSlug: "owner/repo",
    version,
    platformKey: "linux-x64-gnu",
    targetTriple: "x86_64-unknown-linux-gnu",
    downloadTextFn,
    getDownloadBaseFn: () => base,
    manifestCandidateNamesFn: () => ["docdexd-manifest.json", "manifest.json"],
    logger: createCapturingLogger().logger
  });

  assert.equal(plan.archive, "docdexd-linux-x64-gnu.tar.gz");
  assert.equal(plan.expectedSha256, "a".repeat(64));
  assert.equal(plan.source, "manifest:docdexd-manifest.json");
});

test("installer resolves from manifest.assets array shape deterministically", async () => {
  const base = "https://example.test/releases/download";
  const version = "0.0.0";

  const manifestText = fixture("manifest/valid-assets.json");
  const downloadTextFn = async (url) => {
    if (url === `${base}/v${version}/docdex-manifest.json`) return manifestText;
    throw httpError(404, `not found: ${url}`);
  };

  const plan = await resolveInstallerDownloadPlan({
    repoSlug: "owner/repo",
    version,
    platformKey: "darwin-arm64",
    targetTriple: "aarch64-apple-darwin",
    downloadTextFn,
    getDownloadBaseFn: () => base,
    manifestCandidateNamesFn: () => ["docdex-manifest.json"],
    logger: createCapturingLogger().logger
  });

  assert.equal(plan.archive, "docdexd-darwin-arm64.tar.gz");
  assert.equal(plan.expectedSha256, "b".repeat(64));
  assert.equal(plan.source, "manifest:docdex-manifest.json");
});

test("installer falls back deterministically when no manifest candidates exist", async () => {
  const base = "https://example.test/releases/download";
  const version = "0.0.0";
  const sha = "c".repeat(64);

  const { logger, logs, warns } = createCapturingLogger();

  const downloadTextFn = async (url) => {
    if (url.endsWith(".json")) throw httpError(404, `not found: ${url}`);
    if (url === `${base}/v${version}/docdexd-linux-x64-gnu.tar.gz.sha256`) {
      return `${sha}  docdexd-linux-x64-gnu.tar.gz\n`;
    }
    throw httpError(404, `not found: ${url}`);
  };

  const plan = await resolveInstallerDownloadPlan({
    repoSlug: "owner/repo",
    version,
    platformKey: "linux-x64-gnu",
    targetTriple: "x86_64-unknown-linux-gnu",
    downloadTextFn,
    getDownloadBaseFn: () => base,
    manifestCandidateNamesFn: () => ["docdexd-manifest.json"],
    logger
  });

  assert.equal(plan.archive, "docdexd-linux-x64-gnu.tar.gz");
  assert.equal(plan.expectedSha256, sha);
  assert.equal(plan.source, "fallback");
  assert.deepEqual(logs, ["[docdex] No manifest found; falling back to deterministic asset naming."]);
  assert.deepEqual(warns, []);
});

test("installer falls back deterministically on invalid JSON manifests with stable warning output", async () => {
  const base = "https://example.test/releases/download";
  const version = "0.0.0";
  const sha = "d".repeat(64);

  const { logger, logs, warns } = createCapturingLogger();

  const downloadTextFn = async (url) => {
    if (url === `${base}/v${version}/docdexd-manifest.json`) return fixture("manifest/invalid-json.txt");
    if (url.endsWith(".json")) throw httpError(404, `not found: ${url}`);
    if (url === `${base}/v${version}/docdexd-linux-x64-gnu.tar.gz.sha256`) {
      return `${sha}  docdexd-linux-x64-gnu.tar.gz\n`;
    }
    throw httpError(404, `not found: ${url}`);
  };

  const plan = await resolveInstallerDownloadPlan({
    repoSlug: "owner/repo",
    version,
    platformKey: "linux-x64-gnu",
    targetTriple: "x86_64-unknown-linux-gnu",
    downloadTextFn,
    getDownloadBaseFn: () => base,
    manifestCandidateNamesFn: () => ["docdexd-manifest.json", "docdex-manifest.json"],
    logger
  });

  assert.equal(plan.archive, "docdexd-linux-x64-gnu.tar.gz");
  assert.equal(plan.expectedSha256, sha);
  assert.equal(plan.source, "fallback");
  assert.deepEqual(logs, []);
  assert.deepEqual(warns, [
    "[docdex] Manifest unavailable; falling back. Details: Malformed manifest (docdexd-manifest.json): invalid JSON"
  ]);
});

test("installer fails deterministically when a manifest exists but is malformed (no fallback)", async () => {
  const base = "https://example.test/releases/download";
  const version = "0.0.0";

  const downloadTextFn = async (url) => {
    if (url === `${base}/v${version}/docdexd-manifest.json`) return fixture("manifest/invalid-shape.json");
    throw httpError(404, `not found: ${url}`);
  };

  await assert.rejects(
    () =>
      resolveInstallerDownloadPlan({
        repoSlug: "owner/repo",
        version,
        platformKey: "linux-x64-gnu",
        targetTriple: "x86_64-unknown-linux-gnu",
        downloadTextFn,
        getDownloadBaseFn: () => base,
        manifestCandidateNamesFn: () => ["docdexd-manifest.json"],
        logger: createCapturingLogger().logger
      }),
    (err) => {
      assert.ok(err instanceof ManifestResolutionError);
      assert.equal(err.code, "DOCDEX_MANIFEST_MALFORMED");
      assert.match(err.message, /^Manifest docdexd-manifest\.json: Malformed manifest:/);
      return true;
    }
  );
});

test("installer integrity failures include stable expected + actual sha256", async () => {
  const filePath = path.join(__dirname, "fixtures", "archive", "fake-archive.bin");
  const actual = await sha256File(filePath);
  const expected = "a".repeat(64);
  const archiveName = "docdexd-linux-x64-gnu.tar.gz";

  await assert.rejects(
    () => verifyDownloadedFileIntegrity({ filePath, expectedSha256: expected, archiveName }),
    (err) => {
      assert.equal(
        err.message,
        `Integrity check failed for ${archiveName}: expected sha256=${expected} got sha256=${actual}`
      );
      return true;
    }
  );
});
