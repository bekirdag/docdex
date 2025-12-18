"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");

const { resolveInstallerDownloadPlan } = require("../lib/install");

function httpError(statusCode, message) {
  const err = new Error(message || `HTTP ${statusCode}`);
  err.statusCode = statusCode;
  return err;
}

test("integrity metadata sources can disable manifest fetching (checksums only)", async () => {
  const base = "https://example.test/releases/download";
  const version = "0.0.0";
  const sha = "f".repeat(64);

  const downloadTextFn = async (url) => {
    if (url.endsWith(".json")) {
      throw new Error(`manifest fetch should not happen: ${url}`);
    }
    if (url === `${base}/v${version}/SHA256SUMS`) {
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
    manifestCandidateNamesFn: () => ["docdex-release-manifest.json"],
    checksumCandidateNamesFn: () => ["SHA256SUMS"],
    integrityConfigFn: () => ({ metadataSources: ["checksums"], missingPolicy: "fallback" })
  });

  assert.equal(plan.archive, "docdexd-linux-x64-gnu.tar.gz");
  assert.equal(plan.expectedSha256, sha);
  assert.equal(plan.source, "fallback");
  assert.equal(plan.integrity?.metadataSource, "checksums");
  assert.equal(plan.integrity?.metadataName, "SHA256SUMS");
});

test("missing metadata policy abort prevents fallback to other sources", async () => {
  const base = "https://example.test/releases/download";
  const version = "0.0.0";

  const downloadTextFn = async (url) => {
    if (url.endsWith("docdex-release-manifest.json")) throw httpError(404, `not found: ${url}`);
    if (url.endsWith("SHA256SUMS")) throw new Error("checksums fetch should not happen when policy=abort");
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
        manifestCandidateNamesFn: () => ["docdex-release-manifest.json"],
        checksumCandidateNamesFn: () => ["SHA256SUMS"],
        integrityConfigFn: () => ({ metadataSources: ["manifest", "checksums"], missingPolicy: "abort" })
      }),
    (err) => {
      assert.equal(err.code, "DOCDEX_CHECKSUM_UNUSABLE");
      assert.equal(err.details?.integrityMissingPolicy, "abort");
      assert.deepEqual(err.details?.integrityAttemptedSources, ["manifest"]);
      return true;
    }
  );
});

test("integrity metadata sources can disable sidecar fallback (checksums only)", async () => {
  const base = "https://example.test/releases/download";
  const version = "0.0.0";

  const downloadTextFn = async (url) => {
    if (url.endsWith(".sha256")) throw new Error(`sidecar fetch should not happen: ${url}`);
    if (url === `${base}/v${version}/SHA256SUMS`) {
      return `${"0".repeat(64)}  some-other-file.tar.gz\n`;
    }
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
        manifestCandidateNamesFn: () => ["docdex-release-manifest.json"],
        checksumCandidateNamesFn: () => ["SHA256SUMS"],
        integrityConfigFn: () => ({ metadataSources: ["checksums"], missingPolicy: "fallback" })
      }),
    (err) => {
      assert.equal(err.code, "DOCDEX_CHECKSUM_UNUSABLE");
      assert.deepEqual(err.details?.integrityAttemptedSources, ["checksums"]);
      return true;
    }
  );
});

