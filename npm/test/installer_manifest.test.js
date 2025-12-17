"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const { ManifestResolutionError } = require("../lib/release_manifest");
const {
  ChecksumResolutionError,
  resolveInstallerDownloadPlan,
  parseSha256File,
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
    if (url === `${base}/v${version}/docdex-release-manifest.json`) return manifestText;
    throw httpError(404, `not found: ${url}`);
  };

  const plan = await resolveInstallerDownloadPlan({
    repoSlug: "owner/repo",
    version,
    platformKey: "linux-x64-gnu",
    targetTriple: "x86_64-unknown-linux-gnu",
    downloadTextFn,
    getDownloadBaseFn: () => base,
    manifestCandidateNamesFn: () => ["docdex-release-manifest.json", "docdexd-manifest.json"],
    logger: createCapturingLogger().logger
  });

  assert.equal(plan.archive, "docdexd-linux-x64-gnu.tar.gz");
  assert.equal(plan.expectedSha256, "a".repeat(64));
  assert.equal(plan.source, "manifest:docdex-release-manifest.json");
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
    manifestCandidateNamesFn: () => ["docdexd-manifest.json", "docdex-manifest.json"],
    logger
  });

  assert.equal(plan.archive, "docdexd-linux-x64-gnu.tar.gz");
  assert.equal(plan.expectedSha256, sha);
  assert.equal(plan.source, "fallback");
  assert.deepEqual(logs, []);
  assert.deepEqual(warns, [
    "[docdex] Manifest unavailable; falling back. Details: [DOCDEX_MANIFEST_JSON_INVALID] Malformed manifest (docdexd-manifest.json): invalid JSON"
  ]);
});

test("installer falls back deterministically when a manifest exists but is malformed", async () => {
  const base = "https://example.test/releases/download";
  const version = "0.0.0";
  const sha = "e".repeat(64);

  const { logger, logs, warns } = createCapturingLogger();

  const downloadTextFn = async (url) => {
    if (url === `${base}/v${version}/docdexd-manifest.json`) return fixture("manifest/invalid-shape.json");
    if (url === `${base}/v${version}/SHA256SUMS`) return `${sha}  docdexd-linux-x64-gnu.tar.gz\n`;
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
  assert.deepEqual(logs, []);
  assert.deepEqual(warns, [
    "[docdex] Manifest unavailable; falling back. Details: [DOCDEX_MANIFEST_UNUSABLE] Manifest unusable (docdexd-manifest.json): DOCDEX_MANIFEST_MALFORMED Malformed manifest: expected `targets` object or `assets` array"
  ]);
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

test("installer fails deterministically when manifest exists but does not support target triple (no fallback)", async () => {
  const base = "https://example.test/releases/download";
  const version = "0.0.0";

  const manifestText = JSON.stringify(
    {
      manifestVersion: 1,
      targets: {
        "x86_64-unknown-linux-gnu": {
          asset: { name: "docdexd-linux-x64-gnu.tar.gz" },
          integrity: { sha256: "a".repeat(64) }
        }
      }
    },
    null,
    2
  );

  const downloadTextFn = async (url) => {
    if (url === `${base}/v${version}/docdexd-manifest.json`) return manifestText;
    throw httpError(404, `not found: ${url}`);
  };

  await assert.rejects(
    () =>
      resolveInstallerDownloadPlan({
        repoSlug: "owner/repo",
        version,
        platformKey: "linux-x64-gnu",
        targetTriple: "aarch64-unknown-linux-gnu",
        downloadTextFn,
        getDownloadBaseFn: () => base,
        manifestCandidateNamesFn: () => ["docdexd-manifest.json"],
        logger: createCapturingLogger().logger
      }),
    (err) => {
      assert.ok(err instanceof ManifestResolutionError);
      assert.equal(err.code, "DOCDEX_ASSET_NO_MATCH");
      assert.equal(err.details.fallbackAttempted, false);
      assert.equal(err.details.fallbackReason, "manifest_present_but_unusable");
      assert.equal(err.details.manifestName, "docdexd-manifest.json");
      assert.equal(err.details.manifestUrl, `${base}/v${version}/docdexd-manifest.json`);
      return true;
    }
  );
});

test("installer falls back deterministically when manifest entry is missing sha256 integrity metadata", async () => {
  const base = "https://example.test/releases/download";
  const version = "0.0.0";
  const sha = "f".repeat(64);

  const { logger, warns } = createCapturingLogger();

  const manifestText = JSON.stringify(
    {
      manifestVersion: 1,
      targets: {
        "x86_64-unknown-linux-gnu": {
          asset: { name: "docdexd-linux-x64-gnu.tar.gz" }
        }
      }
    },
    null,
    2
  );

  const downloadTextFn = async (url) => {
    if (url === `${base}/v${version}/docdex-release-manifest.json`) return manifestText;
    if (url === `${base}/v${version}/SHA256SUMS`) return `${sha}  docdexd-linux-x64-gnu.tar.gz\n`;
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
    logger
  });

  assert.equal(plan.archive, "docdexd-linux-x64-gnu.tar.gz");
  assert.equal(plan.expectedSha256, sha);
  assert.equal(plan.source, "fallback");
  assert.equal(warns.length, 1);
  assert.match(warns[0], /\[DOCDEX_MANIFEST_UNUSABLE\]/);
  assert.match(warns[0], /DOCDEX_ASSET_MALFORMED/);
});

test("installer fails deterministically when manifest has multiple assets for a target triple (no fallback)", async () => {
  const base = "https://example.test/releases/download";
  const version = "0.0.0";

  const manifestText = JSON.stringify(
    {
      assets: [
        {
          target_triple: "x86_64-unknown-linux-gnu",
          name: "docdexd-linux-x64-gnu.tar.gz",
          sha256: "a".repeat(64)
        },
        {
          target_triple: "x86_64-unknown-linux-gnu",
          name: "docdexd-linux-x64-gnu-alt.tar.gz",
          sha256: "b".repeat(64)
        }
      ]
    },
    null,
    2
  );

  const downloadTextFn = async (url) => {
    if (url === `${base}/v${version}/docdexd-manifest.json`) return manifestText;
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
      assert.equal(err.code, "DOCDEX_ASSET_MULTI_MATCH");
      assert.equal(err.details.fallbackAttempted, false);
      assert.equal(err.details.fallbackReason, "manifest_present_but_unusable");
      assert.deepEqual(err.details.matches, [
        "docdexd-linux-x64-gnu-alt.tar.gz",
        "docdexd-linux-x64-gnu.tar.gz"
      ]);
      return true;
    }
  );
});

test("installer falls back deterministically when manifest fetch fails with non-404 and logs stable warning", async () => {
  const base = "https://example.test/releases/download";
  const version = "0.0.0";
  const sha = "c".repeat(64);

  const { logger, warns } = createCapturingLogger();

  const downloadTextFn = async (url) => {
    if (url.endsWith(".json")) throw httpError(500, `upstream error: ${url}`);
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
    manifestCandidateNamesFn: () => ["docdexd-manifest.json"],
    logger
  });

  assert.equal(plan.source, "fallback");
  assert.equal(plan.expectedSha256, sha);
  assert.equal(warns.length, 1);
  assert.match(warns[0], /^\[docdex\] Manifest unavailable; falling back\. Details: \[DOCDEX_MANIFEST_FETCH_FAILED\]/);
});

test("installer falls back deterministically when manifest is too large and logs stable warning", async () => {
  const base = "https://example.test/releases/download";
  const version = "0.0.0";
  const sha = "d".repeat(64);

  const { logger, warns } = createCapturingLogger();

  const downloadTextFn = async (url) => {
    if (url.endsWith(".json")) {
      const err = new Error("too large");
      err.code = "DOCDEX_DOWNLOAD_TOO_LARGE";
      err.maxBytes = 1024;
      err.actualBytes = 2048;
      throw err;
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
    manifestCandidateNamesFn: () => ["docdexd-manifest.json"],
    logger
  });

  assert.equal(plan.source, "fallback");
  assert.equal(plan.expectedSha256, sha);
  assert.equal(warns.length, 1);
  assert.match(warns[0], /^\[docdex\] Manifest unavailable; falling back\. Details: \[DOCDEX_MANIFEST_TOO_LARGE\]/);
});

test("installer fails deterministically when fallback checksums are missing", async () => {
  const base = "https://example.test/releases/download";
  const version = "0.0.0";

  const downloadTextFn = async (url) => {
    if (url.endsWith(".json")) throw httpError(404, `not found: ${url}`);
    if (url.endsWith("SHA256SUMS") || url.endsWith("SHA256SUMS.txt")) throw httpError(404, `not found: ${url}`);
    if (url.endsWith(".sha256")) throw httpError(404, `not found: ${url}`);
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
        manifestCandidateNamesFn: () => ["docdex-release-manifest.json"]
      }),
    (err) => {
      assert.ok(err instanceof ChecksumResolutionError);
      assert.equal(err.code, "DOCDEX_CHECKSUM_UNUSABLE");
      assert.equal(err.details.assetName, "docdexd-linux-x64-gnu.tar.gz");
      assert.ok(Array.isArray(err.details.checksumCandidates));
      assert.ok(err.message.includes("Missing SHA-256 integrity metadata"));
      return true;
    }
  );
});

test("parseSha256File handles common sha256 file formats deterministically", () => {
  const expected = "a".repeat(64);
  const other = "b".repeat(64);
  const text = [
    `${other}  other.tar.gz`,
    `${expected} *docdexd-linux-x64-gnu.tar.gz`,
    ""
  ].join("\n");

  assert.equal(parseSha256File(text, "docdexd-linux-x64-gnu.tar.gz"), expected);
  assert.equal(parseSha256File(`${expected}  docdexd-linux-x64-gnu.tar.gz\r\n`, "docdexd-linux-x64-gnu.tar.gz"), expected);
});

test("verifyDownloadedFileIntegrity is deterministic when integrity check is absent or passes", async () => {
  const filePath = path.join(__dirname, "fixtures", "archive", "fake-archive.bin");
  const actual = await sha256File(filePath);

  await assert.rejects(
    () =>
      verifyDownloadedFileIntegrity({
        filePath,
        expectedSha256: null,
        archiveName: "docdexd-linux-x64-gnu.tar.gz"
      }),
    (err) => {
      assert.equal(err.code, "DOCDEX_CHECKSUM_UNUSABLE");
      return true;
    }
  );

  const res = await verifyDownloadedFileIntegrity({
    filePath,
    expectedSha256: actual,
    archiveName: "docdexd-linux-x64-gnu.tar.gz",
    details: { source: "fallback" }
  });
  assert.equal(res.status, "verified_ok");
  assert.equal(res.expectedSha256, actual);
  assert.equal(res.actualSha256, actual);
});
