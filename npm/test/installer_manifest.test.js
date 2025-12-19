"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const { ManifestResolutionError } = require("../lib/release_manifest");
const { artifactName } = require("../lib/platform");
const { PLATFORM_MATRIX } = require("../lib/platform_matrix");
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

test("installer resolves manifest assets for published target matrix deterministically", async () => {
  const base = "https://example.test/releases/download";
  const version = "0.0.0";
  const manifestName = "docdex-release-manifest.json";

  const hex = "0123456789abcdef";
  const published = PLATFORM_MATRIX.filter((entry) => entry.published)
    .slice()
    .sort((a, b) => a.platformKey.localeCompare(b.platformKey));

  const targets = {};
  const shaByTriple = new Map();
  for (const [index, entry] of published.entries()) {
    const sha = hex[index % hex.length].repeat(64);
    targets[entry.targetTriple] = {
      asset: { name: artifactName(entry.platformKey) },
      integrity: { sha256: sha }
    };
    shaByTriple.set(entry.targetTriple, sha);
  }

  const manifestText = JSON.stringify({ manifestVersion: 1, targets }, null, 2);
  const downloadTextFn = async (url) => {
    if (url === `${base}/v${version}/${manifestName}`) return manifestText;
    throw httpError(404, `not found: ${url}`);
  };

  for (const entry of published) {
    const plan = await resolveInstallerDownloadPlan({
      repoSlug: "owner/repo",
      version,
      platformKey: entry.platformKey,
      targetTriple: entry.targetTriple,
      downloadTextFn,
      getDownloadBaseFn: () => base,
      manifestCandidateNamesFn: () => [manifestName],
      logger: createCapturingLogger().logger
    });

    assert.equal(plan.archive, artifactName(entry.platformKey));
    assert.equal(plan.expectedSha256, shaByTriple.get(entry.targetTriple));
    assert.equal(plan.source, `manifest:${manifestName}`);
  }
});

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
  assert.equal(plan.assetId, 123);
  assert.equal(plan.integrity.method, "sha256");
  assert.equal(plan.integrity.sourceType, "manifest");
  assert.equal(plan.integrity.sourceName, "docdex-release-manifest.json");
  assert.equal(plan.integrity.sourceUrl, `${base}/v${version}/docdex-release-manifest.json`);
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
  assert.equal(plan.integrity.sourceType, "manifest");
  assert.equal(plan.integrity.sourceName, "docdex-manifest.json");
  assert.equal(plan.integrity.sourceUrl, `${base}/v${version}/docdex-manifest.json`);
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
  assert.equal(plan.integrity.sourceType, "sha256sums");
  assert.equal(plan.integrity.sourceName, "SHA256SUMS");
  assert.equal(plan.integrity.sourceUrl, `${base}/v${version}/SHA256SUMS`);
  assert.deepEqual(logs, ["[docdex] No manifest found; falling back to deterministic asset naming."]);
  assert.deepEqual(warns, [
    "[docdex] Signature not found for SHA256SUMS; proceeding without signature (policy: optional)."
  ]);
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
  assert.equal(plan.integrity.sourceType, "sha256sums");
  assert.equal(plan.integrity.sourceName, "SHA256SUMS");
  assert.equal(plan.integrity.sourceUrl, `${base}/v${version}/SHA256SUMS`);
  assert.deepEqual(logs, []);
  assert.deepEqual(warns, [
    "[docdex] Manifest unavailable; falling back. Details: [DOCDEX_MANIFEST_JSON_INVALID] Malformed manifest (docdexd-manifest.json): invalid JSON",
    "[docdex] Signature not found for SHA256SUMS; proceeding without signature (policy: optional)."
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
  assert.equal(plan.integrity.sourceType, "sha256sums");
  assert.equal(plan.integrity.sourceName, "SHA256SUMS");
  assert.equal(plan.integrity.sourceUrl, `${base}/v${version}/SHA256SUMS`);
  assert.deepEqual(logs, []);
  assert.deepEqual(warns, [
    "[docdex] Manifest unavailable; falling back. Details: [DOCDEX_MANIFEST_UNUSABLE] Manifest unusable (docdexd-manifest.json): DOCDEX_MANIFEST_MALFORMED Malformed manifest: expected `targets` object or `assets` array",
    "[docdex] Signature not found for SHA256SUMS; proceeding without signature (policy: optional)."
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
        detected: { os: "linux", arch: "x64", libc: "gnu" },
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
      assert.equal(err.details.repoSlug, "owner/repo");
      assert.equal(err.details.version, version);
      assert.deepEqual(err.details.detected, { os: "linux", arch: "x64", libc: "gnu" });
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
  assert.equal(warns.length, 2);
  assert.match(warns[0], /\[DOCDEX_MANIFEST_UNUSABLE\]/);
  assert.match(warns[0], /DOCDEX_ASSET_MALFORMED/);
  assert.equal(warns[1], "[docdex] Signature not found for SHA256SUMS; proceeding without signature (policy: optional).");
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
        detected: { os: "linux", arch: "x64", libc: "gnu" },
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
      assert.equal(err.details.repoSlug, "owner/repo");
      assert.equal(err.details.version, version);
      assert.deepEqual(err.details.detected, { os: "linux", arch: "x64", libc: "gnu" });
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
  assert.equal(warns.length, 2);
  assert.match(warns[0], /^\[docdex\] Manifest unavailable; falling back\. Details: \[DOCDEX_MANIFEST_FETCH_FAILED\]/);
  assert.equal(warns[1], "[docdex] Signature not found for SHA256SUMS; proceeding without signature (policy: optional).");
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
  assert.equal(warns.length, 2);
  assert.match(warns[0], /^\[docdex\] Manifest unavailable; falling back\. Details: \[DOCDEX_MANIFEST_TOO_LARGE\]/);
  assert.equal(warns[1], "[docdex] Signature not found for SHA256SUMS; proceeding without signature (policy: optional).");
});

test("installer verifies manifest signature when required and signature is present", async () => {
  const base = "https://example.test/releases/download";
  const version = "0.0.0";

  const originalPolicy = process.env.DOCDEX_SIGNATURE_POLICY;
  const originalKey = process.env.DOCDEX_RELEASE_SIGNING_PUBLIC_KEY;

  try {
    const { generateKeyPairSync, sign } = require("node:crypto");
    const { publicKey, privateKey } = generateKeyPairSync("ed25519");
    process.env.DOCDEX_SIGNATURE_POLICY = "required";
    process.env.DOCDEX_RELEASE_SIGNING_PUBLIC_KEY = publicKey.export({ format: "pem", type: "spki" });

    const manifestText = fixture("manifest/valid-targets.json");
    const signatureB64 = sign(null, Buffer.from(manifestText, "utf8"), privateKey).toString("base64");

    const { logger, logs, warns } = createCapturingLogger();
    const downloadTextFn = async (url) => {
      if (url === `${base}/v${version}/docdex-release-manifest.json`) return manifestText;
      if (url === `${base}/v${version}/docdex-release-manifest.json.sig`) return signatureB64 + "\n";
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

    assert.equal(plan.source, "manifest:docdex-release-manifest.json");
    assert.deepEqual(warns, []);
    assert.ok(logs.some((l) => l.includes("Verified signature for docdex-release-manifest.json")));
  } finally {
    if (originalPolicy === undefined) delete process.env.DOCDEX_SIGNATURE_POLICY;
    else process.env.DOCDEX_SIGNATURE_POLICY = originalPolicy;
    if (originalKey === undefined) delete process.env.DOCDEX_RELEASE_SIGNING_PUBLIC_KEY;
    else process.env.DOCDEX_RELEASE_SIGNING_PUBLIC_KEY = originalKey;
  }
});

test("installer fails closed when required signature is missing", async () => {
  const base = "https://example.test/releases/download";
  const version = "0.0.0";

  const originalPolicy = process.env.DOCDEX_SIGNATURE_POLICY;
  try {
    process.env.DOCDEX_SIGNATURE_POLICY = "required";

    const manifestText = fixture("manifest/valid-targets.json");
    const downloadTextFn = async (url) => {
      if (url === `${base}/v${version}/docdex-release-manifest.json`) return manifestText;
      if (url === `${base}/v${version}/docdex-release-manifest.json.sig`) throw httpError(404, `not found: ${url}`);
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
          logger: createCapturingLogger().logger
        }),
      (err) => {
        assert.equal(err.code, "DOCDEX_INTEGRITY_SIGNATURE_MISSING");
        return true;
      }
    );
  } finally {
    if (originalPolicy === undefined) delete process.env.DOCDEX_SIGNATURE_POLICY;
    else process.env.DOCDEX_SIGNATURE_POLICY = originalPolicy;
  }
});

test("installer fails closed when signature is present but invalid", async () => {
  const base = "https://example.test/releases/download";
  const version = "0.0.0";

  const originalPolicy = process.env.DOCDEX_SIGNATURE_POLICY;
  try {
    process.env.DOCDEX_SIGNATURE_POLICY = "optional";

    const manifestText = fixture("manifest/valid-targets.json");
    const downloadTextFn = async (url) => {
      if (url === `${base}/v${version}/docdex-release-manifest.json`) return manifestText;
      if (url === `${base}/v${version}/docdex-release-manifest.json.sig`) return "not-a-real-signature\n";
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
          logger: createCapturingLogger().logger
        }),
      (err) => {
        assert.equal(err.code, "DOCDEX_INTEGRITY_SIGNATURE_INVALID");
        return true;
      }
    );
  } finally {
    if (originalPolicy === undefined) delete process.env.DOCDEX_SIGNATURE_POLICY;
    else process.env.DOCDEX_SIGNATURE_POLICY = originalPolicy;
  }
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

test("installer policy allow-missing permits missing integrity metadata deterministically", async () => {
  const base = "https://example.test/releases/download";
  const version = "0.0.0";
  const { logger, warns } = createCapturingLogger();

  const downloadTextFn = async (url) => {
    throw httpError(404, `not found: ${url}`);
  };

  const plan = await resolveInstallerDownloadPlan({
    repoSlug: "owner/repo",
    version,
    platformKey: "linux-x64-gnu",
    targetTriple: "x86_64-unknown-linux-gnu",
    integrityPolicy: "allow-missing",
    downloadTextFn,
    getDownloadBaseFn: () => base,
    manifestCandidateNamesFn: () => ["docdex-release-manifest.json"],
    logger
  });

  assert.equal(plan.archive, "docdexd-linux-x64-gnu.tar.gz");
  assert.equal(plan.expectedSha256, null);
  assert.equal(plan.source, "fallback");
  assert.ok(warns.some((line) => line.includes("Missing SHA-256 integrity metadata")));
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

<<<<<<< HEAD
test("verifyDownloadedFileIntegrity fails closed when integrity metadata is absent", async () => {
=======
test("verifyDownloadedFileIntegrity fails closed when integrity metadata is missing and passes when it matches", async () => {
>>>>>>> mcoda/task/ops-01-us-04-t38
  const filePath = path.join(__dirname, "fixtures", "archive", "fake-archive.bin");
  const actual = await sha256File(filePath);
  const archiveName = "docdexd-linux-x64-gnu.tar.gz";

  await assert.rejects(
    () =>
      verifyDownloadedFileIntegrity({
        filePath,
        expectedSha256: null,
<<<<<<< HEAD
<<<<<<< HEAD
        archiveName: "docdexd-linux-x64-gnu.tar.gz"
      }),
    (err) => {
      assert.equal(err.code, "DOCDEX_CHECKSUM_UNUSABLE");
=======
        archiveName: "docdexd-linux-x64-gnu.tar.gz",
        details: { source: "fallback" }
=======
        archiveName
>>>>>>> mcoda/task/ops-01-us-04-t38
      }),
    (err) => {
      assert.ok(err instanceof ChecksumResolutionError);
      assert.equal(err.code, "DOCDEX_CHECKSUM_UNUSABLE");
<<<<<<< HEAD
      assert.equal(err.details.assetName, "docdexd-linux-x64-gnu.tar.gz");
>>>>>>> mcoda/task/ops-01-us-04-t11
=======
      assert.ok(err.message.includes("Missing SHA-256 integrity metadata"));
>>>>>>> mcoda/task/ops-01-us-04-t38
      return true;
    }
  );

<<<<<<< HEAD
  const res = await verifyDownloadedFileIntegrity({
    filePath,
    expectedSha256: actual,
    archiveName: "docdexd-linux-x64-gnu.tar.gz",
    details: { source: "fallback" }
  });
  assert.equal(res.status, "verified_ok");
  assert.equal(res.expectedSha256, actual);
  assert.equal(res.actualSha256, actual);
=======
  assert.equal(
    await verifyDownloadedFileIntegrity({
      filePath,
      expectedSha256: actual,
      archiveName
    }),
    actual
  );
>>>>>>> mcoda/task/ops-01-us-04-t38
});
test("installer policy allow-missing permits missing integrity metadata deterministically", async () => {
  const base = "https://example.test/releases/download";
  const version = "0.0.0";
  const { logger, warns } = createCapturingLogger();

  const downloadTextFn = async (url) => {
    throw httpError(404, `not found: ${url}`);
  };

  const plan = await resolveInstallerDownloadPlan({
    repoSlug: "owner/repo",
    version,
    platformKey: "linux-x64-gnu",
    targetTriple: "x86_64-unknown-linux-gnu",
    integrityPolicy: "allow-missing",
    downloadTextFn,
    getDownloadBaseFn: () => base,
    manifestCandidateNamesFn: () => ["docdex-release-manifest.json"],
    logger
  });

  assert.equal(plan.archive, "docdexd-linux-x64-gnu.tar.gz");
  assert.equal(plan.expectedSha256, null);
  assert.equal(plan.source, "fallback");
  assert.ok(warns.some((line) => line.includes("Missing SHA-256 integrity metadata")));
});

