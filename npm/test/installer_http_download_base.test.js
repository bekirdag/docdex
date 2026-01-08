"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { detectPlatformKey, targetTripleForPlatformKey } = require("../lib/platform");
const { resolveInstallerDownloadPlan } = require("../lib/install");

test("installer supports http download base for local mirrors", async () => {
  const platformKey = detectPlatformKey();
  const targetTriple = targetTripleForPlatformKey(platformKey);
  const version = "0.0.0";
  const expectedSha = "a".repeat(64);

  const manifest = {
    manifestVersion: 1,
    generatedAt: new Date().toISOString(),
    targets: {
      [targetTriple]: {
        asset: { name: `docdexd-${platformKey}.tar.gz` },
        integrity: { sha256: expectedSha, size: 1 }
      }
    }
  };

  const base = "http://local.test";
  const expectedManifestUrl = `${base}/v${version}/docdexd-manifest.json`;
  let requestedUrl = null;

  const plan = await resolveInstallerDownloadPlan({
    repoSlug: "local/test",
    version,
    platformKey,
    targetTriple,
    getDownloadBaseFn: () => base,
    manifestCandidateNamesFn: () => ["docdexd-manifest.json"],
    downloadTextFn: async (url) => {
      requestedUrl = url;
      if (url === expectedManifestUrl) {
        return JSON.stringify(manifest);
      }
      const err = new Error(`Download failed (404) from ${url}`);
      err.statusCode = 404;
      err.url = url;
      throw err;
    }
  });

  assert.equal(requestedUrl, expectedManifestUrl);
  assert.equal(plan.archive, `docdexd-${platformKey}.tar.gz`);
  assert.equal(plan.expectedSha256, expectedSha);
  assert.equal(plan.source, "manifest:docdexd-manifest.json");
});
