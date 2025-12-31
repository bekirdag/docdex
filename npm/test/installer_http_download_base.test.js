"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");

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

  const server = http.createServer((req, res) => {
    if (req.url === `/v${version}/docdexd-manifest.json`) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(manifest));
      return;
    }
    res.statusCode = 404;
    res.end("not found");
  });

  await new Promise((resolve) => server.listen(0, resolve));
  const { port } = server.address();
  const base = `http://127.0.0.1:${port}`;

  try {
    const plan = await resolveInstallerDownloadPlan({
      repoSlug: "local/test",
      version,
      platformKey,
      targetTriple,
      getDownloadBaseFn: () => base,
      manifestCandidateNamesFn: () => ["docdexd-manifest.json"]
    });

    assert.equal(plan.archive, `docdexd-${platformKey}.tar.gz`);
    assert.equal(plan.expectedSha256, expectedSha);
    assert.equal(plan.source, "manifest:docdexd-manifest.json");
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});
